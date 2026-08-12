// Package spillfile provides a sorted, disk-backed key-value store used as
// the second tier of the DNS cache.  Records are written key-sorted into
// fixed-size blocks (the "sorted region"); a sparse in-memory index holds one
// entry per block, replacing the former full key hash index (~105 B/record)
// with ~10 B/record.  Appends since the last merge land in an unsorted tail
// region covered by a bounded in-memory map; a merge (Compact) folds the tail
// into the sorted region atomically (temp + rename).
//
// Record layout (all big-endian):
//
//	[2B key_len][key][8B ts][4B ttl][1B flags][4B wire_len][wire]
//
// flags bit 0 = validated.  The key is stored verbatim — the store is
// opaque to the wire bytes, so entries, latency and delegation stores can
// share it.  A superseded key (Put twice) keeps one index entry; the
// duplicate record stays on disk until the next merge.
//
// File layout (version 2):
//
//	[header 17B: magic(4) + version(1) + sortedEnd(8) + blockCount(4)]
//	[sorted region: key-sorted records, blockRecords per block]
//	[tail region: unsorted records appended since the last merge]
package spillfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
)

// sparseEntry locates one sorted block: its first key (the binary-search
// key), its byte range in the file and its record count.
type sparseEntry struct {
	firstKey   string
	blockStart int64
	blockEnd   int64
	records    int32
}

// tailEntry is the in-memory index entry for one record in the tail region
// (appended since the last merge).  deleted marks a tombstone: the key was
// Delete()d and its sorted-region record must not be served.
type tailEntry struct {
	ts        int64
	ttl       int
	validated bool
	wireOff   int64
	wireLen   int32
	deleted   bool
}

// Entry is a snapshot of one indexed record, used by callers for startup
// ordering and compaction decisions.
type Entry struct {
	Key       string
	Ts        int64
	Ttl       int
	Validated bool
	WireOff   int64
	WireLen   int32
}

// Store is a sorted-region + tail-region key-value store.
type Store struct {
	f    *os.File
	path string

	mu        sync.Mutex // guards sparse, tailMap, tail, sortedEnd
	sparse    []sparseEntry
	tailMap   map[string]tailEntry
	tail      int64 // next append offset (== physical EOF)
	sortedEnd int64 // byte boundary between the sorted and tail regions
}

// Magic distinguishes a spill file from any other state file.  Deliberately
// distinct from the retired snapfile magic ("ZJNS") — an old snapshot must
// never be parsed as a record stream.
const Magic = "ZJSP"

// Version is the file layout version.
const Version = 2

// Corruption guards — record lengths come from the file, so a corrupt or
// tampered spill file must not drive an unbounded allocation (M3).
const (
	maxKeyLen  = 1 << 16 // 64 KiB — uint16 key length field bound
	maxWireLen = 1 << 24 // 16 MiB — DNS responses are far smaller

	// headerLen = magic(4) + version(1) + sortedEnd(8) + blockCount(4).
	headerLen = 4 + 1 + 8 + 4

	// recordHeaderLen = key_len(2) + ts(8) + ttl(4) + flags(1) + wire_len(4).
	recordHeaderLen = 2 + 8 + 4 + 1 + 4

	// blockRecords is the record count per sorted block — ~64 KB at the
	// ~500 B average record, balancing sparse-index size (blocks × 70 B in
	// RAM) against per-lookup block reads.
	blockRecords = 128

	// maxBlockBufBytes caps pooled block buffers: oversized blocks
	// (pathological records) allocate fresh instead of growing the pool.
	maxBlockBufBytes = 256 * 1024
)

// blockBufPool reuses sorted-block read buffers on the spill-hit hot path.
var blockBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// acquireBlockBuf returns a buffer of at least n bytes from the pool.
func acquireBlockBuf(n int) []byte {
	bp := blockBufPool.Get().(*[]byte)
	if cap(*bp) < n {
		b := make([]byte, n)
		blockBufPool.Put(bp)
		return b
	}
	return (*bp)[:n]
}

// releaseBlockBuf returns a pooled block buffer; buffers grown beyond the
// pool cap are dropped rather than grown in place.
func releaseBlockBuf(b []byte) {
	if cap(b) <= maxBlockBufBytes {
		blockBufPool.Put(&b)
	}
}

// Open opens the spill file at path and rebuilds the in-memory structures by
// scanning it: the sorted region into the sparse index, the tail region into
// the tail map.  A missing file is created empty (cold start).  A foreign
// header or corrupt record returns an error — callers should treat the
// store as unusable rather than overwrite a possibly-salvageable file.
// A truncated trailing record is dropped (the file is cut back to the last
// complete record) since appends are atomic per record.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return nil, err
	}
	st := &Store{f: f, path: path, tailMap: make(map[string]tailEntry)}
	if err := st.scan(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return st, nil
}

// Create truncates path and returns an empty store (used by tests and Clear).
func Create(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return nil, err
	}
	st := &Store{f: f, path: path, tailMap: make(map[string]tailEntry)}
	if err := st.writeHeader(int64(headerLen), 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	st.sortedEnd = int64(headerLen)
	st.tail = int64(headerLen)
	return st, nil
}

// writeHeader writes the file header: magic + version + sortedEnd + blockCount.
func (s *Store) writeHeader(sortedEnd int64, blockCount int32) error {
	buf := make([]byte, headerLen)
	copy(buf, Magic)
	buf[len(Magic)] = Version
	binary.BigEndian.PutUint64(buf[len(Magic)+1:], uint64(sortedEnd))    //nolint:gosec // G115: sortedEnd is a file offset — fits uint64
	binary.BigEndian.PutUint32(buf[len(Magic)+1+8:], uint32(blockCount)) //nolint:gosec // G115: block count bounded by file records
	_, err := s.f.WriteAt(buf, 0)
	return err
}

// scan rebuilds the sparse index and tail map from the file, dropping a
// truncated trailing record and any record that follows a corrupt one
// (append-order trust).
func (s *Store) scan() error {
	var header [headerLen]byte
	n, err := io.ReadFull(s.f, header[:])
	if errors.Is(err, io.EOF) {
		// Fresh empty file — initialise the header.
		if err := s.writeHeader(int64(headerLen), 0); err != nil {
			return err
		}
		s.sortedEnd = int64(headerLen)
		s.tail = int64(headerLen)
		return nil
	}
	if err != nil || n != headerLen {
		return fmt.Errorf("spillfile: corrupt header (%d bytes)", n)
	}
	if string(header[:len(Magic)]) != Magic {
		return errors.New("spillfile: foreign or corrupt header")
	}
	if header[len(Magic)] != Version {
		return fmt.Errorf("spillfile: unsupported version %d (want %d)", header[len(Magic)], Version)
	}
	sortedEnd := int64(binary.BigEndian.Uint64(header[len(Magic)+1:]))    //nolint:gosec // G115: file offsets fit int64
	blockCount := int32(binary.BigEndian.Uint32(header[len(Magic)+1+8:])) //nolint:gosec // G115: block count bounded by file records
	fi, err := s.f.Stat()
	if err != nil {
		return err
	}
	if sortedEnd < headerLen || sortedEnd > fi.Size() || blockCount < 0 {
		return errors.New("spillfile: corrupt header fields")
	}

	s.sortedEnd = sortedEnd
	s.tail = fi.Size()
	s.sparse = make([]sparseEntry, 0, blockCount)

	var (
		keyLenBuf  [2]byte
		tsBuf      [8]byte
		ttlBuf     [4]byte
		flagBuf    [1]byte
		wireLenBuf [4]byte
	)
	pos := int64(headerLen)
	blockStart := pos
	var firstKey string
	records := 0
	// readRecord reads the fixed fields of the record at the current fd
	// position, skipping the wire without allocating.  Returns false on
	// EOF/truncation/corruption — the caller drops the tail there.
	readRecord := func() (key string, ts int64, ttl int, validated bool, wireLen int, ok bool) {
		if _, err := io.ReadFull(s.f, keyLenBuf[:]); err != nil {
			return "", 0, 0, false, 0, false
		}
		keyLen := int(binary.BigEndian.Uint16(keyLenBuf[:]))
		if keyLen == 0 || keyLen > maxKeyLen {
			return "", 0, 0, false, 0, false
		}
		keyBuf := make([]byte, keyLen)
		if _, err := io.ReadFull(s.f, keyBuf); err != nil {
			return "", 0, 0, false, 0, false
		}
		if _, err := io.ReadFull(s.f, tsBuf[:]); err != nil {
			return "", 0, 0, false, 0, false
		}
		if _, err := io.ReadFull(s.f, ttlBuf[:]); err != nil {
			return "", 0, 0, false, 0, false
		}
		if _, err := io.ReadFull(s.f, flagBuf[:]); err != nil {
			return "", 0, 0, false, 0, false
		}
		if _, err := io.ReadFull(s.f, wireLenBuf[:]); err != nil {
			return "", 0, 0, false, 0, false
		}
		wireLen = int(binary.BigEndian.Uint32(wireLenBuf[:]))
		if wireLen > maxWireLen {
			return "", 0, 0, false, 0, false
		}
		if _, err := io.CopyN(io.Discard, s.f, int64(wireLen)); err != nil {
			return "", 0, 0, false, 0, false
		}
		return string(keyBuf),
			int64(binary.BigEndian.Uint64(tsBuf[:])), //nolint:gosec // G115: unix seconds fit int64
			int(binary.BigEndian.Uint32(ttlBuf[:])),
			flagBuf[0]&1 != 0,
			wireLen, true
	}

	// Sorted region: group records into blocks for the sparse index.
	for pos < s.sortedEnd {
		off := pos
		key, _, _, _, wireLen, ok := readRecord()
		if !ok {
			// Corrupt record — fold the in-progress partial block into the
			// sparse index, then cut the file back (append-order trust).
			if records > 0 {
				s.sparse = append(s.sparse, sparseEntry{firstKey: firstKey, blockStart: blockStart, blockEnd: off, records: int32(records)})
			}
			return s.truncateAt(off)
		}
		if records == 0 {
			blockStart = off
			firstKey = key
		}
		records++
		recLen := int64(recordHeaderLen + len(key) + wireLen)
		if records == blockRecords {
			s.sparse = append(s.sparse, sparseEntry{firstKey: firstKey, blockStart: blockStart, blockEnd: off + recLen, records: blockRecords})
			records = 0
		}
		pos = off + recLen
	}
	// Partial trailing block of the sorted region (merge output is block-
	// aligned, so this is the last, possibly short block).
	if records > 0 {
		s.sparse = append(s.sparse, sparseEntry{firstKey: firstKey, blockStart: blockStart, blockEnd: pos, records: int32(records)})
	}

	// Tail region: every record maps into the tail map (later Puts supersede
	// earlier ones by position).
	for pos < s.tail {
		off := pos
		key, ts, ttl, validated, wireLen, ok := readRecord()
		if !ok {
			return s.truncateAt(off)
		}
		recLen := int64(recordHeaderLen + len(key) + wireLen)
		s.tailMap[key] = tailEntry{
			ts: ts, ttl: ttl, validated: validated,
			wireOff: off + int64(recordHeaderLen+len(key)), wireLen: int32(wireLen), //nolint:gosec // G115: wire length bounded by maxWireLen
		}
		pos = off + recLen
	}
	return nil
}

// truncateAt cuts the file back to off, dropping a trailing partial or
// corrupt record and everything after it.  In the sorted region the header is
// patched so sortedEnd never exceeds the new file size (the next Open would
// reject it as corrupt otherwise).  Returns nil (scan continues from the
// good prefix).
func (s *Store) truncateAt(off int64) error {
	if err := s.f.Truncate(off); err != nil {
		return err
	}
	s.tail = off
	if off < s.sortedEnd {
		s.sortedEnd = off
		return s.writeHeader(s.sortedEnd, int32(len(s.sparse))) //nolint:gosec // G115: block count bounded by file records
	}
	return nil
}

// recordBytes serialises one record (see package doc for the layout).
func recordBytes(key string, ts int64, ttl int, validated bool, wire []byte) []byte {
	rec := make([]byte, 0, recordHeaderLen+len(key)+len(wire))
	var buf [8]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(key))) //nolint:gosec // G115: key length bounded by maxKeyLen
	rec = append(rec, buf[:2]...)
	rec = append(rec, key...)
	binary.BigEndian.PutUint64(buf[:], uint64(ts)) //nolint:gosec // G115: unix seconds fit uint64
	rec = append(rec, buf[:8]...)
	binary.BigEndian.PutUint32(buf[:4], uint32(ttl)) //nolint:gosec // G115: TTL bounded by config cap
	rec = append(rec, buf[:4]...)
	flags := byte(0)
	if validated {
		flags = 1
	}
	rec = append(rec, flags)
	binary.BigEndian.PutUint32(buf[:4], uint32(len(wire))) //nolint:gosec // G115: wire length bounded by maxWireLen
	rec = append(rec, buf[:4]...)
	rec = append(rec, wire...)
	return rec
}

// Put appends one record to the tail region and updates the tail map.  The
// write is synchronous to the page cache (no per-write fsync — call Flush
// for durability).  A later Put of the same key supersedes the tail entry.
func (s *Store) Put(key string, ts int64, ttl int, validated bool, wire []byte) error {
	if key == "" || len(key) > maxKeyLen || len(wire) > maxWireLen {
		return fmt.Errorf("spillfile: record out of bounds: key=%d wire=%d", len(key), len(wire))
	}
	rec := recordBytes(key, ts, ttl, validated, wire)

	s.mu.Lock()
	defer s.mu.Unlock()
	off := s.tail
	if _, err := s.f.WriteAt(rec, off); err != nil {
		return err
	}
	s.tail += int64(len(rec))
	s.tailMap[key] = tailEntry{
		ts: ts, ttl: ttl, validated: validated,
		wireOff: off + int64(recordHeaderLen+len(key)), wireLen: int32(len(wire)), //nolint:gosec // G115: wire length bounded by maxWireLen
	}
	return nil
}

// Delete removes key from the store.  A record in the tail region is marked
// deleted in the tail map; a record in the sorted region gets a tombstone.
// The physical record stays on disk until the next merge.
func (s *Store) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if te, found := s.tailMap[key]; found {
		te.deleted = true
		s.tailMap[key] = te
		return
	}
	s.tailMap[key] = tailEntry{deleted: true}
}

// Get returns the record for key.  ok is false when the key is absent or the
// record can no longer be read (corrupted — treated as a miss).  The
// returned wire slice is owned by the caller.
//
// The tail map is checked first (O(1)); a sorted-region miss binary-searches
// the sparse index (~10 steps for 2000 blocks), reads the target block in one
// pread and parses it sequentially.
func (s *Store) Get(key string) (ts int64, ttl int, validated bool, wire []byte, ok bool) {
	// Tail region: O(1) map lookup.
	s.mu.Lock()
	if te, found := s.tailMap[key]; found {
		s.mu.Unlock()
		if te.deleted {
			return 0, 0, false, nil, false
		}
		wire = make([]byte, te.wireLen)
		if _, err := s.f.ReadAt(wire, te.wireOff); err != nil {
			return 0, 0, false, nil, false
		}
		return te.ts, te.ttl, te.validated, wire, true
	}
	// Sorted region: binary-search the sparse index, then parse the block.
	idx := sort.Search(len(s.sparse), func(i int) bool { return s.sparse[i].firstKey > key })
	if idx == 0 {
		s.mu.Unlock()
		return 0, 0, false, nil, false
	}
	blk := s.sparse[idx-1]
	s.mu.Unlock()

	buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
	block := buf[:blk.blockEnd-blk.blockStart]
	defer releaseBlockBuf(block)
	if _, err := s.f.ReadAt(block, blk.blockStart); err != nil {
		return 0, 0, false, nil, false
	}
	rts, rttl, rvalidated, rwire, found := lookupInBlock(block, key)
	if !found {
		return 0, 0, false, nil, false
	}
	return rts, rttl, rvalidated, append([]byte(nil), rwire...), true
}

// lookupInBlock parses the record stream in buf (one sorted block) and
// returns the record matching key.  The returned wire points INTO buf —
// callers must copy before releasing the buffer.  ok=false when the key is
// absent or the block is corrupt.
func lookupInBlock(buf []byte, key string) (ts int64, ttl int, validated bool, wire []byte, ok bool) {
	keyBytes := []byte(key)
	pos := 0
	for pos < len(buf) {
		if pos+recordHeaderLen+2 > len(buf) {
			return 0, 0, false, nil, false
		}
		keyLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
		if keyLen == 0 || keyLen > maxKeyLen || pos+recordHeaderLen+keyLen > len(buf) {
			return 0, 0, false, nil, false
		}
		wireLen := int(binary.BigEndian.Uint32(buf[pos+15+keyLen : pos+19+keyLen]))
		recLen := recordHeaderLen + keyLen + wireLen
		if pos+recLen > len(buf) {
			return 0, 0, false, nil, false
		}
		recKey := buf[pos+2 : pos+2+keyLen]
		switch bytes.Compare(recKey, keyBytes) {
		case 0:
			return int64(binary.BigEndian.Uint64(buf[pos+2+keyLen : pos+10+keyLen])), //nolint:gosec // G115: unix seconds fit int64
				int(binary.BigEndian.Uint32(buf[pos+10+keyLen : pos+14+keyLen])),
				buf[pos+14+keyLen]&1 != 0,
				buf[pos+19+keyLen : pos+recLen], true
		case 1:
			// Sorted order — the key cannot appear later in this block.
			return 0, 0, false, nil, false
		}
		pos += recLen
	}
	return 0, 0, false, nil, false
}

// scanBlock parses every record of one sorted block, calling fn for each
// (wireOff is the record's wire byte offset in the file).  Returns false
// when the block is corrupt.
func scanBlock(blockStart int64, buf []byte, fn func(key string, ts int64, ttl int, validated bool, wireOff int64, wireLen int) bool) bool {
	pos := 0
	for pos < len(buf) {
		if pos+2 > len(buf) {
			return false
		}
		keyLen := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
		if keyLen == 0 || keyLen > maxKeyLen || pos+recordHeaderLen+keyLen > len(buf) {
			return false
		}
		wireLen := int(binary.BigEndian.Uint32(buf[pos+15+keyLen : pos+19+keyLen]))
		recLen := recordHeaderLen + keyLen + wireLen
		if pos+recLen > len(buf) {
			return false
		}
		if !fn(string(buf[pos+2:pos+2+keyLen]),
			int64(binary.BigEndian.Uint64(buf[pos+2+keyLen:pos+10+keyLen])), //nolint:gosec // G115: unix seconds fit int64
			int(binary.BigEndian.Uint32(buf[pos+10+keyLen:pos+14+keyLen])),
			buf[pos+14+keyLen]&1 != 0,
			blockStart+int64(pos)+int64(recordHeaderLen+keyLen), wireLen) {
			return true
		}
		pos += recLen
	}
	return true
}

// Indexed reports whether the store holds a record for key with exactly the
// given timestamp — used by callers to avoid re-appending unchanged entries
// during a full-memory flush.
func (s *Store) Indexed(key string, ts int64) bool {
	s.mu.Lock()
	if te, found := s.tailMap[key]; found {
		s.mu.Unlock()
		return !te.deleted && te.ts == ts
	}
	idx := sort.Search(len(s.sparse), func(i int) bool { return s.sparse[i].firstKey > key })
	if idx == 0 {
		s.mu.Unlock()
		return false
	}
	blk := s.sparse[idx-1]
	s.mu.Unlock()

	buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
	block := buf[:blk.blockEnd-blk.blockStart]
	defer releaseBlockBuf(block)
	if _, err := s.f.ReadAt(block, blk.blockStart); err != nil {
		return false
	}
	rts, _, _, _, found := lookupInBlock(block, key)
	return found && rts == ts
}

// Entries returns a snapshot of all indexed records (unordered).  A key in
// both regions appears once — the tail record supersedes the sorted one,
// and tombstoned keys are absent entirely.
func (s *Store) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, len(s.tailMap)+s.sortedRecordCount())
	for k, te := range s.tailMap {
		if te.deleted {
			continue
		}
		out = append(out, Entry{Key: k, Ts: te.ts, Ttl: te.ttl, Validated: te.validated, WireOff: te.wireOff, WireLen: te.wireLen})
	}
	for _, blk := range s.sparse {
		buf := make([]byte, blk.blockEnd-blk.blockStart)
		if _, err := s.f.ReadAt(buf, blk.blockStart); err != nil {
			continue
		}
		scanBlock(blk.blockStart, buf, func(key string, ts int64, ttl int, validated bool, wireOff int64, wireLen int) bool {
			if _, inTail := s.tailMap[key]; inTail {
				return true // superseded by a tail entry, or tombstoned
			}
			out = append(out, Entry{Key: key, Ts: ts, Ttl: ttl, Validated: validated, WireOff: wireOff, WireLen: int32(wireLen)}) //nolint:gosec // G115: wire length bounded by maxWireLen
			return true
		})
	}
	return out
}

// Compact rewrites the file keeping exactly the records for which keep
// returns true, atomically (temp + rename).  The merge folds the tail region
// into the sorted region, deduplicates (newest ts wins; the tail record wins
// ts ties — it was appended later), and rebuilds the sparse index.  Keep is
// called with the map mutex held; it must not call back into the store.
// Records are visited in key order.
func (s *Store) Compact(keep func(key string, ts int64, ttl int) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pass 1: collect metadata for every live record (no wire bytes — the
	// old file is read per-record during the write pass, keeping the
	// transient memory at O(records) headers instead of O(payload)).
	type meta struct {
		key       string
		ts        int64
		ttl       int
		validated bool
		wireOff   int64
		wireLen   int32
	}
	metas := make([]meta, 0, len(s.tailMap)+s.sortedRecordCount())
	for k, te := range s.tailMap {
		if te.deleted {
			continue
		}
		metas = append(metas, meta{key: k, ts: te.ts, ttl: te.ttl, validated: te.validated, wireOff: te.wireOff, wireLen: te.wireLen})
	}
	for _, blk := range s.sparse {
		buf := make([]byte, blk.blockEnd-blk.blockStart)
		if _, err := s.f.ReadAt(buf, blk.blockStart); err != nil {
			continue
		}
		scanBlock(blk.blockStart, buf, func(key string, ts int64, ttl int, validated bool, wireOff int64, wireLen int) bool {
			if _, inTail := s.tailMap[key]; inTail {
				return true // superseded by a tail entry, or tombstoned
			}
			metas = append(metas, meta{key: key, ts: ts, ttl: ttl, validated: validated, wireOff: wireOff, wireLen: int32(wireLen)}) //nolint:gosec // G115: wire length bounded by maxWireLen
			return true
		})
	}

	// Pass 2: filter with keep, dedup by key, sort by key.
	byKey := make(map[string]meta, len(metas))
	for _, m := range metas {
		if !keep(m.key, m.ts, m.ttl) {
			continue
		}
		if old, dup := byKey[m.key]; !dup || m.ts > old.ts || (m.ts == old.ts && m.wireOff > old.wireOff) {
			byKey[m.key] = m
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Pass 3: write the new file, key-sorted in blocks.
	tmp := s.path + ".tmp"
	tf, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename

	// Placeholder header written first — the records must not be clobbered
	// when the final sortedEnd/blockCount are patched in below.
	hdr := make([]byte, headerLen)
	if _, err := tf.Write(hdr); err != nil {
		_ = tf.Close()
		return err
	}

	newSparse := make([]sparseEntry, 0, (len(keys)+blockRecords-1)/blockRecords)
	tail := int64(headerLen)
	blockStart := tail
	var firstKey string
	records := 0
	// dropped=true when the record was unreadable — skipped, not an error.
	writeRec := func(m meta) (dropped bool, err error) {
		wire := make([]byte, m.wireLen)
		if _, err := s.f.ReadAt(wire, m.wireOff); err != nil {
			return true, nil //nolint:nilerr // unreadable record — drop it
		}
		rec := recordBytes(m.key, m.ts, m.ttl, m.validated, wire)
		if _, err := tf.Write(rec); err != nil {
			return false, err
		}
		if records == 0 {
			blockStart = tail
			firstKey = m.key
		}
		records++
		if records == blockRecords {
			newSparse = append(newSparse, sparseEntry{firstKey: firstKey, blockStart: blockStart, blockEnd: tail + int64(len(rec)), records: blockRecords})
			records = 0
		}
		tail += int64(len(rec))
		return false, nil
	}
	for _, k := range keys {
		if _, err := writeRec(byKey[k]); err != nil {
			_ = tf.Close()
			return err
		}
	}
	if records > 0 {
		newSparse = append(newSparse, sparseEntry{firstKey: firstKey, blockStart: blockStart, blockEnd: tail, records: int32(records)})
	}

	// Patch the placeholder header: sortedEnd == EOF (the tail region is
	// empty after a merge).
	copy(hdr, Magic)
	hdr[len(Magic)] = Version
	binary.BigEndian.PutUint64(hdr[len(Magic)+1:], uint64(tail))             //nolint:gosec // G115: file offsets fit uint64
	binary.BigEndian.PutUint32(hdr[len(Magic)+1+8:], uint32(len(newSparse))) //nolint:gosec // G115: block count bounded by file records
	if _, err := tf.WriteAt(hdr, 0); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		return err
	}
	if err := tf.Close(); err != nil {
		return err
	}
	// Windows cannot rename over an open file — close the old handle first
	// (harmless on POSIX, where the rename would have succeeded anyway).
	if err := s.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		// Reopen the original file so the store stays usable after a failed
		// rename (the tmp file is removed by the deferred cleanup).
		nf, openErr := os.OpenFile(s.path, os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
		if openErr == nil {
			s.f = nf
		}
		return err
	}

	nf, err := os.OpenFile(s.path, os.O_RDWR, 0o644) //nolint:gosec // G304: path from trusted config
	if err != nil {
		return err
	}
	s.f = nf
	s.sparse = newSparse
	s.tailMap = make(map[string]tailEntry)
	s.sortedEnd = tail
	s.tail = tail
	return nil
}

// Clear removes all records (index + file truncated back to the header).
func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writeHeader(int64(headerLen), 0); err != nil {
		return err
	}
	if err := s.f.Truncate(int64(headerLen)); err != nil {
		return err
	}
	s.tail = int64(headerLen)
	s.sortedEnd = int64(headerLen)
	s.sparse = nil
	s.tailMap = make(map[string]tailEntry)
	return nil
}

// Flush fsyncs the file — called periodically and on shutdown for
// durability (Put only reaches the page cache).
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Sync()
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.f.Sync()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// FileSize returns the current file size in bytes (including the header).
func (s *Store) FileSize() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tail
}

// sortedRecordCount returns the total number of records across all sparse
// blocks.  Caller must hold mu.
func (s *Store) sortedRecordCount() int {
	n := 0
	for _, b := range s.sparse {
		n += int(b.records)
	}
	return n
}

// EntryCount returns the number of indexed records, excluding tombstoned
// keys (a full-key scan — called only at startup and in tests).
func (s *Store) EntryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, te := range s.tailMap {
		if !te.deleted {
			n++
		}
	}
	for _, blk := range s.sparse {
		buf := make([]byte, blk.blockEnd-blk.blockStart)
		if _, err := s.f.ReadAt(buf, blk.blockStart); err != nil {
			continue
		}
		scanBlock(blk.blockStart, buf, func(key string, _ int64, _ int, _ bool, _ int64, _ int) bool {
			if _, inTail := s.tailMap[key]; !inTail {
				n++
			}
			return true
		})
	}
	return n
}
