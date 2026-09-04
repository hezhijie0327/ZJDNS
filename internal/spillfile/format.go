// On-disk spill format: the sparse-index and tail-record layout, block
// buffer pooling, record encode/scan primitives, and the index scanner.

package spillfile

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// Magic distinguishes a spill file from any other state file.  Deliberately
// distinct from the retired snapfile magic ("ZJNS") — an old snapshot must
// never be parsed as a record stream.
const Magic = "ZJSP"

// Version is the file layout version.
const Version = 2

// acquireBlockBuf returns a buffer of at least n bytes from the smallest
// tier that fits; oversized blocks allocate fresh (never pooled).
func acquireBlockBuf(n int) []byte {
	switch {
	case n <= blockBufSmall:
		bp := blockBufSmallPool.Get().(*[]byte)
		return (*bp)[:n]
	case n <= blockBufMedium:
		bp := blockBufMediumPool.Get().(*[]byte)
		return (*bp)[:n]
	case n <= blockBufLarge:
		bp := blockBufLargePool.Get().(*[]byte)
		return (*bp)[:n]
	default:
		return make([]byte, n)
	}
}

// releaseBlockBuf returns a tiered block buffer to its class pool; buffers
// that grew in place to odd sizes (the old single-tier pool's retention
// source) are dropped for the GC.  No clear: the only consumers fill the
// requested range with ReadAt before reading, so stale bytes are never
// observed (a memset per 64KB block read cost ~55% on BenchmarkGetSorted).
func releaseBlockBuf(b []byte) {
	switch cap(b) {
	case blockBufSmall:
		bp := &b
		*bp = (*bp)[:blockBufSmall]
		blockBufSmallPool.Put(bp)
	case blockBufMedium:
		bp := &b
		*bp = (*bp)[:blockBufMedium]
		blockBufMediumPool.Put(bp)
	case blockBufLarge:
		bp := &b
		*bp = (*bp)[:blockBufLarge]
		blockBufLargePool.Put(bp)
	}
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

	// br buffers the sequential scan: unbuffered per-record reads cost
	// two read syscalls plus a Seek per record.  A large sequential buffer
	// amortises them to
	// ~1 per scanBufBytes; skipping the wire via Discard reads it through
	// the page cache instead of seeking past it, which the sequential
	// readahead had pulled in anyway.
	br := bufio.NewReaderSize(s.f, scanBufBytes)
	var keyLenBuf [2]byte
	// recBuf is reused across readRecord calls: the per-record buffers
	// (keyBuf make + 4 fixed-field buffers + string copies) were ~19M
	// allocations on a 6.7M-record spill file.  The string(rec[:keyLen])
	// conversion still copies — the map keys must outlive the reused buffer.
	recBuf := make([]byte, 0, recordHeaderLen-2+256)
	pos := int64(headerLen)
	blockStart := pos
	var firstKey string
	records := 0
	// readRecord reads the key and fixed fields of the record at the current
	// scan position (tracked manually — the fd position is meaningless under
	// the buffered reader), skipping the wire without allocating.  Returns
	// false on EOF/truncation/corruption — the caller drops the tail there.
	readRecord := func() (key string, ts int64, ttl int, validated bool, wireLen int, ok bool) {
		if _, err := io.ReadFull(br, keyLenBuf[:]); err != nil {
			return "", 0, 0, false, 0, false
		}
		keyLen := int(binary.BigEndian.Uint16(keyLenBuf[:]))
		if keyLen == 0 || keyLen > maxKeyLen {
			return "", 0, 0, false, 0, false
		}
		need := recordHeaderLen - 2 + keyLen // key + ts(8) + ttl(4) + flags(1) + wire_len(4)
		if cap(recBuf) < need {
			recBuf = make([]byte, need)
		} else {
			recBuf = recBuf[:need]
		}
		if _, err := io.ReadFull(br, recBuf); err != nil {
			return "", 0, 0, false, 0, false
		}
		ts = int64(binary.BigEndian.Uint64(recBuf[keyLen : keyLen+8]))   //nolint:gosec // G115: unix seconds fit int64
		ttl = int(binary.BigEndian.Uint32(recBuf[keyLen+8 : keyLen+12])) //nolint:gosec // G115: ttl is uint32, fits int on all platforms
		validated = recBuf[keyLen+12]&1 != 0
		wireLen = int(binary.BigEndian.Uint32(recBuf[keyLen+13 : keyLen+17])) //nolint:gosec // G115: wire length bounded by maxWireLen
		if wireLen > maxWireLen {
			return "", 0, 0, false, 0, false
		}
		// Skip the wire; the bound check preserves the EOF semantics (a
		// record claiming bytes past the physical EOF is corrupt).
		if pos+recordHeaderLen+int64(keyLen)+int64(wireLen) > s.tail {
			return "", 0, 0, false, 0, false
		}
		if _, err := br.Discard(wireLen); err != nil {
			return "", 0, 0, false, 0, false
		}
		return string(recBuf[:keyLen]), ts, ttl, validated, wireLen, true
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
		if wireLen > maxWireLen { // 32-bit int overflow hardening (F15)
			return 0, 0, false, nil, false
		}
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
		if wireLen > maxWireLen { // 32-bit int overflow hardening (F15)
			return false
		}
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
