// Package spillfile provides a sorted, disk-backed key-value store used as
// the second tier of the DNS cache.  Records are written key-sorted into
// fixed-size blocks (the "sorted region"); a sparse in-memory index holds one
// entry per block (~10 B/record).  Appends since the last merge land in an
// unsorted tail
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
	"fmt"
	"math"
	"os"
	"sort"
	"sync"
)

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

// WarmEntry is one record selected by Warm with its wire read into memory.
// Wire is owned by the caller.
type WarmEntry struct {
	Key       string
	Ts        int64
	Ttl       int
	Validated bool
	Wire      []byte
}

// warmHeap is a min-heap on Ts over at most topN candidates: the root is the
// coldest of the current top-N set and is evicted whenever a newer record
// arrives (top-K newest selection in O(n log max) instead of a full sort).
type warmHeap []Entry

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

// Corruption guards — record lengths come from the file, so a corrupt or
// tampered spill file must not drive an unbounded allocation (M3).
const (
	// maxKeyLen is the exact uint16 domain — a key of len 65536 would wrap
	// the length field to 0 and write a record the scanner treats as
	// corrupt, truncating the file tail on the next open.
	maxKeyLen  = math.MaxUint16
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

	// scanBufBytes is the sequential-scan read buffer: large enough that
	// the per-record read syscalls of the unbuffered scan amortise away on
	// multi-GB spill files.
	scanBufBytes = 1 << 20
)

// Tiered block-buffer pools for the spill-hit hot path: the single-tier pool
// grew every buffer to the largest block it ever served (~64 KB at
// blockRecords × 500 B) and kept them — ~2400 retained 64 KB buffers pinned
// 155 MB live on a loaded server.  Tiering mirrors pool/udp.go's packetBuf
// pattern: per-size-class pools keyed by capacity, so a small tail block
// reuses a small buffer and the working set tracks actual block sizes.
const (
	blockBufSmall  = 4 * 1024         // small stores and trailing (short) blocks
	blockBufMedium = 64 * 1024        // nominal block size: blockRecords(128) × ~500 B
	blockBufLarge  = maxBlockBufBytes // 256 KB — pathological blocks, pool cap
)

var (
	blockBufSmallPool = sync.Pool{
		New: func() any {
			b := make([]byte, 0, blockBufSmall)
			return &b
		},
	}
	blockBufMediumPool = sync.Pool{
		New: func() any {
			b := make([]byte, 0, blockBufMedium)
			return &b
		},
	}
	blockBufLargePool = sync.Pool{
		New: func() any {
			b := make([]byte, 0, blockBufLarge)
			return &b
		},
	}
)

func (h warmHeap) Len() int { return len(h) }

func (h warmHeap) Less(i, j int) bool { return h[i].Ts < h[j].Ts }

func (h warmHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *warmHeap) Push(x any) { *h = append(*h, x.(Entry)) }

func (h *warmHeap) Pop() any { old := *h; n := len(old); e := old[n-1]; *h = old[:n-1]; return e }

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

// Create truncates path and returns an empty store. Tests use it to build
// fixtures; production paths open via Open.
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
	// The whole read runs under s.mu: Compact (also under s.mu) closes and
	// reassigns s.f — a ReadAt released from the lock raced that swap and
	// could read through the closed handle or at generation-stale offsets.
	// pread is thread-safe and page-cache-fast, and the bulk
	// operations (Entries/Warm/Compact) already hold this mutex across IO.
	s.mu.Lock()
	defer s.mu.Unlock()
	// Tail region: O(1) map lookup.
	if te, found := s.tailMap[key]; found {
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
		return 0, 0, false, nil, false
	}
	blk := s.sparse[idx-1]

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

// Indexed reports whether the store holds a record for key with exactly the
// given timestamp — used by callers to avoid re-appending unchanged entries
// during a full-memory flush.
func (s *Store) Indexed(key string, ts int64) bool {
	// Under s.mu for the same Compact-race reason as Get.
	s.mu.Lock()
	defer s.mu.Unlock()
	if te, found := s.tailMap[key]; found {
		return !te.deleted && te.ts == ts
	}
	idx := sort.Search(len(s.sparse), func(i int) bool { return s.sparse[i].firstKey > key })
	if idx == 0 {
		return false
	}
	blk := s.sparse[idx-1]

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
