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
	"sync/atomic"
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

// fileRef is the immutable handle snapshot taken by every reader before it
// leaves the metadata lock: preads run against the snapshot, so a Compact
// swapping the file handle never races an in-flight read.  internal/poll
// guarantees ops on a closed *os.File fail with ErrClosed (no fd-reuse
// hazard), so a reader that loaded the old snapshot across a swap self-heals
// to a miss.
type fileRef struct {
	f *os.File
}

// Store is a sorted-region + tail-region key-value store.
type Store struct {
	path string

	// fref is the current file handle.  Readers snapshot it under mu and
	// pread OUTSIDE the lock (the former Get/Indexed held mu across every
	// pread, serializing all spill reads behind disk latency — and the
	// delegation-promote path on the recursive hot route takes these reads).
	fref atomic.Pointer[fileRef]

	// wmu serializes structural writers (Put/Delete/Compact): Compact holds
	// it across its lock-free rewrite so a concurrent Put cannot append to
	// the old file's tail after the metadata snapshot (records would be
	// lost at the swap).  Reads never take wmu.
	wmu sync.Mutex

	mu        sync.Mutex // guards sparse, tailMap, tail, sortedEnd
	sparse    []sparseEntry
	tailMap   map[string]tailEntry
	tail      int64 // next append offset (== physical EOF)
	sortedEnd int64 // byte boundary between the sorted and tail regions

	// neg memoizes full-miss keys (repeated ECS-variant misses re-reading
	// blocks); invalidated by Put/Delete and cleared by Compact/Clear.
	negMu sync.Mutex
	neg   map[string]struct{}

	// retired holds the previous file generation after a Compact (POSIX:
	// the renamed-away inode stays readable through the open handle, so
	// readers still holding the old snapshot never observe ErrClosed).  It
	// is closed one Compact later — no reader can plausibly hold a snapshot
	// across a full compact cycle — and by Close.
	retired *fileRef
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

	// negCacheMax bounds the memoized-miss map; hitting the cap resets it
	// wholesale (a re-derived miss costs one block read).
	negCacheMax = 8192
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
	st := &Store{path: path, tailMap: make(map[string]tailEntry)}
	st.fref.Store(&fileRef{f: f})
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
	st := &Store{path: path, tailMap: make(map[string]tailEntry)}
	st.fref.Store(&fileRef{f: f})
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

	// wmu first (lock order wmu→mu everywhere): during a Compact the append
	// waits for the swap and then lands on the NEW file with the NEW tail.
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	off := s.tail
	ref := s.fref.Load()
	if _, err := ref.f.WriteAt(rec, off); err != nil {
		s.mu.Unlock()
		return err
	}
	s.tail += int64(len(rec))
	s.tailMap[key] = tailEntry{
		ts: ts, ttl: ttl, validated: validated,
		wireOff: off + int64(recordHeaderLen+len(key)), wireLen: int32(len(wire)), //nolint:gosec // G115: wire length bounded by maxWireLen
	}
	s.mu.Unlock()
	s.forgetMiss(key)
	return nil
}

// Delete removes key from the store.  A record in the tail region is marked
// deleted in the tail map; a record in the sorted region gets a tombstone.
// The physical record stays on disk until the next merge.
func (s *Store) Delete(key string) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forgetMiss(key)
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
	// Memoized miss: repeated absent keys (ECS variants of the same qname)
	// used to re-pay the lock + block pread every time.  Put/Delete
	// invalidate, so a remembered miss cannot mask a fresh record.
	if s.hasMiss(key) {
		return 0, 0, false, nil, false
	}

	// Metadata phase under mu; the pread runs OUTSIDE the lock against a
	// snapshotted handle (see fileRef).  The former design held mu across
	// every pread — Compact's full-file rewrite under the same lock paused
	// all spill reads for its whole duration.
	s.mu.Lock()
	te, found := s.tailMap[key]
	var blk sparseEntry
	if !found {
		idx := sort.Search(len(s.sparse), func(i int) bool { return s.sparse[i].firstKey > key })
		if idx == 0 {
			s.mu.Unlock()
			s.rememberMiss(key)
			return 0, 0, false, nil, false
		}
		blk = s.sparse[idx-1]
	}
	ref := s.fref.Load()
	s.mu.Unlock()

	if found {
		if te.deleted {
			return 0, 0, false, nil, false
		}
		wire = make([]byte, te.wireLen)
		if _, err := ref.f.ReadAt(wire, te.wireOff); err != nil {
			return 0, 0, false, nil, false
		}
		return te.ts, te.ttl, te.validated, wire, true
	}

	// Sorted region: one pread for the target block, parsed sequentially.
	buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
	block := buf[:blk.blockEnd-blk.blockStart]
	defer releaseBlockBuf(block)
	if _, err := ref.f.ReadAt(block, blk.blockStart); err != nil {
		return 0, 0, false, nil, false
	}
	rts, rttl, rvalidated, rwire, found := lookupInBlock(block, key)
	if !found {
		s.rememberMiss(key)
		return 0, 0, false, nil, false
	}
	return rts, rttl, rvalidated, append([]byte(nil), rwire...), true
}

// hasMiss reports whether key is memoized absent.
func (s *Store) hasMiss(key string) bool {
	s.negMu.Lock()
	_, hit := s.neg[key]
	s.negMu.Unlock()
	return hit
}

// rememberMiss memoizes a full miss, bounding the map by wholesale reset —
// negative results are cheap to re-derive (one block read).
func (s *Store) rememberMiss(key string) {
	s.negMu.Lock()
	if s.neg == nil {
		s.neg = make(map[string]struct{}, negCacheMax)
	}
	if len(s.neg) >= negCacheMax {
		s.neg = make(map[string]struct{}, negCacheMax)
	}
	s.neg[key] = struct{}{}
	s.negMu.Unlock()
}

// forgetMiss drops a memoized miss after a Put or Delete made the key
// potentially present again.
func (s *Store) forgetMiss(key string) {
	s.negMu.Lock()
	delete(s.neg, key)
	s.negMu.Unlock()
}

// resetMisses clears the memo — called when the record set is rebuilt.
func (s *Store) resetMisses() {
	s.negMu.Lock()
	s.neg = nil
	s.negMu.Unlock()
}

// Indexed reports whether the store holds a record for key with exactly the
// given timestamp — used by callers to avoid re-appending unchanged entries
// during a full-memory flush.
func (s *Store) Indexed(key string, ts int64) bool {
	// Metadata under mu, pread outside — same protocol as Get.
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
	ref := s.fref.Load()
	s.mu.Unlock()

	buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
	block := buf[:blk.blockEnd-blk.blockStart]
	defer releaseBlockBuf(block)
	if _, err := ref.f.ReadAt(block, blk.blockStart); err != nil {
		return false
	}
	rts, _, _, _, found := lookupInBlock(block, key)
	return found && rts == ts
}

// Entries returns a snapshot of all indexed records (unordered).  A key in
// both regions appears once — the tail record supersedes the sorted one,
// and tombstoned keys are absent entirely.  Metadata is snapshotted under
// mu and the block reads run outside it — same protocol as Get, so a full
// scan never stalls concurrent Get/Set/Put.
func (s *Store) Entries() []Entry {
	s.mu.Lock()
	out := make([]Entry, 0, len(s.tailMap)+s.sortedRecordCount())
	tail := make(map[string]struct{}, len(s.tailMap))
	for k, te := range s.tailMap {
		tail[k] = struct{}{} // tombstoned keys must still suppress the sorted copy
		if te.deleted {
			continue
		}
		out = append(out, Entry{Key: k, Ts: te.ts, Ttl: te.ttl, Validated: te.validated, WireOff: te.wireOff, WireLen: te.wireLen})
	}
	blocks := append([]sparseEntry(nil), s.sparse...)
	ref := s.fref.Load()
	s.mu.Unlock()

	for _, blk := range blocks {
		buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
		block := buf[:blk.blockEnd-blk.blockStart]
		if _, err := ref.f.ReadAt(block, blk.blockStart); err != nil {
			releaseBlockBuf(block)
			continue
		}
		scanBlock(blk.blockStart, block, func(key string, ts int64, ttl int, validated bool, wireOff int64, wireLen int) bool {
			if _, inTail := tail[key]; inTail {
				return true // superseded by a tail entry, or tombstoned
			}
			out = append(out, Entry{Key: key, Ts: ts, Ttl: ttl, Validated: validated, WireOff: wireOff, WireLen: int32(wireLen)}) //nolint:gosec // G115: wire length bounded by maxWireLen
			return true
		})
		releaseBlockBuf(block)
	}
	return out
}

// Clear removes all records (index + file truncated back to the header).
func (s *Store) Clear() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	ref := s.fref.Load()
	if err := s.writeHeader(int64(headerLen), 0); err != nil {
		return err
	}
	if err := ref.f.Truncate(int64(headerLen)); err != nil {
		return err
	}
	s.tail = int64(headerLen)
	s.sortedEnd = int64(headerLen)
	s.sparse = nil
	s.tailMap = make(map[string]tailEntry)
	s.resetMisses()
	return nil
}

// Flush fsyncs the file — called periodically and on shutdown for
// durability (Put only reaches the page cache).  The fsync runs without mu:
// holding it stalls every Get/Set/Put for the full disk sync.
func (s *Store) Flush() error {
	return s.fref.Load().f.Sync()
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	ref := s.fref.Load()
	err := ref.f.Sync()
	if cerr := ref.f.Close(); err == nil {
		err = cerr
	}
	retired := s.retired
	s.retired = nil
	s.mu.Unlock()
	if retired != nil {
		_ = retired.f.Close()
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
// keys (a full-key scan — called only at startup and in tests).  Metadata
// is snapshotted under mu; the block reads run outside it.
func (s *Store) EntryCount() int {
	s.mu.Lock()
	n := 0
	tail := make(map[string]struct{}, len(s.tailMap))
	for k, te := range s.tailMap {
		tail[k] = struct{}{}
		if !te.deleted {
			n++
		}
	}
	blocks := append([]sparseEntry(nil), s.sparse...)
	ref := s.fref.Load()
	s.mu.Unlock()

	for _, blk := range blocks {
		buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
		block := buf[:blk.blockEnd-blk.blockStart]
		if _, err := ref.f.ReadAt(block, blk.blockStart); err != nil {
			releaseBlockBuf(block)
			continue
		}
		scanBlock(blk.blockStart, block, func(key string, _ int64, _ int, _ bool, _ int64, _ int) bool {
			if _, inTail := tail[key]; !inTail {
				n++
			}
			return true
		})
		releaseBlockBuf(block)
	}
	return n
}
