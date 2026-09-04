// Warm-up and compaction: rebuilding the spill file while preserving live
// (stale-servable) records and loading the hottest entries into memory.

package spillfile

import (
	"cmp"
	"container/heap"
	"encoding/binary"
	"maps"
	"os"
	"slices"
)

// Warm selects the newest max records across both regions (keep filters
// stale/unwanted ones), reads their wires, and returns them ordered
// coldest-first — callers inserting front-to-back into an LRU end with the
// hottest entry at the front.  The second return is the number of live
// (non-deleted, non-superseded, keep-passing) records.
//
// One sequential pass over the sorted-region blocks (pooled buffers) plus
// the tail map — cheaper than the Entries() + sort + per-key Get sequence
// it replaced.
//
// Stale records are skipped, not tombstoned — dead weight stays on disk
// until the next Compact, which the caller already schedules.
func (s *Store) Warm(topN int, keep func(ts int64, ttl int) bool) (entries []WarmEntry, live int) {
	if topN < 0 {
		topN = 0
	}
	h := make(warmHeap, 0, min(topN, 1024))
	consider := func(e Entry) {
		if !keep(e.Ts, e.Ttl) {
			return
		}
		live++
		if topN == 0 {
			return
		}
		if h.Len() < topN {
			heap.Push(&h, e)
			return
		}
		if e.Ts > h[0].Ts {
			h[0] = e
			heap.Fix(&h, 0)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, te := range s.tailMap {
		if te.deleted {
			continue
		}
		consider(Entry{Key: k, Ts: te.ts, Ttl: te.ttl, Validated: te.validated, WireOff: te.wireOff, WireLen: te.wireLen})
	}
	for _, blk := range s.sparse {
		buf := acquireBlockBuf(int(blk.blockEnd - blk.blockStart))
		block := buf[:blk.blockEnd-blk.blockStart]
		if _, err := s.f.ReadAt(block, blk.blockStart); err != nil {
			releaseBlockBuf(block)
			continue
		}
		scanBlock(blk.blockStart, block, func(key string, ts int64, ttl int, validated bool, wireOff int64, wireLen int) bool {
			if _, inTail := s.tailMap[key]; inTail {
				return true // superseded by a tail entry, or tombstoned
			}
			consider(Entry{Key: key, Ts: ts, Ttl: ttl, Validated: validated, WireOff: wireOff, WireLen: int32(wireLen)}) //nolint:gosec // G115: wire length bounded by maxWireLen
			return true
		})
		releaseBlockBuf(block)
	}

	// Coldest-first order for LRU insertion.
	slices.SortFunc(h, func(a, b Entry) int { return cmp.Compare(a.Ts, b.Ts) })
	out := make([]WarmEntry, 0, len(h))
	for _, e := range h {
		wire := make([]byte, e.WireLen)
		if _, err := s.f.ReadAt(wire, e.WireOff); err != nil {
			continue // unreadable — drop rather than hand out a zero wire
		}
		out = append(out, WarmEntry{Key: e.Key, Ts: e.Ts, Ttl: e.Ttl, Validated: e.Validated, Wire: wire})
	}
	return out, live
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
	keys := slices.Sorted(maps.Keys(byKey))

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
