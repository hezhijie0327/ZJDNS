// Spill-file loading, promotion, and store accessors for the two-tier
// cache (entries + latency).
package cache

import (
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/spillfile"
	"zjdns/internal/ttl"
)

// loadSpill opens the entries spill store and warms memory with its hottest
// entries.  On failure (foreign/corrupt file) the disk tier is disabled —
// the cache still works, just single-tier.
func (s *Cache) loadSpill(path string, diskCap, maxEntries int) {
	if path == "" {
		return
	}
	spill, err := spillfile.Open(path)
	if err != nil {
		log.Warnf("CACHE: spill store open failed (disk tier disabled): %v", err)
		return
	}
	s.spill = spill
	s.spillCap = diskCap

	// Single-pass warm-up: top-maxEntries newest records, wires read by
	// exact offset (see Store.Warm).  Stale records are skipped in-memory —
	// their disk weight is reclaimed by the periodic compaction.
	warmed, onDisk := spill.Warm(maxEntries, func(ts int64, entryTTL int) bool {
		return ttl.CanServeExpired(ts, entryTTL, config.DefaultStaleMaxAge)
	})
	for _, w := range warmed {
		// Coldest first so the hottest entry ends up at the LRU front.
		// Keys were encoded by cacheKey.encode on eviction; undecodable
		// (pre-struct-key legacy) records stay unread until compaction.
		key, ok := decodeCacheKey(w.Key)
		if !ok {
			continue
		}
		s.entries.Set(key, &cacheEntry{msgWire: w.Wire, ts: w.Ts, ttl: w.Ttl, validated: w.Validated})
	}
	// Spill-on-evict registered AFTER the warm-up load — load-time capacity
	// evictions must not re-spill the very entries just read back.  The
	// write itself is queued to the async writer: OnEvict runs under the
	// entries mutex and a synchronous Put here froze all cache lookups
	// during the write (and queued behind a Compact for its whole rewrite)
	// (2026-09 D2).  Queue-full drops are counted and re-derivable.
	s.spillW = spillfile.NewAsyncWriter(spill)
	s.entries.SetOnEvict(func(key cacheKey, ce *cacheEntry) {
		if ce.ts > 0 && ttl.CanServeExpired(ce.ts, ce.ttl, config.DefaultStaleMaxAge) {
			s.spillW.Enqueue(key.encode(), ce.ts, ce.ttl, ce.validated, ce.msgWire)
		}
	})
	log.Infof("CACHE: spill store ready: %d records on disk, %d loaded to memory", onDisk, len(warmed))
}

// Close flushes and closes the spill stores (the in-memory LRUs need no
// cleanup).  Idempotent — a second Close returns nil instead of
// os.ErrClosed from the spill stores (2026-09 D15).

// getFromSpill reads a spill record by key and promotes it to memory.  An
// expired record is dropped from the index (the file record lingers until
// compaction).  Returns (entry, false) on miss or expiry.
func (s *Cache) getFromSpill(key cacheKey) (*cacheEntry, bool) {
	enc := key.encode()
	ts, entryTTL, validated, wire, ok := s.spill.Get(enc)
	if !ok {
		return nil, false
	}
	if !ttl.CanServeExpired(ts, entryTTL, config.DefaultStaleMaxAge) {
		s.spill.Delete(enc)
		return nil, false
	}
	ce := &cacheEntry{msgWire: wire, ts: ts, ttl: entryTTL, validated: validated}
	s.entries.Set(key, ce)
	return ce, true
}

// SpillStore returns the entries spill store (nil in single-tier mode) —
// used by the server's state maintenance for compaction.
func (s *Cache) SpillStore() *spillfile.Store { return s.spill }

// SpillCap returns the entries spill record cap (≤0 = unbounded).
func (s *Cache) SpillCap() int { return s.spillCap }

// LatencySpillStore returns the latency spill store (nil in single-tier
// mode).
func (s *Cache) LatencySpillStore() *spillfile.Store { return s.spillLat }

// LatencySpillCap returns the latency spill record cap (≤0 = unbounded).
func (s *Cache) LatencySpillCap() int { return s.spillLatCap }
