// Cache core: the Store implementation struct, construction (two-tier
// wiring), lifecycle (Close/Flush) and entry counters.
package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/spillfile"
	"zjdns/internal/stats"
	"zjdns/internal/ttl"
)

// Cache is an in-memory DNS response cache backed by an LRU map, with an
// optional disk spill tier.  It implements the Store interface.

type Cache struct {
	entries    *lrumap.Map[cacheKey, *cacheEntry] // cache key → entry
	maxEntries int
	statsMgr   *stats.Journal // in-memory query stats + per-RCODE top-N journal

	// spill is the second-tier disk store: evicted-but-fresh entries land
	// here and are promoted back on a memory miss.  nil when no state_file
	// is configured (single-tier mode).
	spill    *spillfile.Store
	spillCap int // spill file record cap (≤0 = unbounded)

	// spillW drains eviction writes off the entries-mutex: OnEvict runs
	// under the lrumap lock, where a synchronous WriteAt froze every
	// concurrent Get/Set for the IO duration (2026-09 D2).
	spillW *spillfile.AsyncWriter

	// hasLatencyData gates sortAnswerByLatency: when false (no latency data has
	// ever been written), the per-hit latency lookup is skipped entirely.
	hasLatencyData atomic.Bool

	// latencyGen is the latency-table generation: bumped on every
	// UpdateLatency so per-entry sorted-wire caches can detect staleness
	// without re-reading the latency map.
	latencyGen atomic.Uint64

	// latencies holds per-IP latency data — written by background latency
	// probes, read on the cache-hit hot path (sortAnswerByLatency).  LRU-
	// bounded (latencyMax), TTL-expired lazily on read and physically
	// cleaned by CleanupLatency.
	latencies  *lrumap.Map[string, latEntry]
	latencyMax int

	// spillLat is the latency-table spill tier (same role as spill).
	spillLat    *spillfile.Store
	spillLatCap int

	// spillLatW drains latency-tier eviction writes (same reason as spillW).
	spillLatW *spillfile.AsyncWriter

	closeOnce sync.Once
}

// cacheEntry is one cached DNS response.  msgWire is the pre-packed response
// (format 0x02) with TTL-offset table.  TTL expiry is checked lazily on read.

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap batched IPs per latency lookup
	decompressBufCap    = 4096

	// cacheFormatPrePacked is the BLOB format marker for pre-packed response
	// wire with TTL offset table (format 0x02).
	cacheFormatPrePacked = 0x02

	// dnssecFlagMask is the top bit of the 2-byte num_offsets field in the
	// pre-packed BLOB (bit 7 of msgWire[1]): set when the wire carries
	// DNSSEC record types.  The remaining 15 bits hold the offset count.
	dnssecFlagMask = 0x8000

	// maxSortedWireCache bounds the per-entry latency-sorted wire cache:
	// responses above this size skip caching (a second copy would double
	// large-entry memory) and re-sort per hit instead.
	maxSortedWireCache = 1024

	// maxTTLOffsets caps pooled TTL-offset slices: responses beyond this RR
	// count allocate fresh instead of growing the pool entry (large
	// DNSSEC/ANY responses exceed it routinely).
	maxTTLOffsets = 16
)

// (<= 0 applies the config defaults).  A non-empty spill path enables the
// disk tier for that store: the spill file is opened and its hottest
// entries (by store timestamp) are loaded into memory, up to the mem cap;
// the rest stay on disk and are promoted back on a memory miss.
func New(entriesLimit, latencyLimit config.LimitSettings, spillPath, latencySpillPath string) *Cache {
	maxEntries := entriesLimit.Mem
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxCacheEntries
	}
	latencyMax := latencyLimit.Mem
	if latencyMax <= 0 {
		latencyMax = config.DefaultMaxLatencyEntries
	}
	c := &Cache{
		// Sharded: every query's Get/Set (hit or miss) touches these maps —
		// a single LRU mutex serialised the whole server at high QPS.
		entries:    lrumap.NewSharded[cacheKey, *cacheEntry](maxEntries),
		maxEntries: maxEntries,
		statsMgr:   stats.NewJournal(0),
		latencies:  lrumap.NewSharded[string, latEntry](latencyMax),
		latencyMax: latencyMax,
	}
	c.loadSpill(spillPath, entriesLimit.Disk, maxEntries)
	c.loadLatencySpill(latencySpillPath, latencyLimit.Disk, latencyMax)
	return c
}

func (s *Cache) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.spill != nil {
			if e := s.spill.Close(); e != nil && err == nil {
				err = e
			}
		}
		if s.spillLat != nil {
			if e := s.spillLat.Close(); e != nil && err == nil {
				err = e
			}
		}
	})
	return err
}

// Flush pushes every in-memory entry to its spill store (skipping records
// already on disk unchanged) and fsyncs — called at shutdown so a restart
// warms from disk.  No-op without a disk tier.
func (s *Cache) Flush() {
	// Drain the async writers first so the Indexed check below sees the
	// queued eviction writes; bounded by the shutdown timeout — a stalled
	// disk must not hang shutdown indefinitely (2026-09 D6).
	drainCtx, drainCancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
	defer drainCancel()
	if s.spillW != nil {
		s.spillW.Close(drainCtx)
	}
	if s.spillLatW != nil {
		s.spillLatW.Close(drainCtx)
	}
	// Snapshot the maps under their locks, run the disk IO outside them —
	// Flush overlaps the drain window where in-flight queries still look
	// up the cache (holding the lock per entry stalled them all).
	if s.spill != nil {
		type row struct {
			key cacheKey
			ce  *cacheEntry
		}
		var rows []row
		s.entries.Range(func(key cacheKey, ce *cacheEntry) bool {
			rows = append(rows, row{key, ce})
			return true
		})
		for _, r := range rows {
			if r.ce.ts > 0 && ttl.CanServeExpired(r.ce.ts, r.ce.ttl, config.DefaultStaleMaxAge) && !s.spill.Indexed(r.key.encode(), r.ce.ts) {
				if err := s.spill.Put(r.key.encode(), r.ce.ts, r.ce.ttl, r.ce.validated, r.ce.msgWire); err != nil {
					log.Debugf("CACHE: spill flush: %v", err)
				}
			}
		}
	}
	if s.spillLat != nil {
		type row struct {
			key string
			e   latEntry
		}
		var rows []row
		s.latencies.Range(func(key string, e latEntry) bool {
			rows = append(rows, row{key, e})
			return true
		})
		for _, r := range rows {
			if r.e.lastProbe > 0 && !s.spillLat.Indexed(r.key, r.e.lastProbe) {
				if err := s.spillLat.Put(r.key, r.e.lastProbe, 0, false, marshalLatency(r.e)); err != nil {
					log.Debugf("CACHE: latency spill flush %s: %v", r.key, err)
				}
			}
		}
	}
	if s.spill != nil {
		_ = s.spill.Flush() // _ = error: best-effort fsync, Close reports hard errors
	}
	if s.spillLat != nil {
		_ = s.spillLat.Flush() // _ = error: best-effort fsync, Close reports hard errors
	}
}

// EntryCount returns the number of cached entries.
func (s *Cache) EntryCount() int { return s.entries.Len() }

// LatencyCount returns the number of per-IP latency entries.
func (s *Cache) LatencyCount() int { return s.latencies.Len() }
