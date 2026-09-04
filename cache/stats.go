package cache

import (
	"fmt"
	"net"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/stats"
	"zjdns/internal/ttl"
)

// RecordRequest updates the in-memory query statistics (atomic counters) and,
// for non-hit results, the per-RCODE top-N domain journal. Pure memory — no
// allocation beyond the journal map — so it never blocks or fails the
// query hot path. Stats are not persisted: counters reset on restart. The
// caller must pass a canonical qname (dnsutil.Canonical) in r.Qname.
func (s *Cache) RecordRequest(r *stats.RequestRecord) {
	if r == nil || s.statsMgr == nil {
		return
	}
	s.statsMgr.Record(r)
}

// FlushDB resets a single store: "stats" (in-memory counters), "querylog"
// (in-memory per-RCODE journal), "cache" (entries), "latency" (in-memory
// latency map), "delegation" (in-memory delegation cache), or "zone"
// (in-memory zone rules).
func (s *Cache) FlushDB(target string) (int64, error) {
	// All stores are pure memory.
	switch target {
	case "stats":
		if s.statsMgr != nil {
			s.statsMgr.ResetCounters()
		}
	case "querylog":
		if s.statsMgr != nil {
			s.statsMgr.ResetJournal()
		}
	case "cache":
		// Detach the evict callback for the wipe: Clear() fires OnEvict per
		// entry, which would enqueue one spill write each (a syscall under
		// the entries mutex) only for the file below to be truncated right
		// after — and an async queued write could even land after the
		// truncate, resurrecting wiped entries (2026-09 D5).
		s.entries.SetOnEvict(nil)
		s.entries.Clear()
		if s.spill != nil {
			if err := s.spill.Clear(); err != nil {
				log.Warnf("CACHE: spill clear failed: %v", err)
			}
		}
		if s.spillW != nil {
			s.entries.SetOnEvict(func(key cacheKey, ce *cacheEntry) {
				if ce.ts > 0 && ttl.CanServeExpired(ce.ts, ce.ttl, config.DefaultStaleMaxAge) {
					s.spillW.Enqueue(key.encode(), ce.ts, ce.ttl, ce.validated, ce.msgWire)
				}
			})
		}
	case "latency":
		// Clear in place (lrumap is internally locked) — replacing the map
		// pointer unsynchronized would race the cache-hit hot path and the
		// latency-probe goroutines (H4).  Evict callback detached for the
		// wipe, same reason as the cache tier (2026-09 D5).
		s.latencies.SetOnEvict(nil)
		s.latencies.Clear()
		s.hasLatencyData.Store(false)
		if s.spillLat != nil {
			if err := s.spillLat.Clear(); err != nil {
				log.Warnf("CACHE: latency spill clear failed: %v", err)
			}
		}
		if s.spillLatW != nil {
			s.latencies.SetOnEvict(func(key string, e latEntry) {
				if e.lastProbe > 0 {
					s.spillLatW.Enqueue(key, e.lastProbe, 0, false, marshalLatency(e))
				}
			})
		}
	case "delegation", "zone":
		// Not owned by the cache store — no-op (kept for interface parity).
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
	return 0, nil
}

// Clear resets the whole store: entries and latency data, plus the
// in-memory stats counters and per-RCODE journal.
func (s *Cache) Clear() (int64, error) {
	n1, err := s.FlushDB("cache")
	if err != nil {
		return 0, err
	}
	n2, err := s.FlushDB("stats")
	if err != nil {
		return n1, err
	}
	n3, err := s.FlushDB("querylog")
	if err != nil {
		return n1 + n2, err
	}
	n4, err := s.FlushDB("delegation")
	if err != nil {
		return n1 + n2 + n3, err
	}
	n5, err := s.FlushDB("latency")
	if err != nil {
		return n1 + n2 + n3 + n4, err
	}
	return n1 + n2 + n3 + n4 + n5, nil
}

// Stats returns aggregated cache statistics as formatted TXT records.
//
// Reads the in-memory statsjournal snapshot.  O(1) counters plus a
// per-RCODE top-N sort, so Stats() is cheap regardless of query volume.
func (s *Cache) Stats() []string {
	if s.statsMgr == nil {
		return nil
	}
	return s.statsMgr.FormatLines(int64(s.entries.Len()))
}

// StatsRcode returns the per-RCODE top-N domain journal lines — the
// highest-count domain names per RCODE.  Served by the zjdns.stats.rcode
// CHAOS query, separate from the aggregated Stats() output.
func (s *Cache) StatsRcode() []string {
	if s.statsMgr == nil {
		return nil
	}
	return s.statsMgr.FormatRcodeLines()
}

// UpdateLatency stores a latency measurement keyed by IP only. All domains
// sharing the same IP reuse the same entry — latency is measured once, not
// once per domain.  New measurements are smoothed via integer EWMA
// (srtt = (srtt + rtt) / N) to suppress single-sample jitter; the first
// probe for an IP or an expired entry is stored directly.
func (s *Cache) UpdateLatency(ip string, latencyMS int) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	if net.ParseIP(ip) == nil {
		// Flag AFTER validation: a non-IP arg previously enabled the
		// per-hit latency sort with an empty table that can never reorder
		// anything (D16).
		return
	}
	s.UpdateLatencyBatch(map[string]int{ip: latencyMS})
}

// UpdateLatencyBatch stores a batch of latency measurements and bumps the
// latency generation ONCE when any smoothed value changed — a probe round
// touching N IPs must not invalidate every per-entry sorted-wire cache N
// times.  Entries whose IPs kept their smoothed value (stable RTTs) keep
// serving their cached sort across probe rounds.
func (s *Cache) UpdateLatencyBatch(values map[string]int) {
	if len(values) == 0 {
		return
	}
	s.hasLatencyData.Store(true)

	now := log.NowUnix()
	changed := false
	for ip, latencyMS := range values {
		if latencyMS < 0 {
			latencyMS = 0
		}
		if net.ParseIP(ip) == nil {
			// Flag AFTER validation: a non-IP arg previously enabled the
			// per-hit latency sort with an empty table that can never reorder
			// anything (D16).
			continue
		}
		oldLatency, hadOld := -1, false
		if old, ok := s.latencies.Get(ip); ok {
			if old.lastProbe > 0 && old.lastProbe >= now-defaultStaleMaxAge {
				// Unbiased integer EWMA: srtt = ((N-1)·srtt + rtt) / N.  The
				// naive (srtt + rtt) / N form converges to rtt/(N-1) for
				// N > 2 — a systematic underestimate — so N must weight the
				// previous value.
				latencyMS = ((config.DefaultLatencyProbeSmoothFactor-1)*old.latency + latencyMS) / config.DefaultLatencyProbeSmoothFactor
			}
			oldLatency, hadOld = old.latency, true
		}
		s.latencies.Set(ip, latEntry{latency: latencyMS, lastProbe: now})
		if !hadOld || oldLatency != latencyMS {
			changed = true
		}
	}
	if changed {
		// Bump the latency generation: per-entry sorted-wire caches built
		// under an older generation are stale and rebuild on their next hit.
		s.latencyGen.Add(1)
	}
}

// LatencyLastProbe returns the last probe time for an IP. Returns (0, false)
// if the IP has never been probed or its entry is older than the stale
// window (lazy expiry on read).
// A memory miss is retried against the latency spill tier (promoting on hit).
func (s *Cache) LatencyLastProbe(ip string) (int64, bool) {
	e, ok := s.latencies.Get(ip)
	if !ok && s.spillLat != nil {
		if lat, spillOK := s.getLatencyFromSpill(ip); spillOK {
			e, ok = lat, true
		}
	}
	if !ok {
		return 0, false
	}
	// Note: lastProbe==0 is ambiguous (never probed vs. fresh entry) — both
	// trigger a probe, which is harmless for fresh entries.
	if e.lastProbe == 0 || e.lastProbe < log.NowUnix()-defaultStaleMaxAge {
		return 0, false
	}
	return e.lastProbe, true
}

// PruneQueryJournal is a no-op: the query journal is pure memory (per-RCODE
// top-N counters, bounded by topk capacity) and never grows beyond its bound,
// so there is nothing to prune.  Kept to satisfy StoreLifecycle and its
// existing callers.
func (s *Cache) PruneQueryJournal(retentionSec int64) (int64, error) {
	return 0, nil
}
