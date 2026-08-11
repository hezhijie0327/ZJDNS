package cache

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/topk"
)

// statsMetric is a single (name, count, percentage) entry for the stats TXT
// output.  Zero-count entries are omitted by formatStatsLine.
type statsMetric struct {
	name  string
	count int64
	pct   float64
}

// RecordRequest updates the in-memory query statistics (atomic counters) and,
// for non-hit results, the per-RCODE top-N domain journal. Pure memory — no
// SQL, no allocation beyond the journal map — so it never blocks or fails the
// query hot path. Stats are not persisted: counters reset on restart. The
// caller must pass a canonical qname (dnsutil.Canonical) in r.Qname.
func (s *Cache) RecordRequest(r *RequestRecord) {
	if r == nil || s.statsMgr == nil {
		return
	}
	s.statsMgr.Record(&Record{
		Qname:        r.Qname,
		Result:       r.Result,
		Protocol:     r.Protocol,
		Rcode:        r.Rcode,
		ResponseTime: r.ResponseTime,
		DNSSECStatus: r.DNSSECStatus,
		Poisoned:     r.Poisoned,
	})
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
		s.entries.Clear()
	case "latency":
		// Clear in place (lrumap is internally locked) — replacing the map
		// pointer unsynchronized would race the cache-hit hot path and the
		// latency-probe goroutines (H4).
		s.latencies.Clear()
		s.hasLatencyData.Store(false)
	case "delegation", "zone":
		// Not owned by the cache store — no-op (kept for interface parity).
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
	return 0, nil
}

// Clear resets the whole store: entries, delegations, ip_latency, plus the
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
// Reads the in-memory statsjournal snapshot — no SQL.  O(1) counters plus a
// per-RCODE top-N sort, so Stats() is cheap regardless of query volume.
func (s *Cache) Stats() []string {
	if s.statsMgr == nil {
		return nil
	}

	snap := s.statsMgr.Snapshot(int64(s.entries.Len()))
	total := snap.Total
	totalMS := snap.TotalMS

	var avgMs float64
	if total > 0 {
		avgMs = float64(totalMS) / float64(total)
	}

	// Percentages relative to total (DNSSEC rows relative to the validated
	// subset, mirroring the partitioned selfdb stats layout).
	pct := func(v int64) float64 {
		if total == 0 {
			return 0
		}
		return float64(v) / float64(total) * 100
	}
	hitR, missR, staleR, zoneR := pct(snap.Hits), pct(snap.Misses), pct(snap.Stales), pct(snap.Zones)
	blockedR, badcookieR, errorR := pct(snap.Blocked), pct(snap.Badcookie), pct(snap.Errors)
	noerrR, formerrR, servfailR := pct(snap.Noerr), pct(snap.Formerr), pct(snap.Servfail)
	nxR, nimpR, refR, otherR := pct(snap.NXDomain), pct(snap.Notimp), pct(snap.Refused), pct(snap.Other)
	udpR, tcpR, tlsR, quicR := pct(snap.UDP), pct(snap.TCP), pct(snap.TLS), pct(snap.QUIC)
	httpsR, http3R, dtlsR := pct(snap.HTTPS), pct(snap.HTTP3), pct(snap.DTLS)
	dnscryptR, dnscryptTCPR, tlcpR, httpTLCPR, dtlcpR := pct(snap.DNSCrypt), pct(snap.DNSCryptTCP), pct(snap.TLCP), pct(snap.HTTPTLCP), pct(snap.DTLCP)
	dnssecTotal := snap.Secure + snap.Insecure + snap.Bogus
	poisonedR := pct(snap.Poisoned)
	var dnssecR, dnssecIR, dnssecBR float64
	if dnssecTotal > 0 {
		dt := float64(dnssecTotal)
		dnssecR = float64(snap.Secure) / dt * 100
		dnssecIR = float64(snap.Insecure) / dt * 100
		dnssecBR = float64(snap.Bogus) / dt * 100
	}

	out := make([]string, 0, 7)
	out = append(out, fmt.Sprintf("entries=%d total=%d avg=%.1fms",
		snap.Entries, total, avgMs))

	// Results — omit zero-count entries (selfdb stats format).
	if s := formatStatsLine(
		statsMetric{"hit", snap.Hits, hitR}, statsMetric{"miss", snap.Misses, missR},
		statsMetric{"stale", snap.Stales, staleR}, statsMetric{"zone", snap.Zones, zoneR},
		statsMetric{"blocked", snap.Blocked, blockedR}, statsMetric{"badcookie", snap.Badcookie, badcookieR},
		statsMetric{"error", snap.Errors, errorR},
	); s != "" {
		out = append(out, s)
	}

	// Rcodes.
	if s := formatStatsLine(
		statsMetric{"noerr", snap.Noerr, noerrR}, statsMetric{"formerr", snap.Formerr, formerrR},
		statsMetric{"servfail", snap.Servfail, servfailR}, statsMetric{"nx", snap.NXDomain, nxR},
		statsMetric{"nimp", snap.Notimp, nimpR}, statsMetric{"ref", snap.Refused, refR},
		statsMetric{"other", snap.Other, otherR},
	); s != "" {
		out = append(out, s)
	}

	// Transport protocols.
	if s := formatStatsLine(
		statsMetric{"udp", snap.UDP, udpR}, statsMetric{"tcp", snap.TCP, tcpR},
		statsMetric{"tls", snap.TLS, tlsR}, statsMetric{"quic", snap.QUIC, quicR},
		statsMetric{"https", snap.HTTPS, httpsR}, statsMetric{"http3", snap.HTTP3, http3R},
		statsMetric{"dtls", snap.DTLS, dtlsR}, statsMetric{"dnscrypt", snap.DNSCrypt, dnscryptR},
		statsMetric{"dnscrypt-tcp", snap.DNSCryptTCP, dnscryptTCPR}, statsMetric{"tlcp", snap.TLCP, tlcpR},
		statsMetric{"http-tlcp", snap.HTTPTLCP, httpTLCPR}, statsMetric{"dtlcp", snap.DTLCP, dtlcpR},
	); s != "" {
		out = append(out, s)
	}

	// DNSSEC — percentages relative to the DNSSEC-validated subset.
	if s := formatStatsLine(
		statsMetric{"secure", snap.Secure, dnssecR}, statsMetric{"insecure", snap.Insecure, dnssecIR},
		statsMetric{"bogus", snap.Bogus, dnssecBR},
	); s != "" {
		out = append(out, s)
	}

	// Poisoned stands alone — it is orthogonal to DNSSEC status, so mixing
	// it into the DNSSEC line would break that line's 100% invariant.
	if s := formatStatsLine(statsMetric{"poisoned", snap.Poisoned, poisonedR}); s != "" {
		out = append(out, s)
	}

	return out
}

// StatsRcode returns the per-RCODE top-N domain journal lines — the
// highest-count domain names per RCODE, for debugging which domains produce
// the most NXDOMAIN/SERVFAIL etc.  Served by the zjdns.stats.rcode CHAOS
// query, separate from the aggregated Stats() output.
func (s *Cache) StatsRcode() []string {
	if s.statsMgr == nil {
		return nil
	}
	snap := s.statsMgr.Snapshot(0)
	var out []string
	for _, rcode := range sortedRcodes(snap.TopByRcode) {
		var b strings.Builder
		fmt.Fprintf(&b, "top-rcode%d:", rcode)
		for _, e := range snap.TopByRcode[rcode] {
			fmt.Fprintf(&b, " %s=%d", e.Key, e.Count)
		}
		out = append(out, b.String())
	}
	return out
}

// sortedRcodes returns the journal RCODE keys in ascending order so repeated
// Stats() output is stable.
func sortedRcodes(byRcode map[int][]topk.Entry[string]) []int {
	rcodes := make([]int, 0, len(byRcode))
	for rc := range byRcode {
		rcodes = append(rcodes, rc)
	}
	slices.Sort(rcodes)
	return rcodes
}

// formatStatsLine renders a partitioned stats line: zero-count entries are
// skipped, nonzero entries appear as "name=count(pct%)" (selfdb format).
func formatStatsLine(metrics ...statsMetric) string {
	n := 0
	for _, m := range metrics {
		if m.count != 0 {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(n * 40)
	for _, m := range metrics {
		if m.count == 0 {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%s=%d(%.1f%%)", m.name, m.count, m.pct)
	}
	return b.String()
}

// UpdateLatency stores a latency measurement keyed by IP only. All domains
// sharing the same IP reuse the same entry — latency is measured once, not
// once per domain.  New measurements are smoothed via integer EWMA
// (srtt = (srtt + rtt) / N) to suppress single-sample jitter; the first
// probe for an IP or an expired entry is stored directly.
func (s *Cache) UpdateLatency(ip string, latencyMS int) {
	s.hasLatencyData.Store(true)
	if latencyMS < 0 {
		latencyMS = 0
	}
	if net.ParseIP(ip) == nil {
		return
	}

	now := log.NowUnix()
	if old, ok := s.latencies.Get(ip); ok && old.lastProbe > 0 && old.lastProbe >= now-defaultStaleMaxAge {
		// Unbiased integer EWMA: srtt = ((N-1)·srtt + rtt) / N.  The naive
		// (srtt + rtt) / N form converges to rtt/(N-1) for N > 2 — a
		// systematic underestimate — so N must weight the previous value.
		latencyMS = ((config.DefaultLatencyProbeSmoothFactor-1)*old.latency + latencyMS) / config.DefaultLatencyProbeSmoothFactor
	}
	s.latencies.Set(ip, latEntry{latency: latencyMS, lastProbe: now})
}

// LatencyLastProbe returns the last probe time for an IP. Returns (0, false)
// if the IP has never been probed or its entry is older than the stale
// window (lazy expiry — the former eviction-time DELETE FROM ip_latency).
func (s *Cache) LatencyLastProbe(ip string) (int64, bool) {
	e, ok := s.latencies.Get(ip)
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
