// Latency-sorted serving: reorder cached answer IPs by measured upstream
// latency (EWMA probes stored in the latency map), with a per-entry sorted
// wire cache.
package cache

import (
	"slices"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// latencySortedWire is the cached latency-sort result for one entry.
type latencySortedWire struct {
	wire    []byte
	offsets []uint16
	version uint64 // Cache.latencyGen when built
}

// latEntry is one per-IP latency record.
type latEntry struct {
	latency   int   // measured latency in ms
	lastProbe int64 // log.NowUnix() at probe time; 0 = never probed
}

// clonePooledOffsets copies an offsets table into a pooled slice for a
// per-hit Entry (the cached copy stays owned by the entry).
func clonePooledOffsets(src []uint16) []uint16 {
	if len(src) == 0 {
		return nil
	}
	dst := AcquireTTLOffsets(len(src))
	copy(dst, src)
	return dst
}

// sortAnswerByLatency reorders ONLY the A/AAAA records in entry.Answer by
// probe latency (fastest first), permuting them among their own slots — every
// other record (CNAME, RRSIG, …) keeps its original position and order, so
// RRSIGs stay attached after their RRset (RFC 4035 §3.1.3 convention) and
// CNAME chains keep their wire order.  Latency is per-IP — all domains
// sharing the same IP reuse the same row.  Idempotent when ≤1 A/AAAA.
//
// Reports whether the order actually changed — when it did not, the
// pre-packed wire is already optimal and the caller can skip the repack.
func (s *Cache) sortAnswerByLatency(entry *Entry) bool {
	if !s.hasLatencyData.Load() || len(entry.Answer) <= 1 {
		return false
	}

	// Single pass: collect the A/AAAA records and IPs.  slots records the
	// A/AAAA slots in ascending order — the scatter destinations after the
	// sort (the i-th sorted record belongs in the i-th address slot).
	type slotRR struct {
		slot int
		rr   dns.RR
	}
	addrs := make([]slotRR, 0, len(entry.Answer))
	slots := make([]int, 0, len(entry.Answer))
	rrToIP := make(map[dns.RR]string, len(entry.Answer))
	for i, rr := range entry.Answer {
		if ip, ok := zdnsutil.ExtractIPString(rr); ok {
			addrs = append(addrs, slotRR{slot: i, rr: rr})
			slots = append(slots, i)
			rrToIP[rr] = ip
		}
	}
	if len(addrs) <= 1 {
		return false
	}
	ips := make([]string, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, rrToIP[a.rr])
	}

	// Batch latency lookup from the in-memory map.
	latencies := s.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return false
	}

	// Sort only the address records — pre-computed IP strings avoid
	// O(n log n) type-switch calls inside the comparator.
	slices.SortStableFunc(addrs, func(a, b slotRR) int {
		aLat, aOK := latencies[rrToIP[a.rr]]
		bLat, bOK := latencies[rrToIP[b.rr]]
		switch {
		case aOK != bOK:
			if aOK {
				return -1
			}
			return 1
		case aOK:
			if aLat != bLat {
				return aLat - bLat
			}
		}
		return dns.Compare(a.rr, b.rr)
	})

	// Scatter the i-th sorted record into the i-th A/AAAA slot — every other
	// record keeps its original position (RRSIGs trail their RRset, CNAME
	// chains keep their wire order).
	changed := false
	for i, a := range addrs {
		if entry.Answer[slots[i]] != a.rr {
			changed = true
			entry.Answer[slots[i]] = a.rr
		}
	}
	return changed
}

// lookupIPLatencies fetches latencies for a batch of IPs from the in-memory
// latency map.  Caps at maxLatencyLookupIPs to bound the lookup on unusually
// large answer sets (64+ A/AAAA records).
func (s *Cache) lookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}

	latencies := make(map[string]int, min(len(ips), maxLatencyLookupIPs))
	for _, ip := range ips {
		if e, ok := s.latencies.Get(ip); ok {
			latencies[ip] = e.latency
		}
	}
	return latencies
}
