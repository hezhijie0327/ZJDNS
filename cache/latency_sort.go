// Latency-sorted serving: reorder cached answer IPs by measured upstream
// latency (EWMA probes stored in the latency map), with a per-entry sorted
// wire cache.
package cache

import (
	"slices"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

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

// cacheKey is the exact cache key: (qname, qtype, qclass, ECS address,
// ECS prefix) as one comparable struct — constructed in place on the lookup
// path with zero allocations (the former strings.Builder key allocated on
// every Get, once per ECS candidate).  ecsAddr holds the address bytes with
// ecsLen 4 = IPv4 (first 4 bytes), 16 = IPv6, 0 = no ECS.  The key excludes
// the client's DO bit: outbound queries always carry DO=1 (RFC 6840 §5.9)
// and DO=0 filtering happens at serve time — a DO-split key would store the
// identical raw wire twice per name.

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

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records (CNAME, etc.) at the
// front in their original wire-format order. Latency is per-IP — all domains
// sharing the same IP reuse the same row. Idempotent when ≤1 A/AAAA.
//
// Uses a single pass over entry.Answer to separate A/AAAA from non-A/AAAA
// records and collect IPs simultaneously, halving the iteration overhead.
// sortAnswerByLatency reorders A/AAAA records by latency and reports whether
// the order actually changed — when it did not, the pre-packed wire is
// already optimal and the caller can skip the repack.
func (s *Cache) sortAnswerByLatency(entry *Entry) bool {
	if !s.hasLatencyData.Load() || len(entry.Answer) <= 1 {
		return false
	}
	original := slices.Clone(entry.Answer) // pointer copy — no RR deep clone

	// Single pass: extract IP strings + collect for batch lookup.
	rrToIP := make(map[dns.RR]string, len(entry.Answer))
	ips := make([]string, 0, len(entry.Answer))
	for _, rr := range entry.Answer {
		if ip, ok := zdnsutil.ExtractIPString(rr); ok {
			rrToIP[rr] = ip
			ips = append(ips, ip)
		}
	}
	if len(ips) <= 1 {
		return false
	}

	// Batch latency lookup from the in-memory map.
	latencies := s.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return false
	}

	// In-place sort using pre-computed IP strings — avoids O(n log n)
	// type-switch calls inside the comparator.
	slices.SortStableFunc(entry.Answer, func(a, b dns.RR) int {
		aIP, aIsAddr := rrToIP[a]
		bIP, bIsAddr := rrToIP[b]
		if aIsAddr != bIsAddr {
			if !aIsAddr {
				return -1
			}
			return 1
		}
		if !aIsAddr {
			return 0
		}
		aLat, aOK := latencies[aIP]
		bLat, bOK := latencies[bIP]
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
		return dns.Compare(a, b)
	})
	for i := range entry.Answer {
		if entry.Answer[i] != original[i] {
			return true
		}
	}
	return false
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
