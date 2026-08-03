package cache

import (
	"slices"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// sortAnswerByLatency reorders A/AAAA answer records fastest-first by cached
// probe latency. Unprobed records keep their relative order (stable sort with
// an equal "unknown" key). Best-effort: no latency data leaves the order
// unchanged.
//
// The slice is sorted in place. On the cache-hit path it is the pooled
// message's backing array, rebuilt from scratch by the next Unpack — mutating
// it is safe.
func sortAnswerByLatency(answer []dns.RR, latencies map[string]int) {
	if len(answer) <= 1 {
		return
	}
	slices.SortStableFunc(answer, func(a, b dns.RR) int {
		la, aOK := recordLatency(a, latencies)
		lb, bOK := recordLatency(b, latencies)
		switch {
		case aOK != bOK:
			if aOK {
				return -1
			}
			return 1
		case aOK:
			return la - lb
		}
		return 0
	})
}

// recordLatency returns the cached probe latency for an A/AAAA record's IP.
func recordLatency(rr dns.RR, latencies map[string]int) (int, bool) {
	ip, ok := zdnsutil.ExtractIPString(rr)
	if !ok {
		return 0, false
	}
	lat, ok := latencies[ip]
	return lat, ok
}

// recordLatencyLookup builds the latency map for the answer's distinct IPs via
// the batch lookup (capped at maxLatencyLookupIPs). Returns a nil map when no
// latency data exists — callers skip sorting then.
func (c *Cache) recordLatencyLookup(answer []dns.RR) map[string]int {
	ips := make([]string, 0, len(answer))
	seen := make(map[string]bool, len(answer))
	for _, rr := range answer {
		if dns.RRToType(rr) != dns.TypeA && dns.RRToType(rr) != dns.TypeAAAA {
			continue
		}
		ip, ok := zdnsutil.ExtractIPString(rr)
		if !ok || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	if len(ips) <= 1 {
		return nil
	}
	latencies := c.LookupIPLatencies(ips)
	if len(latencies) == 0 {
		return nil
	}
	return latencies
}
