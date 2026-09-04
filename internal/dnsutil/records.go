// Resource-record filtering and TTL adjustment shared by the cache and the
// response-building paths: DNSSEC-proof exclusion for DO=0 clients, RR
// copying, and elapsed-TTL deduction.

package dnsutil

import (
	"codeberg.org/miekg/dns"
)

// processRR applies DNSSEC filtering, copies, and adjusts TTL on a single
// resource record. Returns nil if the record should be excluded.
func processRR(rr dns.RR, value int64, isElapsed, includeDNSSEC bool) dns.RR {
	if !includeDNSSEC {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			return nil
		}
	}
	// Fast path: no TTL adjustment and no DNSSEC filtering — return as-is
	// to avoid heap-allocating a clone (common on cache-miss → serve path).
	if value == 0 && !isElapsed {
		return rr
	}
	newRR := rr.Clone()
	if newRR == nil {
		return nil
	}
	if isElapsed {
		remaining := max(int64(newRR.Header().TTL)-value, 0)
		newRR.Header().TTL = uint32(remaining) //nolint:gosec // G115: DNS TTL subtraction — protocol-bounded uint32
	} else if value > 0 {
		newRR.Header().TTL = uint32(value) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
	}
	return newRR
}

// ProcessRecords adjusts TTLs on resource records and optionally filters
// DNSSEC record types. The returned slice shares backing arrays with the
// input — callers must not mutate the returned records.
func ProcessRecords(rrs []dns.RR, value int64, isElapsed, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	// Fast path: TTL unchanged (value == 0) — no RR clones needed.
	// isElapsed is irrelevant when the TTL adjustment is zero.
	if value == 0 {
		if includeDNSSEC {
			return rrs
		}
		if !HasDNSSECRecords(rrs) {
			return rrs
		}
	}
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if nr := processRR(rr, value, isElapsed, includeDNSSEC); nr != nil {
			result = append(result, nr)
		}
	}
	return result
}

// hasDNSSECRecords checks whether the slice contains any DNSSEC record types
// that would be filtered by ProcessRecords when includeDNSSEC is false.
func HasDNSSECRecords(rrs []dns.RR) bool {
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			return true
		}
	}
	return false
}
