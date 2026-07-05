// Package cache provides the DNS response cache interface backed by SQLite.
package cache

import (
	"codeberg.org/miekg/dns"

	"zjdns/config"
	"zjdns/internal/ttl"
)

// SetOptions carries per-response metadata stored alongside cache entries for
// analytics via SQL queries against the entries table.
type SetOptions struct {
	Rcode        int    // DNS response code (dns.RcodeSuccess, etc.)
	ResponseTime int64  // Response time in milliseconds
	Server       string // upstream server that resolved this query (e.g. "8.8.8.8:53 (UDP)")
	Fallback     bool   // true if resolved via fallback upstream
	Prefetch     bool   // true if this was a background prefetch refresh
	Hijack       bool   // true if hijack was detected in the response
	Dnssec       string // secure, insecure, bogus, or empty
	Uncacheable  bool   // true for error entries that should not be served from cache
}

// Store defines the cache storage interface.
type Store interface {
	Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool)
	Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
		answer, authority, additional []dns.RR, validated bool, opts SetOptions)
	RecordServe(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, protocol string, stale bool)
	RecordRewrite(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool)
	UpdateLatency(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, ip string, latencyMS int)
	ReverseLookup(ip string) []LookupResult
	Summary() string
	Close() error
}

// Entry holds a cached DNS response with timing metadata.
type Entry struct {
	Answer     []dns.RR `json:"answer"`
	Authority  []dns.RR `json:"authority"`
	Additional []dns.RR `json:"additional"`
	Timestamp  int64    `json:"timestamp"`
	TTL        int      `json:"ttl"`
	Validated  bool     `json:"validated"`
}

// LookupResult holds a PTR reverse-lookup result.
type LookupResult struct {
	Name string
	TTL  uint32
}

// IsExpired reports whether the entry's TTL has elapsed.
func (e *Entry) IsExpired() bool {
	return e != nil && ttl.IsExpired(e.Timestamp, e.TTL)
}

// CanServeExpired reports whether the expired entry is within the maxAge window.
func (e *Entry) CanServeExpired(maxAge int) bool {
	return e != nil && ttl.CanServeExpired(e.Timestamp, e.TTL, maxAge)
}

// RemainingTTL returns the remaining TTL, or a cyclical stale TTL if expired.
func (e *Entry) RemainingTTL() uint32 {
	if e == nil {
		return 0
	}
	return ttl.RemainingTTL(e.Timestamp, e.TTL, uint32(config.DefaultStaleTTL))
}

// ShouldPrefetch reports whether the entry is due for refresh based on a
// percentage threshold of its original TTL.
func (e *Entry) ShouldPrefetch(thresholdPercent int) bool {
	if e == nil {
		return false
	}
	return ttl.ShouldPrefetch(e.Timestamp, e.TTL, thresholdPercent)
}

// processRR applies DNSSEC filtering, copies, and adjusts TTL on a single
// resource record. Returns nil if the record should be excluded.
func processRR(rr dns.RR, value int64, isElapsed bool, includeDNSSEC bool) dns.RR {
	if rr == nil {
		return nil
	}
	if !includeDNSSEC {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
			return nil
		}
	}
	// Fast path: no TTL adjustment and no DNSSEC filtering — return as-is
	// to avoid heap-allocating a clone (common on cache-miss → serve path).
	if value == 0 && !isElapsed && includeDNSSEC {
		return rr
	}
	newRR := rr.Clone()
	if newRR == nil {
		return nil
	}
	if isElapsed {
		remaining := int64(newRR.Header().TTL) - value
		if remaining < 0 {
			remaining = 0
		}
		newRR.Header().TTL = uint32(remaining)
	} else if value > 0 {
		newRR.Header().TTL = uint32(value)
	}
	return newRR
}

// ProcessRecords adjusts TTLs on resource records and optionally filters
// DNSSEC record types.
func ProcessRecords(rrs []dns.RR, value int64, isElapsed bool, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if nr := processRR(rr, value, isElapsed, includeDNSSEC); nr != nil {
			result = append(result, nr)
		}
	}
	return result
}
