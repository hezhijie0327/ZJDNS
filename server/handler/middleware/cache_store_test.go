package middleware

import (
	"testing"
	"time"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// TestCacheStore_BogusEDENotCached verifies that a resolution result with a
// bogus-class DNSSEC EDE is never written to the cache: a dnssec_enforce
// instance sharing the DB would otherwise serve the unauthenticated answer
// from cache, bypassing the enforce gate.
func TestCacheStore_BogusEDENotCached(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	qctx := &handler.QueryContext{
		Req:       mqQuery(t),
		Qname:     "example.com.",
		Qtype:     dns.TypeA,
		StartTime: time.Now().Unix(),
		Protocol:  "udp",
		ResolutionResult: &resolver.QueryResult{
			Answer:    []dns.RR{aRecord("192.0.2.1")},
			Rcode:     dns.RcodeSuccess,
			Cacheable: true,
			DNSSECEDE: dns.ExtendedErrorDNSBogus, // EDE 6 — bogus
		},
	}
	m := &CacheStore{store: store}
	m.buildSuccess(qctx)

	if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false); found {
		t.Fatal("bogus result must not be cached")
	}
}

// TestCacheStore_RRSIGsMissingCached verifies the inverse: EDE
// RRSIGs-missing keeps the existing insecure treatment and stays cacheable.
func TestCacheStore_RRSIGsMissingCached(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	qctx := &handler.QueryContext{
		Req:       mqQuery(t),
		Qname:     "example.com.",
		Qtype:     dns.TypeA,
		StartTime: time.Now().Unix(),
		Protocol:  "udp",
		ResolutionResult: &resolver.QueryResult{
			Answer:    []dns.RR{aRecord("192.0.2.1")},
			Rcode:     dns.RcodeSuccess,
			Cacheable: true,
			DNSSECEDE: dns.ExtendedErrorRRSIGsMissing, // EDE 22 — insecure treatment
		},
	}
	m := &CacheStore{store: store}
	m.buildSuccess(qctx)

	entry, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false)
	if !found || entry == nil {
		t.Fatal("RRSIGs-missing result must stay cacheable")
	}
}

// TestCacheStore_NoEDECached is the baseline: a clean result (secure or
// insecure, no EDE) is cached.
func TestCacheStore_NoEDECached(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	qctx := &handler.QueryContext{
		Req:       mqQuery(t),
		Qname:     "example.com.",
		Qtype:     dns.TypeA,
		StartTime: time.Now().Unix(),
		Protocol:  "udp",
		ResolutionResult: &resolver.QueryResult{
			Answer:    []dns.RR{aRecord("192.0.2.1")},
			Rcode:     dns.RcodeSuccess,
			Cacheable: true,
			Validated: true,
		},
	}
	m := &CacheStore{store: store}
	m.buildSuccess(qctx)

	if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false); !found {
		t.Fatal("clean result must be cached")
	}
}
