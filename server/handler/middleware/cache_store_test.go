package middleware

import (
	"testing"
	"time"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// ── dnssecCacheable unit tests ──────────────────────────────────────────────

func TestDNSSECCacheable(t *testing.T) {
	cases := []struct {
		validated bool
		ede       uint16
		want      bool
		desc      string
	}{
		{true, 0, true, "validated + no EDE"},
		{true, 6, true, "validated + bogus EDE (sticky artifact — always cache)"},
		{true, 7, true, "validated + signature-expired EDE"},
		{true, 8, true, "validated + not-yet-valid EDE"},
		{true, 1, true, "validated + unsupported-algo EDE"},
		{true, 12, true, "validated + NSEC-missing EDE"},
		{true, dns.ExtendedErrorRRSIGsMissing, true, "validated + RRSIGs-missing EDE"},
		{false, 0, true, "unvalidated + no EDE (insecure/unsigned → cache)"},
		{false, dns.ExtendedErrorRRSIGsMissing, true, "unvalidated + RRSIGs-missing (insecure treatment → cache)"},
		{false, 6, false, "unvalidated + DNSBogus → DO NOT cache"},
		{false, 7, false, "unvalidated + signature-expired → DO NOT cache"},
		{false, 8, false, "unvalidated + not-yet-valid → DO NOT cache"},
		{false, 1, false, "unvalidated + unsupported-algo → DO NOT cache"},
		{false, 12, false, "unvalidated + NSEC-missing → DO NOT cache"},
	}
	for _, c := range cases {
		got := dnssecCacheable(c.validated, c.ede)
		if got != c.want {
			t.Errorf("%s: dnssecCacheable(%v,%d)=%v, want %v", c.desc, c.validated, c.ede, got, c.want)
		}
	}
}

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

// TestCacheStore_ValidatedStickyBogusEDE verifies the fix for the sticky
// chain.lastEDECode bug: a validated response with a bogus EDE (stale from
// an earlier delegation level) must still be cached — the bogus EDE is a
// stale artifact from intermediate DNSSEC failures that has since cleared.
func TestCacheStore_ValidatedStickyBogusEDE(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	// Simulates the sticky-EDE scenario: a previous delegation level set
	// EDE=6, final validation succeeded. After the fix this should never
	// happen in production (validateOrRetry clears lastEDECode on success).
	// Verify that if it DOES happen, the response is cached (Validated
	// takes priority over DNSSECEDE).
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
			DNSSECEDE: dns.ExtendedErrorDNSBogus, // EDE 6 — stale from intermediate level
		},
	}
	m := &CacheStore{store: store}
	m.buildSuccess(qctx)

	if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false); !found {
		t.Fatal("validated response must be cached even with stale EDE")
	}
}

// TestCacheStore_UnvalidatedNoEDECached verifies that an unvalidated (unsigned
// or insecure delegation) response IS cached — only bogus-class failures are
// excluded.  This is the normal mode for non-DNSSEC domains.
func TestCacheStore_UnvalidatedNoEDECached(t *testing.T) {
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
			Validated: false,
			DNSSECEDE: 0,
		},
	}
	m := &CacheStore{store: store}
	m.buildSuccess(qctx)

	if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false); !found {
		t.Fatal("unvalidated response without EDE must be cached (insecure/unsigned)")
	}
}

// TestCacheStore_UnvalidatedBogusEDENotCached verifies the end-to-end gate:
// all bogus-class EDE codes (6/7/8/1/12) are rejected from the cache when
// the response is NOT validated.
func TestCacheStore_UnvalidatedBogusEDENotCached(t *testing.T) {
	codes := []struct {
		code uint16
		name string
	}{
		{dns.ExtendedErrorDNSBogus, "DNSBogus"},
		{dns.ExtendedErrorSignatureExpired, "SignatureExpired"},
		{dns.ExtendedErrorSignatureNotYetValid, "SignatureNotYetValid"},
		{dns.ExtendedErrorUnsupportedDNSKEYAlgorithm, "UnsupportedAlgo"},
		{dns.ExtendedErrorNSECMissing, "NSECMissing"},
	}
	for _, c := range codes {
		t.Run(c.name, func(t *testing.T) {
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
					Validated: false,
					DNSSECEDE: c.code,
				},
			}
			m := &CacheStore{store: store}
			m.buildSuccess(qctx)

			if _, found, _ := store.Get("example.com.", dns.TypeA, dns.ClassINET, nil, false); found {
				t.Fatalf("unvalidated %s must NOT be cached", c.name)
			}
		})
	}
}
