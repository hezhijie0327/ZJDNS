package middleware

import (
	"testing"
	"zjdns/cache"

	"codeberg.org/miekg/dns"
)

// nilSOAAncestorStore forces NegativeAncestor's SOA-less branch (nil SOA,
// ok=true).  Unreachable through a real Store today — Set never caches a
// negative without an SOA — but the branch is part of NegativeAncestor's
// contract and must not panic the cut path if it ever fires (Round 6 D7).
type nilSOAAncestorStore struct {
	cache.Store
}

func (s nilSOAAncestorStore) NegativeAncestor(string) (dns.RR, int, bool) {
	return nil, 30, true
}

// TestCacheLookup_NilSOAAncestorServesWithoutPanic pins the D7 guard: a
// SOA-less ancestor cut must skip the TTL patch (previously an unconditional
// soa.Header() deref) and fall through to normal resolution — the SOA-less
// negative cannot be re-cached (cacheTTL 0), so serveSynthesized lands on
// next.
func TestCacheLookup_NilSOAAncestorServesWithoutPanic(t *testing.T) {
	store := nilSOAAncestorStore{Store: testStore(t)}
	defer func() { _ = store.Close() }()

	req := testQuery(t)
	req.Question[0].Header().Name = "cut.example.com."
	qctx, nextRan, err := runCacheLookup(t, store, false, false, req, "cut.example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("ServeDNS: %v", err)
	}
	if !nextRan {
		t.Fatal("next handler did not run — the SOA-less cut dead-ended instead of falling through to resolution")
	}
	if qctx.Res != nil {
		t.Fatalf("served %v, want no synthesized response from a SOA-less cut", qctx.Res)
	}
}
