package resolver

import (
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"

	"codeberg.org/miekg/dns"
)

// newHopCacheTest builds a CNAME resolver wired to a real cache store.
func newHopCacheTest(t *testing.T) (*CNAME, cache.Store) {
	t.Helper()
	r := newTestResolver(&fakeNSClient{handlers: map[string]nsScriptHandler{}})
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	t.Cleanup(func() { _ = store.Close() })
	r.cache = store
	return &CNAME{resolver: r}, store
}

// TestCachedHopResult_Hit verifies that a fresh cached entry serves the hop:
// answer content, rcode, validated flag, and TTLs rewritten to the entry's
// remaining TTL (a reused hop must not gain freshness).
func TestCachedHopResult_Hit(t *testing.T) {
	c, store := newHopCacheTest(t)
	a := &dns.A{Hdr: dns.Header{Name: "target.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}
	sig := &dns.RRSIG{Hdr: dns.Header{Name: "target.example.com.", Class: dns.ClassINET, TTL: 300}, TypeCovered: dns.TypeA}
	store.Set("target.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{a, sig}, nil, nil, true, 0)

	q := Question{Name: "target.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	hop := c.cachedHopResult(q, nil)
	if hop == nil {
		t.Fatal("expected cache hit for fresh entry")
	}
	if hop.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%d, want NOERROR", hop.Rcode)
	}
	if !hop.Validated {
		t.Fatal("validated flag lost on hop reuse")
	}
	if len(hop.Answer) != 2 {
		t.Fatalf("answer=%d records, want 2", len(hop.Answer))
	}
	if hop.Answer[0].(*dns.A).Addr.String() != "192.0.2.1" {
		t.Fatal("answer content changed on hop reuse")
	}
	// Store-time remaining == the record TTL; the rewrite must have applied it.
	if got := hop.Answer[0].Header().TTL; got != 300 {
		t.Fatalf("rewritten TTL=%d, want remaining 300", got)
	}
	// The cached entry itself must be untouched (clone, not in-place edit).
	entry, found, _ := store.Get("target.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		t.Fatal("entry vanished")
	}
	defer entry.ReleaseOffsets()
	_ = entry.Unpack()
	if got := entry.Answer[0].Header().TTL; got != 300 {
		t.Fatalf("cached entry TTL mutated to %d, want original 300", got)
	}
}

// TestCachedHopResult_Negative verifies that a cached NXDOMAIN serves the hop
// as NXDOMAIN (the chain ends, RFC 6604 §3) instead of walking.
func TestCachedHopResult_Negative(t *testing.T) {
	c, store := newHopCacheTest(t)
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900}, Minttl: 60}
	store.Set("gone.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{soa}, nil, false, dns.RcodeNameError)

	hop := c.cachedHopResult(Question{Name: "gone.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil)
	if hop == nil {
		t.Fatal("expected cache hit for cached NXDOMAIN")
	}
	if hop.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode=%d, want NXDOMAIN", hop.Rcode)
	}
	if len(hop.Authority) != 1 {
		t.Fatalf("authority=%d records, want the SOA", len(hop.Authority))
	}
}

// TestCachedHopResult_Miss verifies the nil path for a missing entry.  The
// expired path is covered by the cache store's own expiry tests — the entry
// TTL floor (DefaultTTL 10s) makes a sleep-based expiry case too slow.
func TestCachedHopResult_Miss(t *testing.T) {
	c, _ := newHopCacheTest(t)

	if hop := c.cachedHopResult(Question{Name: "nothere.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, nil); hop != nil {
		t.Fatal("served a hop from a missing entry")
	}
}

// TestCachedHopResult_ECSScoped verifies that ECS-carrying hops only reuse
// entries stored under the same ECS scope.
func TestCachedHopResult_ECSScoped(t *testing.T) {
	c, store := newHopCacheTest(t)
	a := &dns.A{Hdr: dns.Header{Name: "geo.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.3")}
	store.Set("geo.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)

	q := Question{Name: "geo.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	if hop := c.cachedHopResult(q, nil); hop == nil {
		t.Fatal("expected hit for the ECS-less entry")
	}
	ecs := &edns.ECSOption{Family: 1, SourcePrefix: 24, Address: []byte{203, 0, 113, 0}}
	if hop := c.cachedHopResult(q, ecs); hop != nil {
		t.Fatal("served an ECS-scoped hop from an ECS-less entry")
	}
}
