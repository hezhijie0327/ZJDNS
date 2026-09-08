package middleware

import (
	"context"
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// aggressiveNSECFixture feeds the denial index the way StoreIfCacheable does
// after a validated recursive NXDOMAIN for cat.example.com: the covering
// NSEC plus the wildcard-denial NSEC (RFC 4035 §5.4 step 6).
func aggressiveNSECFixture(t *testing.T, store cache.Store) {
	t.Helper()
	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
		Ns:  "ns1.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Minttl: 900,
	}
	cover := &dns.NSEC{
		Hdr:        dns.Header{Name: "albatross.example.com.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "elephant.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	wild := &dns.NSEC{
		Hdr:        dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "albatross.example.com.",
		TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG},
	}
	proof := []dns.RR{cover, wild}
	authority := []dns.RR{
		soa, cover, wild,
		&dns.RRSIG{Hdr: dns.Header{Name: cover.Hdr.Name, Class: dns.ClassINET, TTL: 86400}, TypeCovered: dns.TypeNSEC},
		&dns.RRSIG{Hdr: dns.Header{Name: wild.Hdr.Name, Class: dns.ClassINET, TTL: 86400}, TypeCovered: dns.TypeNSEC},
	}
	store.IndexNegative("cat.example.com.", dns.ClassINET, proof, authority)
}

// runCacheLookup runs the Stats→CacheLookup chain for one query and reports
// whether the next handler ran plus the served response.
func runCacheLookup(t *testing.T, store cache.Store, aggressive, dns64 bool, req *dns.Msg, qname string, qtype uint16) (*handler.QueryContext, bool, error) {
	t.Helper()
	nextRan := false
	next := handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		nextRan = true
		return nil
	})
	m := (&Stats{store: store}).Wrap((&CacheLookup{
		store:          store,
		aggressiveNSEC: aggressive,
		dns64:          dns64,
	}).Wrap(next))
	qctx := (&handler.QueryContext{
		Req:      req,
		Qname:    qname,
		Qtype:    qtype,
		Protocol: "udp",
	}).InitQuestion()
	err := m.ServeDNS(context.Background(), qctx)
	return qctx, nextRan, err
}

func TestCacheLookup_SynthesizesNegative(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()
	aggressiveNSECFixture(t, store)

	req := testQuery(t)
	req.Question[0].Header().Name = "dog.example.com."
	qctx, nextRan, err := runCacheLookup(t, store, true, false, req, "dog.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if nextRan {
		t.Fatal("next chain invoked despite a synthesizable NSEC range")
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("served rcode = %v, want NXDOMAIN", qctx.Res)
	}
	if qctx.Result != "hit" {
		t.Fatalf("Result = %q, want hit", qctx.Result)
	}

	// The synthesized denial was written through the normal cache path: a
	// second query must now be a plain cache hit (no re-synthesis needed).
	if entry, found, expired := store.Get("dog.example.com.", dns.TypeA, dns.ClassINET, nil); !found || expired {
		t.Fatalf("synthesized negative not persisted: found=%v expired=%v", found, expired)
	} else {
		entry.ReleaseOffsets()
	}
}

func TestCacheLookup_AggressiveNSECGates(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()
	aggressiveNSECFixture(t, store)

	// Feature disabled → normal resolution.
	req := testQuery(t)
	req.Question[0].Header().Name = "dog.example.com."
	if _, nextRan, err := runCacheLookup(t, store, false, false, req, "dog.example.com.", dns.TypeA); err != nil || !nextRan {
		t.Fatalf("disabled feature: nextRan=%v err=%v, want fall-through", nextRan, err)
	}

	// CD bit set → RFC 8198 App. A: resolve as usual.
	req = testQuery(t)
	req.Question[0].Header().Name = "dog.example.com."
	req.CheckingDisabled = true
	if _, nextRan, err := runCacheLookup(t, store, true, false, req, "dog.example.com.", dns.TypeA); err != nil || !nextRan {
		t.Fatalf("CD bit: nextRan=%v err=%v, want fall-through", nextRan, err)
	}

	// DNS64 wired + AAAA query → skip synthesis (RFC 6147 §5.1.2 A-fallback).
	req = testQuery(t)
	req.Question[0].Header().Name = "dog.example.com."
	if _, nextRan, err := runCacheLookup(t, store, true, true, req, "dog.example.com.", dns.TypeAAAA); err != nil || !nextRan {
		t.Fatalf("dns64 AAAA: nextRan=%v err=%v, want fall-through", nextRan, err)
	}

	// DNS64 wired + A query → synthesis still applies.
	req = testQuery(t)
	req.Question[0].Header().Name = "dog.example.com."
	if qctx, nextRan, err := runCacheLookup(t, store, true, true, req, "dog.example.com.", dns.TypeA); err != nil || nextRan {
		t.Fatalf("dns64 A: nextRan=%v err=%v, want synthesis", nextRan, err)
	} else if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("dns64 A: served rcode = %v, want NXDOMAIN", qctx.Res)
	}
}

// RFC 8198 §5.3: a miss whose covering NSEC is cached and whose wildcard
// expansion was previously seen for another name is synthesized as a
// validated positive answer without an upstream round trip.
func TestCacheLookup_SynthesizesWildcardPositive(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.org.", Class: dns.ClassINET, TTL: 3600},
		Ns:  "ns1.example.org.", Mbox: "hostmaster.example.org.", Serial: 1, Minttl: 900,
	}
	cover := &dns.NSEC{
		Hdr:        dns.Header{Name: "avocado.example.org.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "zucchini.example.org.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	// Prior validated NXDOMAIN indexes the covering range...
	proof := []dns.RR{cover}
	authority := []dns.RR{
		soa, cover,
		&dns.RRSIG{Hdr: dns.Header{Name: cover.Hdr.Name, Class: dns.ClassINET, TTL: 86400}, TypeCovered: dns.TypeNSEC},
	}
	store.IndexNegative("cat.example.org.", dns.ClassINET, proof, authority)
	// ...and a prior wildcard expansion for leek feeds the wildcard cache.
	aRec := &dns.A{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, Addr: netipMustParse("192.0.2.7")}
	aSig := &dns.RRSIG{Hdr: dns.Header{Name: "leek.example.org.", Class: dns.ClassINET, TTL: 300}, TypeCovered: dns.TypeA, Labels: 2}
	store.IndexWildcard("leek.example.org.", dns.ClassINET, []dns.RR{aRec}, []dns.RR{soa, aSig})

	req := testQuery(t)
	req.Question[0].Header().Name = "banana.example.org."
	qctx, nextRan, err := runCacheLookup(t, store, true, false, req, "banana.example.org.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if nextRan {
		t.Fatal("next chain invoked despite a synthesizable wildcard expansion")
	}
	// The response is served pre-packed (msg.Data) — unpack to inspect sections.
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeSuccess {
		t.Fatalf("served response = %v, want NOERROR", qctx.Res)
	}
	if err := qctx.Res.Unpack(); err != nil {
		t.Fatal(err)
	}
	if len(qctx.Res.Answer) == 0 {
		t.Fatalf("served response = %v, want a positive wildcard answer", qctx.Res)
	}
	if qctx.Res.Answer[0].Header().Name != "banana.example.org." {
		t.Fatalf("answer owner = %s, want banana.example.org.", qctx.Res.Answer[0].Header().Name)
	}
	if qctx.Result != "hit" {
		t.Fatalf("Result = %q, want hit", qctx.Result)
	}
}

func netipMustParse(s string) netip.Addr { return netip.MustParseAddr(s) }

// RFC 8020 NXDOMAIN cut: a cached NXDOMAIN for an ancestor answers the whole
// subtree without resolution — independent of the aggressive_nsec switch and
// of the CD bit (rcode semantics, no DNSSEC angle; RFC 8020 §2/§3).
func TestCacheLookup_NXDOMAINCut(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
		Ns:  "ns1.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Minttl: 900,
	}
	store.Set("nothere.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{soa}, nil, false, dns.RcodeNameError)

	req := testQuery(t)
	req.Question[0].Header().Name = "deep.nothere.example.com."
	qctx, nextRan, err := runCacheLookup(t, store, false, false, req, "deep.nothere.example.com.", dns.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if nextRan {
		t.Fatal("next chain invoked despite the RFC 8020 cut")
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("served rcode = %v, want NXDOMAIN", qctx.Res)
	}
	if qctx.Result != "hit" {
		t.Fatalf("Result = %q, want hit", qctx.Result)
	}

	// CD-bit queries get the cut too (it is not a DNSSEC assertion).
	req = testQuery(t)
	req.Question[0].Header().Name = "deep2.nothere.example.com."
	req.CheckingDisabled = true
	if qctx, nextRan, err := runCacheLookup(t, store, false, false, req, "deep2.nothere.example.com.", dns.TypeA); err != nil || nextRan {
		t.Fatalf("CD bit: nextRan=%v err=%v, want the cut", nextRan, err)
	} else if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeNameError {
		t.Fatalf("CD bit: rcode = %v, want NXDOMAIN", qctx.Res)
	}

	// The cut is also written through the plain cache: an exact repeat is a
	// plain negative-cache hit with no synthesis at all.
	if entry, found, expired := store.Get("deep.nothere.example.com.", dns.TypeA, dns.ClassINET, nil); !found || expired {
		t.Fatalf("cut NXDOMAIN not persisted: found=%v expired=%v", found, expired)
	} else {
		entry.ReleaseOffsets()
	}
}

// Siblings of the denied name are not cut (RFC 8020 §2 first-query example:
// bar.foo.example NXDOMAIN says nothing about baz.foo.example).
func TestCacheLookup_NXDOMAINCut_SiblingResolves(t *testing.T) {
	store := testStore(t)
	defer func() { _ = store.Close() }()

	soa := &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
		Ns:  "ns1.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Minttl: 900,
	}
	store.Set("bar.foo.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{soa}, nil, false, dns.RcodeNameError)

	req := testQuery(t)
	req.Question[0].Header().Name = "baz.foo.example.com."
	if _, nextRan, err := runCacheLookup(t, store, false, false, req, "baz.foo.example.com.", dns.TypeA); err != nil || !nextRan {
		t.Fatalf("sibling: nextRan=%v err=%v, want normal resolution", nextRan, err)
	}
}
