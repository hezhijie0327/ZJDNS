package middleware

import (
	"context"
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
