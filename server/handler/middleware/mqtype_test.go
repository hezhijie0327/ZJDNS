package middleware

import (
	"context"
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/database"
	"zjdns/edns"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

// fakeMQResolver implements handler.Resolver for MQTYPE tests.
type fakeMQResolver struct {
	servers int
	results map[uint16]*resolver.QueryResult
}

var errTestNotFound = mqtypeError("not found")

func (f *fakeMQResolver) Query(_ context.Context, q handler.Question, _ *edns.ECSOption) *resolver.QueryResult {
	if r, ok := f.results[q.Qtype]; ok {
		return r
	}
	return &resolver.QueryResult{Err: errTestNotFound}
}

func (f *fakeMQResolver) UpstreamServers() []*config.UpstreamServer {
	return make([]*config.UpstreamServer, f.servers)
}

func mqTestStore(t *testing.T) cache.Store {
	t.Helper()
	db, err := database.Open("", 0, database.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return cache.New(db)
}

func mqQuery(t *testing.T, types ...uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	req.Pseudo = append(req.Pseudo, &dns.MQQUERY{Types: types})
	return req
}

func aRecord(ip string) *dns.A {
	return &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr(ip)}}
}

// TestMQTYPE_NoOption_Delegates verifies queries without MQTYPE-Query pass
// through untouched.
func TestMQTYPE_NoOption_Delegates(t *testing.T) {
	nextCalled := false
	chain := (&MQTYPE{}).Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))
	req := new(dns.Msg)
	req.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	if err := chain.ServeDNS(context.Background(), &handler.QueryContext{Req: req}); err != nil {
		t.Fatal(err)
	}
	if !nextCalled {
		t.Error("queries without MQTYPE-Query must delegate")
	}
}

// TestMQTYPE_InvalidOptions_FORMERR verifies RFC 10029 §3.3 FORMERR conditions.
func TestMQTYPE_InvalidOptions_FORMERR(t *testing.T) {
	cases := []struct {
		name  string
		types []uint16
	}{
		{"empty list", nil},
		{"meta type", []uint16{dns.TypeANY}},
		{"duplicate", []uint16{dns.TypeAAAA, dns.TypeAAAA}},
		{"duplicates primary", []uint16{dns.TypeA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chain := (&MQTYPE{}).Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
				t.Error("next must not run for invalid MQTYPE-Query")
				return nil
			}))
			qctx := &handler.QueryContext{Req: mqQuery(t, tc.types...)}
			if err := chain.ServeDNS(context.Background(), qctx); err != nil {
				t.Fatal(err)
			}
			if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeFormatError {
				t.Errorf("rcode = %v, want FORMERR", qctx.Res)
			}
		})
	}
}

// TestMQTYPE_DuplicateOption_FORMERR verifies §3.3: a second MQTYPE-Query
// option is rejected with FORMERR (and must not panic).
func TestMQTYPE_DuplicateOption_FORMERR(t *testing.T) {
	chain := (&MQTYPE{}).Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		t.Error("next must not run for duplicate MQTYPE-Query")
		return nil
	}))
	req := mqQuery(t, dns.TypeAAAA)
	req.Pseudo = append(req.Pseudo, &dns.MQQUERY{Types: []uint16{dns.TypeTXT}})
	qctx := &handler.QueryContext{Req: req}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %v, want FORMERR", qctx.Res)
	}
}

// TestMQTYPE_InboundResponse_FORMERR verifies §3.3: an MQTYPE-Response in an
// inbound message is rejected with FORMERR.
func TestMQTYPE_InboundResponse_FORMERR(t *testing.T) {
	chain := (&MQTYPE{}).Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		t.Error("next must not run for inbound MQTYPE-Response")
		return nil
	}))
	req := new(dns.Msg)
	req.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}}}
	req.Pseudo = append(req.Pseudo, &dns.MQRESPONSE{Types: []uint16{dns.TypeAAAA}})
	qctx := &handler.QueryContext{Req: req}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil || qctx.Res.Rcode != dns.RcodeFormatError {
		t.Errorf("rcode = %v, want FORMERR", qctx.Res)
	}
}

// TestMQTYPE_Merge_CacheHit verifies recursive-mode merging: the additional
// type is resolved from the cache, merged into the primary response, and the
// MQTYPE-Response option lists the completed type.
func TestMQTYPE_Merge_CacheHit(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	// Cache an AAAA entry for the additional type.
	store.Set("example.com.", dns.TypeAAAA, dns.ClassINET, nil, false,
		[]dns.RR{&dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr("2001:db8::1")}}},
		nil, nil, false, 0)

	fake := &fakeMQResolver{results: map[uint16]*resolver.QueryResult{}}
	m := &MQTYPE{store: store, resolver: fake, pending: nil}
	chain := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		// Primary response: A record.
		qctx.Res = handler.BuildResponseMsg(qctx.Req)
		qctx.Res.Answer = []dns.RR{aRecord("192.0.2.1")}
		return nil
	}))

	qctx := &handler.QueryContext{Req: mqQuery(t, dns.TypeAAAA)}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}

	if len(qctx.Res.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2 (A + AAAA)", len(qctx.Res.Answer))
	}
	var foundMQ bool
	for _, rr := range qctx.Res.Pseudo {
		if mqr, ok := rr.(*dns.MQRESPONSE); ok {
			foundMQ = true
			if len(mqr.Types) != 1 || mqr.Types[0] != dns.TypeAAAA {
				t.Errorf("MQRESPONSE types = %v, want [AAAA]", mqr.Types)
			}
		}
	}
	if !foundMQ {
		t.Error("MQTYPE-Response option missing from merged response")
	}
}

// TestMQTYPE_Merge_SkipMismatch verifies §3.4: a QTx with mismatching RCODE
// is not merged and not listed.
func TestMQTYPE_Merge_SkipMismatch(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	fake := &fakeMQResolver{results: map[uint16]*resolver.QueryResult{
		dns.TypeAAAA: {Rcode: dns.RcodeNameError, Cacheable: true}, // NXDOMAIN ≠ primary NOERROR
	}}
	m := &MQTYPE{store: store, resolver: fake, pending: nil}
	chain := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		qctx.Res = handler.BuildResponseMsg(qctx.Req)
		qctx.Res.Answer = []dns.RR{aRecord("192.0.2.1")}
		return nil
	}))

	qctx := &handler.QueryContext{Req: mqQuery(t, dns.TypeAAAA)}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}

	if len(qctx.Res.Answer) != 1 {
		t.Errorf("answer count = %d, want 1 (mismatched type must not merge)", len(qctx.Res.Answer))
	}
	// §3.4: the option must still be present, with an empty list.
	for _, rr := range qctx.Res.Pseudo {
		if mqr, ok := rr.(*dns.MQRESPONSE); ok && len(mqr.Types) != 0 {
			t.Errorf("MQRESPONSE types = %v, want empty", mqr.Types)
		}
	}
}

// TestMQTYPE_ForwardingMode_SkipsMerge verifies forwarding mode does not merge
// locally (the upstream handles it via pass-through).
func TestMQTYPE_ForwardingMode_SkipsMerge(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	fake := &fakeMQResolver{servers: 1} // upstream configured → forwarding mode
	m := &MQTYPE{store: store, resolver: fake, pending: nil}
	chain := m.Wrap(handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		qctx.Res = handler.BuildResponseMsg(qctx.Req)
		qctx.Res.Answer = []dns.RR{aRecord("192.0.2.1")}
		return nil
	}))

	qctx := &handler.QueryContext{Req: mqQuery(t, dns.TypeAAAA)}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if len(qctx.Res.Answer) != 1 {
		t.Errorf("answer count = %d, want 1 (forwarding must not merge)", len(qctx.Res.Answer))
	}
	for _, rr := range qctx.Res.Pseudo {
		if _, ok := rr.(*dns.MQRESPONSE); ok {
			t.Error("forwarding mode must not add MQTYPE-Response")
		}
	}
}

// TestMergeRRs_Deduplicates verifies RFC 10029 §3.4 RR deduplication.
func TestMergeRRs_Deduplicates(t *testing.T) {
	a := aRecord("192.0.2.1")
	b := aRecord("192.0.2.2")
	merged := mergeRRs([]dns.RR{a, b}, []dns.RR{a, b, aRecord("192.0.2.3")})
	if len(merged) != 3 {
		t.Errorf("merged length = %d, want 3 (duplicates removed)", len(merged))
	}
}
