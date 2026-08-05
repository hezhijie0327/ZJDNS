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
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// fakeMQResolver implements handler.Resolver for MQTYPE tests.
type fakeMQResolver struct {
	servers          int
	recursiveServers int // pseudo-servers with protocol=recursive
	results          map[uint16]*resolver.QueryResult
}

var errTestNotFound = mqtypeError("not found")

func (f *fakeMQResolver) Query(_ context.Context, q handler.Question, _ *edns.ECSOption) *resolver.QueryResult {
	if r, ok := f.results[q.Qtype]; ok {
		return r
	}
	return &resolver.QueryResult{Err: errTestNotFound}
}

func (f *fakeMQResolver) UpstreamServers() []*config.UpstreamServer {
	out := make([]*config.UpstreamServer, 0, f.servers+f.recursiveServers)
	for range f.recursiveServers {
		out = append(out, &config.UpstreamServer{Protocol: config.ProtoRecursive})
	}
	for range f.servers {
		out = append(out, &config.UpstreamServer{})
	}
	return out
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

// ── Chain-integration tests (H1 / H2 / H4) ───────────────────────────────────
// These exercise the REAL AssembleChain order, where MQTYPE runs inside EDNS
// and outside CacheStore:
//
//	Response → EDNS → MQTYPE → CacheStore → ... → Resolution
//
// H1: miss path — CacheStore.post builds qctx.Res before MQTYPE.post merges.
// H2: hit path — a pre-packed cache response is unpacked inside merge so the
//     merged RRs survive the outer Response middleware.
// H4: plain UDP/TCP — the request arrives with Pseudo empty (miekg
//     MsgOptionUnpackQuestion); EDNS.pre unpacks it before MQTYPE.pre.

func aaaaRecord(ip string) *dns.AAAA {
	return &dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, AAAA: rdata.AAAA{Addr: netip.MustParseAddr(ip)}}
}

// chainTestDeps builds the AssembleChain dependencies with a real cache store
// and EDNS handler.
func chainTestDeps(store cache.Store, res handler.Resolver) *Dependencies {
	ednsHandler, _ := edns.NewHandler(config.ECSConfig{})
	return &Dependencies{
		Config:   &config.ServerConfig{Server: config.ServerSettings{Features: config.FeatureFlags{}}},
		Cache:    store,
		EDNS:     ednsHandler,
		Resolver: res,
	}
}

// TestMQTYPE_Chain_MissPath (H1): recursive-mode cache miss — the primary
// response is built by CacheStore from ResolutionResult AFTER MQTYPE.post
// previously ran, so the merge never executed.  With the chain reorder the
// merged AAAA and MQTYPE-Response must appear.
func TestMQTYPE_Chain_MissPath(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	fake := &fakeMQResolver{results: map[uint16]*resolver.QueryResult{
		dns.TypeA:    {Answer: []dns.RR{aRecord("192.0.2.1")}, Cacheable: true},
		dns.TypeAAAA: {Answer: []dns.RR{aaaaRecord("2001:db8::1")}, Cacheable: true},
	}}
	chain := AssembleChain(chainTestDeps(store, fake))

	req := mqQuery(t, dns.TypeAAAA)
	qctx := &handler.QueryContext{Req: req, Qname: "example.com.", Qtype: dns.TypeA}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response produced")
	}
	var foundAAAA, foundMQ bool
	for _, rr := range qctx.Res.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			foundAAAA = true
		}
	}
	for _, rr := range qctx.Res.Pseudo {
		if _, ok := rr.(*dns.MQRESPONSE); ok {
			foundMQ = true
		}
	}
	if !foundAAAA {
		t.Error("miss path: AAAA not merged into the response (H1)")
	}
	if !foundMQ {
		t.Error("miss path: MQTYPE-Response option missing (H1)")
	}
}

// TestMQTYPE_Chain_HitPath (H2): recursive-mode cache hit — CacheLookup sets
// a pre-packed primary (Data set, sections nil); merge must unpack it so the
// merged AAAA and MQTYPE-Response survive the outer Response middleware
// (which would otherwise rebuild the sections from the wire and lose them).
func TestMQTYPE_Chain_HitPath(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	// Pre-warm the primary (A) and the additional (AAAA).
	store.Set("example.com.", dns.TypeA, dns.ClassINET, nil, false,
		[]dns.RR{aRecord("192.0.2.1")}, nil, nil, false, 0)
	store.Set("example.com.", dns.TypeAAAA, dns.ClassINET, nil, false,
		[]dns.RR{aaaaRecord("2001:db8::1")}, nil, nil, false, 0)

	fake := &fakeMQResolver{results: map[uint16]*resolver.QueryResult{}}
	chain := AssembleChain(chainTestDeps(store, fake))

	req := mqQuery(t, dns.TypeAAAA)
	qctx := &handler.QueryContext{Req: req, Qname: "example.com.", Qtype: dns.TypeA}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response produced")
	}
	var foundAAAA, foundMQ bool
	for _, rr := range qctx.Res.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			foundAAAA = true
		}
	}
	for _, rr := range qctx.Res.Pseudo {
		if _, ok := rr.(*dns.MQRESPONSE); ok {
			foundMQ = true
		}
	}
	if !foundAAAA {
		t.Error("hit path: AAAA not merged into the response (H2)")
	}
	if !foundMQ {
		t.Error("hit path: MQTYPE-Response option missing (H2)")
	}
}

// TestMQTYPE_Chain_PlainTransportPseudoEmpty (H4): plain UDP/TCP listeners
// deliver question-only messages (Pseudo nil, Options=MsgOptionUnpackQuestion
// semantics).  EDNS.pre must populate Pseudo before MQTYPE.pre's findMQQUERY,
// so the merge runs — previously the MQTYPE-Query option was invisible on
// plain transports.
func TestMQTYPE_Chain_PlainTransportPseudoEmpty(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	fake := &fakeMQResolver{results: map[uint16]*resolver.QueryResult{
		dns.TypeA:    {Answer: []dns.RR{aRecord("192.0.2.1")}, Cacheable: true},
		dns.TypeAAAA: {Answer: []dns.RR{aaaaRecord("2001:db8::1")}, Cacheable: true},
	}}
	chain := AssembleChain(chainTestDeps(store, fake))

	// Build the request exactly as a miekg dns.Server delivers it: wire in
	// Data, only the question unpacked, Pseudo nil.
	req := mqQuery(t, dns.TypeAAAA)
	req.Options = dns.MsgOptionUnpackQuestion
	if err := req.Pack(); err != nil {
		t.Fatalf("pack request: %v", err)
	}
	wire := req.Data
	req2 := new(dns.Msg)
	req2.Data = wire
	req2.Options = dns.MsgOptionUnpackQuestion
	if err := req2.Unpack(); err != nil {
		// Simulate the listener's question-only unpack.
		t.Fatalf("unpack request: %v", err)
	}
	if len(req2.Pseudo) != 0 {
		t.Fatal("test setup: expected Pseudo empty after question-only unpack")
	}

	qctx := &handler.QueryContext{Req: req2, Qname: "example.com.", Qtype: dns.TypeA}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response produced")
	}
	var foundAAAA, foundMQ bool
	for _, rr := range qctx.Res.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			foundAAAA = true
		}
	}
	for _, rr := range qctx.Res.Pseudo {
		if _, ok := rr.(*dns.MQRESPONSE); ok {
			foundMQ = true
		}
	}
	if !foundAAAA {
		t.Error("plain transport: AAAA not merged (H4 — MQTYPE-Query invisible)")
	}
	if !foundMQ {
		t.Error("plain transport: MQTYPE-Response option missing (H4)")
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

// ── entryRcode (M6) ───────────────────────────────────────────────────────────

// TestEntryRcode_ExtendedRcode verifies that rcodes >= 16 are read from the
// OPT record's TTL high byte (RFC 6891 §6.1.3) — previously only the low
// nibble was read, misclassifying e.g. BADVERS as NOERROR and breaking the
// RFC 10029 §3.4 RCODE-match check.
func TestEntryRcode_ExtendedRcode(t *testing.T) {
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeBadVers // 16 — extended rcode
	msg.UDPSize = 1232
	msg.Pseudo = append(msg.Pseudo, &dns.PADDING{}) // force OPT at pack
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	entry := &cache.Entry{ResponseWire: msg.Data}
	if got := entryRcode(entry); got != dns.RcodeBadVers {
		t.Errorf("entryRcode = %d, want %d (extended rcode via OPT)", got, dns.RcodeBadVers)
	}
}

func TestEntryRcode_LowRcode(t *testing.T) {
	msg := new(dns.Msg)
	dnsutil.SetQuestion(msg, "example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError // 3 — fits the header nibble
	if err := msg.Pack(); err != nil {
		t.Fatalf("pack: %v", err)
	}
	entry := &cache.Entry{ResponseWire: msg.Data}
	if got := entryRcode(entry); got != dns.RcodeNameError {
		t.Errorf("entryRcode = %d, want %d", got, dns.RcodeNameError)
	}
}

func TestEntryRcode_ShortWire(t *testing.T) {
	if got := entryRcode(&cache.Entry{}); got != 0 {
		t.Errorf("entryRcode on empty wire = %d, want 0", got)
	}
}

// TestMQTYPE_Chain_MissPath_RecursivePseudoServer: the recursive-only
// config puts a protocol=recursive pseudo-server in the upstream list —
// the forwarding gate must not treat it as a real upstream, or the merge
// is silently skipped in recursive mode (live-test catch, DEBUG.md).
func TestMQTYPE_Chain_MissPath_RecursivePseudoServer(t *testing.T) {
	store := mqTestStore(t)
	defer func() { _ = store.Close() }()

	fake := &fakeMQResolver{
		recursiveServers: 1, // {protocol: recursive} pseudo-server
		results: map[uint16]*resolver.QueryResult{
			dns.TypeA:    {Answer: []dns.RR{aRecord("192.0.2.1")}, Cacheable: true},
			dns.TypeAAAA: {Answer: []dns.RR{aaaaRecord("2001:db8::1")}, Cacheable: true},
		},
	}
	chain := AssembleChain(chainTestDeps(store, fake))

	req := mqQuery(t, dns.TypeAAAA)
	qctx := &handler.QueryContext{Req: req, Qname: "example.com.", Qtype: dns.TypeA}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response produced")
	}
	var foundAAAA, foundMQ bool
	for _, rr := range qctx.Res.Answer {
		if _, ok := rr.(*dns.AAAA); ok {
			foundAAAA = true
		}
	}
	for _, rr := range qctx.Res.Pseudo {
		if _, ok := rr.(*dns.MQRESPONSE); ok {
			foundMQ = true
		}
	}
	if !foundAAAA {
		t.Error("recursive pseudo-server in list must not suppress the merge (AAAA missing)")
	}
	if !foundMQ {
		t.Error("recursive pseudo-server in list must not suppress the merge (MQRESPONSE missing)")
	}
}
