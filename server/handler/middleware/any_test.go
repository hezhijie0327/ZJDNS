package middleware

import (
	"context"
	"net/netip"
	"testing"
	"zjdns/config"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// newMsg builds a query message for the given question record.
func newAnyMsg(qname string) *dns.Msg {
	req := new(dns.Msg)
	req.Question = []dns.RR{&dns.ANY{Hdr: dns.Header{Name: qname, Class: dns.ClassINET}}}
	return req
}

// TestAnyMiddleware_SynthesizesHINFO verifies RFC 8482 behavior: an ANY query
// is answered with a single HINFO "RFC8482" "" record, short-circuiting the
// chain.
func TestAnyMiddleware_SynthesizesHINFO(t *testing.T) {
	nextCalled := false
	chain := (&Any{}).Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))

	qctx := (&handler.QueryContext{Req: newAnyMsg("example.com.")}).InitQuestion()
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if nextCalled {
		t.Error("ANY query must short-circuit without reaching next")
	}
	if qctx.Res == nil {
		t.Fatal("no response built")
	}
	if len(qctx.Res.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1 HINFO", len(qctx.Res.Answer))
	}
	hinfo, ok := qctx.Res.Answer[0].(*dns.HINFO)
	if !ok {
		t.Fatalf("answer[0] = %T, want *dns.HINFO", qctx.Res.Answer[0])
	}
	if hinfo.Cpu != "RFC8482" || hinfo.Os != "" {
		t.Errorf("HINFO = %q/%q, want RFC8482/\"\"", hinfo.Cpu, hinfo.Os)
	}
	if hinfo.Hdr.Name != "example.com." {
		t.Errorf("HINFO owner = %q, want example.com.", hinfo.Hdr.Name)
	}
	if hinfo.Hdr.TTL != config.DefaultHINFOTTL {
		t.Errorf("HINFO TTL = %d, want %d", hinfo.Hdr.TTL, config.DefaultHINFOTTL)
	}
}

// TestAnyMiddleware_NonANY_Delegates verifies non-ANY queries pass through.
func TestAnyMiddleware_NonANY_Delegates(t *testing.T) {
	nextCalled := false
	chain := (&Any{}).Wrap(handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
		nextCalled = true
		return nil
	}))

	req := new(dns.Msg)
	req.Question = []dns.RR{&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET}, Addr: netip.MustParseAddr("192.0.2.1")}}
	qctx := (&handler.QueryContext{Req: req}).InitQuestion()
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if !nextCalled {
		t.Error("non-ANY query must delegate to next")
	}
}
