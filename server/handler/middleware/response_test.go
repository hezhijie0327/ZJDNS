package middleware

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// newResponseChain wires the Response middleware over a next handler that
// sets qctx.Res to a pre-packed response (Data populated, RR sections nil —
// the cache-hit buildFromPrePacked output).  Returns the chain and the
// request to echo.
func newResponseChain(t *testing.T, secure bool) (handler.QueryHandler, *dns.Msg) {
	t.Helper()
	ednsH, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	m := &Response{edns: ednsH}

	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	req.ID = 0xBEEF

	packed := new(dns.Msg)
	dnsutil.SetReply(packed, req)
	packed.Answer = []dns.RR{&dns.A{
		Hdr: dns.Header{Name: "example.com.", TTL: 300, Class: dns.ClassINET},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}}
	if err := packed.Pack(); err != nil {
		t.Fatalf("pack pre-packed response: %v", err)
	}
	packed.Answer = nil // pre-packed: sections unparsed
	packed.ID = 0x1234  // stale ID from cache Set() time

	next := handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		qctx.Res = packed
		return nil
	})
	return m.Wrap(next), req
}

// TestResponseMiddleware_PrePackedFastPath verifies the direct-wire serve:
// a pre-packed response needing no EDNS option and no zone rewrite keeps
// Data populated and gets only the client's message ID patched in.
func TestResponseMiddleware_PrePackedFastPath(t *testing.T) {
	chain, req := newResponseChain(t, false)

	qctx := &handler.QueryContext{Req: req}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response built")
	}
	if len(qctx.Res.Data) == 0 {
		t.Fatal("fast path must keep pre-packed Data for direct serve")
	}
	if got := binary.BigEndian.Uint16(qctx.Res.Data[0:2]); got != req.ID {
		t.Fatalf("wire ID = %#x, want client ID %#x", got, req.ID)
	}
	if len(qctx.Res.Pseudo) != 0 {
		t.Errorf("fast path must not apply EDNS options, got %d", len(qctx.Res.Pseudo))
	}
}

// TestResponseMiddleware_PrePackedEDNSPath verifies that an EDE (stale-answer
// or error) forces the unpack path: Data is cleared, RRs are parsed, and the
// EDE option is appended for bridge.go to re-pack.
func TestResponseMiddleware_PrePackedEDNSPath(t *testing.T) {
	chain, req := newResponseChain(t, false)

	qctx := &handler.QueryContext{Req: req, EDE: &dns.EDE{InfoCode: dns.ExtendedErrorNetworkError}}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if len(qctx.Res.Data) != 0 {
		t.Error("EDNS path must clear pre-packed Data so bridge.go re-packs")
	}
	if len(qctx.Res.Answer) == 0 {
		t.Error("EDNS path must unpack the pre-packed wire into RR sections")
	}
	foundEDE := false
	for _, o := range qctx.Res.Pseudo {
		if ede, ok := o.(*dns.EDE); ok && ede.InfoCode == dns.ExtendedErrorNetworkError {
			foundEDE = true
		}
	}
	if !foundEDE {
		t.Error("EDE option not applied to response")
	}
}

// TestResponseMiddleware_SecurePaddingSinglePack verifies the padding
// single-pack contract: a secure response gets its PADDING option and the
// final pack leaves Data populated so bridge.go skips its own packSafe.
func TestResponseMiddleware_SecurePaddingSinglePack(t *testing.T) {
	chain, req := newResponseChain(t, true)

	qctx := &handler.QueryContext{Req: req, IsSecure: true}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	foundPadding := false
	for _, o := range qctx.Res.Pseudo {
		if _, ok := o.(*dns.PADDING); ok {
			foundPadding = true
		}
	}
	if !foundPadding {
		t.Error("PADDING option not applied for secure response")
	}
	if len(qctx.Res.Data) == 0 {
		t.Error("padding pack must leave Data populated for direct serve (single pack)")
	}
}

// prePackedWithNSEC returns a pre-packed NODATA response whose authority
// section carries an NSEC proof (as a DO=1 upstream returns), plus the
// request it echoes.
func prePackedWithNSEC(t *testing.T) (req, packed *dns.Msg) {
	t.Helper()
	req = dnsutil.SetQuestion(new(dns.Msg), "missing.example.com.", dns.TypeA)
	req.ID = 0xBEEF

	packed = new(dns.Msg)
	dnsutil.SetReply(packed, req)
	packed.RecursionAvailable = true
	packed.Ns = []dns.RR{
		&dns.NSEC{Hdr: dns.Header{Name: "alpha.example.com.", Class: dns.ClassINET, TTL: 600}, NSEC: rdata.NSEC{NextDomain: "zulu.example.com."}},
		&dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 900}, SOA: rdata.SOA{Ns: "ns1.example.com.", Mbox: "admin.example.com."}},
	}
	if err := packed.Pack(); err != nil {
		t.Fatal(err)
	}
	packed.Answer = nil
	packed.Ns = nil
	packed.Extra = nil
	return req, packed
}

// TestResponseMiddleware_DNSSECFilterDO0 verifies that a DO=0 client does not
// receive DNSSEC proofs from a pre-packed entry: the wire carries NSEC, so
// the unpack+filter path must run and strip it.
func TestResponseMiddleware_DNSSECFilterDO0(t *testing.T) {
	ednsH, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	req, packed := prePackedWithNSEC(t)
	next := handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		qctx.Res = packed
		return nil
	})
	chain := (&Response{edns: ednsH}).Wrap(next)

	qctx := &handler.QueryContext{Req: req} // DO=0
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if len(qctx.Res.Data) != 0 {
		t.Error("DO=0 client with DNSSEC-bearing wire must take the unpack path (Data cleared)")
	}
	for _, rr := range qctx.Res.Ns {
		if dns.RRToType(rr) == dns.TypeNSEC || dns.RRToType(rr) == dns.TypeRRSIG {
			t.Errorf("DO=0 client received DNSSEC record %s", dns.TypeToString[dns.RRToType(rr)])
		}
	}
	hasSOA := false
	for _, rr := range qctx.Res.Ns {
		if dns.RRToType(rr) == dns.TypeSOA {
			hasSOA = true
		}
	}
	if !hasSOA {
		t.Error("SOA should survive the DNSSEC filter")
	}
}

// TestResponseMiddleware_DNSSECFilterDO1 verifies that a DO=1 client keeps
// the DNSSEC proofs: the unpack path runs (the response OPT must echo DO)
// but no DNSSEC filtering happens.
func TestResponseMiddleware_DNSSECFilterDO1(t *testing.T) {
	ednsH, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	req, packed := prePackedWithNSEC(t)
	next := handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		qctx.Res = packed
		return nil
	})
	chain := (&Response{edns: ednsH}).Wrap(next)

	qctx := &handler.QueryContext{Req: req, ClientRequestedDNSSEC: true}
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if len(qctx.Res.Data) != 0 {
		t.Error("DO=1 client must take the unpack path (Data cleared)")
	}
	foundNSEC := false
	for _, rr := range qctx.Res.Ns {
		if dns.RRToType(rr) == dns.TypeNSEC {
			foundNSEC = true
		}
	}
	if !foundNSEC {
		t.Error("DO=1 client must keep the NSEC proof")
	}
}
