package middleware

import (
	"context"
	"net"
	"testing"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// newEDNSChain wires the EDNS middleware (inner) under the Response
// middleware (outer) — the real chain order — with a pass-through next.
func newEDNSChain(t *testing.T) (*EDNS, handler.QueryHandler) {
	t.Helper()
	ednsH, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	m := &EDNS{edns: ednsH}
	next := handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error { return nil })
	resp := &Response{edns: ednsH}
	return m, resp.Wrap(m.Wrap(next))
}

// queryMsg builds a request message with the given EDNS pseudo-options,
// packed so the EDNS middleware's full unpack pass can re-parse them.
func queryMsg(t *testing.T, pseudo ...dns.RR) *dns.Msg {
	t.Helper()
	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	req.UDPSize = 1232
	req.Pseudo = append(req.Pseudo, pseudo...)
	if err := req.Pack(); err != nil {
		t.Fatalf("pack request: %v", err)
	}
	return req
}

// TestEDNSMiddleware_BadCookieSingleOption verifies M4: a BADCOOKIE response
// built by the EDNS middleware must not receive a second round of EDNS
// options from the Response middleware — one COOKIE option per message.
func TestEDNSMiddleware_BadCookieSingleOption(t *testing.T) {
	_, chain := newEDNSChain(t)

	// 8-byte client cookie + 15-byte server cookie (hex): the server cookie
	// length != 16 triggers the RFC 7873 BADCOOKIE path.
	req := queryMsg(t, &dns.COOKIE{Cookie: "0123456789abcdef0123456789abcde0"}) // 16 + 15 hex chars
	qctx := (&handler.QueryContext{Req: req, ClientIP: net.IPv4(192, 0, 2, 1)}).InitQuestion()
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response built")
	}
	if qctx.Res.Rcode != dns.RcodeBadCookie {
		t.Fatalf("rcode = %d, want BADCOOKIE", qctx.Res.Rcode)
	}
	var cookies, subnets int
	for _, o := range qctx.Res.Pseudo {
		switch o.(type) {
		case *dns.COOKIE:
			cookies++
		case *dns.SUBNET:
			subnets++
		}
	}
	if cookies != 1 {
		t.Errorf("response carries %d COOKIE options, want 1", cookies)
	}
	if subnets > 1 {
		t.Errorf("response carries %d SUBNET options, want at most 1", subnets)
	}
}

// TestEDNSMiddleware_BadVers verifies M5: a request with EDNS version != 0
// must be answered with RCODE=BADVERS carrying an OPT (RFC 6891 §6.1.3).
func TestEDNSMiddleware_BadVers(t *testing.T) {
	_, chain := newEDNSChain(t)

	req := queryMsg(t, &dns.PADDING{})
	// Manually raise the EDNS version in the packed OPT. Layout after the
	// 12-byte header and the 17-byte question ("\x07example\x03com\x00" +
	// qtype/qclass): OPT name "." (1) + type (2) + class (2) + TTL (4).
	// The TTL's second octet carries the version per RFC 6891 §6.1.3.
	const versionOctet = 12 + 17 + 1 + 2 + 2 + 1
	if len(req.Data) < versionOctet+1 {
		t.Fatalf("packed message too short (%d bytes)", len(req.Data))
	}
	req.Data[versionOctet] = 1

	// Simulate the server MsgOptionUnpackQuestion: only the question
	// section was parsed, so Pseudo is empty.  The middleware must do a
	// full Unpack to extract the EDNS version from the wire.
	req.Pseudo = nil
	req.Version = 0

	qctx := (&handler.QueryContext{Req: req, ClientIP: net.IPv4(192, 0, 2, 1)}).InitQuestion()
	if err := chain.ServeDNS(context.Background(), qctx); err != nil {
		t.Fatal(err)
	}
	if qctx.Res == nil {
		t.Fatal("no response built")
	}
	if qctx.Res.Rcode != dns.RcodeBadVers {
		t.Fatalf("rcode = %d, want BADVERS", qctx.Res.Rcode)
	}
	if qctx.Res.UDPSize == 0 {
		t.Error("BADVERS response missing OPT (UDPSize unset)")
	}
}
