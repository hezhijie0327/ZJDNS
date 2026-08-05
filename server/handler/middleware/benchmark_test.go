package middleware

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// BenchmarkResponseServePrePacked measures the Response middleware over a
// pre-packed cache-hit response, comparing the direct-wire fast path (no EDNS
// modification) against the unpack+EDNS+repack path.  The fast path should
// allocate nothing and skip the full RR parse.
func BenchmarkResponseServePrePacked(b *testing.B) {
	ednsH, err := edns.NewHandler(config.ECSConfig{})
	if err != nil {
		b.Fatal(err)
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
		b.Fatal(err)
	}
	wire := slices.Clone(packed.Data)
	packed.Answer = nil // pre-packed: sections unparsed
	packed.ID = 0x1234  // stale ID from cache Set() time

	next := handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		qctx.Res = packed
		return nil
	})
	chain := m.Wrap(next)

	b.Run("direct-wire", func(b *testing.B) {
		qctx := &handler.QueryContext{Req: req}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			packed.Data = wire
			packed.Answer = nil
			packed.Pseudo = nil
			if err := chain.ServeDNS(context.Background(), qctx); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("unpack-EDNS", func(b *testing.B) {
		qctx := &handler.QueryContext{Req: req, EDE: &dns.EDE{InfoCode: dns.ExtendedErrorNetworkError}}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			packed.Data = wire
			packed.Answer = nil
			packed.Pseudo = nil
			if err := chain.ServeDNS(context.Background(), qctx); err != nil {
				b.Fatal(err)
			}
		}
	})
}
