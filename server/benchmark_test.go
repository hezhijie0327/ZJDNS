package server

import (
	"net/netip"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// oversizedResponse builds a packed response with n A records — large enough
// to exceed the RFC 9715 1400-byte UDP response cap.
func oversizedResponse(b *testing.B, n int) (msg *dns.Msg, wire []byte) {
	b.Helper()
	req := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	req.ID = 0xBEEF
	msg = new(dns.Msg)
	dnsutil.SetReply(msg, req)
	msg.RecursionAvailable = true
	for range n {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr:  dns.Header{Name: "example.com.", TTL: 300, Class: dns.ClassINET},
			Addr: netip.MustParseAddr("192.0.2.1"),
		})
	}
	if err := msg.Pack(); err != nil {
		b.Fatal(err)
	}
	if len(msg.Data) <= config.DefaultMaxUDPResponseSize {
		b.Fatalf("test wire too small: %d bytes, want > %d", len(msg.Data), config.DefaultMaxUDPResponseSize)
	}
	wire = make([]byte, len(msg.Data))
	copy(wire, msg.Data)
	return msg, wire
}

// BenchmarkUDPTruncateOversized measures the RFC 9715 truncation path on a
// pre-packed cache hit exceeding the 1400-byte cap: truncateWire sets TC and
// drops the RR sections in place — no Unpack/Pack round-trip.
func BenchmarkUDPTruncateOversized(b *testing.B) {
	msg, wire := oversizedResponse(b, 100)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Data = wire
		msg.Data = truncateWire(msg.Data)
	}
}
