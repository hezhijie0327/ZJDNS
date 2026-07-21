package dns64

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func BenchmarkSynthesizer_MapAddr(b *testing.B) {
	s, _ := New("64:ff9b::/96")
	ip4 := netip.MustParseAddr("192.0.2.1")
	b.ResetTimer()
	for b.Loop() {
		_ = s.MapAddr(ip4)
	}
}

func BenchmarkSynthesizer_ExtractIPv4(b *testing.B) {
	s, _ := New("64:ff9b::/96")
	ip6 := s.MapAddr(netip.MustParseAddr("192.0.2.1"))
	b.ResetTimer()
	for b.Loop() {
		_, _ = s.ExtractIPv4(ip6)
	}
}

func BenchmarkSynthesizer_IsSynthesized(b *testing.B) {
	s, _ := New("64:ff9b::/96")
	ip6 := s.MapAddr(netip.MustParseAddr("192.0.2.1"))
	b.ResetTimer()
	for b.Loop() {
		_ = s.IsSynthesized(ip6)
	}
}

func BenchmarkSynthesizer_Synthesize(b *testing.B) {
	s, _ := New("64:ff9b::/96")
	aRec := &dns.A{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}
	b.ResetTimer()
	for b.Loop() {
		answer, _, _ := s.Synthesize(nil, nil, nil, []dns.RR{aRec}, nil, nil, false)
		_ = answer
	}
}

func BenchmarkNew(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		_, _ = New("64:ff9b::/96")
	}
}
