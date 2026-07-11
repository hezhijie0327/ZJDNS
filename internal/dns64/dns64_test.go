package dns64

import (
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func TestMapAddr_WellKnownPrefix(t *testing.T) {
	s, _ := New(defaultPrefix)
	ip6 := s.MapAddr(netip.MustParseAddr("1.2.3.4"))
	expected := netip.MustParseAddr("64:ff9b::102:304")
	if ip6 != expected {
		t.Errorf("MapAddr(1.2.3.4) = %s, want %s", ip6, expected)
	}
}

func TestMapAddr_CustomPrefix(t *testing.T) {
	s, _ := New("2001:db8::/32")
	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := s.MapAddr(ip4)
	got, ok := s.ExtractIPv4(ip6)
	if !ok || got != ip4 {
		t.Errorf("round-trip failed: %s -> %s -> %s", ip4, ip6, got)
	}
}

func TestExtractIPv4_RoundTrip(t *testing.T) {
	s, _ := New(defaultPrefix)
	ip4 := netip.MustParseAddr("10.20.30.40")
	got, ok := s.ExtractIPv4(s.MapAddr(ip4))
	if !ok || got != ip4 {
		t.Errorf("round-trip failed: %s → %s", ip4, got)
	}
}

func TestExtractIPv4_NotInPrefix(t *testing.T) {
	s, _ := New(defaultPrefix)
	_, ok := s.ExtractIPv4(netip.MustParseAddr("2001:db8::1"))
	if ok {
		t.Error("should not be synthesized")
	}
}

func TestIsSynthesized(t *testing.T) {
	s, _ := New(defaultPrefix)
	if !s.IsSynthesized(netip.MustParseAddr("64:ff9b::1")) {
		t.Error("64:ff9b::1 should be in prefix")
	}
	if s.IsSynthesized(netip.MustParseAddr("2001:db8::1")) {
		t.Error("2001:db8::1 should NOT be in prefix")
	}
}

func TestSynthesize(t *testing.T) {
	s, _ := New(defaultPrefix)
	aAnswer := []dns.RR{
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
		},
	}
	answer, _, _ := s.Synthesize(nil, nil, nil, aAnswer, nil, nil, false)
	if len(answer) != 1 {
		t.Fatalf("expected 1 record, got %d", len(answer))
	}
	aaaa := answer[0].(*dns.AAAA)
	if aaaa.Addr != netip.MustParseAddr("64:ff9b::5db8:d822") {
		t.Errorf("addr = %s", aaaa.Addr)
	}
	if aaaa.Hdr.TTL != 300 {
		t.Errorf("TTL = %d, want 300", aaaa.Hdr.TTL)
	}
}
