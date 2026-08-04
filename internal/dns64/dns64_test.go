package dns64

import (
	"net/netip"
	"strconv"
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
	ip6 := s.MapAddr(netip.MustParseAddr("192.0.2.1"))
	expected := netip.MustParseAddr("2001:db8:c000:201::")
	if ip6 != expected {
		t.Errorf("MapAddr(192.0.2.1) = %s, want %s", ip6, expected)
	}
}

// TestMapAddr_RFC6052Golden asserts the RFC 6052 Table 1 vectors: the IPv4
// address placement is prefix-length dependent, not a fixed /96 layout.
func TestMapAddr_RFC6052Golden(t *testing.T) {
	cases := []struct {
		prefix string
		ip4    string
		want   string
	}{
		{"2001:db8::/32", "192.0.2.33", "2001:db8:c000:221::"},
		{"2001:db8:100::/40", "192.0.2.33", "2001:db8:1c0:2:21::"},
		{"2001:db8:122::/48", "192.0.2.33", "2001:db8:122:c000:2:2100::"},
		{"2001:db8:122:300::/56", "192.0.2.33", "2001:db8:122:3c0:0:221::"},
		{"2001:db8:122:344::/64", "192.0.2.33", "2001:db8:122:344:c0:2:2100:0"}, // == RFC 6052 "…:c0:2:2100::"
		{"2001:db8:122:344::/96", "192.0.2.33", "2001:db8:122:344::c000:221"},
		// Well-known prefix (RFC 6052 §2.1): /96, IPv4 at bits 96-127.
		{"64:ff9b::/96", "192.0.2.33", "64:ff9b::c000:221"},
	}
	for _, tc := range cases {
		s, err := New(tc.prefix)
		if err != nil {
			t.Fatalf("New(%s): %v", tc.prefix, err)
		}
		got := s.MapAddr(netip.MustParseAddr(tc.ip4))
		if got.String() != tc.want {
			t.Errorf("prefix %s: MapAddr(%s) = %s, want %s", tc.prefix, tc.ip4, got, tc.want)
		}
	}
}

// TestMapAddr_AllPrefixLens checks every valid prefix length leaves the u
// octet (bits 64-71) zero per RFC 6052.
func TestMapAddr_AllPrefixLens(t *testing.T) {
	for pl := range validPrefixLens {
		s, err := New("2001:db8:122:344::/" + strconv.Itoa(pl))
		if err != nil {
			t.Fatalf("New(/%d): %v", pl, err)
		}
		ip6 := s.MapAddr(netip.MustParseAddr("203.0.113.7"))
		if b := ip6.As16()[8]; b != 0 {
			t.Errorf("prefix /%d: u octet = %#02x, want 0", pl, b)
		}
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
