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

// TestMapAddr_RFC6052Vectors verifies the IPv4 embedding and u-octet
// handling for every supported prefix length, using the exact examples from
// RFC 6052 Table 1 (192.0.2.33). All non-/96 prefixes embed the FULL IPv4
// address split across the u octet, so round-trip recovers it completely.
func TestMapAddr_RFC6052Vectors(t *testing.T) {
	ip4 := netip.MustParseAddr("192.0.2.33") // c0 00 02 21
	tests := []struct {
		prefix      string
		want        string
		wantExtract string
	}{
		{"2001:db8::/32", "2001:db8:c000:221::", "192.0.2.33"},
		{"2001:db8:100::/40", "2001:db8:1c0:2:21::", "192.0.2.33"},
		{"2001:db8:122::/48", "2001:db8:122:c000:2:2100::", "192.0.2.33"},
		{"2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::", "192.0.2.33"},
		{"2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::", "192.0.2.33"},
		{"64:ff9b::/96", "64:ff9b::c000:221", "192.0.2.33"},
	}
	for _, tc := range tests {
		s, err := New(tc.prefix)
		if err != nil {
			t.Fatalf("New(%s): %v", tc.prefix, err)
		}
		got := s.MapAddr(ip4)
		want := netip.MustParseAddr(tc.want)
		if got != want {
			t.Errorf("MapAddr(%s) with %s = %s, want %s", ip4, tc.prefix, got, want)
		}
		back, ok := s.ExtractIPv4(got)
		wantExtract := netip.MustParseAddr(tc.wantExtract)
		if !ok || back != wantExtract {
			t.Errorf("ExtractIPv4(%s) with %s = %s (ok=%v), want %s", got, tc.prefix, back, ok, wantExtract)
		}
	}
}

// TestIsSynthesized_UOctet verifies that an address inside the prefix but
// with a nonzero u octet is not reported as synthesized (RFC 6052 §2.2).
func TestIsSynthesized_UOctet(t *testing.T) {
	s, _ := New("2001:db8::/48")
	if !s.IsSynthesized(netip.MustParseAddr("2001:db8:0:c000::")) {
		t.Error("synthesized address (u=0) should be recognized")
	}
	if s.IsSynthesized(netip.MustParseAddr("2001:db8:0:0:100:0:0:0")) {
		t.Error("address with nonzero u octet must not count as synthesized")
	}
}

// TestSynthesize_CDGated verifies RFC 6147 §5.5: with the CD bit set no
// synthesis happens (client validates for itself); without CD, CNAME chains
// are preserved (RFC 6147 §5.1.5) while RRSIG and unrelated records are
// stripped from the synthesized answer.
func TestSynthesize_CDGated(t *testing.T) {
	s, _ := New(defaultPrefix)
	aAnswer := []dns.RR{
		&dns.CNAME{
			Hdr:   dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
			CNAME: rdata.CNAME{Target: "example.com."},
		},
		&dns.A{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
			A:   rdata.A{Addr: netip.MustParseAddr("93.184.216.34")},
		},
		&dns.RRSIG{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		},
		&dns.TXT{
			Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		},
	}
	// CD bit set: pass through untouched.
	answer, _, _ := s.Synthesize(aAnswer, nil, nil, aAnswer, nil, nil, true)
	if len(answer) != 4 {
		t.Fatalf("CD-set response must pass through, got %d records", len(answer))
	}
	// No CD: CNAME survives, A becomes AAAA, RRSIG/TXT stripped.
	answer, _, _ = s.Synthesize(nil, nil, nil, aAnswer, nil, nil, false)
	if len(answer) != 2 {
		t.Fatalf("expected CNAME + AAAA, got %d records", len(answer))
	}
	if _, ok := answer[0].(*dns.CNAME); !ok {
		t.Fatalf("expected CNAME preserved first, got %T", answer[0])
	}
	if _, ok := answer[1].(*dns.AAAA); !ok {
		t.Fatalf("expected AAAA synthesized, got %T", answer[1])
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

// TestMapAddr_MultiIPVectors verifies embedding correctness across IPs with
// different byte patterns (boundary values, small octets, RFC 1918 ranges)
// for every prefix length: the u octet stays zero, the prefix is preserved,
// and round-trip recovers the original address completely.
func TestMapAddr_MultiIPVectors(t *testing.T) {
	prefixes := []string{
		"2001:db8::/32", "2001:db8:100::/40", "2001:db8:122::/48",
		"2001:db8:122:300::/56", "2001:db8:122:344::/64", "64:ff9b::/96",
	}
	ips := []string{"192.0.2.33", "255.255.255.255", "1.2.3.4", "0.0.0.1", "10.0.0.1", "172.16.5.9"}
	for _, p := range prefixes {
		s, err := New(p)
		if err != nil {
			t.Fatalf("New(%s): %v", p, err)
		}
		pref := netip.MustParsePrefix(s.Prefix())
		for _, ipStr := range ips {
			ip4 := netip.MustParseAddr(ipStr)
			mapped := s.MapAddr(ip4)
			b := mapped.As16()
			if p[len(p)-3:] != "/96" && b[8] != 0 {
				t.Errorf("%s MapAddr(%s): u octet = %#x, want 0", p, ipStr, b[8])
			}
			if !pref.Contains(mapped) {
				t.Errorf("%s MapAddr(%s): %s not in prefix", p, ipStr, mapped)
			}
			back, ok := s.ExtractIPv4(mapped)
			if !ok || back != ip4 {
				t.Errorf("%s round-trip %s -> %s -> %s (ok=%v)", p, ipStr, mapped, back, ok)
			}
			if !s.IsSynthesized(mapped) {
				t.Errorf("%s IsSynthesized(%s) = false", p, mapped)
			}
		}
	}
}
