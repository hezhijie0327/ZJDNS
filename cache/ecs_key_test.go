package cache

import (
	"net"
	"net/netip"
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

func ecsOpt(t *testing.T, cidr string, prefix uint8) *config.ECSOption {
	t.Helper()
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse cidr: %v", err)
	}
	return &config.ECSOption{Address: ip, SourcePrefix: prefix}
}

// TestSet_ECSVariantsCollapse pins the cache-key ECS scope cap: client
// /32 (v4) or /128 (v6) variants within one outbound scope (/24, /56) share
// a single cache entry instead of multiplying entries — a per-query
// rotation of client subnets must not evict the cache.
func TestSet_ECSVariantsCollapse(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	defer func() { _ = s.Close() }()

	answer := []dns.RR{&dns.A{Hdr: dns.Header{Name: "cdn.example.com.", Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("203.0.113.9")}}
	s.Set("cdn.example.com.", dns.TypeA, dns.ClassINET, ecsOpt(t, "198.51.100.1/32", 32), answer, nil, nil, false, dns.RcodeSuccess)
	s.Set("cdn.example.com.", dns.TypeA, dns.ClassINET, ecsOpt(t, "198.51.100.200/32", 32), answer, nil, nil, false, dns.RcodeSuccess)

	if _, ok, _ := s.Get("cdn.example.com.", dns.TypeA, dns.ClassINET, ecsOpt(t, "198.51.100.77/32", 32)); !ok {
		t.Fatal("a third /32 variant in the same /24 must hit the shared entry")
	}
	if _, ok, _ := s.Get("cdn.example.com.", dns.TypeA, dns.ClassINET, ecsOpt(t, "198.51.100.1/32", 32)); !ok {
		t.Fatal("the first variant's own /32 lookup must hit the shared entry too")
	}
}

// TestSet_MixedCaseQnameKeyedCanonically pins the Set-side key
// canonicalization: a mixed-case qname (case-echoing glue) stores under the
// lowercase key the client lookup path uses.
func TestSet_MixedCaseQnameKeyedCanonically(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	defer func() { _ = s.Close() }()

	answer := []dns.RR{&dns.A{Hdr: dns.Header{Name: "Ns1.ExAmPlE.CoM.", Class: dns.ClassINET, TTL: 60}, Addr: netip.MustParseAddr("192.0.2.53")}}
	s.Set("Ns1.ExAmPlE.CoM.", dns.TypeA, dns.ClassINET, nil, answer, nil, nil, false, dns.RcodeSuccess)

	if _, ok, _ := s.Get("ns1.example.com.", dns.TypeA, dns.ClassINET, nil); !ok {
		t.Fatal("lowercase lookup must hit the mixed-case Set entry — the key must be canonical")
	}
}
