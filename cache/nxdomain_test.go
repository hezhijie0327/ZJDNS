package cache

import (
	"testing"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

func nxdomainSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600},
		Ns:  "ns1.example.com.", Mbox: "hostmaster.example.com.", Serial: 1, Minttl: 900,
	}
}

// RFC 8020 §2: a cached NXDOMAIN for a name denies its whole subtree.
func TestNegativeAncestor_Cut(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	s.Set("foo.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{nxdomainSOA()}, nil, false, dns.RcodeNameError)

	soa, ttl, ok := s.NegativeAncestor("deep.bar.foo.example.com.")
	if !ok || soa == nil || ttl <= 0 || ttl > 900 {
		t.Fatalf("NegativeAncestor = ok=%v ttl=%d, want the cached cut with remaining TTL ≤ 900", ok, ttl)
	}
	if soa.Header().Name != "example.com." {
		t.Fatalf("SOA owner = %s", soa.Header().Name)
	}
}

// The denied name's siblings stay resolvable, and exact negatives still come
// from the plain cache path (NegativeAncestor only sees ancestors).
func TestNegativeAncestor_NoSiblingLeak(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	s.Set("bar.foo.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{nxdomainSOA()}, nil, false, dns.RcodeNameError)

	if _, _, ok := s.NegativeAncestor("baz.foo.example.com."); ok {
		t.Fatal("sibling cut leaked (RFC 8020 §2: only the subtree is denied)")
	}
	// Deeper descendant cuts.
	if _, _, ok := s.NegativeAncestor("x.bar.foo.example.com."); !ok {
		t.Fatal("descendant of the denied name not cut")
	}
}

// RFC 6604/§2: a CNAME chain's NXDOMAIN belongs to the chain's final target —
// the original qname (which exists) must not cut its subtree.
func TestNegativeAncestor_CNAMEChainNotIndexed(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	cname := &dns.CNAME{Hdr: dns.Header{Name: "alias.example.com.", Class: dns.ClassINET, TTL: 300}, Target: "gone.example.net."}
	s.Set("alias.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{cname}, []dns.RR{nxdomainSOA()}, nil, false, dns.RcodeNameError)

	if _, _, ok := s.NegativeAncestor("sub.alias.example.com."); ok {
		t.Fatal("CNAME-chain response cut the (existing) chain-head subtree")
	}
}

// Entries without a cacheable negative TTL (no SOA) are not indexed.
func TestNegativeAncestor_NoSOANotIndexed(t *testing.T) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	s.Set("noSoa.example.com.", dns.TypeA, dns.ClassINET, nil, nil, nil, nil, false, dns.RcodeNameError)

	if _, _, ok := s.NegativeAncestor("x.noSoa.example.com."); ok {
		t.Fatal("indexed an NXDOMAIN that was never cached (no SOA, RFC 2308 §6.1)")
	}
}
