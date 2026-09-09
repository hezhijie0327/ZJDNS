package handler

import (
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// TestStoreIfCacheableNoCacheEDE verifies the belt-and-suspenders gate: a
// result carrying a ZJDNS no-cache EDE (fallback provenance or defense
// uncertainty) is refused even if Cacheable was left set.
func TestStoreIfCacheableNoCacheEDE(t *testing.T) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")

	q := dnsutil.SetQuestion(new(dns.Msg), "example.com.", dns.TypeA)
	_ = q
	rr := &dns.A{
		Hdr:  dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("93.184.216.34"),
	}

	qr := &resolver.QueryResult{
		Cacheable:   true,
		Answer:      []dns.RR{rr},
		Rcode:       dns.RcodeSuccess,
		UpstreamEDE: &dns.EDE{InfoCode: edns.EDEZJDNSDefenseUncertain},
	}
	if StoreIfCacheable(store, "example.com", dns.TypeA, dns.ClassINET, nil, qr) {
		t.Fatal("defense-uncertain result must not be cached")
	}

	qr.UpstreamEDE = &dns.EDE{InfoCode: edns.EDEZJDNSFallback}
	if StoreIfCacheable(store, "example.com", dns.TypeA, dns.ClassINET, nil, qr) {
		t.Fatal("fallback result must not be cached")
	}

	// Control: without the EDE the same result is cacheable.
	qr.UpstreamEDE = nil
	if !StoreIfCacheable(store, "example.com", dns.TypeA, dns.ClassINET, nil, qr) {
		t.Fatal("plain result must be cacheable")
	}
	if _, found, _ := store.Get("example.com", dns.TypeA, dns.ClassINET, nil); !found {
		t.Fatal("control result must have been stored")
	}
}
