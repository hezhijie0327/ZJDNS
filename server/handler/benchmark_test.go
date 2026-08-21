package handler

import (
	"net/netip"
	"testing"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// BenchmarkPatchQuestionCase measures the cache-hit question-case patch on a
// real pre-packed entry.  The direct-wire fast path promises 0 B/op /
// 0 allocs/op — the patch must not break that contract.
func BenchmarkPatchQuestionCase(b *testing.B) {
	store := cache.New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	store.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{&dns.A{
		Hdr:  dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}}, nil, nil, false, 0)
	entry, found, _ := store.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	if !found {
		b.Fatal("cache entry not found")
	}

	req := new(dns.Msg)
	dnsutil.SetQuestion(req, "wWw.ExAmPle.CoM.", dns.TypeA, dns.ClassINET)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		msg := BuildCacheEntryResponse(req, entry, false, false)
		if msg == nil {
			b.Fatal("nil response")
		}
		// Mirror the real serve path: the caller returns the message to the
		// pool (the wire itself is entry-owned memory, not pool memory).
		pool.DefaultMessage.Put(msg)
	}
}
