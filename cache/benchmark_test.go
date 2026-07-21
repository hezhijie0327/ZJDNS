package cache

import (
	"fmt"
	"net/netip"
	"testing"
	"zjdns/database"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func BenchmarkStoreSetGet(b *testing.B) {
	log.Default.SetLevel(log.Error)
	db, _ := database.Open("", 0, database.Options{})
	c := New(db)
	defer func() { _ = c.Close() }()

	a := &dns.A{
		Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		A:   rdata.A{Addr: netip.MustParseAddr("192.0.2.1")},
	}

	b.ResetTimer()
	for b.Loop() {
		c.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, false, []dns.RR{a}, nil, nil, false)
		c.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil, false)
	}
}

func BenchmarkStoreParallel(b *testing.B) {
	log.Default.SetLevel(log.Error)
	db, _ := database.Open("", 0, database.Options{})
	c := New(db)
	defer func() { _ = c.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("host%d.example.com.", i%1000)
			a := &dns.A{
				Hdr: dns.Header{Name: fmt.Sprintf("host%d.example.com.", i), Class: dns.ClassINET, TTL: 300},
				A:   rdata.A{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 256)})},
			}
			c.Set(name, dns.TypeA, dns.ClassINET, nil, false, []dns.RR{a}, nil, nil, false)
			c.Get(name, dns.TypeA, dns.ClassINET, nil, false)
			i++
		}
	})
}
