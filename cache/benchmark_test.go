package cache

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

func BenchmarkStoreSetGet(b *testing.B) {
	log.Default.SetLevel(log.Error)
	c := newTestCache()
	defer func() { _ = c.Close() }()

	a := &dns.A{
		Hdr:  dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}

	b.ResetTimer()
	for b.Loop() {
		c.Set("www.example.com.", dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)
		c.Get("www.example.com.", dns.TypeA, dns.ClassINET, nil)
	}
}

func BenchmarkStoreParallel(b *testing.B) {
	log.Default.SetLevel(log.Error)
	c := newTestCache()
	defer func() { _ = c.Close() }()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			name := fmt.Sprintf("host%d.example.com.", i%1000)
			a := &dns.A{
				Hdr:  dns.Header{Name: fmt.Sprintf("host%d.example.com.", i), Class: dns.ClassINET, TTL: 300},
				Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 256)}),
			}
			c.Set(name, dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)
			c.Get(name, dns.TypeA, dns.ClassINET, nil)
			i++
		}
	})
}

// spillBenchCache builds a two-tier cache with a temp spill file.
func spillBenchCache(b *testing.B, mem int) *Cache {
	b.Helper()
	c := New(
		config.LimitSettings{Mem: mem, Disk: 0},
		config.LimitSettings{Mem: 0, Disk: 0},
		filepath.Join(b.TempDir(), "bench.cache"), "",
	)
	b.Cleanup(func() { _ = c.Close() })
	return c
}

// BenchmarkStoreGetSpillHit measures the memory-miss path with the disk
// tier: spill index lookup + file read + promote back into memory.  Each
// iteration first deletes the target from memory (its OnEvict re-spills the
// unchanged record), so every Get is a genuine disk hit.
func BenchmarkStoreGetSpillHit(b *testing.B) {
	log.Default.SetLevel(log.Error)
	c := spillBenchCache(b, 1000)

	// Pre-fill 1001 distinct entries: host0 overflows the mem cap and lands
	// on disk, host1000 stays in memory.
	a := &dns.A{
		Hdr:  dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300},
		Addr: netip.MustParseAddr("192.0.2.1"),
	}
	for i := range 1001 {
		name := fmt.Sprintf("host%d.example.com.", i)
		c.Set(name, dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)
	}
	if c.EntryCount() != 1000 || c.SpillStore().EntryCount() != 1 {
		b.Fatalf("setup: mem=%d spill=%d", c.EntryCount(), c.SpillStore().EntryCount())
	}

	name := "host0.example.com."
	key := cacheKey{qname: name, qtype: dns.TypeA, qclass: dns.ClassINET}
	b.ResetTimer()
	for b.Loop() {
		c.entries.Delete(key) // memory miss → disk tier
		c.Get(name, dns.TypeA, dns.ClassINET, nil)
	}
}

// BenchmarkStoreSetWithSpill measures the Set hot path when the mem cap is
// reached: every Set evicts the LRU tail, which spills to disk.  Compare
// against BenchmarkStoreSetGet (single-tier) for the eviction-write cost.
func BenchmarkStoreSetWithSpill(b *testing.B) {
	log.Default.SetLevel(log.Error)
	c := spillBenchCache(b, 1000)

	for i := range 1000 {
		name := fmt.Sprintf("host%d.example.com.", i)
		a := &dns.A{
			Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
			Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 256)}),
		}
		c.Set(name, dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("new%d.example.com.", i%1000)
		a := &dns.A{
			Hdr:  dns.Header{Name: name, Class: dns.ClassINET, TTL: 300},
			Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 256)}),
		}
		c.Set(name, dns.TypeA, dns.ClassINET, nil, []dns.RR{a}, nil, nil, false, 0)
	}
}

// BenchmarkSynthesizeNegative_NSECHit measures the RFC 8198 aggressive lookup
// on the miss path: zone pick (map iteration) + canonical binary search +
// Appendix B + wildcard-denial scan over a populated table.
func BenchmarkSynthesizeNegative_NSECHit(b *testing.B) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, Minttl: 900}
	wild := &dns.NSEC{
		Hdr:        dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "albatross.example.com.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS},
	}
	cover := &dns.NSEC{
		Hdr:        dns.Header{Name: "albatross.example.com.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "elephant.example.com.", TypeBitMap: []uint16{dns.TypeA},
	}
	s.IndexNegative("cat.example.com.", dns.ClassINET, []dns.RR{wild, cover}, []dns.RR{soa, wild, cover})

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET); !ok {
			b.Fatal("synthesis missed")
		}
	}
}

// BenchmarkNegativeAncestor measures the RFC 8020 probe: the ancestor walk is
// on EVERY cache miss, so it must stay allocation-free.
func BenchmarkNegativeAncestor_Miss(b *testing.B) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, ok := s.NegativeAncestor("deep.sub.example.com."); ok {
			b.Fatal("unexpected cut")
		}
	}
}

func BenchmarkNegativeAncestor_Hit(b *testing.B) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, Minttl: 900}
	s.Set("foo.example.com.", dns.TypeA, dns.ClassINET, nil, nil, []dns.RR{soa}, nil, false, dns.RcodeNameError)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, ok := s.NegativeAncestor("x.foo.example.com."); !ok {
			b.Fatal("cut missed")
		}
	}
}

// BenchmarkNSECZonePick512 measures the worst-case zone pick: 512 zone
// tables iterated per miss-path synthesis attempt.
func BenchmarkNSECZonePick512(b *testing.B) {
	s := New(config.LimitSettings{}, config.LimitSettings{}, "", "")
	soa := &dns.SOA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 3600}, Minttl: 900}
	wild := &dns.NSEC{
		Hdr:        dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "albatross.example.com.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS},
	}
	cover := &dns.NSEC{
		Hdr:        dns.Header{Name: "albatross.example.com.", Class: dns.ClassINET, TTL: 86400},
		NextDomain: "elephant.example.com.", TypeBitMap: []uint16{dns.TypeA},
	}
	s.IndexNegative("cat.example.com.", dns.ClassINET, []dns.RR{wild, cover}, []dns.RR{soa, wild, cover})
	for i := range 511 {
		s.insertRanges(nsecZoneKey{apex: zdnsutil.Canonical("z" + strconv.Itoa(i) + ".example."), class: dns.ClassINET},
			[]*nsecRange{{owner: "a." + zdnsutil.Canonical("z"+strconv.Itoa(i)+".example."), next: "z." + zdnsutil.Canonical("z"+strconv.Itoa(i)+".example."), ts: 1, ttl: 3600}},
			nil, nsec3Params{}, 1)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, _, ok := s.SynthesizeNegative("dog.example.com.", dns.TypeA, dns.ClassINET); !ok {
			b.Fatal("synthesis missed")
		}
	}
}
