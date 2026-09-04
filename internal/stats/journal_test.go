package stats

import (
	"sync"
	"testing"
)

func TestCountersEveryDimension(t *testing.T) {
	m := NewJournal(10)
	recs := []*RequestRecord{
		{Qname: "a.com.", Result: "hit", Protocol: "udp", Rcode: 0, ResponseTime: 1},
		{Qname: "b.com.", Result: "miss", Protocol: "tcp", Rcode: 3, ResponseTime: 2, DNSSECStatus: "bogus", Poisoned: true},
		{Qname: "c.com.", Result: "stale", Protocol: "tls", Rcode: 5, ResponseTime: 3},
		{Qname: "d.com.", Result: "zone", Protocol: "quic", Rcode: 1, ResponseTime: 4},
		{Qname: "e.com.", Result: "error", Protocol: "https", Rcode: 2, ResponseTime: 5, DNSSECStatus: "secure"},
		{Qname: "f.com.", Result: "blocked", Protocol: "http3", Rcode: 4, ResponseTime: 6},
		{Qname: "g.com.", Result: "badcookie", Protocol: "dtls", Rcode: 7, ResponseTime: 7, DNSSECStatus: "insecure"},
		{Qname: "h.com.", Result: "hit", Protocol: "dnscrypt", Rcode: 0, ResponseTime: 8},
		{Qname: "i.com.", Result: "miss", Protocol: "dnscrypt-tcp", Rcode: 3, ResponseTime: 9},
		{Qname: "j.com.", Result: "hit", Protocol: "tlcp", Rcode: 0, ResponseTime: 10},
		{Qname: "k.com.", Result: "hit", Protocol: "http-tlcp", Rcode: 0, ResponseTime: 11},
		{Qname: "l.com.", Result: "hit", Protocol: "dtlcp", Rcode: 0, ResponseTime: 12},
	}
	for _, r := range recs {
		m.Record(r)
	}

	s := m.Snapshot(42)
	if s.Entries != 42 {
		t.Fatalf("Entries = %d, want 42", s.Entries)
	}
	if s.Total != 12 {
		t.Fatalf("Total = %d, want 12", s.Total)
	}
	if s.Hits != 5 || s.Misses != 2 || s.Stales != 1 || s.Zones != 1 ||
		s.Errors != 1 || s.Blocked != 1 || s.Badcookie != 1 {
		t.Fatalf("result counters wrong: %+v", s)
	}
	if s.UDP != 1 || s.TCP != 1 || s.TLS != 1 || s.QUIC != 1 || s.HTTPS != 1 ||
		s.HTTP3 != 1 || s.DTLS != 1 || s.DNSCrypt != 1 || s.DNSCryptTCP != 1 ||
		s.TLCP != 1 || s.HTTPTLCP != 1 || s.DTLCP != 1 {
		t.Fatalf("protocol counters wrong: %+v", s)
	}
	if s.Noerr != 5 || s.Formerr != 1 || s.Servfail != 1 || s.NXDomain != 2 ||
		s.Notimp != 1 || s.Refused != 1 || s.Other != 1 {
		t.Fatalf("rcode counters wrong: %+v", s)
	}
	if s.Secure != 1 || s.Insecure != 1 || s.Bogus != 1 {
		t.Fatalf("dnssec counters wrong: %+v", s)
	}
	if s.Poisoned != 1 {
		t.Fatalf("Poisoned = %d, want 1", s.Poisoned)
	}
	if s.TotalMS != 78 { // 1+2+...+12
		t.Fatalf("TotalMS = %d, want 78", s.TotalMS)
	}
}

func TestJournalTopNAndSkipHits(t *testing.T) {
	m := NewJournal(10)
	// Hits must not enter the journal.
	m.Record(&RequestRecord{Qname: "hit.com.", Result: "hit", Rcode: 3})
	// RCODE 3: a=5, b=3, c=2
	for range 5 {
		m.Record(&RequestRecord{Qname: "a.com.", Result: "miss", Rcode: 3})
	}
	for range 3 {
		m.Record(&RequestRecord{Qname: "b.com.", Result: "error", Rcode: 3})
	}
	for range 2 {
		m.Record(&RequestRecord{Qname: "c.com.", Result: "stale", Rcode: 3})
	}
	// RCODE 5: x=4
	for range 4 {
		m.Record(&RequestRecord{Qname: "x.net.", Result: "refused", Rcode: 5})
	}

	s := m.Snapshot(0)
	rc3 := s.TopByRcode[3]
	if len(rc3) != 3 {
		t.Fatalf("rcode 3 top len = %d, want 3", len(rc3))
	}
	if rc3[0].Key != "a.com." || rc3[0].Count != 5 {
		t.Fatalf("rcode 3 top[0] = %+v, want {a.com. 5}", rc3[0])
	}
	if rc3[1].Key != "b.com." || rc3[1].Count != 3 {
		t.Fatalf("rcode 3 top[1] = %+v, want {b.com. 3}", rc3[1])
	}
	if _, ok := s.TopByRcode[0]; ok {
		t.Fatal("rcode 0 (hits) must not have journal entries")
	}
	rc5 := s.TopByRcode[5]
	if len(rc5) != 1 || rc5[0].Key != "x.net." || rc5[0].Count != 4 {
		t.Fatalf("rcode 5 top = %+v, want {x.net. 4}", rc5)
	}
}

func TestJournalBoundedCapacity(t *testing.T) {
	m := NewJournal(3)
	// First key dominates; then 10 one-off keys overflow the capacity.
	for range 100 {
		m.Record(&RequestRecord{Qname: "hot.com.", Result: "miss", Rcode: 1})
	}
	for i := range 10 {
		m.Record(&RequestRecord{Qname: string(rune('a'+i)) + ".one.com.", Result: "miss", Rcode: 1})
	}
	s := m.Snapshot(0)
	if got := len(s.TopByRcode[1]); got != 3 {
		t.Fatalf("journal len = %d, want 3 (capacity)", got)
	}
	if s.TopByRcode[1][0].Key != "hot.com." {
		t.Fatalf("top[0] = %s, want hot.com. (high count must survive)", s.TopByRcode[1][0].Key)
	}
}

func TestConcurrentRecord(t *testing.T) {
	m := NewJournal(1000)
	const workers, iters = 8, 1000
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range iters {
				m.Record(&RequestRecord{Qname: "x.com.", Result: "miss", Protocol: "udp", Rcode: 3, ResponseTime: 1})
			}
		})
	}
	wg.Wait()
	s := m.Snapshot(0)
	if s.Total != workers*iters {
		t.Fatalf("Total = %d, want %d", s.Total, workers*iters)
	}
	if s.Misses != workers*iters {
		t.Fatalf("Misses = %d, want %d", s.Misses, workers*iters)
	}
	if s.TopByRcode[3][0].Count != workers*iters {
		t.Fatalf("journal count = %d, want %d", s.TopByRcode[3][0].Count, workers*iters)
	}
}

func BenchmarkRecord(b *testing.B) {
	m := NewJournal(1000)
	r := &RequestRecord{Qname: "example.com.", Result: "miss", Protocol: "udp", Rcode: 3, ResponseTime: 42}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.Record(r)
		}
	})
}

func BenchmarkSnapshot(b *testing.B) {
	m := NewJournal(1000)
	for range 100 {
		m.Record(&RequestRecord{Qname: "example.com.", Result: "miss", Protocol: "udp", Rcode: 3})
	}
	b.ReportAllocs()
	for range b.N {
		m.Snapshot(0)
	}
}
