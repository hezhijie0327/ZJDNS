package cache

import (
	"testing"

	"codeberg.org/miekg/dns"
)

// BenchmarkGet_SortedByLatency measures the cache-hit path with A/AAAA
// latency reordering active (3 probed IPs in a 4-record answer).
func BenchmarkGet_SortedByLatency(b *testing.B) {
	mc := New(0, "")
	defer func() { _ = mc.Close() }()
	mc.Set("x.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"), nil, nil, false, dns.RcodeSuccess)
	mc.UpdateLatency("192.0.2.1", 50)
	mc.UpdateLatency("192.0.2.2", 5)
	mc.UpdateLatency("192.0.2.3", 25)

	b.ResetTimer()
	for b.Loop() {
		if _, found, _ := mc.Get("x.example.com.", dns.TypeA, dns.ClassINET, nil, false); !found {
			b.Fatal("miss")
		}
	}
}

// BenchmarkGet_NoLatency measures the cache-hit path without any latency data
// (sorting skipped entirely).
func BenchmarkGet_NoLatency(b *testing.B) {
	mc := New(0, "")
	defer func() { _ = mc.Close() }()
	mc.Set("x.example.com.", dns.TypeA, dns.ClassINET, nil, false,
		aRRs("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"), nil, nil, false, dns.RcodeSuccess)

	b.ResetTimer()
	for b.Loop() {
		if _, found, _ := mc.Get("x.example.com.", dns.TypeA, dns.ClassINET, nil, false); !found {
			b.Fatal("miss")
		}
	}
}
