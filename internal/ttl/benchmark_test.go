package ttl

import (
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

func BenchmarkIsExpired(b *testing.B) {
	now := NowUnix()
	b.ResetTimer()
	for b.Loop() {
		_ = IsExpired(now-100, 60)
	}
}

func BenchmarkRemainingTTL_Fresh(b *testing.B) {
	now := NowUnix()
	b.ResetTimer()
	for b.Loop() {
		_ = RemainingTTL(now, 300, 60)
	}
}

func BenchmarkRemainingTTL_Stale(b *testing.B) {
	now := NowUnix()
	b.ResetTimer()
	for b.Loop() {
		_ = RemainingTTL(now-400, 300, 60)
	}
}

func BenchmarkCanServeExpired(b *testing.B) {
	now := NowUnix()
	b.ResetTimer()
	for b.Loop() {
		_ = CanServeExpired(now-400, 300, 3600)
	}
}

func BenchmarkShouldPrefetch(b *testing.B) {
	now := NowUnix()
	b.ResetTimer()
	for b.Loop() {
		_ = ShouldPrefetch(now-200, 300, 50)
	}
}

func BenchmarkElapsed(b *testing.B) {
	now := NowUnix()
	b.ResetTimer()
	for b.Loop() {
		_ = Elapsed(now - 60)
	}
}

func BenchmarkDeductElapsedCyclical(b *testing.B) {
	rrs := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{}},
		&dns.AAAA{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 600}, AAAA: rdata.AAAA{}},
	}
	b.ResetTimer()
	for b.Loop() {
		_ = DeductElapsedCyclical(rrs, 120)
	}
}
