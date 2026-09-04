package log

import (
	"net"
	"testing"
)

// The hot-path cost of a FILTERED-OUT call: the level check inside Log()
// happens after the call site has already boxed the variadic args.
func BenchmarkDebugfFiltered(b *testing.B) {
	SetLevel(Info) // Debug calls filtered
	b.ReportAllocs()
	b.ResetTimer()
	qname := "www.example.com."
	qtype := "A"
	ip := net.IPv4(192, 0, 2, 1)
	for b.Loop() {
		Debugf("ZONE: evaluating rules for %s qtype=%s client=%s tags=%v", qname, qtype, ip, b.N)
	}
}

func BenchmarkDebugfGated(b *testing.B) {
	SetLevel(Info)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if IsDebug() {
			Debugf("ZONE: evaluating rules for %s qtype=%s client=%s tags=%v", "www.example.com.", "A", "192.0.2.1", nil)
		}
	}
}

func BenchmarkDebugfNoArgsFiltered(b *testing.B) {
	SetLevel(Info)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		Debugf("ZONE: static message")
	}
}
