package dnsutil

import (
	"crypto/rand"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
)

type testTimeoutError struct{}

func (e *testTimeoutError) Error() string { return "timeout" }
func (e *testTimeoutError) Timeout() bool { return true }

// ── zstd compression benchmarks ──────────────────────────────────────────────

func BenchmarkCompress(b *testing.B) {
	// Generate realistic DNS wire-format data (~512 bytes).
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	b.ResetTimer()
	for b.Loop() {
		_ = Compress(data)
	}
}

func BenchmarkCompressSmall(b *testing.B) {
	data := make([]byte, 64)
	_, _ = rand.Read(data)
	b.ResetTimer()
	for b.Loop() {
		_ = Compress(data)
	}
}

func BenchmarkDecompress(b *testing.B) {
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	compressed := Compress(data)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Decompress(compressed, nil)
	}
}

func BenchmarkDecompressReuseBuffer(b *testing.B) {
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	compressed := Compress(data)
	dst := make([]byte, 0, 1024)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Decompress(compressed, dst)
	}
}

func BenchmarkCompressDecompressRoundTrip(b *testing.B) {
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	b.ResetTimer()
	for b.Loop() {
		c := Compress(data)
		_, _ = Decompress(c, nil)
	}
}

// ── Domain helpers ───────────────────────────────────────────────────────────

func BenchmarkIsSecureProtocol(b *testing.B) {
	protos := []string{"tls", "quic", "https", "http3", "dtls", "tlcp", "http-tlcp", "dtlcp", "udp", "tcp"}
	b.ResetTimer()
	for b.Loop() {
		for _, p := range protos {
			_ = IsSecureProtocol(p)
		}
	}
}

func BenchmarkExtractIP(b *testing.B) {
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}
	b.ResetTimer()
	for b.Loop() {
		_ = ExtractIP(a)
	}
}

func BenchmarkExtractIPString(b *testing.B) {
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("192.0.2.1")}
	b.ResetTimer()
	for b.Loop() {
		_, _ = ExtractIPString(a)
	}
}

func BenchmarkIsTemporaryError(b *testing.B) {
	err := &testTimeoutError{}
	b.ResetTimer()
	for b.Loop() {
		_ = IsTemporaryError(err)
	}
}

// ── Handshake logging (debug disabled path) ──────────────────────────────────

func BenchmarkLogHandshake(b *testing.B) {
	info := &HandshakeInfo{
		Role:       "TLS",
		Direction:  "handshake from",
		RemoteAddr: "192.0.2.1:443",
		Version:    0x0304,
		Cipher:     "TLS_AES_256_GCM_SHA384",
		Group:      "X25519",
		ALPN:       "dot",
	}
	b.ResetTimer()
	for b.Loop() {
		LogHandshake(info)
	}
}

// BenchmarkFoldCaseNoOp: the dominant path — already-lowercase answers must
// not allocate beyond the presentation serialisation (2026-09 F5 fast path).
func BenchmarkFoldCaseNoOp(b *testing.B) {
	rrs := []dns.RR{
		&dns.A{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("93.184.216.34")},
		&dns.CNAME{Hdr: dns.Header{Name: "www.example.com.", Class: dns.ClassINET, TTL: 300}, Target: "edge.example.net."},
	}
	FoldCase(rrs)
	if rrs[0].Header().Name != "www.example.com." {
		b.Fatal("fold mutated an already-canonical owner")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		FoldCase(rrs)
	}
}

// BenchmarkFoldCaseMixed: the rare path — 0x20-echoed case in owners/rdata.
func BenchmarkFoldCaseMixed(b *testing.B) {
	mk := func() []dns.RR {
		return []dns.RR{
			&dns.A{Hdr: dns.Header{Name: "WwW.ExAmPlE.CoM.", Class: dns.ClassINET, TTL: 300}, Addr: netip.MustParseAddr("93.184.216.34")},
			&dns.CNAME{Hdr: dns.Header{Name: "WwW.ExAmPlE.CoM.", Class: dns.ClassINET, TTL: 300}, Target: "EdGe.ExAmPlE.nEt."},
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		rrs := mk()
		FoldCase(rrs)
		if rrs[0].Header().Name != "www.example.com." {
			b.Fatal("owner not folded")
		}
	}
}
