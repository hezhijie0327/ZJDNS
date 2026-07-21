package dnsutil

import (
	"crypto/rand"
	"net/netip"
	"testing"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
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
		_, _ = Decompress(compressed)
	}
}

func BenchmarkDecompressTo(b *testing.B) {
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	compressed := Compress(data)
	dst := make([]byte, 0, 1024)
	b.ResetTimer()
	for b.Loop() {
		_, _ = DecompressTo(compressed, dst)
	}
}

func BenchmarkCompressDecompressRoundTrip(b *testing.B) {
	data := make([]byte, 512)
	_, _ = rand.Read(data)
	b.ResetTimer()
	for b.Loop() {
		c := Compress(data)
		_, _ = Decompress(c)
	}
}

// ── Domain helpers ───────────────────────────────────────────────────────────

func BenchmarkParseReverseDNSName(b *testing.B) {
	names := []string{
		"1.0.0.127.in-addr.arpa.",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
	}
	b.ResetTimer()
	for b.Loop() {
		for _, name := range names {
			_ = ParseReverseDNSName(name)
		}
	}
}

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
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	b.ResetTimer()
	for b.Loop() {
		_ = ExtractIP(a)
	}
}

func BenchmarkExtractIPString(b *testing.B) {
	a := &dns.A{Hdr: dns.Header{Name: "example.com.", Class: dns.ClassINET, TTL: 300}, A: rdata.A{Addr: netip.MustParseAddr("192.0.2.1")}}
	b.ResetTimer()
	for b.Loop() {
		_, _ = ExtractIPString(a)
	}
}

func BenchmarkNewPTRRecord(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		_ = NewPTRRecord("1.0.0.127.in-addr.arpa.", "localhost.", 300, 1)
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
