package stamp

import (
	"encoding/base64"
	"testing"
)

// ── Stamp parse benchmarks (one per protocol) ────────────────────────────────

func BenchmarkParsePlainDNS(b *testing.B) {
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString(
		append(append([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, byte(len("1.1.1.1:53"))), []byte("1.1.1.1:53")...),
	)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseDNSCrypt(b *testing.B) {
	stampStr := "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseDoH(b *testing.B) {
	stampStr := "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseDoT(b *testing.B) {
	addr := []byte("1.1.1.1")
	host := []byte("cloudflare-dns.com")
	binary := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	binary = append(binary, 0x00, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString(binary)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseDoQ(b *testing.B) {
	addr := []byte("94.140.14.14")
	host := []byte("dns.adguard.com")
	binary := []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	binary = append(binary, 0x00, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString(binary)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseODoHTarget(b *testing.B) {
	host := []byte("odoh.cloudflare.com")
	path := []byte("/proxy")
	binary := []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	binary = append(binary, byte(len(path))) //nolint:gosec // G115: test vector
	binary = append(binary, path...)
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString(binary)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseDNSCryptRelay(b *testing.B) {
	addr := []byte("1.2.3.4:8443")
	binary := []byte{0x81}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString(binary)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

func BenchmarkParseODoHRelay(b *testing.B) {
	addr := []byte("1.2.3.4")
	host := []byte("relay.example.com")
	path := []byte("/proxy")
	binary := []byte{0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	binary = append(binary, 0x00, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	binary = append(binary, byte(len(path))) //nolint:gosec // G115: test vector
	binary = append(binary, path...)
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString(binary)
	b.ResetTimer()
	for b.Loop() {
		_, _ = Parse(stampStr)
	}
}

// ── Stamp encode (String) benchmarks ─────────────────────────────────────────

func BenchmarkStringPlainDNS(b *testing.B) {
	s := &DNSStamp{Proto: ProtoPlain, Address: "1.1.1.1:53", Props: PropDNSSEC | PropNoLog}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringDNSCrypt(b *testing.B) {
	pk := make([]byte, 32)
	s := &DNSStamp{Proto: ProtoDNSCrypt, Address: "9.9.9.9:8443", ProviderName: "2.dnscrypt-cert.quad9.net", PublicKey: pk, Props: PropDNSSEC | PropNoLog}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringDoH(b *testing.B) {
	hash := make([]byte, 32)
	s := &DNSStamp{Proto: ProtoDOH, Address: "9.9.9.9", ProviderName: "dns9.quad9.net:443", Path: "/dns-query", Hashes: [][]byte{hash}, Props: PropDNSSEC}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringDoT(b *testing.B) {
	s := &DNSStamp{Proto: ProtoDOT, Address: "1.1.1.1", ProviderName: "cloudflare-dns.com", Props: PropDNSSEC}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringDoQ(b *testing.B) {
	s := &DNSStamp{Proto: ProtoDOQ, Address: "94.140.14.14", ProviderName: "dns.adguard.com", Props: PropDNSSEC}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringODoHTarget(b *testing.B) {
	s := &DNSStamp{Proto: ProtoODoHTarget, ProviderName: "odoh.cloudflare.com", Path: "/proxy"}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringDNSCryptRelay(b *testing.B) {
	s := &DNSStamp{Proto: ProtoDNSCryptRelay, Address: "1.2.3.4:8443"}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

func BenchmarkStringODoHRelay(b *testing.B) {
	s := &DNSStamp{Proto: ProtoODoHRelay, Address: "1.2.3.4", ProviderName: "relay.example.com", Path: "/proxy", Props: PropDNSSEC}
	b.ResetTimer()
	for b.Loop() {
		_ = s.String()
	}
}

// ── Round-trip (Parse → String → Parse) benchmarks ───────────────────────────

func BenchmarkRoundTripDoH(b *testing.B) {
	stampStr := "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"
	b.ResetTimer()
	for b.Loop() {
		s, _ := Parse(stampStr)
		_ = s.String()
	}
}

func BenchmarkRoundTripDNSCrypt(b *testing.B) {
	stampStr := "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"
	b.ResetTimer()
	for b.Loop() {
		s, _ := Parse(stampStr)
		_ = s.String()
	}
}

// ── BuildDoHURL benchmark ────────────────────────────────────────────────────

func BenchmarkBuildDoHURL(b *testing.B) {
	s := &DNSStamp{Proto: ProtoDOH, Address: "9.9.9.9:443", ProviderName: "dns.quad9.net", Path: "/dns-query"}
	b.ResetTimer()
	for b.Loop() {
		_ = s.BuildDoHURL()
	}
}

// ── ProtoToConfig benchmark ──────────────────────────────────────────────────

func BenchmarkProtoToConfig(b *testing.B) {
	protos := []ProtoType{ProtoPlain, ProtoDNSCrypt, ProtoDOH, ProtoDOT, ProtoDOQ, ProtoODoHTarget, ProtoDNSCryptRelay, ProtoODoHRelay}
	b.ResetTimer()
	for b.Loop() {
		for _, p := range protos {
			_ = ProtoToConfig(p)
		}
	}
}

// ── Real-world stamps batch parse benchmark ──────────────────────────────────

func BenchmarkParseRealWorldStamps(b *testing.B) {
	b.ResetTimer()
	for b.Loop() {
		for _, stampStr := range realWorldStamps {
			_, _ = Parse(stampStr)
		}
	}
}
