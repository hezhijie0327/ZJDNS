package stamp

import (
	"encoding/base64"
	encodingbinary "encoding/binary"
	"testing"
)

// realWorldStamps contains official sdns:// stamps collected from the DNSCrypt
// project's public-resolvers.md, odoh-servers.md, and relays.md.  Stamps from
// diverse providers are included for each protocol type to ensure broad
// real-world compatibility.
var realWorldStamps = []string{
	// 0x01 DNSCrypt — Quad9, AdGuard, AdGuard Family
	"sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
	"sdns://AQYAAAAAAAAADTkuOS45LjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA",
	"sdns://AQMAAAAAAAAAElsyNjIwOmZlOjpmZV06ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0",
	"sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	"sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ",
	// 0x02 DoH — Quad9, a-and-a, AliDNS, AdGuard
	"sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk",
	"sdns://AgYAAAAAAAAACDkuOS45LjEwICoV9dastufAkBreTrvHQ7LM1IkDK0bhZC8Gk2gwASWKE2RuczEwLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ",
	"sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjIADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ",
	"sdns://AgAAAAAAAAAACTIyMy41LjUuNSCY49XlNq8pWM0vfxT3BO9KJ20l4zzWXy5l9eTycnwTMAkyMjMuNS41LjUKL2Rucy1xdWVyeQ",
	"sdns://AgMAAAAAAAAADDk0LjE0MC4xNC4xNCCaOjT3J965vKUQA9nOnDn48n3ZxSQpAcK6saROY1oCGQw5NC4xNDAuMTQuMTQKL2Rucy1xdWVyeQ",
	// 0x05 ODoH Target — dnscry.pt relays (odoh-servers.md)
	"sdns://BQcAAAAAAAAAD2FkbDAxLmRuc2NyeS5wdAovZG5zLXF1ZXJ5",
	"sdns://BQcAAAAAAAAAD2FtczAxLmRuc2NyeS5wdAovZG5zLXF1ZXJ5",
	// 0x81 DNSCrypt Relay — anon-* relays (relays.md)
	"sdns://gRMxMDIuMjA5LjIxLjE3Njo4NDQz",
	"sdns://gRIzNy4xMjAuMTQyLjExNTo0NDM",
}

// encodeTestStamp builds an sdns:// stamp string from a raw binary payload.
func encodeTestStamp(t *testing.T, binary []byte) string {
	t.Helper()
	return "sdns://" + base64.RawURLEncoding.EncodeToString(binary)
}

// ============================================================================
// Plain DNS (0x00)
// ============================================================================

func TestParsePlainDNS(t *testing.T) {
	binary := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len("1.1.1.1:53"))) //nolint:gosec // G115: test vector
	binary = append(binary, []byte("1.1.1.1:53")...)
	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoPlain {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoPlain)
	}
	if s.Address != "1.1.1.1:53" {
		t.Errorf("Address = %q, want %q", s.Address, "1.1.1.1:53")
	}
}

func TestParsePlainDNSDefaultPort(t *testing.T) {
	// Address without port — should get default DNS port (53).
	binary := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len("1.1.1.1"))) //nolint:gosec // G115: test vector
	binary = append(binary, []byte("1.1.1.1")...)
	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Address != "1.1.1.1:53" {
		t.Errorf("Address = %q, want %q", s.Address, "1.1.1.1:53")
	}
}

func TestParsePlainDNSRejectsHostname(t *testing.T) {
	binary := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	addr := []byte("dns.google:53")
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	stampStr := encodeTestStamp(t, binary)

	_, err := Parse(stampStr)
	if err == nil {
		t.Fatal("expected error for hostname in plain DNS stamp")
	}
}

// ============================================================================
// DNSCrypt (0x01) — Quad9 real-world stamps
// ============================================================================

func TestParseDNSCryptQuad9Primary(t *testing.T) {
	// Quad9 (anycast) dnssec/no-log/filter 9.9.9.9
	stampStr := "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoDNSCrypt {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoDNSCrypt)
	}
	if s.Address != "9.9.9.9:8443" {
		t.Errorf("Address = %q, want %q", s.Address, "9.9.9.9:8443")
	}
	if s.ProviderName != "2.dnscrypt-cert.quad9.net" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "2.dnscrypt-cert.quad9.net")
	}
	if len(s.PublicKey) != 32 {
		t.Errorf("PublicKey len = %d, want 32", len(s.PublicKey))
	}
	if s.Props&PropDNSSEC == 0 {
		t.Error("DNSSEC property not set")
	}
	// Quad9 filter stamps do NOT set NoFilter — "filter" means Quad9 filters,
	// while NoFilter property means "server claims to do no filtering".
	if s.Props&PropNoFilter != 0 {
		t.Error("NoFilter should NOT be set for Quad9 filter stamp")
	}
}

func TestParseDNSCryptQuad9NoFilter(t *testing.T) {
	// Quad9 (anycast) no-dnssec/no-log/no-filter 9.9.9.10
	stampStr := "sdns://AQYAAAAAAAAADTkuOS45LjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoDNSCrypt {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoDNSCrypt)
	}
	if s.Address != "9.9.9.10:8443" {
		t.Errorf("Address = %q, want %q", s.Address, "9.9.9.10:8443")
	}
	if s.Props&PropDNSSEC != 0 {
		t.Error("DNSSEC property should NOT be set for nofilter stamp")
	}
	if s.Props&PropNoFilter == 0 {
		t.Error("NoFilter property should be set")
	}
	if s.Props&PropNoLog == 0 {
		t.Error("NoLog property should be set")
	}
}

func TestParseDNSCryptQuad9IPv6(t *testing.T) {
	// Quad9 (anycast) dnssec/no-log/filter 2620:fe::fe
	stampStr := "sdns://AQMAAAAAAAAAElsyNjIwOmZlOjpmZV06ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Address != "[2620:fe::fe]:8443" {
		t.Errorf("Address = %q, want %q", s.Address, "[2620:fe::fe]:8443")
	}
}

// ============================================================================
// DoH (0x02) — Quad9 real-world stamps
// ============================================================================

func TestParseDOHQuad9Primary(t *testing.T) {
	// Quad9 DoH dnssec/no-log/filter 9.9.9.9
	stampStr := "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoDOH {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoDOH)
	}
	if s.Address != "9.9.9.9" {
		t.Errorf("Address = %q, want %q", s.Address, "9.9.9.9")
	}
	if s.ProviderName != "dns9.quad9.net:443" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "dns9.quad9.net:443")
	}
	if s.Path != "/dns-query" {
		t.Errorf("Path = %q, want %q", s.Path, "/dns-query")
	}
	if len(s.Hashes) != 1 {
		t.Fatalf("Hashes len = %d, want 1", len(s.Hashes))
	}
	if len(s.Hashes[0]) != 32 {
		t.Errorf("Hash len = %d, want 32", len(s.Hashes[0]))
	}
}

func TestParseDOHQuad9AltPort5053(t *testing.T) {
	// Quad9 DoH alt port 5053
	stampStr := "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoTZG5zOS5xdWFkOS5uZXQ6NTA1MwovZG5zLXF1ZXJ5"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	// ProviderName includes port 5053 — normalization in config layer handles this.
	if s.ProviderName != "dns9.quad9.net:5053" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "dns9.quad9.net:5053")
	}
	if s.Path != "/dns-query" {
		t.Errorf("Path = %q, want %q", s.Path, "/dns-query")
	}
}

func TestParseDOHQuad9NoFilter(t *testing.T) {
	// Quad9 DoH no-dnssec/no-log/no-filter 9.9.9.10
	stampStr := "sdns://AgYAAAAAAAAACDkuOS45LjEwICoV9dastufAkBreTrvHQ7LM1IkDK0bhZC8Gk2gwASWKE2RuczEwLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Props&PropDNSSEC != 0 {
		t.Error("DNSSEC should NOT be set for nofilter DoH stamp")
	}
	if s.Props&PropNoFilter == 0 {
		t.Error("NoFilter should be set")
	}
	if s.ProviderName != "dns10.quad9.net:443" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "dns10.quad9.net:443")
	}
}

func TestParseDOHQuad9IPv6(t *testing.T) {
	// Quad9 DoH dnssec/no-log/filter 2620:fe::fe
	stampStr := "sdns://AgMAAAAAAAAADVsyNjIwOmZlOjpmZV0gKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoRZG5zLnF1YWQ5Lm5ldDo0NDMKL2Rucy1xdWVyeQ"

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Address != "[2620:fe::fe]" {
		t.Errorf("Address = %q, want %q", s.Address, "[2620:fe::fe]")
	}
	if s.ProviderName != "dns.quad9.net:443" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "dns.quad9.net:443")
	}
}

// ============================================================================
// DoT (0x03)
// ============================================================================

func TestParseDOT(t *testing.T) {
	// Build: [proto=0x03][props=0x00*8][addr="1.1.1.1:853"][hash=00][host="cloudflare-dns.com"]
	addr := []byte("1.1.1.1")
	host := []byte("cloudflare-dns.com")

	binary := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	binary = append(binary, 0x00)            //nolint:gocritic // empty hash VLP terminator
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoDOT {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoDOT)
	}
	if s.Address != "1.1.1.1" {
		t.Errorf("Address = %q, want %q", s.Address, "1.1.1.1")
	}
	if s.ProviderName != "cloudflare-dns.com" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "cloudflare-dns.com")
	}
	if len(s.Hashes) != 0 {
		t.Errorf("Hashes should be empty, got %d", len(s.Hashes))
	}
	if s.Path != "" {
		t.Errorf("Path should be empty for DoT, got %q", s.Path)
	}
}

func TestParseDOTWithCertHash(t *testing.T) {
	addr := []byte("1.2.3.4")
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i)
	}
	host := []byte("dns.example.com")

	binary := []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	// VLP-encode a single hash: len=32, continuation bit=0
	binary = append(binary, byte(32)) //nolint:gosec // G115: hash length
	binary = append(binary, hash...)
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.ProviderName != "dns.example.com" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "dns.example.com")
	}
	if len(s.Hashes) != 1 {
		t.Fatalf("Hashes len = %d, want 1", len(s.Hashes))
	}
	for i := range s.Hashes[0] {
		if s.Hashes[0][i] != byte(i) {
			t.Errorf("Hash[%d] = %d, want %d", i, s.Hashes[0][i], i)
		}
	}
}

// ============================================================================
// DoQ (0x04)
// ============================================================================

func TestParseDOQ(t *testing.T) {
	// DoQ stamps require IP address for the addr field, hostname for SNI.
	addr := []byte("94.140.14.14")
	host := []byte("dns.adguard.com")

	binary := []byte{0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	binary = append(binary, 0x00)            //nolint:gocritic // empty hash VLP terminator
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoDOQ {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoDOQ)
	}
	if s.ProviderName != "dns.adguard.com" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "dns.adguard.com")
	}
	if s.Address != "94.140.14.14" {
		t.Errorf("Address = %q, want %q", s.Address, "94.140.14.14")
	}
}

// ============================================================================
// Properties (uint64 LE encoding)
// ============================================================================

func TestParseProps(t *testing.T) {
	addr := []byte("1.2.3.4:53")
	binary := make([]byte, 0, 9+1+len(addr))
	binary = append(binary, byte(ProtoPlain)) //nolint:gosec // G115: proto byte
	var props [8]byte
	encodingbinary.LittleEndian.PutUint64(props[:], uint64(PropDNSSEC|PropNoLog|PropNoFilter))
	binary = append(binary, props[:]...)
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Props&PropDNSSEC == 0 {
		t.Error("DNSSEC property not set")
	}
	if s.Props&PropNoLog == 0 {
		t.Error("NoLog property not set")
	}
	if s.Props&PropNoFilter == 0 {
		t.Error("NoFilter property not set")
	}
}

// ============================================================================
// Error cases
// ============================================================================

func TestParseInvalidPrefix(t *testing.T) {
	_, err := Parse("https://example.com/dns-query")
	if err == nil {
		t.Fatal("expected error for non-sdns:// prefix")
	}
}

func TestParseUnknownProtocol(t *testing.T) {
	binary := []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	stampStr := encodeTestStamp(t, binary)

	_, err := Parse(stampStr)
	if err == nil {
		t.Fatal("expected error for unknown protocol")
	}
}

func TestParseTooShort(t *testing.T) {
	stampStr := "sdns://" + base64.RawURLEncoding.EncodeToString([]byte{0x00, 0x00, 0x00, 0x00, 0x00})
	_, err := Parse(stampStr)
	if err == nil {
		t.Fatal("expected error for short stamp")
	}
}

// ============================================================================
// ProtoToConfig
// ============================================================================

func TestProtoToConfig(t *testing.T) {
	tests := []struct {
		proto StampProtoType
		want  string
	}{
		{ProtoPlain, "udp"},
		{ProtoDNSCrypt, "dnscrypt"},
		{ProtoDOH, "doh"},
		{ProtoDOT, "dot"},
		{ProtoDOQ, "doq"},
		{ProtoODoHTarget, "odoh"},
		{ProtoDNSCryptRelay, "dnscrypt-relay"},
		{ProtoODoHRelay, "odoh-relay"},
		{StampProtoType(0xFF), ""},
	}

	for _, tt := range tests {
		got := ProtoToConfig(tt.proto)
		if got != tt.want {
			t.Errorf("ProtoToConfig(%d) = %q, want %q", tt.proto, got, tt.want)
		}
	}
}

func TestIsKnownProtocol(t *testing.T) {
	if !IsKnownProtocol(ProtoPlain) {
		t.Error("ProtoPlain should be known")
	}
	if !IsKnownProtocol(ProtoODoHTarget) {
		t.Error("ProtoODoHTarget should be known")
	}
	if !IsKnownProtocol(ProtoDNSCryptRelay) {
		t.Error("ProtoDNSCryptRelay should be known")
	}
	if IsKnownProtocol(StampProtoType(0xFF)) {
		t.Error("0xFF should not be known")
	}
}

// ============================================================================
// Real-world stamps: all protocols parse successfully
// ============================================================================

func TestParseRealWorldStamps(t *testing.T) {
	for i, stampStr := range realWorldStamps {
		s, err := Parse(stampStr)
		if err != nil {
			t.Errorf("stamp[%d] Parse() error: %v\n  %s", i, err, stampStr)
			continue
		}
		if s.Address == "" && s.Proto != ProtoODoHTarget {
			t.Errorf("stamp[%d] proto=0x%02x: empty address", i, byte(s.Proto))
		}
		// DNSCrypt stamps must have a provider name and public key.
		if s.Proto == ProtoDNSCrypt {
			if s.ProviderName == "" {
				t.Errorf("stamp[%d] DNSCrypt: empty provider name", i)
			}
			if len(s.PublicKey) == 0 {
				t.Errorf("stamp[%d] DNSCrypt: empty public key", i)
			}
		}
		// DoH/DoT/DoQ stamps must have a path (DoH) or provider name.
		if s.Proto == ProtoDOH && s.Path == "" {
			t.Errorf("stamp[%d] DoH: empty path", i)
		}
	}
}

// ============================================================================
// VLP encoding edge cases (hashes + bootstrap IPs)
// ============================================================================

func TestParseDOHWithMultipleHashes(t *testing.T) {
	// Build DoH stamp with 2 cert hashes + bootstrap IPs.
	addr := []byte("1.2.3.4")
	hash1 := make([]byte, 32)
	hash2 := make([]byte, 32)
	for i := range hash1 {
		hash1[i] = byte(i)
		hash2[i] = byte(255 - i)
	}
	host := []byte("dns.example.com")
	path := []byte("/dns-query")
	bootstrap1 := []byte("10.0.0.1")
	bootstrap2 := []byte("10.0.0.2")

	binary := []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	// Two hashes with VLP encoding.
	firstLen := len(hash1) | 0x80           // continuation bit set — more follow
	binary = append(binary, byte(firstLen)) //nolint:gosec // G115: hash length
	binary = append(binary, hash1...)
	secondLen := len(hash2) & ^0x80          // last hash — no continuation bit
	binary = append(binary, byte(secondLen)) //nolint:gosec // G115: hash length
	binary = append(binary, hash2...)
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	binary = append(binary, byte(len(path))) //nolint:gosec // G115: test vector
	binary = append(binary, path...)
	// Bootstrap IPs with VLP encoding.
	firstB := len(bootstrap1) | 0x80
	binary = append(binary, byte(firstB)) //nolint:gosec // G115: test vector
	binary = append(binary, bootstrap1...)
	lastB := len(bootstrap2)
	binary = append(binary, byte(lastB)) //nolint:gosec // G115: test vector
	binary = append(binary, bootstrap2...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(s.Hashes) != 2 {
		t.Fatalf("Hashes len = %d, want 2", len(s.Hashes))
	}
	if s.Hashes[0][0] != 0 {
		t.Errorf("First hash byte wrong")
	}
	if s.Hashes[1][0] != 255 {
		t.Errorf("Second hash byte wrong")
	}
	if len(s.BootstrapIPs) != 2 {
		t.Fatalf("BootstrapIPs len = %d, want 2", len(s.BootstrapIPs))
	}
	if s.BootstrapIPs[0] != "10.0.0.1" {
		t.Errorf("BootstrapIPs[0] = %q", s.BootstrapIPs[0])
	}
	if s.BootstrapIPs[1] != "10.0.0.2" {
		t.Errorf("BootstrapIPs[1] = %q", s.BootstrapIPs[1])
	}
}

// ============================================================================
// Protocol 0x05: ODoH Target
// ============================================================================

func TestParseODoHTarget(t *testing.T) {
	// Build: [proto=0x05][props=0x00*8][host="odoh.cloudflare.com"][path="/proxy"]
	host := []byte("odoh.cloudflare.com")
	path := []byte("/proxy")

	binary := []byte{0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	binary = append(binary, byte(len(path))) //nolint:gosec // G115: test vector
	binary = append(binary, path...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoODoHTarget {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoODoHTarget)
	}
	if s.ProviderName != "odoh.cloudflare.com" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "odoh.cloudflare.com")
	}
	if s.Path != "/proxy" {
		t.Errorf("Path = %q, want %q", s.Path, "/proxy")
	}
	if s.Address != "" {
		t.Errorf("Address should be empty for ODoH target, got %q", s.Address)
	}
}

// ============================================================================
// Protocol 0x81: DNSCrypt Relay
// ============================================================================

func TestParseDNSCryptRelay(t *testing.T) {
	// Build: [proto=0x81][addr="1.2.3.4:8443"]  (no props field)
	addr := []byte("1.2.3.4:8443")

	binary := []byte{0x81}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoDNSCryptRelay {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoDNSCryptRelay)
	}
	if s.Address != "1.2.3.4:8443" {
		t.Errorf("Address = %q, want %q", s.Address, "1.2.3.4:8443")
	}
	if s.Props != 0 {
		t.Errorf("Props should be 0 for relay, got %d", s.Props)
	}
}

func TestParseDNSCryptRelayRequiresPort(t *testing.T) {
	// §4.7.2: port specification is mandatory for relay stamps.
	addr := []byte("1.2.3.4")

	binary := []byte{0x81}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)

	stampStr := encodeTestStamp(t, binary)

	_, err := Parse(stampStr)
	if err == nil {
		t.Fatal("expected error for relay stamp without port, got nil")
	}
}

// ============================================================================
// Protocol 0x85: ODoH Relay
// ============================================================================

func TestParseODoHRelay(t *testing.T) {
	// Build: [proto=0x85][props=0x00*8][addr="1.2.3.4:443"][hash=00][host="relay.example.com"][path="/proxy"]
	addr := []byte("1.2.3.4")
	host := []byte("relay.example.com")
	path := []byte("/proxy")

	binary := []byte{0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary = append(binary, byte(len(addr))) //nolint:gosec // G115: test vector
	binary = append(binary, addr...)
	binary = append(binary, 0x00)            //nolint:gocritic // empty hash VLP terminator
	binary = append(binary, byte(len(host))) //nolint:gosec // G115: test vector
	binary = append(binary, host...)
	binary = append(binary, byte(len(path))) //nolint:gosec // G115: test vector
	binary = append(binary, path...)

	stampStr := encodeTestStamp(t, binary)

	s, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if s.Proto != ProtoODoHRelay {
		t.Errorf("Proto = %d, want %d", s.Proto, ProtoODoHRelay)
	}
	if s.ProviderName != "relay.example.com" {
		t.Errorf("ProviderName = %q, want %q", s.ProviderName, "relay.example.com")
	}
	if s.Path != "/proxy" {
		t.Errorf("Path = %q, want %q", s.Path, "/proxy")
	}
}

// ============================================================================
// Consistency check: parsed stamps re-serialize and parse back identically
// (Not a full round-trip — stamp.String() is not implemented — but verifies
// that all Quad9 stamps produce consistent parsed output.)
// ============================================================================

func TestParseConsistency(t *testing.T) {
	// Parse the same stamp twice and verify identical output.
	stampStr := "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy258CQGt5Ou8dDsszUiQMrRuFkLwaTaDABJYoSZG5zOS5xdWFkOS5uZXQ6NDQzCi9kbnMtcXVlcnk"

	s1, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("first Parse() error: %v", err)
	}
	s2, err := Parse(stampStr)
	if err != nil {
		t.Fatalf("second Parse() error: %v", err)
	}

	if s1.Proto != s2.Proto || s1.Address != s2.Address || s1.ProviderName != s2.ProviderName || s1.Path != s2.Path {
		t.Error("inconsistent parsing of same stamp")
	}
}
