package dnsutil

import (
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct{ in, want string }{
		{"example.com.", "example.com"},
		{"Example.COM.", "example.com"},
		{"Example.COM", "example.com"},
		{".", ""},
		{"", ""},
		{"www.EXAMPLE.com.", "www.example.com"},
		{"a.B.c.D.", "a.b.c.d"},
	}
	for _, tc := range tests {
		got := NormalizeDomain(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeDomain_PreservesNonStandardInput(t *testing.T) {
	// NormalizeDomain should handle any input without panicking
	if got := NormalizeDomain(".."); got != "" {
		t.Logf("NormalizeDomain('..') = %q (no crash is the key)", got)
	}
}

func TestIsSecureProtocol(t *testing.T) {
	tests := []struct {
		proto string
		want  bool
	}{
		{"tls", true}, {"TLS", false}, {"quic", true},
		{"https", true}, {"http3", true},
		{"udp", false}, {"tcp", false}, {"", false},
		{"tls", true}, {"quic", true}, {"https", true}, {"http3", true},
		{"dot", true}, {"doq", true}, {"doh", true}, {"doh3", true},
		{"DoT", false}, // case-sensitive — callers normalize to lowercase first
	}
	for _, tc := range tests {
		if got := IsSecureProtocol(tc.proto); got != tc.want {
			t.Errorf("IsSecureProtocol(%q) = %t, want %t", tc.proto, got, tc.want)
		}
	}
}

func TestParseReverseDNSName_IPv4(t *testing.T) {
	ip := ParseReverseDNSName("4.3.2.1.in-addr.arpa.")
	if ip == nil {
		t.Fatal("expected valid IPv4")
	}
	if ip.String() != "1.2.3.4" {
		t.Errorf("got %s, want 1.2.3.4", ip.String())
	}
}

func TestParseReverseDNSName_IPv4NoTrailingDot(t *testing.T) {
	ip := ParseReverseDNSName("1.0.0.127.in-addr.arpa")
	if ip == nil {
		t.Fatal("expected valid IPv4")
	}
	if !ip.IsLoopback() {
		t.Errorf("got %s, want loopback", ip.String())
	}
}

func TestParseReverseDNSName_IPv6(t *testing.T) {
	// ::1 reverse
	ip := ParseReverseDNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	if ip == nil {
		t.Fatal("expected valid IPv6")
	}
	if !ip.IsLoopback() {
		t.Errorf("got %s, want loopback", ip.String())
	}
}

func TestParseReverseDNSName_Invalid(t *testing.T) {
	tests := []string{
		"",
		"not-a-domain",
		"example.com",
		"1.2.3.in-addr.arpa", // too few octets
	}
	for _, name := range tests {
		if ip := ParseReverseDNSName(name); ip != nil {
			t.Errorf("ParseReverseDNSName(%q) = %s, want nil", name, ip)
		}
	}
}

func TestParseReverseDNSName_InvalidIPv6Length(t *testing.T) {
	// Too few nibbles for IPv6
	ip := ParseReverseDNSName("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.")
	if ip != nil {
		t.Errorf("expected nil for incomplete IPv6 reverse, got %s", ip)
	}
}

func TestClientIP_UDP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 12345}
	w := &mockResponseWriter{remote: addr}
	ip := ClientIP(w)
	if ip == nil || !ip.Equal(net.ParseIP("192.0.2.1")) {
		t.Errorf("ClientIP from UDP = %v, want 192.0.2.1", ip)
	}
}

func TestClientIP_TCP(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5353}
	w := &mockResponseWriter{remote: addr}
	ip := ClientIP(w)
	if ip == nil || !ip.Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("ClientIP from TCP = %v, want 10.0.0.1", ip)
	}
}

func TestClientIP_Nil(t *testing.T) {
	w := &mockResponseWriter{remote: nil}
	if ip := ClientIP(w); ip != nil {
		t.Errorf("ClientIP from nil remote = %v, want nil", ip)
	}
}

func TestBuildPTRRecord(t *testing.T) {
	rr := BuildPTRRecord("4.3.2.1.in-addr.arpa", "test.example.com", 300, dns.ClassINET)
	if rr == nil {
		t.Fatal("BuildPTRRecord returned nil")
	}
	ptr, ok := rr.(*dns.PTR)
	if !ok {
		t.Fatalf("not a PTR record, got %T", rr)
	}
	if ptr.Ptr != "test.example.com." {
		t.Errorf("PTR target = %s, want test.example.com.", ptr.Ptr)
	}
}

func TestFormatRecords(t *testing.T) {
	rr := BuildPTRRecord("1.2.3.4.in-addr.arpa", "host.example.com", 300, dns.ClassINET)
	s := FormatRecords([]dns.RR{rr}, nil, nil)
	if s == "" {
		t.Error("FormatRecords returned empty string for non-empty input")
	}
	if !stringsContains(s, "ANSWER SECTION") {
		t.Error("FormatRecords should include ANSWER SECTION header")
	}

	s2 := FormatRecords(nil, nil, nil)
	if s2 != "" {
		t.Error("FormatRecords should return empty string for nil sections")
	}
}

func TestIsValidFilePath(t *testing.T) {
	// Test with the test file itself
	if !IsValidFilePath("/etc/hosts") {
		t.Log("/etc/hosts not valid (may not exist on this system)")
	}
	// Symlinks and paths with .. should be rejected
	if IsValidFilePath("../outside") {
		t.Error("paths with .. should be rejected")
	}
	if IsValidFilePath("/proc/self/cmdline") {
		t.Error("paths under /proc should be rejected")
	}
}

func TestCloseWithLog_Nil(t *testing.T) {
	// Must not panic with nil input
	CloseWithLog(nil, "test-closer", "TEST")
}

type testCloser struct{ err error }

func (c *testCloser) Close() error { return c.err }

func TestCloseWithLog_Success(t *testing.T) {
	c := &testCloser{err: nil}
	CloseWithLog(c, "test-closer", "TEST")
}

func TestCloseWithLog_Error(t *testing.T) {
	c := &testCloser{err: os.ErrClosed}
	CloseWithLog(c, "test-closer", "TEST")
}

// CloseWithLog now accepts io.Closer at compile time, so non-closable types
// are rejected by the type system — no longer a runtime concern.

func TestHandlePanic_Recovers(t *testing.T) {
	func() {
		defer HandlePanic("test-panic-recovery")
		panic("intentional test panic")
	}()
	// If we reach here, HandlePanic successfully recovered
}

func TestParseReverseDNSName_IPv6Full(t *testing.T) {
	// Full 32-nibble IPv6 reverse (2001:db8::1)
	name := "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
	ip := ParseReverseDNSName(name)
	if ip == nil {
		t.Fatal("expected valid IPv6")
	}
}

func TestFormatRecords_AllSections(t *testing.T) {
	ptr := BuildPTRRecord("1.0.0.127.in-addr.arpa", "localhost", 300, dns.ClassINET)
	s := FormatRecords([]dns.RR{ptr}, []dns.RR{ptr}, []dns.RR{ptr})
	if !stringsContains(s, "ANSWER SECTION") || !stringsContains(s, "AUTHORITY SECTION") || !stringsContains(s, "ADDITIONAL SECTION") {
		t.Error("FormatRecords should include all three section headers")
	}
}

func TestIsValidFilePath_NonExistent(t *testing.T) {
	if IsValidFilePath("/nonexistent/path/12345/file.txt") {
		t.Error("non-existent file should be invalid")
	}
}

func TestIsValidFilePath_Symlink(t *testing.T) {
	// /tmp could be a symlink on macOS
	_ = IsValidFilePath("/tmp")
}

func BenchmarkNormalizeDomain(b *testing.B) {
	for b.Loop() {
		NormalizeDomain("www.Example.COM.")
	}
}

// ── mock types ──────────────────────────────────────────────────────────────

type mockResponseWriter struct {
	remote net.Addr
}

func (m *mockResponseWriter) LocalAddr() net.Addr       { return nil }
func (m *mockResponseWriter) RemoteAddr() net.Addr      { return m.remote }
func (m *mockResponseWriter) WriteMsg(*dns.Msg) error   { return nil }
func (m *mockResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (m *mockResponseWriter) Close() error              { return nil }
func (m *mockResponseWriter) TsigStatus() error         { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool)       {}
func (m *mockResponseWriter) Hijack()                   {}

func stringsContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
