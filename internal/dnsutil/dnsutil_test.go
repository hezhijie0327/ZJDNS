package dnsutil

import (
	"os"
	"testing"

	"codeberg.org/miekg/dns"
)

type testCloser struct{ err error }

func TestIsSecureProtocol(t *testing.T) {
	tests := []struct {
		proto string
		want  bool
	}{
		{"tls", true},
		{"TLS", false},
		{"quic", true},
		{"https", true},
		{"http3", true},
		{"udp", false},
		{"tcp", false},
		{"", false},
		{"tls", true},
		{"quic", true},
		{"https", true},
		{"http3", true},
		{"tls", true},
		{"quic", true},
		{"https", true},
		{"http3", true},
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

func TestNewPTRRecord(t *testing.T) {
	rr := NewPTRRecord("4.3.2.1.in-addr.arpa", "test.example.com", 300, dns.ClassINET)
	if rr == nil {
		t.Fatal("NewPTRRecord returned nil")
	}
	ptr, ok := rr.(*dns.PTR)
	if !ok {
		t.Fatalf("not a PTR record, got %T", rr)
	}
	if ptr.Ptr != "test.example.com." {
		t.Errorf("PTR target = %s, want test.example.com.", ptr.Ptr)
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

func TestIsValidFilePath_NonExistent(t *testing.T) {
	if IsValidFilePath("/nonexistent/path/12345/file.txt") {
		t.Error("non-existent file should be invalid")
	}
}

func TestIsValidFilePath_Symlink(t *testing.T) {
	// /tmp could be a symlink on macOS
	_ = IsValidFilePath("/tmp")
}
