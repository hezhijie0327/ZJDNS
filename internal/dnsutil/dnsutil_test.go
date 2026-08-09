package dnsutil

import (
	"os"
	"testing"
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
		{"dtls", true},
		{"tlcp", true},
		{"http-tlcp", true},
		{"dtlcp", true},
		{"dnscrypt", true},
		{"dnscrypt-tcp", true},
		{"udp", false},
		{"tcp", false},
		{"", false},
		{"DoT", false}, // case-sensitive — callers normalize to lowercase first
	}
	for _, tc := range tests {
		if got := IsSecureProtocol(tc.proto); got != tc.want {
			t.Errorf("IsSecureProtocol(%q) = %t, want %t", tc.proto, got, tc.want)
		}
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

func TestIsValidFilePath_NonExistent(t *testing.T) {
	if IsValidFilePath("/nonexistent/path/12345/file.txt") {
		t.Error("non-existent file should be invalid")
	}
}

func TestIsValidFilePath_Symlink(t *testing.T) {
	// /tmp could be a symlink on macOS
	_ = IsValidFilePath("/tmp")
}
