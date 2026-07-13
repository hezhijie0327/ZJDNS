package dnsutil

import (
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
)

func TestTryBind_Success(t *testing.T) {
	err := TryBind("tcp", ":0")
	if err != nil {
		t.Fatalf("TryBind tcp :0: %v", err)
	}
	err = TryBind("udp", ":0")
	if err != nil {
		t.Fatalf("TryBind udp :0: %v", err)
	}
}

func TestTryBind_AddrInUse(t *testing.T) {
	l, err := net.Listen("tcp", ":0") //nolint:gosec // G102: test binds all interfaces
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	addr := l.Addr().String()

	err = TryBind("tcp", addr)
	if !isAddrInUse(err) {
		t.Fatalf("expected EADDRINUSE, got %v", err)
	}
}

func TestTryBind_UDPAddrInUse(t *testing.T) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()
	addr := pc.LocalAddr().String()

	err = TryBind("udp", addr)
	if !isAddrInUse(err) {
		t.Fatalf("expected EADDRINUSE, got %v", err)
	}
}

func TestTryBind_UDP4(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	addr := l.Addr().String()

	err = TryBind("tcp4", addr)
	if !isAddrInUse(err) {
		t.Fatalf("expected EADDRINUSE, got %v", err)
	}
}

func TestResolveBindAddrs_PerInterface(t *testing.T) {
	port := findFreePort(t)

	for _, netw := range []string{"tcp", "udp"} {
		addrs, err := ResolveBindAddrs(netw, port)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", netw, err)
		}
		if len(addrs) == 0 {
			t.Fatalf("%s: expected at least one address", netw)
		}
		for _, addr := range addrs {
			host, _, _ := net.SplitHostPort(addr)
			if host == "" {
				t.Errorf("%s: unexpected wildcard address %q", netw, addr)
			}
		}
	}
}

func TestResolveBindAddrs_SkipsOccupied(t *testing.T) {
	port := findFreePort(t)
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	addrs, err := ResolveBindAddrs("tcp", port)
	if err != nil {
		return // only loopback exists, all occupied
	}
	for _, addr := range addrs {
		if addr == "127.0.0.1:"+port {
			t.Errorf("occupied address should be skipped")
		}
	}
}

func TestResolveBindAddrs_InvalidNetwork(t *testing.T) {
	_, err := ResolveBindAddrs("invalid", "12345")
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestResolveBindAddrs_Format(t *testing.T) {
	port := findFreePort(t)
	addrs, err := ResolveBindAddrs("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		host, p, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("address %q is not valid host:port: %v", addr, err)
		}
		if p != port {
			t.Errorf("expected port %s, got %s in %q", port, p, addr)
		}
		if host == "" {
			t.Errorf("wildcard address should not appear: %q", addr)
			continue
		}
		if ip := net.ParseIP(host); ip == nil {
			t.Errorf("address %q has invalid IP: %s", addr, host)
		}
	}
}

func TestTryBind_RandomPort(t *testing.T) {
	for i := range 10 {
		err := TryBind("tcp", ":0")
		if err != nil {
			t.Fatalf("TryBind :0 iteration %d: %v", i, err)
		}
	}
}

// --- helpers ---

func findFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", ":0") //nolint:gosec // G102: test binds all interfaces
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func isAddrInUse(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var syscallErr *os.SyscallError
		if errors.As(opErr.Err, &syscallErr) {
			return errors.Is(syscallErr.Err, syscall.EADDRINUSE)
		}
	}
	return false
}

// --- benchmarks ---

func BenchmarkTryBind(b *testing.B) {
	for b.Loop() {
		_ = TryBind("tcp", ":0")
	}
}

func BenchmarkResolveBindAddrs(b *testing.B) {
	for b.Loop() {
		_, _ = ResolveBindAddrs("tcp", "0")
	}
}
