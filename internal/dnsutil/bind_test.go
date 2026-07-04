package dnsutil

import (
	"net"
	"os"
	"syscall"
	"testing"
)

func TestTryBind_Success(t *testing.T) {
	err := tryBind("tcp", ":0")
	if err != nil {
		t.Fatalf("tryBind tcp :0: %v", err)
	}
	err = tryBind("udp", ":0")
	if err != nil {
		t.Fatalf("tryBind udp :0: %v", err)
	}
}

func TestTryBind_AddrInUse(t *testing.T) {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	addr := l.Addr().String()

	err = tryBind("tcp", addr)
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

	err = tryBind("udp", addr)
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

	err = tryBind("tcp4", addr)
	if !isAddrInUse(err) {
		t.Fatalf("expected EADDRINUSE, got %v", err)
	}
}

func TestResolveBindAddrs_WildcardAvailable(t *testing.T) {
	port := findFreePort(t)

	addrs, err := ResolveBindAddrs("tcp", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ":"+port {
		t.Fatalf("expected [:%s], got %v", port, addrs)
	}

	addrs, err = ResolveBindAddrs("udp", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != ":"+port {
		t.Fatalf("expected [:%s], got %v", port, addrs)
	}
}

func TestResolveBindAddrs_WildcardOccupied(t *testing.T) {
	port := findFreePort(t)
	l, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	addrs, err := ResolveBindAddrs("tcp", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(addrs) == 0 {
		t.Log("no non-loopback interfaces — fallback returned empty")
	}
	for _, addr := range addrs {
		if addr == ":"+port {
			t.Errorf("wildcard should not be in result when occupied")
		}
	}
}

func TestResolveBindAddrs_InvalidNetwork(t *testing.T) {
	_, err := ResolveBindAddrs("invalid", "12345")
	if err == nil {
		t.Fatal("expected error for invalid network")
	}
}

func TestResolveBindAddrs_FallbackSkipsOccupied(t *testing.T) {
	port := findFreePort(t)
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	l2, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()

	addrs, err := ResolveBindAddrs("tcp", port)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, addr := range addrs {
		if addr == "127.0.0.1:"+port {
			t.Errorf("127.0.0.1 should be skipped when occupied")
		}
	}
}

func TestResolveBindAddrs_NoAvailable(t *testing.T) {
	port := findFreePort(t)
	l, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}

	var listeners []net.Listener
	for _, iface := range ifaces {
		ips, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, ip := range ips {
			ipNet, ok := ip.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			addr := net.JoinHostPort(ipNet.IP.String(), port)
			l, err := net.Listen("tcp", addr)
			if err != nil {
				continue
			}
			listeners = append(listeners, l)
		}
	}
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()

	addrs, err := ResolveBindAddrs("tcp", port)
	if err == nil && len(addrs) > 0 {
		for _, addr := range addrs {
			host, _, _ := net.SplitHostPort(addr)
			if host != "" {
				ip := net.ParseIP(host)
				if ip != nil && ip.IsLoopback() {
					t.Errorf("loopback address %s should be excluded", addr)
				}
			}
		}
	}
}

func TestResolveBindAddrs_UDPWildcardOccupied(t *testing.T) {
	port := findFreePort(t)
	pc, err := net.ListenPacket("udp", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	_, err = ResolveBindAddrs("udp", port)
	if err == nil {
		t.Log("fallback found available addresses despite wildcard occupation")
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
			continue // wildcard, fine
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Errorf("address %q has invalid IP: %s", addr, host)
		}
		if ip.IsLoopback() {
			t.Errorf("loopback address should be excluded: %s", addr)
		}
		if ip.IsLinkLocalUnicast() {
			t.Errorf("link-local address should be excluded: %s", addr)
		}
	}
}

func TestTryBind_RandomPort(t *testing.T) {
	for i := 0; i < 10; i++ {
		err := tryBind("tcp", ":0")
		if err != nil {
			t.Fatalf("tryBind :0 iteration %d: %v", i, err)
		}
	}
}

// --- helpers ---

func findFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", ":0")
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
	if err == nil {
		return false
	}
	if oe, ok := err.(*net.OpError); ok {
		if se, ok := oe.Err.(*os.SyscallError); ok {
			return se.Err == syscall.EADDRINUSE
		}
	}
	return false
}

// --- benchmarks ---

func BenchmarkTryBind(b *testing.B) {
	for b.Loop() {
		_ = tryBind("tcp", ":0")
	}
}

func BenchmarkResolveBindAddrs(b *testing.B) {
	for b.Loop() {
		_, _ = ResolveBindAddrs("tcp", "0")
	}
}
