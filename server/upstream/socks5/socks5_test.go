package socks5

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// ── Unit tests (no proxy required) ──────────────────────────────────────

func TestDialerReuse(t *testing.T) {
	proxyURL := "socks5://127.0.0.1:1080"

	d1, err := New(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("New(1): %v", err)
	}
	defer func() { _ = d1.Close() }()

	d2, err := New(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("New(2): %v", err)
	}
	defer func() { _ = d2.Close() }()

	if d1 == d2 {
		t.Log("Same dialer struct (expected: package-level singleton)")
	} else {
		t.Log("Different dialer structs (Client.getProxyDialer would cache)")
	}
}

func TestSOCKS5InvalidURL(t *testing.T) {
	tests := []struct {
		url string
	}{
		{"not-a-url"},
		{"http://127.0.0.1:1080"},
		{"socks5://:1080"},
	}

	for _, tt := range tests {
		_, err := New(tt.url, 5*time.Second)
		if err == nil {
			t.Errorf("expected error for %q, got nil", tt.url)
		} else {
			t.Logf("Correctly rejected %q: %v", tt.url, err)
		}
	}
}

// ── Integration tests (local SOCKS5 server) ────────────────────────────

// TestListenPacketIndependentRelays verifies each ListenPacket gets an
// independent relay and closing one does not break another.
func TestListenPacketIndependentRelays(t *testing.T) {
	addr, shutdown := startSOCKSServer(t)
	defer shutdown()

	proxyURL := "socks5://" + addr

	d1, err := New(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("New(1): %v", err)
	}
	defer func() { _ = d1.Close() }()

	d2, err := New(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("New(2): %v", err)
	}
	defer func() { _ = d2.Close() }()

	ctx := context.Background()

	pc1, err := d1.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket(1): %v", err)
	}
	pc2, err := d2.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket(2): %v", err)
	}

	t.Logf("Relay 1: local=%s", pc1.LocalAddr())
	t.Logf("Relay 2: local=%s", pc2.LocalAddr())

	// Verify both are alive by setting deadlines.
	if err := pc1.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("pc1.SetDeadline: %v", err)
	}
	if err := pc2.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("pc2.SetDeadline: %v", err)
	}

	// Close first — must NOT affect the second.
	if err := pc1.Close(); err != nil {
		t.Fatalf("Close(1): %v", err)
	}

	// pc2 should still be functional.
	if err := pc2.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("pc2.SetDeadline after pc1.Close: %v", err)
	}

	// Send a packet through pc2 — should echo back.
	dst := &net.UDPAddr{IP: net.IPv4(8, 8, 8, 8), Port: 53}
	msg := []byte("hello-relay")
	if _, err := pc2.WriteTo(msg, dst); err != nil {
		t.Fatalf("pc2.WriteTo: %v", err)
	}

	buf := make([]byte, 2048)
	if err := pc2.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("pc2.SetReadDeadline: %v", err)
	}
	n, src, err := pc2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("pc2.ReadFrom: %v", err)
	}
	t.Logf("Echoed %d bytes from %s: %q", n, src, string(buf[:n]))

	_ = pc2.Close()
}

// TestListenPacketConcurrentRelays verifies concurrent callers each get
// an operable relay.
func TestListenPacketConcurrentRelays(t *testing.T) {
	addr, shutdown := startSOCKSServer(t)
	defer shutdown()

	proxyURL := "socks5://" + addr

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			d, err := New(proxyURL, 5*time.Second)
			if err != nil {
				errs[idx] = err
				return
			}
			defer func() { _ = d.Close() }()

			pc, err := d.ListenPacket(context.Background())
			if err != nil {
				errs[idx] = err
				return
			}

			if err := pc.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				_ = pc.Close()
				errs[idx] = err
				return
			}
			if pc.LocalAddr() == nil {
				_ = pc.Close()
				errs[idx] = errors.New("nil local addr")
				return
			}

			// Send and receive a packet to verify the relay works.
			dst := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 53}
			if _, err := pc.WriteTo([]byte("test"), dst); err != nil {
				_ = pc.Close()
				errs[idx] = err
				return
			}

			buf := make([]byte, 2048)
			_, _, err = pc.ReadFrom(buf)
			if err != nil {
				errs[idx] = err
			}

			_ = pc.Close()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

// TestDialUDPConn verifies DialUDP returns an independent net.Conn that
// can send and receive UDP datagrams through the proxy relay.
func TestDialUDPConn(t *testing.T) {
	addr, shutdown := startSOCKSServer(t)
	defer shutdown()

	proxyURL := "socks5://" + addr

	d, err := New(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = d.Close() }()

	ctx := context.Background()
	conn, err := d.DialUDP(ctx, "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}

	t.Logf("DialUDP: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())

	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Send data and verify the relay echoes it back.
	msg := []byte("hello-dialudp")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	t.Logf("Echoed: %q", string(buf[:n]))

	_ = conn.Close()
}
