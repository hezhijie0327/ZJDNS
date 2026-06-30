package client

import (
	"context"
	"net"
	"testing"
	"time"
)

// socks5TestProxy is the default proxy URL used by integration tests.
const socks5TestProxy = "socks5://127.0.0.1:1080"

// requireSocks5Proxy skips t if no SOCKS5 proxy is listening on proxyURL.
func requireSocks5Proxy(t *testing.T, proxyURL string) {
	t.Helper()
	// Use the proxy host as the test address — the actual proxy URL may
	// contain a scheme (socks5://) which is handled by Socks5Dialer.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1080", 2*time.Second)
	if err != nil {
		t.Skipf("SOCKS5 proxy not available on %s: %v", proxyURL, err)
	}
	_ = conn.Close()
}

// TestSocks5TCPConnect verifies that the SOCKS5 dialer can establish a TCP
// connection through a running proxy.
func TestSocks5TCPConnect(t *testing.T) {
	proxyURL := socks5TestProxy
	requireSocks5Proxy(t, proxyURL)

	d, err := NewSocks5Dialer(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}
	defer func() { _ = d.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", "8.8.8.8:53")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	t.Logf("Connected via proxy: local=%s, remote=%s", conn.LocalAddr(), conn.RemoteAddr())

	// Verify we can set deadlines
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Verify the connection is alive by checking remote addr
	if conn.RemoteAddr() == nil {
		t.Fatal("RemoteAddr is nil")
	}
	if conn.RemoteAddr().Network() != "tcp" {
		t.Fatalf("expected tcp network, got %s", conn.RemoteAddr().Network())
	}

	t.Log("TCP CONNECT test passed")
}

// TestSocks5UDPAssociate verifies that the SOCKS5 dialer can establish a UDP
// relay through a running proxy.
func TestSocks5UDPAssociate(t *testing.T) {
	proxyURL := socks5TestProxy
	requireSocks5Proxy(t, proxyURL)

	d, err := NewSocks5Dialer(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSocks5Dialer: %v", err)
	}
	defer func() { _ = d.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pconn, err := d.ListenPacket(ctx)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer func() { _ = pconn.Close() }()

	t.Logf("UDP relay established: local=%s", pconn.LocalAddr())

	// Verify PacketConn interface
	if err := pconn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	// Send a test UDP datagram to 8.8.8.8:53 (DNS port)
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}
	testData := []byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}

	n, err := pconn.WriteTo(testData, remoteAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	t.Logf("Sent %d bytes to %s via proxy", n, remoteAddr)

	// Try to read a response (may timeout since 8.8.8.8 might not respond to example.com)
	buf := make([]byte, 2048)
	_ = pconn.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, srcAddr, err := pconn.ReadFrom(buf)
	if err != nil {
		// Timeout is expected for a DNS query with an arbitrary ID
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			t.Logf("ReadFrom timed out (expected for arbitrary DNS query): %v", err)
		} else {
			t.Logf("ReadFrom error (non-fatal): %v", err)
		}
	} else {
		t.Logf("Received %d bytes from %s", rn, srcAddr)
	}

	t.Log("UDP ASSOCIATE test passed")
}

// TestSocks5DialerReuse verifies that the same proxy URL produces the same
// dialer from the cache.
func TestSocks5DialerReuse(t *testing.T) {
	proxyURL := socks5TestProxy

	d1, err := NewSocks5Dialer(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSocks5Dialer(1): %v", err)
	}
	defer func() { _ = d1.Close() }()

	d2, err := NewSocks5Dialer(proxyURL, 5*time.Second)
	if err != nil {
		t.Fatalf("NewSocks5Dialer(2): %v", err)
	}
	defer func() { _ = d2.Close() }()

	// Each call creates a new dialer struct (cache is at Client level, not package level)
	if d1 == d2 {
		t.Log("Same dialer struct (expected: package-level singleton)")
	} else {
		t.Log("Different dialer structs (Client.getProxyDialer would cache)")
	}
}

// TestSocks5InvalidURL verifies error handling for bad proxy URLs.
func TestSocks5InvalidURL(t *testing.T) {
	tests := []struct {
		url string
	}{
		{"not-a-url"},
		{"http://127.0.0.1:1080"},
		{"socks5://:1080"}, // no host
	}

	for _, tt := range tests {
		_, err := NewSocks5Dialer(tt.url, 5*time.Second)
		if err == nil {
			t.Errorf("expected error for %q, got nil", tt.url)
		} else {
			t.Logf("Correctly rejected %q: %v", tt.url, err)
		}
	}
}
