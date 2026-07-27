package ipttl

import (
	"net"
	"testing"
)

// localUDPPair returns two connected *net.UDPConn sockets.
// The server writes to the client; both have RemoteAddr set.
func localUDPPair(t *testing.T, network string, ip net.IP) (client, server *net.UDPConn) {
	t.Helper()

	// Bind a free port then dial to get a connected socket.
	tmp, err := net.ListenUDP(network, &net.UDPAddr{IP: ip, Port: 0})
	if err != nil {
		t.Skipf("listen %s: %v", network, err)
	}
	addr := tmp.LocalAddr().(*net.UDPAddr)
	_ = tmp.Close()

	// Both sides use DialUDP for connected sockets (RemoteAddr is set).
	server, err = net.DialUDP(network, &net.UDPAddr{IP: ip, Port: 0}, addr)
	if err != nil {
		t.Fatalf("dial server %s: %v", network, err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err = net.DialUDP(network, nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial client %s: %v", network, err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client, server
}

func TestNew_IPv4(t *testing.T) {
	client, server := localUDPPair(t, "udp4", net.IPv4(127, 0, 0, 1))

	payload := []byte("hello-ipttl")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := New(server)
	if c == nil {
		t.Skip("platform does not support IP_RECVTTL — skipping capture test")
	}

	buf := make([]byte, 1500)
	n, ttl, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(payload) {
		t.Errorf("ReadFrom: got %d bytes, want %d", n, len(payload))
	}
	if ttl == 0 {
		t.Error("ReadFrom: TTL is 0, expected non-zero from localhost")
	}
	t.Logf("IPv4 localhost TTL: %d", ttl)
}

func TestNew_IPv6(t *testing.T) {
	client, server := localUDPPair(t, "udp6", net.IPv6loopback)

	payload := []byte("hello-ipttl-v6")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	c := New(server)
	if c == nil {
		t.Skip("platform does not support IPV6_RECVHOPLIMIT — skipping capture test")
	}

	buf := make([]byte, 1500)
	n, hlim, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != len(payload) {
		t.Errorf("ReadFrom: got %d bytes, want %d", n, len(payload))
	}
	if hlim == 0 {
		t.Error("ReadFrom: HopLimit is 0, expected non-zero from localhost")
	}
	t.Logf("IPv6 localhost HopLimit: %d", hlim)
}

func TestNew_UnsupportedPlatform(t *testing.T) {
	client, server := localUDPPair(t, "udp4", net.IPv4(127, 0, 0, 1))
	_ = client

	c := New(server)
	if c == nil {
		t.Log("New returned nil — platform does not support IP_RECVTTL (expected on Windows)")
	} else {
		t.Log("New returned non-nil — platform supports IP_RECVTTL (expected on Linux/macOS)")
	}
}
