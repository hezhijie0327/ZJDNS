package socks5

import (
	"net"
	"testing"
)

// TestUDPConnReadPreservesNetError pins the net.Error identity contract of
// socks5UDPConn.Read: read errors that implement net.Error must pass a bare
// type assertion through unwrapped — consumers (gotlcp's DTLCP retransmit
// path) decide on `err.(net.Error)`, and a fmt.Errorf wrap breaks them
// (same contract as ReadFrom).
func TestUDPConnReadPreservesNetError(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	udp := conn.(*net.UDPConn)
	if err := udp.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	c := &socks5UDPConn{conn: udp, done: func() {}}
	_, err = c.Read(make([]byte, 64))
	if err == nil {
		t.Fatal("Read on a closed conn must fail")
	}
	if _, ok := err.(net.Error); !ok { //nolint:errorlint // the bare assertion is the contract under test
		t.Fatalf("Read error %T fails the bare net.Error assertion: %v", err, err)
	}
}
