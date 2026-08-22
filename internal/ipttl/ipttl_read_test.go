package ipttl

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestReadFrom_Deadline verifies a timeout read surfaces as a net error with
// Timeout()==true — the same shape readLoop's errors.As branch expects — on
// both the RawConn recvmsg path (unix) and the x/net path (other platforms).
func TestReadFrom_Deadline(t *testing.T) {
	client, server := localUDPPair(t, "udp4", net.IPv4(127, 0, 0, 1))
	_ = client

	c := New(server)
	if c == nil {
		t.Skip("platform does not support IP_RECVTTL — skipping capture test")
	}

	if err := server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1500)
	_, _, err := c.ReadFrom(buf)
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("timeout read: err = %v, want net.Error with Timeout()==true", err)
	}
}
