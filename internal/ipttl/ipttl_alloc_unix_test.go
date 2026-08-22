//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package ipttl

import (
	"net"
	"testing"
)

// TestReadFrom_ZeroAllocs verifies the unix recvmsg path performs no
// per-packet heap allocation beyond the unavoidable Sockaddr that
// unix.Recvmsg returns for the source address (measured floor of 1).  The
// x/net path it replaced allocated a control message, a Sockaddr and a
// UDPAddr per read — ~1B allocations on a loaded server.
func TestReadFrom_ZeroAllocs(t *testing.T) {
	client, server := localUDPPair(t, "udp4", net.IPv4(127, 0, 0, 1))

	c := New(server)
	if c == nil {
		t.Skip("platform does not support IP_RECVTTL — skipping capture test")
	}

	payload := []byte("alloc-check")
	buf := make([]byte, 1500)

	// Warmup: first read may allocate lazily (oob buffer, closures).
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := c.ReadFrom(buf); err != nil {
		t.Fatalf("warmup ReadFrom: %v", err)
	}

	allocs := testing.AllocsPerRun(100, func() {
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := c.ReadFrom(buf); err != nil {
			t.Fatalf("ReadFrom: %v", err)
		}
	})
	if allocs > 1 {
		t.Fatalf("ReadFrom allocates %.2f objects/read, want <= 1 (unix.Recvmsg Sockaddr floor)", allocs)
	}
}
