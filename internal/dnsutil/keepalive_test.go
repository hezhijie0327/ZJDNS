package dnsutil_test

import (
	"net"
	"testing"
	"time"
	"zjdns/config"
	"zjdns/internal/dnsutil"
)

// TestTCPKeepAlivePeriodConsistency guards the duplicated constant in
// keepalive.go: internal/dnsutil cannot import config (layering), so
// defaultTCPKeepAlivePeriod mirrors config.DefaultTCPKeepAlivePeriod.
// This external test package can import both and catches drift.
func TestTCPKeepAlivePeriodConsistency(t *testing.T) {
	const mirroredKeepAlivePeriod = 30 * time.Second // must match keepalive.go's defaultTCPKeepAlivePeriod
	if config.DefaultTCPKeepAlivePeriod != mirroredKeepAlivePeriod {
		t.Fatalf("config.DefaultTCPKeepAlivePeriod = %v, but keepalive.go mirrors %v — update both",
			config.DefaultTCPKeepAlivePeriod, mirroredKeepAlivePeriod)
	}
}

// TestLimitListener verifies the admission cap: a second Accept blocks while
// the first connection is open, and completes once it closes (slot release).
func TestLimitListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = raw.Close() }()
	l := dnsutil.NewLimitListener(raw, 1)

	// Two dials succeed at the TCP level — the second queues in the backlog.
	c1, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer func() { _ = c1.Close() }()
	c2, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer func() { _ = c2.Close() }()

	a1, err := l.Accept()
	if err != nil {
		t.Fatalf("accept 1: %v", err)
	}

	// Second Accept must block at the cap.
	accepted := make(chan net.Conn, 1)
	go func() {
		a, err := l.Accept()
		if err != nil {
			t.Errorf("accept 2: %v", err)
			return
		}
		accepted <- a
	}()
	select {
	case <-accepted:
		t.Fatal("second Accept must block while at the cap")
	case <-time.After(200 * time.Millisecond):
	}

	// Closing the first connection releases the slot; the queued connection
	// is then accepted.
	_ = a1.Close()
	select {
	case a2 := <-accepted:
		_ = a2.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("Accept must complete after the slot is released")
	}
}

// TestLimitListener_Unlimited verifies max <= 0 returns the listener
// unwrapped — no admission cap.
func TestLimitListener_Unlimited(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = raw.Close() }()
	if got := dnsutil.NewLimitListener(raw, 0); got != raw {
		t.Error("max<=0 must return the listener unwrapped")
	}
}
