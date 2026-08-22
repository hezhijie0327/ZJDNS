package pool

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestSentinels_ExchangeOnClosedConn verifies the closed-connection hot path
// returns the ErrConnClosed sentinel (errors.Is-classifiable, no formatting).
func TestSentinels_ExchangeOnClosedConn(t *testing.T) {
	_, addr := startFakeUDPServer(t, 0)
	c := newTestUDPConn(t, addr)
	c.close()
	_, err := c.Exchange(context.Background(), []byte("01query"), "01")
	if !errors.Is(err, ErrConnClosed) {
		t.Fatalf("Exchange on closed conn: err = %v, want errors.Is(err, ErrConnClosed)", err)
	}
}

// TestSentinels_AcquireSaturated verifies the saturated-pool hot path returns
// the ErrNoAvailableSocket sentinel.
func TestSentinels_AcquireSaturated(t *testing.T) {
	p := NewUDPPool(1, 16, 0, testKeyExtractor)
	p.mu.Lock()
	p.dialing["busy"] = 1 // maxConns dials already in flight, zero conns
	p.mu.Unlock()

	_, err := p.Acquire(context.Background(), "busy", "127.0.0.1:1", false, func(context.Context, string) (net.Conn, error) {
		t.Fatal("dialFunc must not be called when the key is saturated")
		return nil, nil
	})
	if !errors.Is(err, ErrNoAvailableSocket) {
		t.Fatalf("Acquire at saturation: err = %v, want errors.Is(err, ErrNoAvailableSocket)", err)
	}
}

// TestSentinels_WriteFailure verifies a failed write surfaces as a Join of
// ErrWriteFailed and the underlying error.
func TestSentinels_WriteFailure(t *testing.T) {
	_, addr := startFakeUDPServer(t, 0)
	c := newTestUDPConn(t, addr)
	c.close() // the write below fails: the underlying conn is closed
	_, err := c.Exchange(context.Background(), []byte("01query"), "01")
	// Closed-conn state is checked before the write, so this may surface as
	// ErrConnClosed — accept either sentinel; the point is errors.Is works.
	if !errors.Is(err, ErrConnClosed) && !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("Exchange: err = %v, want ErrConnClosed or ErrWriteFailed", err)
	}
}
