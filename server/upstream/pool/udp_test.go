package pool

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUDPServer echoes a response whose first two bytes are the request's
// first two bytes (the match key), optionally with jitter to force out-of-
// order replies.  It can also inject datagrams that match nothing in flight.
type fakeUDPServer struct {
	conn     net.PacketConn
	jitter   time.Duration
	injected atomic.Int64
}

func startFakeUDPServer(t *testing.T, jitter time.Duration) (srv *fakeUDPServer, addr string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeUDPServer{conn: conn, jitter: jitter}
	go func() {
		buf := make([]byte, 2048)
		for {
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			key := make([]byte, 2)
			copy(key, buf[:2])
			go func() {
				if s.jitter > 0 {
					// Floor of 5ms: the CtxCancel test relies on responses
					// NEVER arriving inside its 2ms context.
					time.Sleep(time.Duration(5+rand.IntN(int(s.jitter/time.Millisecond))) * time.Millisecond) //nolint:gosec // G404: test-only jitter
				}
				// Echo key + 'R' marker.
				resp := make([]byte, 3)
				copy(resp, key)
				resp[2] = 'R'
				_, _ = conn.WriteTo(resp, addr)
			}()
		}
	}()
	t.Cleanup(func() { _ = conn.Close() })
	return s, conn.LocalAddr().String()
}

func testKeyExtractor(payload []byte) (string, bool) {
	if len(payload) < 2 {
		return "", false
	}
	return string(payload[:2]), true
}

func newTestUDPConn(t *testing.T, addr string) *UDPConn {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &UDPConn{
		conn:        conn,
		addr:        addr,
		inflight:    make(map[string]*udpPending),
		capacity:    make(chan struct{}, 16),
		maxPipe:     16,
		extractKey:  testKeyExtractor,
		idleTimeout: 2 * time.Second,
	}
	go c.readLoop()
	t.Cleanup(c.close)
	return c
}

// TestUDPConn_Multiplex verifies concurrent queries on one socket each get
// their own response (routed by match key).
func TestUDPConn_Multiplex(t *testing.T) {
	_, addr := startFakeUDPServer(t, 5*time.Millisecond)
	c := newTestUDPConn(t, addr)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		key := fmt.Sprintf("%02d", i)
		wg.Go(func() {
			resp, err := c.Exchange(context.Background(), []byte(key+"query"), key)
			if err != nil {
				errs <- err
				return
			}
			if string(resp[:2]) != key || resp[2] != 'R' {
				errs <- fmt.Errorf("query %s got response %q", key, resp)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestUDPConn_UnknownDatagramDropped verifies a datagram whose key matches no
// in-flight query is dropped and does not disturb the waiting query.
func TestUDPConn_UnknownDatagramDropped(t *testing.T) {
	s, addr := startFakeUDPServer(t, 0)
	c := newTestUDPConn(t, addr)

	// Inject an orphan datagram before the real query.
	_, _ = s.conn.WriteTo([]byte("99orphan"), c.conn.LocalAddr())
	s.injected.Add(1)

	resp, err := c.Exchange(context.Background(), []byte("01query"), "01")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if string(resp[:2]) != "01" || resp[2] != 'R' {
		t.Fatalf("got response %q, want routed response for key 01", resp)
	}
}

// TestUDPConn_CtxCancelLeavesSocketUsable verifies a cancelled query unlinks
// its key and a subsequent query on the same socket still works (the late
// response to the cancelled query is drained, not delivered).
func TestUDPConn_CtxCancelLeavesSocketUsable(t *testing.T) {
	_, addr := startFakeUDPServer(t, 20*time.Millisecond)
	c := newTestUDPConn(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	if _, err := c.Exchange(ctx, []byte("01query"), "01"); err == nil {
		t.Fatal("short-ctx exchange should time out")
	}
	cancel()

	// The same key is reusable after cancellation; the late response must not
	// leak into the new query (it is drained by the deferred cleanup).
	time.Sleep(30 * time.Millisecond) // let the late response arrive
	resp, err := c.Exchange(context.Background(), []byte("01query"), "01")
	if err != nil {
		t.Fatalf("re-exchange: %v", err)
	}
	if string(resp[:2]) != "01" || resp[2] != 'R' {
		t.Fatalf("got response %q, want response for key 01", resp)
	}
}

// TestUDPConn_SocketReuse verifies the same socket serves sequential queries
// (the readLoop keeps running, in-flight map stays clean).
func TestUDPConn_SocketReuse(t *testing.T) {
	_, addr := startFakeUDPServer(t, 0)
	c := newTestUDPConn(t, addr)

	for i := range 5 {
		key := fmt.Sprintf("%02d", i)
		resp, err := c.Exchange(context.Background(), []byte(key+"query"), key)
		if err != nil {
			t.Fatalf("exchange %d: %v", i, err)
		}
		if string(resp[:2]) != key {
			t.Fatalf("exchange %d: got response for %q", i, resp)
		}
	}
	c.mu.RLock()
	left := len(c.inflight)
	c.mu.RUnlock()
	if left != 0 {
		t.Errorf("in-flight entries left after exchanges: %d", left)
	}
}

// TestUDPPool_AcquireReuses verifies the pool hands out the same socket for
// repeated acquires and dials at most once.
func TestUDPPool_AcquireReuses(t *testing.T) {
	_, addr := startFakeUDPServer(t, 0)
	p := NewUDPPool(4, 16, testKeyExtractor)

	var dials atomic.Int64
	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "udp", a)
	}

	c1, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if _, err := c1.Exchange(context.Background(), []byte("01query"), "01"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	c2, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if c1 != c2 {
		t.Error("second Acquire should reuse the first socket")
	}
	if dials.Load() != 1 {
		t.Errorf("dials = %d, want 1 (socket reused)", dials.Load())
	}
}

// TestUDPPool_ReapDead removes idle-recycled dead sockets and empty keys from
// the pool (H1): a socket closed by its readLoop stays pinned under its
// address key until ReapDead runs.
func TestUDPPool_ReapDead(t *testing.T) {
	_, addr1 := startFakeUDPServer(t, 0)
	_, addr2 := startFakeUDPServer(t, 0)
	p := NewUDPPool(4, 16, testKeyExtractor)

	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", a)
	}

	// Two keys, one live socket each.
	c1, err := p.Acquire(context.Background(), addr1, addr1, dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	c2, err := p.Acquire(context.Background(), addr2, addr2, dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}

	// Kill both sockets the way readLoop does — close() only, the pool never
	// hears about it.
	c1.close()
	c2.close()
	if !c1.IsDead() || !c2.IsDead() {
		t.Fatal("sockets should be dead after close")
	}

	p.ReapDead()

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) != 0 {
		t.Errorf("ReapDead left %d keys behind, want 0", len(p.conns))
	}
	if len(p.dialing) != 0 {
		t.Errorf("dialing map should be empty, got %d entries", len(p.dialing))
	}
}

// TestUDPPool_ReapDeadKeepsLive keeps live sockets and prunes only dead ones
// within a mixed pool.
func TestUDPPool_ReapDeadKeepsLive(t *testing.T) {
	_, addr := startFakeUDPServer(t, 0)
	p := NewUDPPool(4, 16, testKeyExtractor)

	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", a)
	}

	c1, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	// Second socket for the same key: cap 4 > 2, so both stay.
	old := p.replaceDead(addr)
	if old != nil {
		t.Fatal("unexpected dead socket before any close")
	}
	dead := c1
	dead.close()
	// A fresh live socket — keep.
	if _, err := p.Acquire(context.Background(), addr, addr, dialFunc); err != nil {
		t.Fatalf("acquire live: %v", err)
	}

	p.ReapDead()

	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.conns[addr]
	if len(conns) == 0 {
		t.Fatal("live socket must survive ReapDead")
	}
	for _, c := range conns {
		if c.IsDead() {
			t.Error("dead socket survived ReapDead")
		}
	}
}
