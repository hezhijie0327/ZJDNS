package pool

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRawServer struct {
	accepted atomic.Int64
}

// startFakeRawServer accepts connections and echoes each frame's first two
// bytes back as the response key ('R' marker), mimicking the DNSCrypt/cert
// header shapes the extractor keys on.
func startFakeRawServer(t *testing.T, jitter time.Duration) (srv *fakeRawServer, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeRawServer{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var lenBuf [2]byte
				for {
					if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
						return
					}
					frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
					body := make([]byte, frameLen)
					if _, err := io.ReadFull(c, body); err != nil {
						return
					}
					if jitter > 0 {
						time.Sleep(jitter)
					}
					// Echo key + 'R' marker.
					resp := make([]byte, 3)
					copy(resp, body[:2])
					resp[2] = 'R'
					frame := make([]byte, 2+len(resp))
					binary.BigEndian.PutUint16(frame[:2], uint16(len(resp))) //nolint:gosec // G115: test frame — 3 bytes
					copy(frame[2:], resp)
					_, _ = c.Write(frame)
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return s, l.Addr().String()
}

func rawTestExtractor(payload []byte) (string, bool) {
	if len(payload) < 2 {
		return "", false
	}
	return string(payload[:2]), true
}

func newTestRawConn(t *testing.T, addr string) *RawConn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &RawConn{
		conn:        conn,
		addr:        addr,
		inflight:    make(map[string]*rawPending),
		capacity:    make(chan struct{}, 16),
		maxPipe:     16,
		extractKey:  rawTestExtractor,
		idleTimeout: 2 * time.Second,
	}
	go c.readLoop()
	t.Cleanup(c.close)
	return c
}

// TestRawConn_Multiplex verifies concurrent exchanges on one connection each
// get their own response (routed by match key).
func TestRawConn_Multiplex(t *testing.T) {
	_, addr := startFakeRawServer(t, 5*time.Millisecond)
	c := newTestRawConn(t, addr)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		key := fmt.Sprintf("%02d", i)
		wg.Go(func() {
			resp, err := c.Exchange(context.Background(), []byte(key+"payload"), key)
			if err != nil {
				errs <- err
				return
			}
			if string(resp[:2]) != key || resp[2] != 'R' {
				errs <- fmt.Errorf("key %s got response %q", key, resp)
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestRawConn_Reuse verifies the same connection serves sequential exchanges
// (the readLoop keeps running, in-flight map stays clean).
func TestRawConn_Reuse(t *testing.T) {
	_, addr := startFakeRawServer(t, 0)
	c := newTestRawConn(t, addr)

	for i := range 5 {
		key := fmt.Sprintf("%02d", i)
		resp, err := c.Exchange(context.Background(), []byte(key+"payload"), key)
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

// TestRawConn_CtxCancelLeavesConnUsable verifies a cancelled exchange unlinks
// its key and a subsequent exchange still works (the late response to the
// cancelled exchange is drained, not delivered).
func TestRawConn_CtxCancelLeavesConnUsable(t *testing.T) {
	_, addr := startFakeRawServer(t, 20*time.Millisecond)
	c := newTestRawConn(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Millisecond)
	if _, err := c.Exchange(ctx, []byte("01payload"), "01"); err == nil {
		t.Fatal("short-ctx exchange should time out")
	}
	cancel()

	time.Sleep(30 * time.Millisecond) // let the late response arrive
	resp, err := c.Exchange(context.Background(), []byte("01payload"), "01")
	if err != nil {
		t.Fatalf("re-exchange: %v", err)
	}
	if string(resp[:2]) != "01" || resp[2] != 'R' {
		t.Fatalf("got response %q, want response for key 01", resp)
	}
}

// TestRawPool_AcquireReuses verifies the pool hands out the same connection
// for repeated acquires and dials at most once.
func TestRawPool_AcquireReuses(t *testing.T) {
	_, addr := startFakeRawServer(t, 0)
	p := NewRawPool(4, 16, rawTestExtractor)

	var dials atomic.Int64
	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", a)
	}

	c1, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if _, err := c1.Exchange(context.Background(), []byte("01payload"), "01"); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	c2, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if c1 != c2 {
		t.Error("second Acquire should reuse the first connection")
	}
	if dials.Load() != 1 {
		t.Errorf("dials = %d, want 1 (connection reused)", dials.Load())
	}
}

// TestRawPool_DeadConnRecycled verifies a connection closed by its readLoop
// (or the peer) is replaced on the next dial rather than handed out.
func TestRawPool_DeadConnRecycled(t *testing.T) {
	_, addr := startFakeRawServer(t, 0)
	p := NewRawPool(4, 16, rawTestExtractor)

	var dials atomic.Int64
	dialFunc := func(ctx context.Context, a string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, "tcp", a)
	}

	c1, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	c1.close() // readLoop-equivalent death — the pool never hears about it

	c2, err := p.Acquire(context.Background(), addr, addr, dialFunc)
	if err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	if c1 == c2 {
		t.Error("dead connection must not be handed out")
	}
	if dials.Load() != 2 {
		t.Errorf("dials = %d, want 2 (dead conn replaced)", dials.Load())
	}
}
