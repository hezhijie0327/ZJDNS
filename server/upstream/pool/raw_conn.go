// RawConn: one connected raw socket keyed by an opaque payload matcher —
// the exchange path and read loop for non-DNS framed protocols (DTLS/QUIC
// keying).

package pool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// rawPending is one in-flight frame awaiting its response.
type rawPending struct {
	resultCh chan []byte // raw response payload (ownership transferred)
}

// RawConn is a length-prefixed TCP connection multiplexing concurrent
// raw-frame exchanges, demultiplexed by extractKey.
type RawConn struct {
	conn      net.Conn
	addr      string
	writeMu   sync.Mutex
	mu        sync.RWMutex
	inflight  map[string]*rawPending
	capacity  chan struct{}
	inFlight  atomic.Int32
	lastUsed  atomic.Int64 // log.NowUnix() of the last exchange — LRU eviction key
	maxPipe   int32
	closed    atomic.Bool
	closeOnce sync.Once

	extractKey  func(payload []byte) (string, bool) // response → match key
	idleTimeout time.Duration
}

// Exchange sends one length-prefixed frame and waits for the response whose
// extracted match key equals matchKey.  The returned slice is owned by the
// caller.
func (c *RawConn) Exchange(ctx context.Context, payload []byte, matchKey string) ([]byte, error) {
	if len(payload) > rawMaxFrame {
		return nil, fmt.Errorf("raw pool: frame too large (%d bytes)", len(payload))
	}
	select {
	case c.capacity <- struct{}{}:
		c.inFlight.Add(1)
		c.lastUsed.Store(log.NowUnix())
		defer func() {
			c.inFlight.Add(-1)
			<-c.capacity
		}()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if c.closed.Load() {
		return nil, ErrConnClosed
	}

	resultCh := make(chan []byte, 1)
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return nil, ErrConnClosed
	}
	if _, dup := c.inflight[matchKey]; dup {
		c.mu.Unlock()
		// Match-key collision (2^-96 for DNSCrypt nonces, ID reuse for plain
		// DNS after 65536 queries) — fail the new exchange; the caller falls
		// back to a per-query dial.
		return nil, ErrKeyCollision
	}
	c.inflight[matchKey] = &rawPending{resultCh: resultCh}
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inflight, matchKey)
		c.mu.Unlock()
		// Drain an orphaned response that arrived after ctx cancellation and
		// return the tiered-pool payload buffer.  A nil value marks connection
		// close — nothing to release (same discipline as the UDP pool).
		select {
		case resp := <-resultCh:
			if resp != nil {
				ReleaseUDPPayload(resp)
			}
		default:
		}
	}()

	// Serialise writes and bound them by ctx: a stalled peer with a full
	// receive window must not block every queued frame on this connection
	// beyond the query budget.
	frame := [2]byte{}
	binary.BigEndian.PutUint16(frame[:], uint16(len(payload))) //nolint:gosec // G115: bounded by rawMaxFrame above
	c.writeMu.Lock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
	}
	_, err := (&net.Buffers{frame[:], payload}).WriteTo(c.conn)
	_ = c.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if err != nil {
		c.close()
		return nil, errors.Join(ErrWriteFailed, err)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, ErrConnClosed
		}
		return resp, nil
	case <-ctx.Done():
		// Only cancel this exchange, not the connection; the deferred cleanup
		// unlinks the match key and drains a late response.
		return nil, ctx.Err()
	}
}

// readLoop reads frames, routes them by the extracted match key and transfers
// buffer ownership to the waiting caller.  Idle connections (nothing in
// flight past idleTimeout) are closed for recycling.
func (c *RawConn) readLoop() {
	defer zdnsutil.HandlePanic("raw pool reader")
	defer c.close()

	var lengthBuf [2]byte

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.idleTimeout))

		if _, err := io.ReadFull(c.conn, lengthBuf[:]); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				c.mu.RLock()
				idle := len(c.inflight) == 0
				c.mu.RUnlock()
				if idle {
					return // recycle: the pool redials on demand
				}
				continue // exchanges still in flight — keep waiting
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf[:])
		if msgLen == 0 {
			return
		}
		// Frame payload from the tiered packet pool — the waiter owns the
		// slice and releases it by capacity class once unpacked/decrypted
		// (same discipline as the UDP pool).
		body, release := acquirePacketBuf(int(msgLen)) //nolint:gosec // G115: msgLen is uint16, fits int
		if _, err := io.ReadFull(c.conn, body); err != nil {
			release()
			return
		}

		key, ok := c.extractKey(body)
		if !ok {
			release()
			continue // not a response for any of our exchanges — drop
		}
		// Lookup AND delivery under RLock: close() delivers nil into the
		// resultChs under the write lock (channels are never closed here),
		// so a send can never race a closed channel (same discipline as the
		// UDP pool).
		c.mu.RLock()
		p, ok := c.inflight[key]
		if !ok {
			c.mu.RUnlock()
			release()
			continue // response for an exchange we no longer track — drop
		}
		select {
		case p.resultCh <- body:
		default:
			// Waiter already gave up (ctx cancelled) — drop.
			release()
		}
		c.mu.RUnlock()
	}
}

// close terminates the connection and wakes all waiters with nil.
func (c *RawConn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.conn.Close()
		c.mu.Lock()
		for _, p := range c.inflight {
			select {
			case p.resultCh <- nil:
			default:
			}
		}
		c.inflight = make(map[string]*rawPending)
		c.mu.Unlock()
	})
}

// IsDead reports whether the connection has been closed.
func (c *RawConn) IsDead() bool { return c.closed.Load() }

// IsFull reports whether the connection has reached its in-flight cap.
func (c *RawConn) IsFull() bool { return c.inFlight.Load() >= c.maxPipe }

func newRawConn(addr string, conn net.Conn, maxPipe int, extractKey func(payload []byte) (string, bool)) *RawConn {
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
		_ = tcpConn.SetNoDelay(true)
	}
	c := &RawConn{
		conn:        conn,
		addr:        addr,
		inflight:    make(map[string]*rawPending),
		capacity:    make(chan struct{}, maxPipe),
		maxPipe:     int32(maxPipe),
		extractKey:  extractKey,
		idleTimeout: config.DefaultTCPPoolIdleTimeout,
	}
	c.lastUsed.Store(log.NowUnix())
	go c.readLoop()
	return c
}
