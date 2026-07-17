package pool

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"

	"github.com/quic-go/quic-go"

	zpool "zjdns/internal/pool"
)

// QUICConn wraps a QUIC connection with lifecycle tracking.
type QUICConn struct {
	Conn      *quic.Conn
	addr      string
	closed    atomic.Bool
	closeOnce sync.Once
}

// QUIC manages a set of QUIC connections per upstream server key.
type QUIC struct {
	mu       sync.Mutex
	conns    map[string][]*QUICConn
	dialing  map[string]int
	maxConns int
	closed   bool
}

func (c *QUICConn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.Conn.CloseWithError(zpool.QUICCodeNoError, "pool connection closed")
	})
}

func (c *QUICConn) isDead() bool {
	if c.closed.Load() {
		return true
	}
	// Also check the underlying quic-go connection context, which closes when
	// the remote peer terminates the connection or an unrecoverable transport
	// error occurs.
	select {
	case <-c.Conn.Context().Done():
		c.closed.Store(true)
		return true
	default:
		return false
	}
}

// NewQUIC creates a QUIC with the specified maximum connections.
func NewQUIC(maxConns int) *QUIC {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	return &QUIC{
		conns:    make(map[string][]*QUICConn),
		dialing:  make(map[string]int),
		maxConns: maxConns,
	}
}

// Acquire gets a reusable QUIC connection, dialing a new one if needed.
func (p *QUIC) Acquire(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) (*QUICConn, error) {
	// Snapshot the connection list under the lock, then evaluate liveness
	// outside it.  isDead() does a non-blocking channel select on
	// Context().Done() — cheap, but unnecessary to keep the pool-wide
	// mutex held during it.
	p.mu.Lock()
	conns := p.conns[key]
	all := make([]*QUICConn, len(conns))
	copy(all, conns)
	p.mu.Unlock()

	// Filter dead connections outside the lock.
	live := all[:0]
	for _, pc := range all {
		if !pc.isDead() {
			live = append(live, pc)
		}
	}

	// Update the stored live list under the lock.
	p.mu.Lock()
	p.conns[key] = live

	if len(live) > 0 {
		// Round-robin across live connections rather than always returning
		// live[0], which would leave connections[1..N] unused.
		idx := rand.IntN(len(live)) //nolint:gosec // G404: QUIC connection selection — not cryptographic
		pc := live[idx]
		p.mu.Unlock()
		return pc, nil
	}

	if len(live)+p.dialing[key] < p.maxConns {
		p.dialing[key]++
		p.mu.Unlock()
		conn, err := dialFunc(ctx, key)
		if err != nil {
			p.mu.Lock()
			p.dialing[key]--
			if p.dialing[key] == 0 {
				delete(p.dialing, key)
			}
			p.mu.Unlock()
			return nil, fmt.Errorf("client: dial %s: %w", key, err)
		}
		pc := &QUICConn{Conn: conn, addr: key}
		p.mu.Lock()
		p.dialing[key]--
		// Pool was shut down while we were dialing — discard the connection.
		if p.closed {
			if p.dialing[key] == 0 {
				delete(p.dialing, key)
			}
			p.mu.Unlock()
			pc.close()
			return nil, fmt.Errorf("client: pool shut down for %s", key)
		}
		if len(p.conns[key]) >= p.maxConns {
			if p.dialing[key] == 0 {
				delete(p.dialing, key)
			}
			p.mu.Unlock()
			pc.close()
			return nil, fmt.Errorf("client: pool filled during dial for %s", key)
		}
		p.conns[key] = append(p.conns[key], pc)
		n := len(p.conns[key])
		if p.dialing[key] == 0 {
			delete(p.dialing, key)
		}
		p.mu.Unlock()
		log.Debugf("UPSTREAM: dialed new QUIC connection to %s (pool=%d/%d)", key, n, p.maxConns)
		return pc, nil
	}

	p.mu.Unlock()
	return nil, fmt.Errorf("client: no available connection to %s", key)
}

// WarmUp dials a new QUIC connection and adds it to the pool without returning
// it.  This pre-establishes the QUIC handshake so the first real query avoids
// the dial latency.  If the pool is full the connection is discarded.
func (p *QUIC) WarmUp(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) error {
	_, err := p.Acquire(ctx, key, dialFunc)
	return err
}

// Shutdown closes all pooled QUIC connections and clears the pool. It is safe
// to call multiple times.
func (p *QUIC) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for key, conns := range p.conns {
		for _, pc := range conns {
			pc.close()
		}
		delete(p.conns, key)
	}
}

// Put returns a QUIC connection to the pool for reuse.  If the connection
// is already pooled (same *quic.Conn pointer), it is silently discarded to
// prevent duplicate entries from exceeding maxConns.
func (p *QUIC) Put(key string, conn *quic.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Dedup: if this connection is already in the pool, drop it.
	for _, existing := range p.conns[key] {
		if existing.Conn == conn {
			return
		}
	}

	if len(p.conns[key]) >= p.maxConns {
		_ = conn.CloseWithError(0, "pool full")
		return
	}
	p.conns[key] = append(p.conns[key], &QUICConn{Conn: conn, addr: key})
}

// Remove closes and removes a QUIC connection from the pool.
func (p *QUIC) Remove(pc *QUICConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.conns[pc.addr]
	for i, c := range conns {
		if c == pc {
			p.conns[pc.addr] = append(conns[:i], conns[i+1:]...)
			if len(p.conns[pc.addr]) == 0 {
				delete(p.conns, pc.addr)
			}
			pc.close()
			return
		}
	}
}
