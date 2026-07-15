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

// QUICPool manages a set of QUIC connections per upstream server key.
type QUICPool struct {
	mu       sync.Mutex
	conns    map[string][]*QUICConn
	dialing  map[string]int
	maxConns int
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

// NewQUICPool creates a QUICPool with the specified maximum connections.
func NewQUICPool(maxConns int) *QUICPool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	return &QUICPool{
		conns:    make(map[string][]*QUICConn),
		dialing:  make(map[string]int),
		maxConns: maxConns,
	}
}

// Acquire gets a reusable QUIC connection, dialing a new one if needed.
func (p *QUICPool) Acquire(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) (*QUICConn, error) {
	p.mu.Lock()

	conns := p.conns[key]
	live := make([]*QUICConn, 0, len(conns))
	for _, pc := range conns {
		if pc.isDead() {
			continue
		}
		live = append(live, pc)
	}
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

// Shutdown closes all pooled QUIC connections and clears the pool. It is safe
// to call multiple times.
func (p *QUICPool) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, conns := range p.conns {
		for _, pc := range conns {
			pc.close()
		}
		delete(p.conns, key)
	}
}

// Put returns a QUIC connection to the pool for reuse.
func (p *QUICPool) Put(key string, conn *quic.Conn) {
	pc := &QUICConn{Conn: conn, addr: key}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns[key]) >= p.maxConns {
		pc.close()
		return
	}
	p.conns[key] = append(p.conns[key], pc)
}

// Remove closes and removes a QUIC connection from the pool.
func (p *QUICPool) Remove(pc *QUICConn) {
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
