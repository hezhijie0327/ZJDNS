package pool

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/doq"
	"zjdns/internal/log"

	"github.com/quic-go/quic-go"
)

// QUICConn wraps a QUIC connection with lifecycle tracking.
type QUICConn struct {
	Conn      *quic.Conn
	addr      string
	lastUsed  atomic.Int64 // log.NowUnix() of the last acquire — LRU eviction key
	closed    atomic.Bool
	closeOnce sync.Once
}

// QUIC manages a set of QUIC connections per upstream server key.
type QUIC struct {
	mu       sync.Mutex
	conns    map[string][]*QUICConn
	dialing  map[string]int
	maxConns int
	maxTotal int // global cap on live connections across all keys (0 = unlimited)
	total    int // live connections currently tracked in conns
	closed   bool
}

func (c *QUICConn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.Conn.CloseWithError(doq.QUICCodeNoError, "pool connection closed")
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

// decDialing decrements the in-flight dialing count and removes the key from the
// dialing map when it reaches zero. Must be called with p.mu held.
func (p *QUIC) decDialing(key string) {
	p.dialing[key]--
	if p.dialing[key] == 0 {
		delete(p.dialing, key)
	}
}

// NewQUIC creates a QUIC with the specified maximum connections.  maxTotal
// caps the live connection count across all keys (0 = unlimited).
func NewQUIC(maxConns, maxTotal int) *QUIC {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	if maxTotal <= 0 {
		maxTotal = config.DefaultMaxPoolTotalConns
	}
	return &QUIC{
		conns:    make(map[string][]*QUICConn),
		dialing:  make(map[string]int),
		maxConns: maxConns,
		maxTotal: maxTotal,
	}
}

// Acquire gets a reusable QUIC connection, dialing a new one if needed.
func (p *QUIC) Acquire(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) (*QUICConn, error) {
	// Check for context cancellation before acquiring the lock to avoid
	// a potentially blocking lock acquisition on a cancelled context.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrPoolShutdown
	}
	live := p.conns[key][:0]
	for _, pc := range p.conns[key] {
		if !pc.isDead() {
			live = append(live, pc)
		}
	}
	p.total -= len(p.conns[key]) - len(live) // dead-filter accounting (U1)
	p.conns[key] = live

	if len(live) > 0 {
		// Round-robin across live connections rather than always returning
		// live[0], which would leave connections[1..N] unused.
		idx := rand.IntN(len(live)) //nolint:gosec // G404: QUIC connection selection — not cryptographic
		pc := live[idx]
		pc.lastUsed.Store(log.NowUnix())
		p.mu.Unlock()
		return pc, nil
	}

	if len(live)+p.dialing[key] < p.maxConns {
		p.dialing[key]++
		p.mu.Unlock()
		conn, err := dialFunc(ctx, key)
		if err != nil {
			p.mu.Lock()
			p.decDialing(key)
			p.mu.Unlock()
			return nil, fmt.Errorf("client: dial %s: %w", key, err)
		}
		pc := &QUICConn{Conn: conn, addr: key}
		pc.lastUsed.Store(log.NowUnix())
		p.mu.Lock()
		p.decDialing(key)
		// Pool was shut down while we were dialing — discard the connection.
		if p.closed {
			p.mu.Unlock()
			pc.close()
			return nil, ErrPoolShutdown
		}
		if len(p.conns[key]) >= p.maxConns {
			p.mu.Unlock()
			pc.close()
			return nil, ErrMaxConnsReached
		}
		p.conns[key] = append(p.conns[key], pc)
		p.total++
		// Global cap (H1): a flood of distinct upstream keys must not grow
		// the connection working set without bound.  Evict connections to
		// make room — dead ones first, then the least-recently-used — and
		// close them after unlocking.
		var evicted []*QUICConn
		for p.total > p.maxTotal {
			victim, removed := p.evictOne(pc)
			if !removed {
				break // nothing evictable — the new connection stays
			}
			if victim != nil {
				evicted = append(evicted, victim)
			}
		}
		n := len(p.conns[key]) // captured under the lock — the logs below run unlocked
		total := p.total
		p.mu.Unlock()
		for _, v := range evicted {
			v.close()
			log.Debugf("UPSTREAM: evicted QUIC %s for capacity (total=%d/%d)", v.addr, total, p.maxTotal)
		}
		log.Debugf("UPSTREAM: dialed new QUIC connection to %s (pool=%d/%d, total=%d/%d)", key, n, p.maxConns, total, p.maxTotal)
		return pc, nil
	}

	p.mu.Unlock()
	return nil, ErrNoAvailableSocket
}

// evictOne removes one connection from the pool to make room for a new dial,
// preferring (1) dead connections (already closed — nil victim), (2) the
// least-recently-used live connection.  QUIC multiplexes queries over
// per-connection streams, so there is no per-conn in-flight signal to prefer
// idle connections over — unlike the UDP/TCP/Raw pools (which never evict
// in-flight connections), a busy QUIC connection may be evicted; its dial
// cost is bounded by 0-RTT resumption, and this matches the pre-soft-cap
// behavior deliberately.  Must be called with p.mu held; skip is never
// evicted.  The live victim is returned WITHOUT closing — the caller closes
// it outside p.mu.
func (p *QUIC) evictOne(skip *QUICConn) (victim *QUICConn, removed bool) {
	// (1) Dead connections cost a slot while waiting for lazy pruning —
	// drop them without closing anything (their peer already terminated).
	for key, conns := range p.conns {
		for i, c := range conns {
			if !c.isDead() {
				continue
			}
			p.conns[key] = append(conns[:i], conns[i+1:]...)
			if len(p.conns[key]) == 0 {
				delete(p.conns, key)
			}
			p.total--
			return nil, true
		}
	}
	// (2): least-recently-used live connection.
	var victimKey string
	var victimIdx int
	oldest := int64(math.MaxInt64)
	for key, conns := range p.conns {
		for i, c := range conns {
			if c == skip || c.isDead() {
				continue
			}
			if last := c.lastUsed.Load(); last < oldest {
				oldest = last
				victim, victimKey, victimIdx = c, key, i
			}
		}
	}
	if victim == nil {
		return nil, false
	}
	p.conns[victimKey] = append(p.conns[victimKey][:victimIdx], p.conns[victimKey][victimIdx+1:]...)
	if len(p.conns[victimKey]) == 0 {
		delete(p.conns, victimKey)
	}
	p.total--
	return victim, true
}

// ReapDead drops dead connections from every pool key and deletes keys with
// no live connections left.  Called periodically by the server — a peer-
// closed connection otherwise stays pinned under its address key (counting
// against the global cap) until that address is queried again.
func (p *QUIC) ReapDead() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, conns := range p.conns {
		live := conns[:0]
		for _, c := range conns {
			if !c.isDead() {
				live = append(live, c)
			}
		}
		removed := len(conns) - len(live)
		if removed > 0 {
			p.total -= removed
		}
		if len(live) == 0 {
			delete(p.conns, key)
			continue
		}
		p.conns[key] = live
	}
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
	p.closed = true
	var all []*QUICConn
	for _, conns := range p.conns {
		all = append(all, conns...)
	}
	p.conns = make(map[string][]*QUICConn)
	p.total = 0
	p.mu.Unlock()
	for _, pc := range all {
		pc.close()
	}
}

// Put returns a QUIC connection to the pool for reuse.  If the connection
// is already pooled (same *quic.Conn pointer), it is silently discarded to
// prevent duplicate entries from exceeding maxConns.
func (p *QUIC) Put(key string, conn *quic.Conn) {
	p.mu.Lock()

	if p.closed {
		p.mu.Unlock()
		_ = conn.CloseWithError(doq.QUICCodeNoError, "pool closed")
		return
	}

	// Dedup: if this connection is already in the pool, drop it.
	for _, existing := range p.conns[key] {
		if existing.Conn == conn {
			p.mu.Unlock()
			return
		}
	}

	// Reject dead connections: a concurrently-closed conn (e.g. after a
	// Remove by another query sharing the same *quic.Conn) would consume a
	// pool slot until the next Acquire filters it out.
	if conn.Context().Err() != nil {
		p.mu.Unlock()
		_ = conn.CloseWithError(doq.QUICCodeNoError, "connection already closed")
		return
	}

	if len(p.conns[key]) >= p.maxConns {
		p.mu.Unlock()
		_ = conn.CloseWithError(doq.QUICCodeNoError, "pool full")
		return
	}
	pc := &QUICConn{Conn: conn, addr: key}
	pc.lastUsed.Store(log.NowUnix())
	p.conns[key] = append(p.conns[key], pc)
	p.total++
	// Same global-cap eviction as the Acquire dial path — Put-inserted
	// connections previously bypassed the cap entirely and drifted the
	// accounting (every Remove→Put cycle double-decremented p.total),
	// while the zero lastUsed made fresh connections evict first (U3).
	var evicted []*QUICConn
	for p.total > p.maxTotal {
		victim, removed := p.evictOne(pc)
		if !removed {
			break // nothing evictable — the new connection stays
		}
		if victim != nil {
			evicted = append(evicted, victim)
		}
	}
	p.mu.Unlock()
	for _, v := range evicted {
		v.close()
		log.Debugf("UPSTREAM: evicted QUIC %s for capacity after Put (total=%d/%d)", v.addr, p.total, p.maxTotal)
	}
}

// Remove closes and removes a QUIC connection from the pool.  The close runs
// outside the lock, matching the TCP pool's close-outside-lock discipline.
func (p *QUIC) Remove(pc *QUICConn) {
	p.mu.Lock()
	conns := p.conns[pc.addr]
	found := false
	for i, c := range conns {
		if c != pc {
			continue
		}
		p.conns[pc.addr] = append(conns[:i], conns[i+1:]...)
		if len(p.conns[pc.addr]) == 0 {
			delete(p.conns, pc.addr)
		}
		p.total--
		found = true
		break
	}
	p.mu.Unlock()
	if found {
		pc.close()
	}
}
