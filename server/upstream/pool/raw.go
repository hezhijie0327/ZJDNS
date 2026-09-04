// RawConn and RawPool multiplex concurrent length-prefixed TCP frame
// exchanges (2-byte big-endian length + opaque payload) over a shared
// connection, routing responses by a caller-supplied match key extracted
// from each frame header.  Unlike Conn, no DNS parsing is performed — the
// payloads are opaque.  This serves DNSCrypt over TCP, where the DNS message
// ID is inside the encrypted query and unreachable; the client-nonce prefix
// in the response header is the demultiplexing key, exactly as the UDP pool
// does for DNSCrypt datagrams.  Plain-DNS frames (certificate fetches) route
// by the echoed message ID through the same pool.
package pool

import (
	"context"
	"fmt"
	"math"
	"net"
	"sync"
	"zjdns/config"
	"zjdns/internal/log"
)

// RawPool manages a set of reusable raw-frame connections per upstream key.
type RawPool struct {
	mu         sync.Mutex
	conns      map[string][]*RawConn
	dialing    map[string]int
	maxConns   int
	maxPipe    int
	maxTotal   int // global cap on live connections across all keys (0 = unlimited)
	total      int // live connections currently tracked in conns
	closed     bool
	extractKey func(payload []byte) (string, bool)
}

// rawMaxFrame is the largest frame the 16-bit length prefix can represent.
const rawMaxFrame = 0xFFFF

// NewRawPool creates a RawPool.  maxTotal caps the live connection count
// across all keys (0 = unlimited).  extractKey derives a response's match
// key from its raw payload.
func NewRawPool(maxConns, maxPipe, maxTotal int, extractKey func(payload []byte) (string, bool)) *RawPool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	if maxTotal <= 0 {
		maxTotal = config.DefaultMaxPoolTotalConns
	}
	return &RawPool{
		conns:      make(map[string][]*RawConn),
		dialing:    make(map[string]int),
		maxConns:   maxConns,
		maxPipe:    maxPipe,
		maxTotal:   maxTotal,
		extractKey: extractKey,
	}
}

// Acquire gets a reusable raw-frame connection, dialing a new one if needed.
func (p *RawPool) Acquire(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*RawConn, error) {
	p.mu.Lock()
	conns := p.conns[key]

	if len(conns) == 0 {
		if p.dialing[key] < p.maxConns {
			return p.dialAndAdd(ctx, key, dialAddr, dialFunc)
		}
		p.mu.Unlock()
		return nil, ErrNoAvailableSocket
	}

	liveConns := make([]*RawConn, 0, len(conns))
	var leastLoaded *RawConn
	leastCount := math.MaxInt
	for i, c := range conns {
		if c.IsDead() {
			continue
		}
		liveConns = append(liveConns, c)
		if !c.IsFull() {
			for j := i + 1; j < len(conns); j++ {
				if !conns[j].IsDead() {
					liveConns = append(liveConns, conns[j])
				}
			}
			p.total -= len(conns) - len(liveConns) // dead-filter accounting (U1)
			p.conns[key] = liveConns
			p.mu.Unlock()
			return c, nil
		}
		if inFlight := int(c.inFlight.Load()); inFlight < leastCount {
			leastCount = inFlight
			leastLoaded = c
		}
	}
	p.total -= len(conns) - len(liveConns) // dead-filter accounting (U1)
	p.conns[key] = liveConns

	if len(liveConns)+p.dialing[key] < p.maxConns {
		c, err := p.dialAndAdd(ctx, key, dialAddr, dialFunc)
		if err != nil && leastLoaded != nil && !leastLoaded.IsDead() {
			return leastLoaded, nil
		}
		return c, err
	}

	p.mu.Unlock()
	if leastLoaded != nil {
		return leastLoaded, nil
	}
	return nil, fmt.Errorf("raw pool: no available connection to %s", key)
}

// dialAndAdd dials a new connection and adds it to the pool.  Must be called
// with p.mu held; releases and re-acquires the lock during dial.
func (p *RawPool) dialAndAdd(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*RawConn, error) {
	p.dialing[key]++
	p.mu.Unlock()

	conn, dialErr := dialFunc(ctx, dialAddr)

	p.mu.Lock()
	p.dialing[key]--
	if p.dialing[key] == 0 {
		delete(p.dialing, key)
	}
	if p.closed {
		p.mu.Unlock()
		if dialErr == nil {
			_ = conn.Close()
		}
		return nil, ErrPoolShutdown
	}
	if dialErr != nil {
		p.mu.Unlock()
		return nil, fmt.Errorf("raw pool: dial %s: %w", key, dialErr)
	}

	c := newRawConn(key, conn, p.maxPipe, p.extractKey)

	if len(p.conns[key]) >= p.maxConns {
		old := p.replaceDead(key)
		if old == nil {
			p.mu.Unlock()
			c.close()
			log.Debugf("TCPPOOL: raw pool for %s already at limit (%d), discarding extra connection", key, p.maxConns)
			return nil, ErrMaxConnsReached
		}
		p.conns[key] = append(p.conns[key], c)
		p.total++ // replaceDead decremented for the dead one — net-zero swap (U2)
		n := len(p.conns[key])
		p.mu.Unlock()
		old.close()
		log.Debugf("TCPPOOL: dialed new raw connection to %s (pool=%d/%d)", key, n, p.maxConns)
		return c, nil
	}

	p.conns[key] = append(p.conns[key], c)
	p.total++
	// Global cap (H1): a flood of distinct upstream keys must not grow the
	// connection working set without bound.  Evict connections to make room
	// — dead ones first, then the least-recently-used — and close them after
	// unlocking (ABBA convention, as in Remove/Shutdown).
	var evicted []*RawConn
	for p.total > p.maxTotal {
		victim, removed := p.evictOne(c)
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
		log.Debugf("TCPPOOL: evicted raw %s for capacity (total=%d/%d)", v.addr, total, p.maxTotal)
	}
	log.Debugf("TCPPOOL: dialed new raw connection to %s (pool=%d/%d, total=%d/%d)", key, n, p.maxConns, total, p.maxTotal)
	return c, nil
}

// evictOne removes one connection from the pool to make room for a new dial,
// preferring (1) dead connections (already closed — nil victim), (2) idle
// live connections (nothing in flight) oldest first.  In-flight connections
// are NEVER evicted: killing a busy connection fails every exchange waiting
// on it, and the callers fall through to per-query dials that re-enter the
// pool — a self-reinforcing dial/evict churn loop under saturation.  When
// every connection is busy the pool overshoots maxTotal transiently; idle
// connections self-close via the read-loop idle timeout and ReapDead reclaims
// their slots.  Must be called with p.mu held; skip is never evicted.  The
// live victim is returned WITHOUT closing — the caller closes it outside
// p.mu (ABBA convention, as in Remove/Shutdown).
func (p *RawPool) evictOne(skip *RawConn) (victim *RawConn, removed bool) {
	// (1) Dead connections cost a slot while waiting for the reap —
	// drop them without closing anything (their readLoop already closed).
	for key, conns := range p.conns {
		for i, c := range conns {
			if !c.IsDead() {
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
	// (2): least-recently-used idle connection — an in-flight eviction costs
	// its waiters a failed exchange; an idle one costs nothing.
	var victimKey string
	var victimIdx int
	oldest := int64(math.MaxInt64)
	for key, conns := range p.conns {
		for i, c := range conns {
			if c == skip || c.IsDead() || c.inFlight.Load() > 0 {
				continue
			}
			if last := c.lastUsed.Load(); last < oldest {
				oldest = last
				victim, victimKey, victimIdx = c, key, i
			}
		}
	}
	if victim == nil {
		return nil, false // only busy connections left — soft-cap overshoot
	}
	p.conns[victimKey] = append(p.conns[victimKey][:victimIdx], p.conns[victimKey][victimIdx+1:]...)
	if len(p.conns[victimKey]) == 0 {
		delete(p.conns, victimKey)
	}
	p.total--
	return victim, true
}

// ReapDead drops dead connections from every pool key and deletes keys with
// no live connections left.  Called periodically by the server — a connection
// idle-recycled by its readLoop otherwise stays pinned under its address key
// (counting against the global cap) until that address is queried again.
func (p *RawPool) ReapDead() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, conns := range p.conns {
		live := conns[:0]
		for _, c := range conns {
			if !c.IsDead() {
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

// replaceDead removes and returns a dead connection from the pool.  Must be
// called with p.mu held; the caller closes it outside the lock.
func (p *RawPool) replaceDead(key string) *RawConn {
	for i, c := range p.conns[key] {
		if !c.IsDead() {
			continue
		}
		p.conns[key] = append(p.conns[key][:i], p.conns[key][i+1:]...)
		if len(p.conns[key]) == 0 {
			delete(p.conns, key)
		}
		p.total--
		return c
	}
	return nil
}

// Remove closes and removes a connection from the pool.
func (p *RawPool) Remove(target *RawConn) {
	p.mu.Lock()
	conns := p.conns[target.addr]
	for i, c := range conns {
		if c != target {
			continue
		}
		p.conns[target.addr] = append(conns[:i], conns[i+1:]...)
		if len(p.conns[target.addr]) == 0 {
			delete(p.conns, target.addr)
		}
		p.total--
		p.mu.Unlock()
		target.close()
		return
	}
	p.mu.Unlock()
}

// Shutdown closes all pooled connections and clears the pool.
func (p *RawPool) Shutdown() {
	p.mu.Lock()
	p.closed = true
	var all []*RawConn
	for _, conns := range p.conns {
		all = append(all, conns...)
	}
	p.conns = make(map[string][]*RawConn)
	p.total = 0
	p.mu.Unlock()

	for _, c := range all {
		c.close()
	}
}
