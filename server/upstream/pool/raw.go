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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
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
		return nil, fmt.Errorf("raw pool: connection to %s is closed", c.addr)
	}

	resultCh := make(chan []byte, 1)
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return nil, fmt.Errorf("raw pool: connection to %s closed before write", c.addr)
	}
	if _, dup := c.inflight[matchKey]; dup {
		c.mu.Unlock()
		// Match-key collision (2^-96 for DNSCrypt nonces, ID reuse for plain
		// DNS after 65536 queries) — fail the new exchange; the caller falls
		// back to a per-query dial.
		return nil, fmt.Errorf("raw pool: match key collision on %s", c.addr)
	}
	c.inflight[matchKey] = &rawPending{resultCh: resultCh}
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inflight, matchKey)
		c.mu.Unlock()
		// Drain an orphaned response that arrived after ctx cancellation.  A
		// nil value marks connection close — nothing to release.
		select {
		case <-resultCh:
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
		return nil, fmt.Errorf("raw pool: write to %s: %w", c.addr, err)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, fmt.Errorf("raw pool: connection to %s closed", c.addr)
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
		body := make([]byte, msgLen)
		if _, err := io.ReadFull(c.conn, body); err != nil {
			return
		}

		key, ok := c.extractKey(body)
		if !ok {
			continue // not a response for any of our exchanges — drop
		}
		// Lookup AND delivery under RLock: close() closes resultChs under the
		// write lock, so a send can never race a closed channel (same
		// discipline as the UDP pool).
		c.mu.RLock()
		p, ok := c.inflight[key]
		if !ok {
			c.mu.RUnlock()
			continue // response for an exchange we no longer track — drop
		}
		select {
		case p.resultCh <- body:
		default:
			// Waiter already gave up (ctx cancelled) — drop.
			_ = body
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
		return nil, fmt.Errorf("raw pool: no available connection to %s", key)
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
			p.conns[key] = liveConns
			p.mu.Unlock()
			return c, nil
		}
		if inFlight := int(c.inFlight.Load()); inFlight < leastCount {
			leastCount = inFlight
			leastLoaded = c
		}
	}
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
		return nil, fmt.Errorf("raw pool: pool shut down for %s", key)
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
			return nil, fmt.Errorf("raw pool: max conns reached for %s", key)
		}
		p.conns[key] = append(p.conns[key], c)
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
// live connections (nothing in flight) oldest first, (3) any live connection
// oldest first.  Must be called with p.mu held; skip is never evicted.  The
// live victim is returned WITHOUT closing — the caller closes it outside
// p.mu (ABBA convention, as in Remove/Shutdown).
func (p *RawPool) evictOne(skip *RawConn) (victim *RawConn, removed bool) {
	// (1) Dead connections cost a slot while waiting for lazy pruning —
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
	// (2)+(3): least-recently-used live connection.  Prefer idle connections
	// — an in-flight eviction costs its waiters a failed exchange; an idle
	// one costs nothing.
	for preferIdle := true; ; preferIdle = false {
		var victimKey string
		var victimIdx int
		oldest := int64(math.MaxInt64)
		for key, conns := range p.conns {
			for i, c := range conns {
				if c == skip || c.IsDead() {
					continue
				}
				if preferIdle && c.inFlight.Load() > 0 {
					continue
				}
				if last := c.lastUsed.Load(); last < oldest {
					oldest = last
					victim, victimKey, victimIdx = c, key, i
				}
			}
		}
		if victim == nil {
			if preferIdle {
				continue // second pass: in-flight connections allowed
			}
			return nil, false
		}
		p.conns[victimKey] = append(p.conns[victimKey][:victimIdx], p.conns[victimKey][victimIdx+1:]...)
		if len(p.conns[victimKey]) == 0 {
			delete(p.conns, victimKey)
		}
		p.total--
		return victim, true
	}
}

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
