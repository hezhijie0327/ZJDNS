// Package pool — UDP socket reuse.
//
// UDPConn multiplexes many in-flight queries over one connected UDP socket,
// demultiplexing responses by a per-protocol match key (plain DNS: the message
// ID; DNSCrypt: the client-nonce prefix echoed in the response header).  This
// amortises the per-query socket()/connect()/close() syscall churn that
// dominated the outbound UDP hot path.  RFC 5452 source-port randomisation is
// preserved by the pool: multiple sockets per upstream, each with its own
// ephemeral port, chosen round-robin via least-loaded.
//
// Cross-talk safety is layered: the read loop routes by the extracted match
// key, and every waiting caller re-verifies the payload it receives (plain:
// response ID + question; DNSCrypt: nonce half + decryption + message ID), so
// a misrouted or injected datagram can never be served as another query's
// response.
package pool

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

// udpPending is one in-flight query awaiting its response.
type udpPending struct {
	resultCh chan []byte // raw response payload (ownership transferred)
}

// UDPConn is a connected UDP socket shared by concurrent queries.
type UDPConn struct {
	conn      net.Conn
	addr      string
	writeMu   sync.Mutex
	mu        sync.RWMutex
	inflight  map[string]*udpPending
	capacity  chan struct{}
	inFlight  atomic.Int32
	nextID    atomic.Uint32
	maxPipe   int32
	closed    atomic.Bool
	closeOnce sync.Once

	extractKey  func(payload []byte) (string, bool) // response → match key
	idleTimeout time.Duration
}

// UDPPool manages a set of reusable UDP sockets per upstream key.
type UDPPool struct {
	mu         sync.Mutex
	conns      map[string][]*UDPConn
	dialing    map[string]int
	maxConns   int
	maxPipe    int
	closed     bool
	extractKey func(payload []byte) (string, bool)
}

// NextID returns the next DNS message ID for this connection, skipping 0.
// Plain-DNS callers rewrite their query ID to it, making in-flight IDs unique
// per socket (response demultiplexing key).
func (c *UDPConn) NextID() uint16 {
	id := uint16(c.nextID.Add(1)) //nolint:gosec // G115: intentional wraparound of the DNS ID space
	for id == 0 {
		id = uint16(c.nextID.Add(1)) //nolint:gosec // G115: intentional wraparound of the DNS ID space
	}
	return id
}

// Exchange sends payload and waits for the response whose extracted match key
// equals matchKey.  The returned slice is owned by the caller.
func (c *UDPConn) Exchange(ctx context.Context, payload []byte, matchKey string) ([]byte, error) {
	select {
	case c.capacity <- struct{}{}:
		c.inFlight.Add(1)
		defer func() {
			c.inFlight.Add(-1)
			<-c.capacity
		}()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if c.closed.Load() {
		return nil, fmt.Errorf("udp client: connection to %s is closed", c.addr)
	}

	resultCh := make(chan []byte, 1)
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return nil, fmt.Errorf("udp client: connection to %s closed before write", c.addr)
	}
	if _, dup := c.inflight[matchKey]; dup {
		c.mu.Unlock()
		// Match-key collision (2^-96 for DNSCrypt nonces, ID reuse for plain
		// DNS after 65536 queries) — fail the new query; the caller retries
		// on a fresh connection.
		return nil, fmt.Errorf("udp client: match key collision on %s", c.addr)
	}
	c.inflight[matchKey] = &udpPending{resultCh: resultCh}
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inflight, matchKey)
		c.mu.Unlock()
		// Drain an orphaned response that arrived after ctx cancellation.
		// The payload is a plain allocation (readLoop copies it out of its
		// read buffer) — dropping it lets the GC reclaim it.
		select {
		case <-resultCh:
		default:
		}
	}()

	// Serialise writes: UDP datagrams are atomic, but concurrent Write calls
	// on one socket must not interleave (kernel treats each Write as one
	// datagram, yet the Go netpoll path is only safe under serialisation).
	c.writeMu.Lock()
	_, err := c.conn.Write(payload)
	c.writeMu.Unlock()
	if err != nil {
		c.close()
		return nil, fmt.Errorf("udp client: write to %s: %w", c.addr, err)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, fmt.Errorf("udp client: connection to %s closed", c.addr)
		}
		return resp, nil
	case <-ctx.Done():
		// Only cancel this query, not the connection; the deferred cleanup
		// unlinks the match key and drains a late response.
		return nil, ctx.Err()
	}
}

// readLoop reads datagrams, routes them by the extracted match key and
// transfers buffer ownership to the waiting caller.  Idle connections
// (nothing in flight past idleTimeout) are closed for recycling.
func (c *UDPConn) readLoop() {
	defer zdnsutil.HandlePanic("UDP pool reader")
	defer c.close()

	buf := make([]byte, 65535) // max UDP payload; one allocation per conn

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
		n, err := c.conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				c.mu.RLock()
				idle := len(c.inflight) == 0
				c.mu.RUnlock()
				if idle {
					return // recycle: the pool redials on demand
				}
				continue // queries still in flight — keep waiting
			}
			return
		}

		key, ok := c.extractKey(buf[:n])
		if !ok {
			continue // not a response for any of our queries — drop
		}
		c.mu.RLock()
		p, ok := c.inflight[key]
		c.mu.RUnlock()
		if !ok {
			continue // response for a query we no longer track — drop
		}

		// Copy the payload out of the read buffer — the waiter decrypts/
		// unpacks asynchronously and owns the returned slice.
		packet := make([]byte, n)
		copy(packet, buf[:n])
		select {
		case p.resultCh <- packet:
		default:
			// Waiter already gave up (ctx cancelled) — drop.
		}
	}
}

// close terminates the connection and wakes all waiters with nil.
func (c *UDPConn) close() {
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
		c.inflight = make(map[string]*udpPending)
		c.mu.Unlock()
	})
}

// IsDead reports whether the connection has been closed.
func (c *UDPConn) IsDead() bool { return c.closed.Load() }

// IsFull reports whether the connection has reached its in-flight cap.
func (c *UDPConn) IsFull() bool { return c.inFlight.Load() >= c.maxPipe }

// NewUDPPool creates a UDPPool.  extractKey derives a response's match key
// from its raw payload.
func NewUDPPool(maxConns, maxPipe int, extractKey func(payload []byte) (string, bool)) *UDPPool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	return &UDPPool{
		conns:      make(map[string][]*UDPConn),
		dialing:    make(map[string]int),
		maxConns:   maxConns,
		maxPipe:    maxPipe,
		extractKey: extractKey,
	}
}

// Acquire gets a reusable UDP socket, dialing a new one if needed.
func (p *UDPPool) Acquire(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*UDPConn, error) {
	p.mu.Lock()
	conns := p.conns[key]

	if len(conns) == 0 {
		if p.dialing[key] < p.maxConns {
			return p.dialAndAdd(ctx, key, dialAddr, dialFunc)
		}
		p.mu.Unlock()
		return nil, fmt.Errorf("udp client: no available socket to %s", key)
	}

	liveConns := make([]*UDPConn, 0, len(conns))
	var leastLoaded *UDPConn
	leastCount := math.MaxInt
	for i, c := range conns {
		if c.IsDead() {
			continue
		}
		liveConns = append(liveConns, c)
		inFlight := int(c.inFlight.Load())
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
		if inFlight < leastCount {
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
	return nil, fmt.Errorf("udp client: no available socket to %s", key)
}

// dialAndAdd dials a new socket and adds it to the pool.  Must be called with
// p.mu held; releases and re-acquires the lock during dial.
func (p *UDPPool) dialAndAdd(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*UDPConn, error) {
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
		return nil, fmt.Errorf("udp client: pool shut down for %s", key)
	}
	if dialErr != nil {
		p.mu.Unlock()
		return nil, fmt.Errorf("udp client: dial %s: %w", key, dialErr)
	}

	c := &UDPConn{
		conn:        conn,
		addr:        key,
		inflight:    make(map[string]*udpPending),
		capacity:    make(chan struct{}, p.maxPipe),
		maxPipe:     int32(p.maxPipe), //nolint:gosec // G115: bounded by DefaultMaxPipe (16)
		extractKey:  p.extractKey,
		idleTimeout: config.DefaultTCPPoolIdleTimeout,
	}
	go c.readLoop()

	if len(p.conns[key]) >= p.maxConns {
		old := p.replaceDead(key)
		if old == nil {
			p.mu.Unlock()
			c.close()
			log.Debugf("UDPPOOL: pool for %s already at limit (%d), discarding extra socket", key, p.maxConns)
			return nil, fmt.Errorf("udp client: max conns reached for %s", key)
		}
		p.conns[key] = append(p.conns[key], c)
		p.mu.Unlock()
		old.close()
		return c, nil
	}

	p.conns[key] = append(p.conns[key], c)
	p.mu.Unlock()
	log.Debugf("UDPPOOL: dialed new socket to %s (pool=%d/%d)", key, len(p.conns[key]), p.maxConns)
	return c, nil
}

// replaceDead removes and returns a dead socket from the pool.  Must be called
// with p.mu held; the caller closes it outside the lock.
func (p *UDPPool) replaceDead(key string) *UDPConn {
	for i, c := range p.conns[key] {
		if !c.IsDead() {
			continue
		}
		p.conns[key] = append(p.conns[key][:i], p.conns[key][i+1:]...)
		if len(p.conns[key]) == 0 {
			delete(p.conns, key)
		}
		return c
	}
	return nil
}

// Remove closes and removes a socket from the pool.
func (p *UDPPool) Remove(target *UDPConn) {
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
		p.mu.Unlock()
		target.close()
		return
	}
	p.mu.Unlock()
}

// Shutdown closes all pooled sockets and clears the pool.
func (p *UDPPool) Shutdown() {
	p.mu.Lock()
	p.closed = true
	var all []*UDPConn
	for _, conns := range p.conns {
		all = append(all, conns...)
	}
	p.conns = make(map[string][]*UDPConn)
	p.mu.Unlock()

	for _, c := range all {
		c.close()
	}
}
