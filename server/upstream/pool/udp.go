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
	"fmt"
	"math"
	"net"
	"sync"
	"zjdns/config"
	"zjdns/internal/ipttl"
	"zjdns/internal/log"
)

// UDPPool manages a set of reusable UDP sockets per upstream key.
type UDPPool struct {
	mu         sync.Mutex
	conns      map[string][]*UDPConn
	dialing    map[string]int
	maxConns   int
	maxPipe    int
	maxTotal   int // global cap on live sockets across all keys (0 = unlimited)
	total      int // live sockets currently tracked in conns
	closed     bool
	extractKey func(payload []byte) (string, bool)
}

// Tiered payload-buffer pools for the pooled-UDP read loop: the per-response
// make([]byte, n) allocation on the hot path (every plain-UDP, DNSCrypt and
// raw-framed response) is replaced with a size-classed pool (M-3-6).
const (
	packetBufSmall  = 512   // typical A/AAAA responses
	packetBufMedium = 1500  // Ethernet MTU
	packetBufLarge  = 16384 // DNSSEC responses and DNSCrypt frames — matches the read buffer
)

var (
	packetBufSmallPool  = sync.Pool{New: func() any { b := make([]byte, packetBufSmall); return &b }}
	packetBufMediumPool = sync.Pool{New: func() any { b := make([]byte, packetBufMedium); return &b }}
	packetBufLargePool  = sync.Pool{New: func() any { b := make([]byte, packetBufLarge); return &b }}
)

// drainCollectCh empties a collect channel without blocking, returning each
// queued payload buffer to its tier pool (M-3-6).
func drainCollectCh(ch <-chan collectPacket) {
	for {
		select {
		case pkt, ok := <-ch:
			if !ok {
				// Closed (the conn died): a non-blocking receive on a closed
				// channel is always ready, so without this check the loop
				// spun forever on zero-value packets — one 100% core per
				// dead connection.
				return
			}
			if pkt.Release != nil {
				pkt.Release()
			}
		default:
			return
		}
	}
}

// NewUDPPool creates a UDPPool.  maxTotal caps the live socket count across
// all keys (0 = unlimited).  extractKey derives a response's match key from
// its raw payload.
func NewUDPPool(maxConns, maxPipe, maxTotal int, extractKey func(payload []byte) (string, bool)) *UDPPool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	if maxTotal <= 0 {
		maxTotal = config.DefaultMaxPoolTotalConns
	}
	return &UDPPool{
		conns:      make(map[string][]*UDPConn),
		dialing:    make(map[string]int),
		maxConns:   maxConns,
		maxPipe:    maxPipe,
		maxTotal:   maxTotal,
		extractKey: extractKey,
	}
}

// Acquire gets a reusable UDP socket, dialing a new one if needed.  wantTTL
// requests IP TTL/HopLimit capture on freshly dialed sockets (hopguard);
// sockets dialed without it serve TTL-less reads (callers treat TTL 0 as
// "not confident"), which avoids the ipttl setup — and its per-packet
// control-message cost — for upstreams that never consume TTL.
func (p *UDPPool) Acquire(ctx context.Context, key, dialAddr string, wantTTL bool, dialFunc func(context.Context, string) (net.Conn, error)) (*UDPConn, error) {
	p.mu.Lock()
	conns := p.conns[key]

	if len(conns) == 0 {
		if p.dialing[key] < p.maxConns {
			return p.dialAndAdd(ctx, key, dialAddr, wantTTL, dialFunc)
		}
		p.mu.Unlock()
		return nil, ErrNoAvailableSocket
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
			p.total -= len(conns) - len(liveConns) // dead-filter accounting (U1)
			p.conns[key] = liveConns
			p.mu.Unlock()
			return c, nil
		}
		if inFlight < leastCount {
			leastCount = inFlight
			leastLoaded = c
		}
	}
	p.total -= len(conns) - len(liveConns) // dead-filter accounting (U1)
	if len(liveConns) == 0 {
		delete(p.conns, key)
	} else {
		p.conns[key] = liveConns
	}

	if len(liveConns)+p.dialing[key] < p.maxConns {
		c, err := p.dialAndAdd(ctx, key, dialAddr, wantTTL, dialFunc)
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
func (p *UDPPool) dialAndAdd(ctx context.Context, key, dialAddr string, wantTTL bool, dialFunc func(context.Context, string) (net.Conn, error)) (*UDPConn, error) {
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
		return nil, fmt.Errorf("udp client: dial %s: %w", key, dialErr)
	}

	// TTL/HopLimit capture for the read loop — only when the caller asked
	// for it (hopguard upstreams).  ipttl.New is a one-time socket setup with
	// a per-read control-message cost, so sockets for upstreams that never
	// consume TTL skip it entirely.  nil on platforms without control-message
	// support (e.g. Windows) or non-UDP sockets.
	var capture *ipttl.Capture
	if wantTTL {
		if udpConn, ok := conn.(*net.UDPConn); ok {
			capture = ipttl.New(udpConn)
		}
	}

	c := &UDPConn{
		conn:        conn,
		capture:     capture,
		addr:        key,
		inflight:    make(map[string]*udpPending),
		capacity:    make(chan struct{}, p.maxPipe),
		maxPipe:     int32(p.maxPipe), //nolint:gosec // G115: bounded by DefaultMaxPipe (16)
		extractKey:  p.extractKey,
		idleTimeout: config.DefaultUDPPoolIdleTimeout,
	}
	c.lastUsed.Store(log.NowUnix())
	go c.readLoop()

	if len(p.conns[key]) >= p.maxConns {
		old := p.replaceDead(key)
		if old == nil {
			p.mu.Unlock()
			c.close()
			log.Debugf("UDPPOOL: pool for %s already at limit (%d), discarding extra socket", key, p.maxConns)
			return nil, ErrMaxConnsReached
		}
		p.conns[key] = append(p.conns[key], c)
		p.total++ // replaceDead decremented for the dead one — net-zero swap (U2)
		p.mu.Unlock()
		old.close()
		return c, nil
	}

	p.conns[key] = append(p.conns[key], c)
	p.total++
	// Global cap (H1): a flood of distinct authoritative NS addresses must
	// not grow the socket working set without bound.  Evict sockets to make
	// room — dead ones first, then the least-recently-used — and close them
	// after unlocking (ABBA convention, as in Remove/Shutdown).
	var evicted []*UDPConn
	for p.total > p.maxTotal {
		victim, removed := p.evictOne(c)
		if !removed {
			break // nothing evictable — the new socket stays
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
		log.Debugf("UDPPOOL: evicted %s for capacity (total=%d/%d)", v.addr, total, p.maxTotal)
	}
	log.Debugf("UDPPOOL: dialed new socket to %s (pool=%d/%d, total=%d/%d)", key, n, p.maxConns, total, p.maxTotal)
	return c, nil
}

// evictOne removes one socket from the pool to make room for a new dial,
// preferring (1) dead sockets awaiting the periodic ReapDead sweep (already
// closed — nil victim), (2) idle live sockets (nothing in flight) oldest
// first.  In-flight sockets are NEVER evicted: killing a busy socket fails
// every query waiting on it, and the callers fall through to per-query dials
// that re-enter the pool — a self-reinforcing dial/evict churn loop under
// saturation (the remote pprof finding that drove this soft-cap).  When
// every socket is busy the pool overshoots maxTotal transiently; idle
// sockets self-close via the read-loop idle timeout and ReapDead reclaims
// their slots.  Must be called with p.mu held; skip is never evicted.  The
// live victim is returned WITHOUT closing — the caller closes it outside
// p.mu (ABBA convention, as in Remove/Shutdown).
func (p *UDPPool) evictOne(skip *UDPConn) (victim *UDPConn, removed bool) {
	// (1) Dead sockets cost a slot while waiting for ReapDead — drop them
	// without closing anything (their readLoop already closed the conn).
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
	// (2): least-recently-used idle socket — an in-flight eviction costs its
	// waiters a failed query; an idle one costs nothing.
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
		return nil, false // only busy sockets left — soft-cap overshoot
	}
	p.conns[victimKey] = append(p.conns[victimKey][:victimIdx], p.conns[victimKey][victimIdx+1:]...)
	if len(p.conns[victimKey]) == 0 {
		delete(p.conns, victimKey)
	}
	p.total--
	return victim, true
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
		p.total--
		return c
	}
	return nil
}

// ReapDead drops dead connections from every pool key and deletes keys with
// no live connections left.  Called periodically by the server — a socket
// idle-recycled by its readLoop otherwise stays pinned under its address key
// until that address is queried again, and the key space itself grows with
// every distinct authoritative NS address ever seen (H1).
func (p *UDPPool) ReapDead() {
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
		p.total--
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
	p.total = 0
	p.mu.Unlock()

	for _, c := range all {
		c.close()
	}
}
