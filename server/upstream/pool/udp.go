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
	"zjdns/internal/ipttl"
	"zjdns/internal/log"
)

// collectPacket is one datagram delivered to a collect-mode caller, carrying
// the IP-layer TTL/HopLimit captured by readLoop (0 when unavailable).
// Release must be called exactly once after Data is consumed (the caller
// copies it out — processPacket's copyData — before releasing).
type collectPacket struct {
	Data    []byte
	TTL     uint8
	Release func()
}

// udpPending is one in-flight query awaiting its response.
type udpPending struct {
	resultCh  chan []byte        // raw response payload (ownership transferred)
	collectCh chan collectPacket // buffered multi-packet channel for collect mode
}

// UDPConn is a connected UDP socket shared by concurrent queries.
type UDPConn struct {
	conn      net.Conn
	capture   *ipttl.Capture // TTL/HopLimit capture; nil when unsupported
	addr      string
	writeMu   sync.Mutex
	mu        sync.RWMutex
	inflight  map[string]*udpPending
	capacity  chan struct{}
	inFlight  atomic.Int32
	nextID    atomic.Uint32
	lastUsed  atomic.Int64 // log.NowUnix() of the last query — LRU eviction key
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

// acquirePacketBuf returns a payload buffer of at least n bytes and the
// release func that must be called exactly once after the payload has been
// consumed (read, decrypted, unpacked).
func acquirePacketBuf(n int) (packet []byte, release func()) {
	switch {
	case n <= packetBufSmall:
		bp := packetBufSmallPool.Get().(*[]byte)
		return (*bp)[:n], func() { clear(*bp); packetBufSmallPool.Put(bp) }
	case n <= packetBufMedium:
		bp := packetBufMediumPool.Get().(*[]byte)
		return (*bp)[:n], func() { clear(*bp); packetBufMediumPool.Put(bp) }
	case n <= packetBufLarge:
		bp := packetBufLargePool.Get().(*[]byte)
		return (*bp)[:n], func() { clear(*bp); packetBufLargePool.Put(bp) }
	default:
		b := make([]byte, n)
		return b, func() {}
	}
}

// ReleaseUDPPayload returns a pooled payload buffer to its tier.  Used by
// result-channel consumers that received the raw slice (collect-mode callers
// use collectPacket.release instead).
func ReleaseUDPPayload(packet []byte) { releasePacketBuf(packet) }

// releasePacketBuf returns a pooled payload buffer to its tier, keyed by
// capacity class.  Heap buffers (cap not matching a tier) are left for the GC.
// No clear: the only writer (readLoop's copy) always fills the consumed
// range [0:n] before delivery, and the slice length bounds every reader to
// n — a memset per released packet (up to 16KB on the large tier) was pure
// cost on the loaded-server profile, same reasoning as spillfile's block
// buffers.
func releasePacketBuf(packet []byte) {
	switch cap(packet) {
	case packetBufSmall:
		bp := &packet
		*bp = (*bp)[:packetBufSmall]
		packetBufSmallPool.Put(bp)
	case packetBufMedium:
		bp := &packet
		*bp = (*bp)[:packetBufMedium]
		packetBufMediumPool.Put(bp)
	case packetBufLarge:
		bp := &packet
		*bp = (*bp)[:packetBufLarge]
		packetBufLargePool.Put(bp)
	}
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
		// DNS after 65536 queries) — fail the new query; the caller retries
		// on a fresh connection.
		return nil, ErrKeyCollision
	}
	c.inflight[matchKey] = &udpPending{resultCh: resultCh}
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inflight, matchKey)
		c.mu.Unlock()
		// Drain an orphaned response that arrived after ctx cancellation and
		// return the tiered-pool payload buffer (M9).  A nil value marks
		// connection close — nothing to release.
		select {
		case resp := <-resultCh:
			if resp != nil {
				ReleaseUDPPayload(resp)
			}
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
		return nil, errors.Join(ErrWriteFailed, err)
	}

	// Retransmit the datagram when the silence window expires without a
	// response — a single lost packet otherwise stalls the query until the
	// full context deadline (RFC 1035 §4.2.1).  The retransmit reuses the
	// same tracking ID, so the (possibly duplicate) response still matches
	// the registered in-flight key.
	retransmitTimer := time.NewTimer(config.DefaultUDPRetransmitInterval)
	defer retransmitTimer.Stop()
	retransmits := 0
	for {
		select {
		case resp := <-resultCh:
			if resp == nil {
				return nil, ErrConnClosed
			}
			return resp, nil
		case <-ctx.Done():
			// Only cancel this query, not the connection; the deferred cleanup
			// unlinks the match key and drains a late response.
			return nil, ctx.Err()
		case <-retransmitTimer.C:
			if retransmits >= config.DefaultUDPRetransmitCount {
				// Retransmit budget exhausted — wait out the deadline for a
				// late response (a retry storm on a dead server is worse than
				// the wait).
				select {
				case resp := <-resultCh:
					if resp == nil {
						return nil, ErrConnClosed
					}
					return resp, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			retransmits++
			c.writeMu.Lock()
			_, err = c.conn.Write(payload)
			c.writeMu.Unlock()
			if err != nil {
				c.close()
				return nil, errors.Join(ErrWriteFailed, err)
			}
			retransmitTimer.Reset(config.DefaultUDPRetransmitInterval)
		}
	}
}

// ExchangeCollect is like Exchange but the caller receives every response
// matching matchKey — the inflight entry is NOT deleted after the first
// packet.  The caller must call ReleaseCollect when done to clean up.
// collectCh is buffered at 4 slots (2 EDNS candidates + non-EDNS fallback +
// one overflow); packets beyond that are silently dropped.
func (c *UDPConn) ExchangeCollect(ctx context.Context, payload []byte, matchKey string) (<-chan collectPacket, error) {
	select {
	case c.capacity <- struct{}{}:
		c.inFlight.Add(1)
		c.lastUsed.Store(log.NowUnix())
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if c.closed.Load() {
		c.inFlight.Add(-1)
		<-c.capacity
		return nil, ErrConnClosed
	}

	collectCh := make(chan collectPacket, 4)
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		c.inFlight.Add(-1)
		<-c.capacity
		return nil, ErrConnClosed
	}
	if _, dup := c.inflight[matchKey]; dup {
		c.mu.Unlock()
		c.inFlight.Add(-1)
		<-c.capacity
		return nil, ErrKeyCollision
	}
	c.inflight[matchKey] = &udpPending{collectCh: collectCh}
	c.mu.Unlock()

	// Serialise writes.
	c.writeMu.Lock()
	_, err := c.conn.Write(payload)
	c.writeMu.Unlock()
	if err != nil {
		c.close()
		c.mu.Lock()
		delete(c.inflight, matchKey)
		c.mu.Unlock()
		drainCollectCh(collectCh)
		c.inFlight.Add(-1)
		<-c.capacity
		return nil, errors.Join(ErrWriteFailed, err)
	}
	return collectCh, nil
}

// ReleaseCollect unregisters matchKey, returns the queued collect packets'
// payload buffers to their tier pools, and releases the capacity slot held by
// an ExchangeCollect caller (M8 — without the drain, up to 4 pooled buffers
// were abandoned per collect round).  The entry is removed under the lock
// (H2), so readLoop can no longer deliver to it; draining outside the lock
// cannot race a new delivery.
func (c *UDPConn) ReleaseCollect(matchKey string) {
	c.mu.Lock()
	p := c.inflight[matchKey]
	delete(c.inflight, matchKey)
	c.mu.Unlock()
	if p != nil && p.collectCh != nil {
		drainCollectCh(p.collectCh)
	}
	c.inFlight.Add(-1)
	<-c.capacity
}

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

// readLoop reads datagrams, routes them by the extracted match key and
// transfers buffer ownership to the waiting caller.  Idle connections
// (nothing in flight past idleTimeout) are closed for recycling.
func (c *UDPConn) readLoop() {
	defer zdnsutil.HandlePanic("UDP pool reader")
	defer c.close()

	// Read buffer: 16KB covers every realistic DNS response — DNSSEC-signed
	// referrals rarely exceed 8KB, oversized responses trigger TC and are
	// retried over TCP.  The previous 64KB (max UDP payload) cost 4x the
	// memory per connection, and with recursive resolution holding one
	// connection per authoritative server, the working set scaled badly.
	buf := make([]byte, packetBufLarge) // one allocation per conn

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.idleTimeout))
		var n int
		var ttl uint8
		var err error
		if c.capture != nil {
			n, ttl, err = c.capture.ReadFrom(buf)
			if errors.Is(err, ipttl.ErrNoControlMessage) {
				// Datagram received without TTL metadata — keep the packet,
				// TTL stays 0 (callers treat it as not confident).
				err = nil
			}
		} else {
			n, err = c.conn.Read(buf)
		}
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
		// Lookup AND delivery under RLock: close() closes collectChs under the
		// write lock, so a send can never race a closed channel (H2).
		c.mu.RLock()
		p, ok := c.inflight[key]
		if !ok {
			c.mu.RUnlock()
			continue // response for a query we no longer track — drop
		}

		// Copy the payload out of the read buffer — the waiter decrypts/
		// unpacks asynchronously and owns the returned slice.  The release
		// func travels with the data; result-channel consumers call
		// releasePacketBuf by capacity class (M-3-6).
		packet, release := acquirePacketBuf(n)
		copy(packet, buf[:n])

		// Collect mode: deliver every matching packet; the caller runs a
		// multi-read loop (spoofguard) and calls ReleaseCollect to clean up.
		if p.collectCh != nil {
			select {
			case p.collectCh <- collectPacket{Data: packet, TTL: ttl, Release: release}:
			default:
				// collectCh full (4 candidates already queued) — drop.
				release()
			}
			c.mu.RUnlock()
			continue
		}

		select {
		case p.resultCh <- packet:
		default:
			// Waiter already gave up (ctx cancelled) — drop.
			release()
		}
		c.mu.RUnlock()
	}
}

// close terminates the connection and wakes all waiters with nil.
func (c *UDPConn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.conn.Close()
		c.mu.Lock()
		for _, p := range c.inflight {
			if p.collectCh != nil {
				// Collect-mode waiters block on collectCh — closing it wakes
				// them (the !ok branch in executeUDPCollect).  Previously
				// they were never signalled and burned the full query
				// budget on a dead socket (M-3-6).
				close(p.collectCh)
			} else {
				select {
				case p.resultCh <- nil:
				default:
				}
			}
		}
		c.inflight = make(map[string]*udpPending)
		c.mu.Unlock()
	})
}

// IsDead reports whether the connection has been closed.
func (c *UDPConn) IsDead() bool { return c.closed.Load() }

// Capture returns the TTL/HopLimit capture wrapper, or nil when the platform
// or socket type does not support control-message reads.
func (c *UDPConn) Capture() *ipttl.Capture { return c.capture }

// IsFull reports whether the connection has reached its in-flight cap.
func (c *UDPConn) IsFull() bool { return c.inFlight.Load() >= c.maxPipe }

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
			p.conns[key] = liveConns
			p.mu.Unlock()
			return c, nil
		}
		if inFlight < leastCount {
			leastCount = inFlight
			leastLoaded = c
		}
	}
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
