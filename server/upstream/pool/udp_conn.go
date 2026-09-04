// UDPConn: one connected UDP socket shared by pipelined queries — the
// exchange paths (plain and spoofguard multi-read collect), the read loop,
// and the packet buffer pool.

package pool

import (
	"context"
	"errors"
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
