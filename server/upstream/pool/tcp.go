// Package pool provides RFC 7766 pipelined TCP/DoT and QUIC connection pools
// for multiplexed outbound DNS queries.
package pool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"

	zpool "zjdns/internal/pool"
)

type pending struct {
	resultCh chan *dns.Msg
	qname    string // RFC 7766 §7: verify response matches query
	qtype    uint16
	qclass   uint16
}

// Conn is a pipelined TCP connection that multiplexes multiple in-flight
// queries.
type Conn struct {
	conn      net.Conn
	addr      string
	writeMu   sync.Mutex
	mu        sync.RWMutex
	inflight  map[uint16]*pending
	nextID    atomic.Uint32
	lastUsed  atomic.Int64 // log.NowUnix() of the last query — LRU eviction key
	capacity  chan struct{}
	inFlight  atomic.Int32
	maxPipe   int32
	closed    atomic.Bool
	closeOnce sync.Once

	segmentSize int // 0 = no segmentation
}

// Pool manages a set of pipelined TCP connections per upstream server key.
type ConnPool struct {
	mu       sync.Mutex
	conns    map[string][]*Conn
	dialing  map[string]int
	maxConns int
	maxPipe  int
	maxTotal int // global cap on live connections across all keys (0 = unlimited)
	total    int // live connections currently tracked in conns
	closed   bool
}

const dnsIDMask = 0xFFFF // 16-bit DNS message ID space

func newConn(addr string, conn net.Conn, maxPipe int) *Conn {
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	// Enable TCP keep-alive to detect dead connections without relying
	// solely on the read deadline, and to keep NAT/firewall bindings alive
	// during idle periods.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
		_ = tcpConn.SetNoDelay(true) // disable Nagle for splitguard small-segment writes
	}
	c := &Conn{
		conn:     conn,
		addr:     addr,
		inflight: make(map[uint16]*pending),
		capacity: make(chan struct{}, maxPipe),
		maxPipe:  int32(maxPipe),

		segmentSize: 0,
	}
	c.lastUsed.Store(log.NowUnix())
	c.nextID.Store(rand.Uint32()) //nolint:gosec // G404: DNS message ID — not cryptographic
	go c.readLoop()
	return c
}

// SetSegmentation configures TCP DNS message segmentation for this connection.
// segSize=0 disables segmentation (normal Write).
func (c *Conn) SetSegmentation(segSize int) {
	c.writeMu.Lock()
	c.segmentSize = segSize
	c.writeMu.Unlock()
}

// Exchange sends a DNS message over the pipelined connection and waits for
// its matching response, keyed by the query ID. The connection is shared:
// concurrent Exchanges on the same Conn are multiplexed (RFC 7766 §7).
func (c *Conn) Exchange(ctx context.Context, msg *dns.Msg) (response *dns.Msg, err error) {
	if msg == nil {
		return nil, errors.New("client: nil query message")
	}
	// msg.ID was rewritten to a tracking ID and Pack() captured it in
	// msg.Data.  On failure the caller falls back to a transport that
	// reuses msg.Data without re-Packing (miekg's Exchange) — a stale
	// tracking-ID wire would then be sent under the restored original
	// msg.ID, and the response check fails with an ID mismatch.  Drop the
	// stale wire so the fallback re-Packs with the true msg.ID.
	defer func() {
		if err != nil {
			msg.Data = nil
		}
	}()
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

	originalID := msg.ID
	trackingID := uint16(c.nextID.Add(1) & dnsIDMask)
	msg.ID = trackingID

	err = msg.Pack()
	msgData := msg.Data
	msg.ID = originalID
	if err != nil {
		return nil, fmt.Errorf("client: pack: %w", err)
	}

	poolBuf := zpool.DefaultBuffer.Get()
	defer zpool.DefaultBuffer.Put(poolBuf)
	writeBuf := poolBuf
	if len(poolBuf) < zdnsutil.DNSFramePrefixLen+len(msgData) {
		writeBuf = make([]byte, zdnsutil.DNSFramePrefixLen+len(msgData))
	}
	writeBuf = writeBuf[:zdnsutil.DNSFramePrefixLen+len(msgData)]
	binary.BigEndian.PutUint16(writeBuf[:zdnsutil.DNSFramePrefixLen], uint16(len(msgData))) //nolint:gosec // G115: DNS length prefix — max 65535 fits uint16
	copy(writeBuf[zdnsutil.DNSFramePrefixLen:], msgData)

	// Safety assertion checked before taking the lock: writeBuf was sized as
	// DNSFramePrefixLen+len(msgData) and any valid DNS message after Pack()
	// has at least 12 bytes (the DNS header), so this is never reached in
	// practice. It must not return while holding c.mu — that would deadlock
	// every subsequent Exchange on this connection.
	if len(writeBuf) < zdnsutil.DNSFramePrefixLen+2 {
		return nil, fmt.Errorf("client: writeBuf too small for trackingID update: %d bytes", len(writeBuf))
	}

	resultCh := make(chan *dns.Msg, 1)
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return nil, ErrConnClosed
	}
	// Detect trackingID collision after wrap-around (every 65536 queries).
	// Advance past any in-flight ID to avoid orphaning the old query.
	// Iteration limit is bounded: at most maxPipe in-flight IDs exist,
	// so the loop will find a free slot within at most maxPipe iterations.
	origTrackingID := trackingID
	for c.inflight[trackingID] != nil {
		trackingID = uint16(c.nextID.Add(1) & dnsIDMask)
	}
	if trackingID != origTrackingID {
		binary.BigEndian.PutUint16(writeBuf[zdnsutil.DNSFramePrefixLen:zdnsutil.DNSFramePrefixLen+2], trackingID)
	}
	c.inflight[trackingID] = &pending{resultCh: resultCh}
	// RFC 7766 §7: store question to verify response matches.
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		c.inflight[trackingID].qname = q.Header().Name
		c.inflight[trackingID].qtype = dns.RRToType(q)
		c.inflight[trackingID].qclass = q.Header().Class
	}
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		if c.inflight != nil {
			delete(c.inflight, trackingID)
		}
		c.mu.Unlock()
		// Drain orphaned response that may have arrived after ctx cancellation.
		select {
		case orphan := <-resultCh:
			if orphan != nil {
				zpool.DefaultMessage.Put(orphan)
			}
		default:
		}
	}()

	// Bound the write: a stalled peer with a full receive window blocks the
	// write (and, behind writeMu, every queued query on this connection)
	// until the readLoop's 60s idle timeout closes it. The deadline set and
	// zero-restore live INSIDE the writeMu critical section: a concurrent
	// Exchange must not have its deadline wiped by another's deferred
	// restore while it is still writing (R3-M5) — serialized under the lock
	// each exchange sets, writes, and clears its own deadline in turn.
	c.writeMu.Lock()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetWriteDeadline(deadline)
	}
	_, writeErr := zdnsutil.WriteTCPMsgSegmented(c.conn, writeBuf, c.segmentSize)
	_ = c.conn.SetWriteDeadline(time.Time{})
	c.writeMu.Unlock()
	if writeErr != nil {
		c.close()
		return nil, errors.Join(ErrWriteFailed, writeErr)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, ErrConnClosed
		}
		resp.ID = originalID
		return resp, nil
	case <-ctx.Done():
		// Only cancel this query, not the connection.
		// The deferred cleanup unlinks trackingID; late
		// responses are discarded by readLoop's default branch.
		return nil, ctx.Err()
	}
}

func (c *Conn) readLoop() {
	defer zdnsutil.HandlePanic("client reader")
	defer c.close()

	var lengthBuf [zdnsutil.DNSFramePrefixLen]byte

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

		if _, err := io.ReadFull(c.conn, lengthBuf[:]); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debugf("TCPPOOL: read length error from %s: %v", c.addr, err)
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf[:])
		if msgLen == 0 {
			log.Debugf("TCPPOOL: invalid message length %d from %s", msgLen, c.addr)
			return
		}

		bodyBuf := zpool.DefaultBuffer.Get()
		var body []byte
		pooled := int(msgLen) <= len(bodyBuf)
		if pooled {
			body = bodyBuf[:msgLen]
		} else {
			zpool.DefaultBuffer.Put(bodyBuf)
			body = make([]byte, msgLen)
		}
		if _, err := io.ReadFull(c.conn, body); err != nil {
			if pooled {
				zpool.DefaultBuffer.Put(bodyBuf)
			}
			log.Debugf("TCPPOOL: read body error from %s: %v", c.addr, err)
			return
		}

		resp := zpool.DefaultMessage.Get()
		resp.Data = body
		if err := resp.Unpack(); err != nil {
			if pooled {
				zpool.DefaultBuffer.Put(bodyBuf)
			}
			log.Debugf("TCPPOOL: unpack error from %s: %v", c.addr, err)
			resp.Data = nil
			zpool.DefaultMessage.Put(resp)
			continue
		}
		// Detach resp.Data from the pooled buffer before returning it,
		// otherwise the message carries a dangling pointer to zeroed memory.
		// NOTE(L15): resp.Data=nil before buffer Put relies on miekg/dns copy-based
		// Unpack. A future zero-copy parser would corrupt pooled responses.
		resp.Data = nil
		if pooled {
			zpool.DefaultBuffer.Put(bodyBuf)
		}

		c.mu.RLock()
		pq, ok := c.inflight[resp.ID]
		c.mu.RUnlock()
		// RFC 7766 §7: verify response question matches the query.
		if ok && len(resp.Question) > 0 {
			rq := resp.Question[0]
			if !dns.EqualName(rq.Header().Name, pq.qname) || dns.RRToType(rq) != pq.qtype || rq.Header().Class != pq.qclass {
				ok = false
			}
		}
		if ok {
			// Re-verify the pending is still registered and deliver UNDER
			// the RLock: Exchange's deferred cleanup (ctx cancellation)
			// deletes+drains under the write lock, so holding the RLock
			// across the (non-blocking, buffered) send makes verify+deliver
			// atomic — a late response can no longer land on a purged
			// channel and leak a pooled *dns.Msg.
			c.mu.RLock()
			pq2, still := c.inflight[resp.ID]
			if !still || pq2 != pq {
				c.mu.RUnlock()
				zpool.DefaultMessage.Put(resp)
			} else {
				select {
				case pq.resultCh <- resp:
				default:
					zpool.DefaultMessage.Put(resp)
				}
				c.mu.RUnlock()
			}
		} else {
			resp.Data = nil
			zpool.DefaultMessage.Put(resp)
		}
	}
}

func (c *Conn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.conn.Close()

		c.mu.Lock()
		for _, pq := range c.inflight {
			select {
			case pq.resultCh <- nil:
			default:
			}
		}
		c.inflight = make(map[uint16]*pending)
		c.mu.Unlock()
	})
}

// IsFull reports whether the connection has reached its maximum in-flight
// query capacity. Uses an atomic counter to avoid the racy len(channel) call.
func (c *Conn) IsFull() bool {
	return c.inFlight.Load() >= c.maxPipe
}

// IsDead reports whether the connection has been closed.
func (c *Conn) IsDead() bool {
	return c.closed.Load()
}

// NewConnPool creates a ConnPool with the specified connection and in-flight
// limits (RFC 7766 pipelining).  maxTotal caps the live connection count
// across all keys (0 = unlimited).
func NewConnPool(maxConns, maxPipe, maxTotal int) *ConnPool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	if maxTotal <= 0 {
		maxTotal = config.DefaultMaxPoolTotalConns
	}
	return &ConnPool{
		conns:    make(map[string][]*Conn),
		dialing:  make(map[string]int),
		maxConns: maxConns,
		maxPipe:  maxPipe,
		maxTotal: maxTotal,
	}
}

// Acquire gets a reusable pipelined connection, dialing a new one if needed.
func (p *ConnPool) Acquire(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*Conn, error) {
	p.mu.Lock()
	conns := p.conns[key]

	// When no connections exist yet, skip the allocation and scan entirely.
	if len(conns) == 0 {
		if p.dialing[key] < p.maxConns {
			return p.dialAndAdd(ctx, key, dialAddr, dialFunc)
		}
		p.mu.Unlock()
		return nil, ErrNoAvailableSocket
	}

	// Single pass: filter dead connections and find a non-full candidate.
	// Pool sizes are small (DefaultMaxConns=4) so the allocation is negligible.
	liveConns := make([]*Conn, 0, len(conns))
	var leastLoaded *Conn
	leastCount := math.MaxInt
	for i, c := range conns {
		if c.IsDead() {
			continue
		}
		liveConns = append(liveConns, c)
		inFlight := int(c.inFlight.Load())
		if !c.IsFull() {
			// Append remaining alive connections from conns[i+1:]
			// to prevent leaking tracked connections and their
			// readLoop goroutines.
			for j := i + 1; j < len(conns); j++ {
				if !conns[j].IsDead() {
					liveConns = append(liveConns, conns[j])
				}
			}
			p.total -= len(conns) - len(liveConns) // dead-filter accounting (U1)
			p.conns[key] = liveConns
			p.mu.Unlock()
			// TOCTOU: readLoop may close c after Unlock.  Benign — Exchange
			// detects it via closed.Load() and the caller retries.
			return c, nil
		}
		if inFlight < leastCount {
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
	return nil, fmt.Errorf("client: no available connection to %s", key)
}

// WarmUp dials a new connection and adds it to the pool without returning it.
// This is used to pre-establish connections (e.g. TLS handshakes) so the first
// real query doesn't pay the dial latency.  When the pool is at capacity the
// call is a no-op — dead connections are replaced lazily by Acquire's live
// scan, not here (R3-L15).
func (p *ConnPool) WarmUp(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) error {
	p.mu.Lock()
	if len(p.conns[key]) >= p.maxConns {
		p.mu.Unlock()
		return nil // pool already full, don't bother
	}
	_, err := p.dialAndAdd(ctx, key, dialAddr, dialFunc)
	return err
}

// dialAndAdd dials a new connection and adds it to the pool. Returns the new
// connection or the least-loaded existing one if the pool filled during dial.
// Must be called with p.mu held; releases and re-acquires the lock during dial.
func (p *ConnPool) dialAndAdd(ctx context.Context, key, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*Conn, error) {
	p.dialing[key]++
	p.mu.Unlock()

	conn, dialErr := dialFunc(ctx, dialAddr)

	p.mu.Lock()
	p.dialing[key]--
	if p.dialing[key] == 0 {
		delete(p.dialing, key)
	}
	// Pool was shut down while we were dialing — discard the connection.
	if p.closed {
		p.mu.Unlock()
		if dialErr == nil {
			_ = conn.Close()
		}
		return nil, ErrPoolShutdown
	}
	if dialErr != nil {
		p.mu.Unlock()
		return nil, fmt.Errorf("client: dial %s: %w", key, dialErr)
	}

	c := newConn(key, conn, p.maxPipe)

	// Pool already at capacity — try evicting a dead connection.
	if len(p.conns[key]) >= p.maxConns {
		old := p.replaceDead(key)
		if old == nil {
			p.mu.Unlock()
			c.close()
			log.Debugf("TCPPOOL: pool for %s already at limit (%d), discarding extra connection", key, p.maxConns)
			return nil, ErrMaxConnsReached
		}
		p.conns[key] = append(p.conns[key], c)
		p.total++ // replaceDead decremented for the dead one — net-zero swap (U2)
		n := len(p.conns[key])
		p.mu.Unlock()
		old.close()
		log.Debugf("TCPPOOL: dialed new connection to %s (pool=%d/%d)", key, n, p.maxConns)
		return c, nil
	}

	p.conns[key] = append(p.conns[key], c)
	p.total++
	// Global cap (H1): a flood of distinct upstream keys (recursive TCP
	// fallbacks, forced-TCP configs) must not grow the connection working
	// set without bound.  Evict connections to make room — dead ones first,
	// then the least-recently-used — and close them after unlocking (ABBA
	// convention, as in Remove/Shutdown).
	var evicted []*Conn
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
		log.Debugf("TCPPOOL: evicted %s for capacity (total=%d/%d)", v.addr, total, p.maxTotal)
	}
	log.Debugf("TCPPOOL: dialed new connection to %s (pool=%d/%d, total=%d/%d)", key, n, p.maxConns, total, p.maxTotal)
	return c, nil
}

// evictOne removes one connection from the pool to make room for a new dial,
// preferring (1) dead connections (already closed — nil victim), (2) idle
// live connections (nothing in flight) oldest first.  In-flight connections
// are NEVER evicted: killing a busy connection fails every query waiting on
// it, and the callers fall through to per-query dials that re-enter the pool
// — a self-reinforcing dial/evict churn loop under saturation (the remote
// pprof finding that drove this soft-cap).  When every connection is busy
// the pool overshoots maxTotal transiently; idle connections self-close via
// the read-loop idle timeout and ReapDead reclaims their slots.  Must be
// called with p.mu held; skip is never evicted.  The live victim is returned
// WITHOUT closing — the caller closes it outside p.mu (ABBA convention, as
// in Remove/Shutdown).
func (p *ConnPool) evictOne(skip *Conn) (victim *Conn, removed bool) {
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
	// its waiters a failed query; an idle one costs nothing.
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
func (p *ConnPool) ReapDead() {
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

// replaceDead removes and returns a dead connection from the pool.
// Returns nil if no dead connection exists. Must be called with p.mu held.
// The caller is responsible for closing the returned connection outside p.mu
// to avoid ABBA deadlock with Conn.mu.
func (p *ConnPool) replaceDead(key string) *Conn {
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

// Shutdown closes all pooled connections and clears the pool. It is safe to
// call multiple times.
func (p *ConnPool) Shutdown() {
	p.mu.Lock()
	p.closed = true
	// Collect connections outside the lock to avoid close() acquiring Conn.mu
	// while holding p.mu, which creates an ABBA deadlock path with Remove().
	var all []*Conn
	for _, conns := range p.conns {
		all = append(all, conns...)
	}
	p.conns = make(map[string][]*Conn)
	p.total = 0
	p.mu.Unlock()

	for _, c := range all {
		c.close()
	}
}

// Remove closes and removes a pipelined connection from the pool.
func (p *ConnPool) Remove(target *Conn) {
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
