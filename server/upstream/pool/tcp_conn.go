// Conn: one TCP/DoT connection multiplexing pipelined DNS queries (RFC
// 7766) — the exchange path with optional splitguard segmentation, the
// length-prefixed read loop, and lifecycle.

package pool

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
