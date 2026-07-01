package pool

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	bufpool "zjdns/internal/pool"
)

const dnsIDMask = 0xFFFF // 16-bit DNS message ID space

type pending struct {
	resultCh chan *dns.Msg
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
	capacity  chan struct{}
	inFlight  atomic.Int32
	maxPipe   int32
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}
}

// Pool manages a set of pipelined TCP connections per upstream server key.
type Pool struct {
	mu       sync.Mutex
	conns    map[string][]*Conn
	dialing  map[string]int
	maxConns int
	maxPipe  int
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
	}
	c := &Conn{
		conn:     conn,
		addr:     addr,
		inflight: make(map[uint16]*pending),
		capacity: make(chan struct{}, maxPipe),
		maxPipe:  int32(maxPipe),
		done:     make(chan struct{}),
	}
	c.nextID.Store(rand.Uint32())
	go c.readLoop()
	return c
}

// Exchange sends a DNS message over the pipelined connection and returns the
// response.
func (c *Conn) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
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
		return nil, fmt.Errorf("client: connection to %s is closed", c.addr)
	}

	originalID := msg.Id
	trackingID := uint16(c.nextID.Add(1) & dnsIDMask)
	msg.Id = trackingID

	msgData, err := msg.Pack()
	msg.Id = originalID
	if err != nil {
		return nil, fmt.Errorf("client: pack: %w", err)
	}

	poolBuf := bufpool.DefaultBufferPool.Get()
	defer bufpool.DefaultBufferPool.Put(poolBuf)
	writeBuf := poolBuf
	if len(poolBuf) < dnsutil.DNSFramePrefixLen+len(msgData) {
		writeBuf = make([]byte, dnsutil.DNSFramePrefixLen+len(msgData))
	}
	writeBuf = writeBuf[:dnsutil.DNSFramePrefixLen+len(msgData)]
	binary.BigEndian.PutUint16(writeBuf[:dnsutil.DNSFramePrefixLen], uint16(len(msgData)))
	copy(writeBuf[dnsutil.DNSFramePrefixLen:], msgData)

	resultCh := make(chan *dns.Msg, 1)
	c.mu.Lock()
	if c.closed.Load() {
		c.mu.Unlock()
		return nil, fmt.Errorf("client: connection to %s closed before write", c.addr)
	}
	c.inflight[trackingID] = &pending{resultCh: resultCh}
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
				bufpool.DefaultMessagePool.Put(orphan)
			}
		default:
		}

	}()

	c.writeMu.Lock()
	_, writeErr := c.conn.Write(writeBuf)
	c.writeMu.Unlock()
	if writeErr != nil {
		c.close()
		return nil, fmt.Errorf("client: write to %s: %w", c.addr, writeErr)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, fmt.Errorf("client: connection to %s closed", c.addr)
		}
		resp.Id = originalID
		return resp, nil
	case <-ctx.Done():
		// Only cancel this query, not the connection.
		// The deferred cleanup unlinks trackingID; late
		// responses are discarded by readLoop's default branch.
		return nil, ctx.Err()
	}
}

func (c *Conn) readLoop() {
	defer dnsutil.HandlePanic("client reader")
	defer c.close()

	lengthBuf := make([]byte, dnsutil.DNSFramePrefixLen)

	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

		if _, err := io.ReadFull(c.conn, lengthBuf); err != nil {
			if err != io.EOF {
				log.Debugf("TCPPOOL: read length error from %s: %v", c.addr, err)
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			log.Debugf("TCPPOOL: invalid message length %d from %s", msgLen, c.addr)
			return
		}

		bodyBuf := bufpool.DefaultBufferPool.Get()
		var body []byte
		pooled := int(msgLen) <= len(bodyBuf)
		if pooled {
			body = bodyBuf[:msgLen]
		} else {
			body = make([]byte, msgLen)
		}
		if _, err := io.ReadFull(c.conn, body); err != nil {
			if pooled {
				bufpool.DefaultBufferPool.Put(bodyBuf)
			}
			log.Debugf("TCPPOOL: read body error from %s: %v", c.addr, err)
			return
		}

		resp := bufpool.DefaultMessagePool.Get()
		if err := resp.Unpack(body); err != nil {
			if pooled {
				bufpool.DefaultBufferPool.Put(bodyBuf)
			}
			log.Debugf("TCPPOOL: unpack error from %s: %v", c.addr, err)
			bufpool.DefaultMessagePool.Put(resp)
			continue
		}
		if pooled {
			bufpool.DefaultBufferPool.Put(bodyBuf)
		}

		c.mu.RLock()
		pq, ok := c.inflight[resp.Id]
		c.mu.RUnlock()
		if ok {
			select {
			case pq.resultCh <- resp:
			default:
				bufpool.DefaultMessagePool.Put(resp)
			}
		} else {
			bufpool.DefaultMessagePool.Put(resp)
		}
	}
}

func (c *Conn) close() {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.done)
		_ = c.conn.Close()

		c.mu.Lock()
		for _, pq := range c.inflight {
			select {
			case pq.resultCh <- nil:
			default:
			}
		}
		c.inflight = nil
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

// NewPool creates a Pool with the specified connection and in-flight limits.
func NewPool(maxConns, maxPipe int) *Pool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	if maxPipe <= 0 {
		maxPipe = config.DefaultMaxPipe
	}
	return &Pool{
		conns:    make(map[string][]*Conn),
		dialing:  make(map[string]int),
		maxConns: maxConns,
		maxPipe:  maxPipe,
	}
}

// Acquire gets a reusable pipelined connection, dialing a new one if needed.
func (p *Pool) Acquire(ctx context.Context, key string, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*Conn, error) {
	p.mu.Lock()

	var leastLoaded *Conn
	leastCount := math.MaxInt
	conns := p.conns[key]
	liveConns := conns[:0]
	for i, c := range conns {
		if c.IsDead() {
			continue
		}
		liveConns = append(liveConns, c)
		inFlight := int(c.inFlight.Load())
		if !c.IsFull() {
			// Append remaining (unchecked) connections so they are not
			// silently dropped from the pool on early return.
			liveConns = append(liveConns, conns[i+1:]...)
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
		p.dialing[key]++
		p.mu.Unlock()
		conn, err := dialFunc(ctx, dialAddr)
		if err != nil {
			p.mu.Lock()
			p.dialing[key]--
			if p.dialing[key] == 0 {
				delete(p.dialing, key)
			}
			p.mu.Unlock()
			return nil, fmt.Errorf("client: dial %s: %w", key, err)
		}
		c := newConn(key, conn, p.maxPipe)
		p.mu.Lock()
		p.dialing[key]--
		if len(p.conns[key]) >= p.maxConns {
			// Pool filled while we were dialing — try replacing a dead
			// connection before discarding this new one.
			replaced := false
			for i, c := range p.conns[key] {
				if c.IsDead() {
					c.close()
					p.conns[key][i] = c
					replaced = true
					log.Debugf("TCPPOOL: replaced dead connection in pool for %s", key)
					break
				}
			}
			if !replaced {
				c.close()
				log.Debugf("TCPPOOL: pool for %s already at limit (%d), discarding extra connection", key, p.maxConns)
			}
			if p.dialing[key] == 0 {
				delete(p.dialing, key)
			}
			p.mu.Unlock()
			if !replaced && leastLoaded != nil && !leastLoaded.IsDead() {
				return leastLoaded, nil
			}
			if !replaced {
				return nil, fmt.Errorf("client: max conns reached for %s", key)
			}
			return c, nil
		}
		p.conns[key] = append(p.conns[key], c)
		n := len(p.conns[key])
		if p.dialing[key] == 0 {
			delete(p.dialing, key)
		}
		p.mu.Unlock()
		log.Debugf("TCPPOOL: dialed new connection to %s (pool=%d/%d)", key, n, p.maxConns)
		return c, nil
	}

	p.mu.Unlock()
	if leastLoaded != nil {
		return leastLoaded, nil
	}
	return nil, fmt.Errorf("client: no available connection to %s", key)
}

// Shutdown closes all pooled connections and clears the pool. It is safe to
// call multiple times.
func (p *Pool) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, conns := range p.conns {
		for _, c := range conns {
			c.close()
		}
		delete(p.conns, key)
	}
}

// Remove closes and removes a pipelined connection from the pool.
func (p *Pool) Remove(target *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	conns := p.conns[target.addr]
	for i, c := range conns {
		if c == target {
			p.conns[target.addr] = append(conns[:i], conns[i+1:]...)
			if len(p.conns[target.addr]) == 0 {
				delete(p.conns, target.addr)
			}
			target.close()
			return
		}
	}
}
