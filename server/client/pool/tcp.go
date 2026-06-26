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
	pc := &Conn{
		conn:     conn,
		addr:     addr,
		inflight: make(map[uint16]*pending),
		capacity: make(chan struct{}, maxPipe),
		maxPipe:  int32(maxPipe),
		done:     make(chan struct{}),
	}
	pc.nextID.Store(rand.Uint32())
	go pc.readLoop()
	return pc
}

// Exchange sends a DNS message over the pipelined connection and returns the
// response.
func (pc *Conn) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	select {
	case pc.capacity <- struct{}{}:
		pc.inFlight.Add(1)
		defer func() {
			pc.inFlight.Add(-1)
			<-pc.capacity
		}()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if pc.closed.Load() {
		return nil, fmt.Errorf("client: connection to %s is closed", pc.addr)
	}

	originalID := msg.Id
	trackingID := uint16(pc.nextID.Add(1) & dnsIDMask)
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
	pc.mu.Lock()
	if pc.closed.Load() {
		pc.mu.Unlock()
		return nil, fmt.Errorf("client: connection to %s closed before write", pc.addr)
	}
	pc.inflight[trackingID] = &pending{resultCh: resultCh}
	pc.mu.Unlock()

	defer func() {
		pc.mu.Lock()
		if pc.inflight != nil {
			delete(pc.inflight, trackingID)
		}
		pc.mu.Unlock()
	}()

	pc.writeMu.Lock()
	_, writeErr := pc.conn.Write(writeBuf)
	pc.writeMu.Unlock()
	if writeErr != nil {
		pc.close()
		return nil, fmt.Errorf("client: write to %s: %w", pc.addr, writeErr)
	}

	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, fmt.Errorf("client: connection to %s closed", pc.addr)
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

func (pc *Conn) readLoop() {
	defer dnsutil.HandlePanic("client reader")
	defer close(pc.done)
	defer pc.close()

	lengthBuf := make([]byte, dnsutil.DNSFramePrefixLen)

	for {
		_ = pc.conn.SetReadDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))

		if _, err := io.ReadFull(pc.conn, lengthBuf); err != nil {
			if err != io.EOF {
				log.Debugf("TCPPOOL: read length error from %s: %v", pc.addr, err)
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 {
			log.Debugf("TCPPOOL: invalid message length %d from %s", msgLen, pc.addr)
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
		if _, err := io.ReadFull(pc.conn, body); err != nil {
			if pooled {
				bufpool.DefaultBufferPool.Put(bodyBuf)
			}
			log.Debugf("TCPPOOL: read body error from %s: %v", pc.addr, err)
			return
		}

		resp := bufpool.DefaultMessagePool.Get()
		if err := resp.Unpack(body); err != nil {
			if pooled {
				bufpool.DefaultBufferPool.Put(bodyBuf)
			}
			log.Debugf("TCPPOOL: unpack error from %s: %v", pc.addr, err)
			bufpool.DefaultMessagePool.Put(resp)
			continue
		}
		if pooled {
			bufpool.DefaultBufferPool.Put(bodyBuf)
		}

		pc.mu.RLock()
		pq, ok := pc.inflight[resp.Id]
		pc.mu.RUnlock()
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

func (pc *Conn) close() {
	pc.closeOnce.Do(func() {
		pc.closed.Store(true)
		_ = pc.conn.Close()

		pc.mu.Lock()
		for _, pq := range pc.inflight {
			select {
			case pq.resultCh <- nil:
			default:
			}
		}
		pc.inflight = nil
		pc.mu.Unlock()
	})
}

// IsFull reports whether the connection has reached its maximum in-flight
// query capacity. Uses an atomic counter to avoid the racy len(channel) call.
func (pc *Conn) IsFull() bool {
	return pc.inFlight.Load() >= pc.maxPipe
}

// IsDead reports whether the connection has been closed.
func (pc *Conn) IsDead() bool {
	return pc.closed.Load()
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
func (cp *Pool) Acquire(ctx context.Context, key string, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*Conn, error) {
	cp.mu.Lock()

	var leastLoaded *Conn
	leastCount := math.MaxInt
	conns := cp.conns[key]
	liveConns := conns[:0]
	for _, pc := range conns {
		if pc.IsDead() {
			continue
		}
		liveConns = append(liveConns, pc)
		inFlight := int(pc.inFlight.Load())
		if !pc.IsFull() {
			cp.conns[key] = liveConns
			cp.mu.Unlock()
			return pc, nil
		}
		if inFlight < leastCount {
			leastCount = inFlight
			leastLoaded = pc
		}
	}
	cp.conns[key] = liveConns

	if len(liveConns)+cp.dialing[key] < cp.maxConns {
		cp.dialing[key]++
		cp.mu.Unlock()
		conn, err := dialFunc(ctx, dialAddr)
		if err != nil {
			cp.mu.Lock()
			cp.dialing[key]--
			if cp.dialing[key] == 0 {
				delete(cp.dialing, key)
			}
			cp.mu.Unlock()
			return nil, fmt.Errorf("client: dial %s: %w", key, err)
		}
		pc := newConn(key, conn, cp.maxPipe)
		cp.mu.Lock()
		cp.dialing[key]--
		if len(cp.conns[key]) >= cp.maxConns {
			// Pool filled while we were dialing — try replacing a dead
			// connection before discarding this new one.
			replaced := false
			for i, c := range cp.conns[key] {
				if c.IsDead() {
					c.close()
					cp.conns[key][i] = pc
					replaced = true
					log.Debugf("TCPPOOL: replaced dead connection in pool for %s", key)
					break
				}
			}
			if !replaced {
				pc.close()
				log.Debugf("TCPPOOL: pool for %s already at limit (%d), discarding extra connection", key, cp.maxConns)
			}
			if cp.dialing[key] == 0 {
				delete(cp.dialing, key)
			}
			cp.mu.Unlock()
			if !replaced && leastLoaded != nil {
				return leastLoaded, nil
			}
			if !replaced {
				return nil, fmt.Errorf("client: max conns reached for %s", key)
			}
			return pc, nil
		}
		cp.conns[key] = append(cp.conns[key], pc)
		n := len(cp.conns[key])
		if cp.dialing[key] == 0 {
			delete(cp.dialing, key)
		}
		cp.mu.Unlock()
		log.Debugf("TCPPOOL: dialed new connection to %s (pool=%d/%d)", key, n, cp.maxConns)
		return pc, nil
	}

	cp.mu.Unlock()
	if leastLoaded != nil {
		return leastLoaded, nil
	}
	return nil, fmt.Errorf("client: no available connection to %s", key)
}

// Shutdown closes all pooled connections and clears the pool. It is safe to
// call multiple times.
func (cp *Pool) Shutdown() {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for key, conns := range cp.conns {
		for _, pc := range conns {
			pc.close()
		}
		delete(cp.conns, key)
	}
}

// Remove closes and removes a pipelined connection from the pool.
func (cp *Pool) Remove(pc *Conn) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	conns := cp.conns[pc.addr]
	for i, c := range conns {
		if c == pc {
			cp.conns[pc.addr] = append(conns[:i], conns[i+1:]...)
			if len(cp.conns[pc.addr]) == 0 {
				delete(cp.conns, pc.addr)
			}
			pc.close()
			return
		}
	}
}
