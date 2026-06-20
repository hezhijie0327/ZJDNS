package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

const (
	defaultMaxPipe  = 16 // max in-flight queries per connection
	defaultMaxConns = 4  // max connections per upstream address
)

// pendingQuery tracks an in-flight query waiting for its response.
type pendingQuery struct {
	resultCh chan *dns.Msg // buffered(1); closed or nil-received signals connection death
}

// pipelinedConn multiplexes multiple in-flight DNS queries over a single
// TCP or TLS connection, implementing RFC 7766 query pipelining (§6.2.1.1).
type pipelinedConn struct {
	conn      net.Conn
	addr      string
	writeMu   sync.Mutex          // serializes writes to the connection
	mu        sync.RWMutex        // guards inflight map
	inflight  map[uint16]*pendingQuery
	nextID    atomic.Uint32       // monotonic tracking ID source
	capacity  chan struct{}       // concurrency limiter
	closed    atomic.Bool
	closeOnce sync.Once
	done      chan struct{}       // closed when reader goroutine exits
}

// newPipelinedConn creates a pipelinedConn, starts its reader goroutine,
// and returns the ready-to-use connection.
func newPipelinedConn(addr string, conn net.Conn, maxPipe int) *pipelinedConn {
	if maxPipe <= 0 {
		maxPipe = defaultMaxPipe
	}
	pc := &pipelinedConn{
		conn:     conn,
		addr:     addr,
		inflight: make(map[uint16]*pendingQuery),
		capacity: make(chan struct{}, maxPipe),
		done:     make(chan struct{}),
	}
	go pc.readLoop()
	return pc
}

// Exchange sends a DNS query on the connection and waits for the response.
// Multiple goroutines may call Exchange concurrently; queries are multiplexed
// by DNS message ID. Callers receive responses in potentially different order
// than the sends.
func (pc *pipelinedConn) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	// Acquire capacity slot for backpressure.
	select {
	case pc.capacity <- struct{}{}:
		defer func() { <-pc.capacity }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if pc.closed.Load() {
		return nil, fmt.Errorf("tcppool: connection to %s is closed", pc.addr)
	}

	// Assign unique tracking ID and prepare wire-format message.
	originalID := msg.Id
	trackingID := uint16(pc.nextID.Add(1) & 0xFFFF)
	msg.Id = trackingID

	msgData, err := msg.Pack()
	msg.Id = originalID
	if err != nil {
		return nil, fmt.Errorf("tcppool: pack: %w", err)
	}

	// 2-byte length prefix per RFC 1035 §4.2.2.
	buf := make([]byte, 2+len(msgData))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(msgData)))
	copy(buf[2:], msgData)

	// Register pending before writing, so the reader can dispatch.
	resultCh := make(chan *dns.Msg, 1)
	pc.mu.Lock()
	if pc.closed.Load() {
		pc.mu.Unlock()
		return nil, fmt.Errorf("tcppool: connection to %s closed before write", pc.addr)
	}
	pc.inflight[trackingID] = &pendingQuery{resultCh: resultCh}
	pc.mu.Unlock()

	defer func() {
		pc.mu.Lock()
		if pc.inflight != nil {
			delete(pc.inflight, trackingID)
		}
		pc.mu.Unlock()
	}()

	// Write (serialized — only one goroutine writes to the socket at a time).
	pc.writeMu.Lock()
	_, writeErr := pc.conn.Write(buf)
	pc.writeMu.Unlock()
	if writeErr != nil {
		pc.close()
		return nil, fmt.Errorf("tcppool: write to %s: %w", pc.addr, writeErr)
	}

	// Wait for response or cancellation.
	select {
	case resp := <-resultCh:
		if resp == nil {
			return nil, fmt.Errorf("tcppool: connection to %s closed", pc.addr)
		}
		resp.Id = originalID
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// readLoop reads DNS responses from the wire and dispatches them to
// waiting callers by DNS message ID. It runs in its own goroutine.
func (pc *pipelinedConn) readLoop() {
	defer dnsutil.HandlePanic("tcppool reader")
	defer close(pc.done)
	defer pc.close()

	lengthBuf := make([]byte, 2)

	for {
		_ = pc.conn.SetReadDeadline(time.Now().Add(OperationTimeout))

		// Read 2-byte length prefix.
		if _, err := io.ReadFull(pc.conn, lengthBuf); err != nil {
			if err != io.EOF {
				log.Debugf("TCPPOOL: read length error from %s: %v", pc.addr, err)
			}
			return
		}
		msgLen := binary.BigEndian.Uint16(lengthBuf)
		if msgLen == 0 || int(msgLen) > pool.SecureBufferSize {
			log.Debugf("TCPPOOL: invalid message length %d from %s", msgLen, pc.addr)
			return
		}

		// Read message body.
		body := make([]byte, msgLen)
		if _, err := io.ReadFull(pc.conn, body); err != nil {
			log.Debugf("TCPPOOL: read body error from %s: %v", pc.addr, err)
			return
		}

		// Unpack DNS response.
		resp := pool.DefaultMessagePool.Get()
		if err := resp.Unpack(body); err != nil {
			log.Debugf("TCPPOOL: unpack error from %s: %v", pc.addr, err)
			pool.DefaultMessagePool.Put(resp)
			continue
		}

		// Dispatch to the waiting caller by message ID.
		pc.mu.RLock()
		pq, ok := pc.inflight[resp.Id]
		pc.mu.RUnlock()
		if ok {
			select {
			case pq.resultCh <- resp:
				// delivered
			default:
				// Caller already timed out; discard response.
				pool.DefaultMessagePool.Put(resp)
			}
		} else {
			// No matching waiter (stale or never registered).
			pool.DefaultMessagePool.Put(resp)
		}
	}
}

// close shuts down the connection and fails all pending requests.
func (pc *pipelinedConn) close() {
	pc.closeOnce.Do(func() {
		pc.closed.Store(true)
		_ = pc.conn.Close()

		pc.mu.Lock()
		for _, pq := range pc.inflight {
			close(pq.resultCh) // signals error to waiting callers
		}
		pc.inflight = nil
		pc.mu.Unlock()
	})
}

// isFull reports whether the connection is at its in-flight capacity.
func (pc *pipelinedConn) isFull() bool {
	return len(pc.capacity) == cap(pc.capacity)
}

// isDead reports whether the connection has been closed.
func (pc *pipelinedConn) isDead() bool {
	return pc.closed.Load()
}

// connPool manages a set of pipelinedConn instances for a specific upstream
// protocol (plain TCP or DoT), following the mosdns-style pool pattern.
type connPool struct {
	mu       sync.Mutex
	conns    map[string][]*pipelinedConn // keyed by pool key (address or address|sni|skipVerify)
	maxConns int
	maxPipe  int
}

// newConnPool creates a connection pool.
func newConnPool(maxConns, maxPipe int) *connPool {
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	if maxPipe <= 0 {
		maxPipe = defaultMaxPipe
	}
	return &connPool{
		conns:    make(map[string][]*pipelinedConn),
		maxConns: maxConns,
		maxPipe:  maxPipe,
	}
}

// acquire returns a pipelinedConn for the given pool key. It prefers an
// existing non-full live connection; if none is available and under the
// connection limit, it dials a new one via dialFunc. Otherwise it returns
// the least loaded connection (caller will block on capacity).
func (cp *connPool) acquire(ctx context.Context, key string, dialAddr string, dialFunc func(context.Context, string) (net.Conn, error)) (*pipelinedConn, error) {
	cp.mu.Lock()

	// 1. Find an existing non-full, alive connection.
	var leastLoaded *pipelinedConn
	leastCount := int(^uint(0) >> 1) // max int
	conns := cp.conns[key]
	liveConns := conns[:0]
	for _, pc := range conns {
		if pc.isDead() {
			continue
		}
		liveConns = append(liveConns, pc)
		inFlight := len(pc.capacity)
		if !pc.isFull() {
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

	// 2. Dial a new connection if under the limit.
	if len(liveConns) < cp.maxConns {
		cp.mu.Unlock()
		conn, err := dialFunc(ctx, dialAddr)
		if err != nil {
			return nil, fmt.Errorf("tcppool: dial %s: %w", key, err)
		}
		pc := newPipelinedConn(key, conn, cp.maxPipe)
		cp.mu.Lock()
		cp.conns[key] = append(cp.conns[key], pc)
		n := len(cp.conns[key])
		cp.mu.Unlock()
		log.Debugf("TCPPOOL: dialed new connection to %s (pool=%d/%d)", key, n, cp.maxConns)
		return pc, nil
	}

	// 3. All connections full — return least loaded.
	cp.mu.Unlock()
	if leastLoaded != nil {
		return leastLoaded, nil
	}
	return nil, fmt.Errorf("tcppool: no available connection to %s", key)
}

// remove evicts a dead connection from the pool and closes it.
func (cp *connPool) remove(pc *pipelinedConn) {
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

