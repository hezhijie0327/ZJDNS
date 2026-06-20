package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"zjdns/internal/log"
)

// quicPoolConn wraps a QUIC connection managed by the quicPool.
type quicPoolConn struct {
	conn      *quic.Conn
	addr      string
	closed    atomic.Bool
	closeOnce sync.Once
}

func (qpc *quicPoolConn) close() {
	qpc.closeOnce.Do(func() {
		qpc.closed.Store(true)
		_ = qpc.conn.CloseWithError(QUICCodeNoError, "pool connection closed")
	})
}

func (qpc *quicPoolConn) isDead() bool {
	return qpc.closed.Load()
}

// quicPool manages a set of QUIC connections per upstream address,
// enabling concurrent query multiplexing over pooled connections.
// Unlike TCP/DoT pipelining, QUIC handles stream multiplexing natively,
// so multiple goroutines can safely use the same connection concurrently.
type quicPool struct {
	mu       sync.Mutex
	conns    map[string][]*quicPoolConn
	maxConns int
}

func newQuicPool(maxConns int) *quicPool {
	if maxConns <= 0 {
		maxConns = defaultMaxConns
	}
	return &quicPool{
		conns:    make(map[string][]*quicPoolConn),
		maxConns: maxConns,
	}
}

// acquire returns a live QUIC connection for the given key. It prefers an
// existing live connection; if none exists and under the limit, dials a new one.
// QUIC handles stream multiplexing natively, so multiple goroutines may use the
// same connection concurrently without a capacity semaphore.
func (qp *quicPool) acquire(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) (*quicPoolConn, error) {
	qp.mu.Lock()

	// Sweep dead connections, return first live one.
	conns := qp.conns[key]
	live := conns[:0]
	for _, pc := range conns {
		if pc.isDead() {
			continue
		}
		live = append(live, pc)
	}
	qp.conns[key] = live

	if len(live) > 0 {
		pc := live[0]
		qp.mu.Unlock()
		return pc, nil
	}

	// No live connection — dial if under limit.
	if len(live) < qp.maxConns {
		qp.mu.Unlock()
		conn, err := dialFunc(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("quicpool: dial %s: %w", key, err)
		}
		pc := &quicPoolConn{conn: conn, addr: key}
		qp.mu.Lock()
		// Double-check: concurrent acquires might have filled the pool.
		if len(qp.conns[key]) >= qp.maxConns {
			qp.mu.Unlock()
			pc.close()
			return nil, fmt.Errorf("quicpool: pool filled during dial for %s", key)
		}
		qp.conns[key] = append(qp.conns[key], pc)
		n := len(qp.conns[key])
		qp.mu.Unlock()
		log.Debugf("UPSTREAM: dialed new QUIC connection to %s (pool=%d/%d)", key, n, qp.maxConns)
		return pc, nil
	}

	qp.mu.Unlock()
	return nil, fmt.Errorf("quicpool: no available connection to %s", key)
}

// put adds a successfully used connection back to the pool for reuse.
// If the pool is at capacity, the connection is closed.
func (qp *quicPool) put(key string, conn *quic.Conn) {
	pc := &quicPoolConn{conn: conn, addr: key}
	qp.mu.Lock()
	defer qp.mu.Unlock()
	if len(qp.conns[key]) >= qp.maxConns {
		pc.close()
		return
	}
	qp.conns[key] = append(qp.conns[key], pc)
}

// remove evicts a dead connection from the pool and closes it.
func (qp *quicPool) remove(pc *quicPoolConn) {
	qp.mu.Lock()
	defer qp.mu.Unlock()
	conns := qp.conns[pc.addr]
	for i, c := range conns {
		if c == pc {
			qp.conns[pc.addr] = append(conns[:i], conns[i+1:]...)
			if len(qp.conns[pc.addr]) == 0 {
				delete(qp.conns, pc.addr)
			}
			pc.close()
			return
		}
	}
}
