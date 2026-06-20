package pool

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"zjdns/internal/log"
)

const (
	// QUICCodeNoError is the QUIC application error code for normal connection
	// close.
	QUICCodeNoError quic.ApplicationErrorCode = 0

	// QUICCodeInternalError is the QUIC application error code for internal
	// errors.
	QUICCodeInternalError quic.ApplicationErrorCode = 1

	// QUICCodeProtocolError is the QUIC application error code for protocol
	// errors.
	QUICCodeProtocolError quic.ApplicationErrorCode = 2
)

// QuicConn wraps a QUIC connection with lifecycle tracking.
type QuicConn struct {
	Conn      *quic.Conn
	addr      string
	closed    atomic.Bool
	closeOnce sync.Once
}

// QuicPool manages a set of QUIC connections per upstream server key.
type QuicPool struct {
	mu       sync.Mutex
	conns    map[string][]*QuicConn
	maxConns int
}

func (qpc *QuicConn) close() {
	qpc.closeOnce.Do(func() {
		qpc.closed.Store(true)
		_ = qpc.Conn.CloseWithError(QUICCodeNoError, "pool connection closed")
	})
}

func (qpc *QuicConn) isDead() bool {
	return qpc.closed.Load()
}

// NewQuicPool creates a QuicPool with the specified maximum connections.
func NewQuicPool(maxConns int) *QuicPool {
	if maxConns <= 0 {
		maxConns = DefaultMaxConns
	}
	return &QuicPool{
		conns:    make(map[string][]*QuicConn),
		maxConns: maxConns,
	}
}

// Acquire gets a reusable QUIC connection, dialing a new one if needed.
func (qp *QuicPool) Acquire(ctx context.Context, key string, dialFunc func(context.Context, string) (*quic.Conn, error)) (*QuicConn, error) {
	qp.mu.Lock()

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

	if len(live) < qp.maxConns {
		qp.mu.Unlock()
		conn, err := dialFunc(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("client: dial %s: %w", key, err)
		}
		pc := &QuicConn{Conn: conn, addr: key}
		qp.mu.Lock()
		if len(qp.conns[key]) >= qp.maxConns {
			qp.mu.Unlock()
			pc.close()
			return nil, fmt.Errorf("client: pool filled during dial for %s", key)
		}
		qp.conns[key] = append(qp.conns[key], pc)
		n := len(qp.conns[key])
		qp.mu.Unlock()
		log.Debugf("UPSTREAM: dialed new QUIC connection to %s (pool=%d/%d)", key, n, qp.maxConns)
		return pc, nil
	}

	qp.mu.Unlock()
	return nil, fmt.Errorf("client: no available connection to %s", key)
}

// Put returns a QUIC connection to the pool for reuse.
func (qp *QuicPool) Put(key string, conn *quic.Conn) {
	pc := &QuicConn{Conn: conn, addr: key}
	qp.mu.Lock()
	defer qp.mu.Unlock()
	if len(qp.conns[key]) >= qp.maxConns {
		pc.close()
		return
	}
	qp.conns[key] = append(qp.conns[key], pc)
}

// Remove closes and removes a QUIC connection from the pool.
func (qp *QuicPool) Remove(pc *QuicConn) {
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
