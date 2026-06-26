package pool

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"

	"zjdns/config"
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
	dialing  map[string]int
	maxConns int
}

func (qpc *QuicConn) close() {
	qpc.closeOnce.Do(func() {
		qpc.closed.Store(true)
		_ = qpc.Conn.CloseWithError(QUICCodeNoError, "pool connection closed")
	})
}

func (qpc *QuicConn) isDead() bool {
	if qpc.closed.Load() {
		return true
	}
	// Also check the underlying quic-go connection context, which closes when
	// the remote peer terminates the connection or an unrecoverable transport
	// error occurs.
	select {
	case <-qpc.Conn.Context().Done():
		qpc.closed.Store(true)
		return true
	default:
		return false
	}
}

// NewQuicPool creates a QuicPool with the specified maximum connections.
func NewQuicPool(maxConns int) *QuicPool {
	if maxConns <= 0 {
		maxConns = config.DefaultMaxConns
	}
	return &QuicPool{
		conns:    make(map[string][]*QuicConn),
		dialing:  make(map[string]int),
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
		// Round-robin across live connections rather than always returning
		// live[0], which would leave connections[1..N] unused.
		idx := rand.IntN(len(live))
		pc := live[idx]
		qp.mu.Unlock()
		return pc, nil
	}

	if len(live)+qp.dialing[key] < qp.maxConns {
		qp.dialing[key]++
		qp.mu.Unlock()
		conn, err := dialFunc(ctx, key)
		if err != nil {
			qp.mu.Lock()
			qp.dialing[key]--
			if qp.dialing[key] == 0 {
				delete(qp.dialing, key)
			}
			qp.mu.Unlock()
			return nil, fmt.Errorf("client: dial %s: %w", key, err)
		}
		pc := &QuicConn{Conn: conn, addr: key}
		qp.mu.Lock()
		qp.dialing[key]--
		if len(qp.conns[key]) >= qp.maxConns {
			if qp.dialing[key] == 0 {
				delete(qp.dialing, key)
			}
			qp.mu.Unlock()
			pc.close()
			return nil, fmt.Errorf("client: pool filled during dial for %s", key)
		}
		qp.conns[key] = append(qp.conns[key], pc)
		n := len(qp.conns[key])
		qp.dialing[key]--
		if qp.dialing[key] == 0 {
			delete(qp.dialing, key)
		}
		qp.mu.Unlock()
		log.Debugf("UPSTREAM: dialed new QUIC connection to %s (pool=%d/%d)", key, n, qp.maxConns)
		return pc, nil
	}

	qp.mu.Unlock()
	return nil, fmt.Errorf("client: no available connection to %s", key)
}

// Shutdown closes all pooled QUIC connections and clears the pool. It is safe
// to call multiple times.
func (qp *QuicPool) Shutdown() {
	qp.mu.Lock()
	defer qp.mu.Unlock()
	for key, conns := range qp.conns {
		for _, pc := range conns {
			pc.close()
		}
		delete(qp.conns, key)
	}
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
