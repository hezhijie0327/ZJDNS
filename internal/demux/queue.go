package demux

import (
	"context"
	"net"
)

// protocolQueue is a channel-based connection queue that implements net.Listener.
// The demux accept loop pushes detected connections into the queue; the
// protocol-specific server (http.Server, eHTTP.Server, etc.) pulls them
// via Accept().  Close() cancels the context, unblocking any pending Accept.
type protocolQueue struct {
	ch     chan net.Conn
	ctx    context.Context
	cancel context.CancelCauseFunc
	addr   net.Addr
}

// newProtocolQueue creates a protocolQueue with a buffered channel.
// queueDepth bounds the number of pending (pre-accepted) connections
// before the demux loop blocks — 64 is generous for DNS workloads.
const queueDepth = 64

func newProtocolQueue(addr net.Addr) *protocolQueue {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &protocolQueue{
		ch:     make(chan net.Conn, queueDepth),
		ctx:    ctx,
		cancel: cancel,
		addr:   addr,
	}
}

// Accept waits for and returns the next connection from the demux.
func (q *protocolQueue) Accept() (net.Conn, error) {
	select {
	case c, ok := <-q.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-q.ctx.Done():
		return nil, net.ErrClosed
	}
}

// Close shuts down the queue, causing pending and future Accept calls
// to return net.ErrClosed.  Connections already buffered in the queue are
// closed here — nothing else owns them once both the demux pusher and the
// protocol Accept loop are gone (F8).
func (q *protocolQueue) Close() error {
	q.cancel(net.ErrClosed)
	for {
		select {
		case c := <-q.ch:
			_ = c.Close() // _ = error: best-effort close of an abandoned conn
		default:
			return nil
		}
	}
}

// Addr returns the bind address of the underlying listener.
func (q *protocolQueue) Addr() net.Addr {
	return q.addr
}

// push enqueues a connection.  It returns false if the queue is closed
// or the channel is full (back-pressure: the caller should close the
// connection in that case).
func (q *protocolQueue) push(c net.Conn) bool {
	select {
	case q.ch <- c:
		// Both cases can be ready when Close races the send — re-check so
		// a conn queued into a dying queue is not reported as delivered.
		select {
		case <-q.ctx.Done():
			return false
		default:
			return true
		}
	case <-q.ctx.Done():
		return false
	default:
		// Channel full — caller must close the connection.
		return false
	}
}
