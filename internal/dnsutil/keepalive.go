package dnsutil

import (
	"net"
	"sync"
	"time"
)

// TCPKeepAliveListener wraps a net.Listener to enable TCP keep-alive on every
// accepted connection.  This prevents unilateral connection teardown by
// intermediate NAT or firewall state timeouts on both server and client sides.
//
// KeepAlivePeriod is injected by the caller (config.DefaultTCPKeepAlivePeriod)
// — internal/dnsutil cannot import config (layering), and duplicating the
// constant here would let the two drift apart.
type TCPKeepAliveListener struct {
	net.Listener
	KeepAlivePeriod time.Duration
}

// LimitListener wraps a net.Listener to cap concurrent connections: while
// the active count is at the limit, Accept blocks and further connections
// queue in the kernel backlog.  Same pattern as x/net/netutil.LimitListener
// (no new dependency).  Used by servers whose accept loops live inside a
// third-party package (miekg/dns, net/http), where a goroutine-semaphore
// admission cap on the handler loop is not possible.
type LimitListener struct {
	net.Listener
	sem chan struct{}
}

// limitConn releases the admission slot when closed.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// Accept implements net.Listener.
func (k *TCPKeepAliveListener) Accept() (net.Conn, error) {
	conn, err := k.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true) // _ = error: non-fatal — connection is still usable
		if k.KeepAlivePeriod > 0 {
			_ = tcpConn.SetKeepAlivePeriod(k.KeepAlivePeriod) // _ = error: non-fatal — connection is still usable
		}
	}
	return conn, nil
}

// NewLimitListener wraps l to admit at most limit concurrent connections.
// limit <= 0 returns l unwrapped (no limit).
func NewLimitListener(l net.Listener, limit int) net.Listener {
	if limit <= 0 {
		return l
	}
	return &LimitListener{Listener: l, sem: make(chan struct{}, limit)}
}

// Accept implements net.Listener.  The slot is released when the returned
// connection is closed — the server must close the connection it accepted.
func (l *LimitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{} // blocks at the cap — connections queue in the kernel backlog
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.sem }}, nil
}

// Close releases the admission slot exactly once, even on double close.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
