package ktls

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"sync"
)

// limitListener caps concurrent connections ABOVE the TLS layer.
type limitListener struct {
	net.Listener
	sem chan struct{}
}

// limitConn releases its admission slot on Close and keeps the conn
// recognisable as TLS for Go 1.27 net/http: the std server probes the
// ConnectionState / HandshakeContext interfaces (crypto/tls signatures) on
// whatever Accept returns — a plain net.Conn wrapper hides them and the conn
// would be served as plaintext HTTP.
type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

// ConnectionState forwards the eTLS conn's stdlib-compatible state.
func (c *limitConn) ConnectionState() stdtls.ConnectionState {
	if cs, ok := c.Conn.(interface{ ConnectionState() stdtls.ConnectionState }); ok {
		return cs.ConnectionState()
	}
	return stdtls.ConnectionState{}
}

// HandshakeContext forwards net/http's handshake drive to the eTLS conn.
func (c *limitConn) HandshakeContext(ctx context.Context) error {
	if h, ok := c.Conn.(interface {
		HandshakeContext(context.Context) error
	}); ok {
		return h.HandshakeContext(ctx)
	}
	return errors.New("ktls: wrapped conn has no TLS handshake")
}

// Close implements net.Conn, releasing the admission slot exactly once.
func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// NewLimitListener wraps l to admit at most limit concurrent connections
// (limit <= 0 returns l unwrapped).  Unlike dnsutil.NewLimitListener it must
// only wrap TLS-backed listeners (ktls.NewListener output): the admission cap
// for a TLS listener has to sit ABOVE the eTLS layer — below it the wrapping
// conn breaks eTLS's *net.TCPConn requirement and silently disables kernel
// TLS offload.
func NewLimitListener(l net.Listener, limit int) net.Listener {
	if limit <= 0 {
		return l
	}
	return &limitListener{Listener: l, sem: make(chan struct{}, limit)}
}

// Accept implements net.Listener.  The slot is released when the returned
// connection is closed — the server must close the connection it accepted.
func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{} // blocks at the cap — connections queue in the kernel backlog
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.sem }}, nil
}
