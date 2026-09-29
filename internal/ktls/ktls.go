// Package ktls bridges the eTLS fork (gitlab.com/go-extension/tls) with the
// standard library: kernel-offload options for the platforms that have them,
// and conn/listener adapters whose ConnectionState is net/http-compatible
// (Go 1.27+ accepts custom TLS backends via that interface).
package ktls

import (
	"net"
	"sync"
	"zjdns/internal/log"

	eTLS "gitlab.com/go-extension/tls"
)

// listener adapts the conns accepted by an eTLS listener so net/http sees a
// stdlib-compatible ConnectionState.  It must stay the top listener layer
// handed to http.Server.Serve — any wrapper above it would hide the method.
type listener struct {
	net.Listener
	config *eTLS.Config
}

// warnOffloadBlocked surfaces, once, that kernel TLS offload was requested
// but cannot engage: eTLS's setup() requires the conn directly beneath the
// eTLS layer to be a *net.TCPConn and skips offload silently otherwise.
var warnOffloadBlocked sync.Once

// Accept waits for and returns the next eTLS connection, wrapped so its
// ConnectionState() returns crypto/tls.ConnectionState.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*eTLS.Conn)
	if !ok {
		return c, nil
	}
	if requested(l.config) {
		if _, ok := tc.NetConn().(*net.TCPConn); !ok {
			warnOffloadBlocked.Do(func() {
				log.Warnf("KTLS: kernel offload requested but the conn under eTLS is %T (want *net.TCPConn) — offload silently disabled for this path", tc.NetConn())
			})
		}
	}
	return tc.Compatible(), nil
}

// NewListener wraps inner with eTLS (same as eTLS.NewListener) and adapts
// accepted connections for net/http: std http.Server drives the handshake
// via HandshakeContext and reads the negotiated protocol (h2/http1.1) from
// the stdlib-compatible ConnectionState.
func NewListener(inner net.Listener, config *eTLS.Config) net.Listener {
	return &listener{Listener: eTLS.NewListener(inner, config), config: config}
}
