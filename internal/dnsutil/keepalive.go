package dnsutil

import (
	"net"
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
