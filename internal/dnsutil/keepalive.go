package dnsutil

import (
	"net"
	"time"
)

// TCPKeepAliveListener wraps a net.Listener to enable TCP keep-alive on every
// accepted connection.  This prevents unilateral connection teardown by
// intermediate NAT or firewall state timeouts on both server and client sides.
type TCPKeepAliveListener struct {
	net.Listener
}

// defaultTCPKeepAlivePeriod mirrors config.DefaultTCPKeepAlivePeriod.
// internal/dnsutil cannot import config (layering), so the constant is
// duplicated here.
const defaultTCPKeepAlivePeriod = 30 * time.Second

// Accept implements net.Listener.
func (k *TCPKeepAliveListener) Accept() (net.Conn, error) {
	conn, err := k.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(defaultTCPKeepAlivePeriod)
	}
	return conn, nil
}
