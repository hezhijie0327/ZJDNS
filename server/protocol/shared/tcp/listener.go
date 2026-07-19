package tcp

import (
	"errors"
	"fmt"
	"net"
	"zjdns/internal/log"
	"zjdns/server/protocol/shared"

	"gitee.com/Trisia/gotlcp/tlcp"
	eTLS "gitlab.com/go-extension/tls"
)

// Listener wraps a raw TCP listener and auto-detects whether each
// accepted connection speaks TLS or TLCP.  The detection peeks at the first
// 5 bytes (TLS record layer header) — major version 0x01 is TLCP, 0x03 is TLS.
//
// Accepted connections are fully handshaked: callers receive either
// *eTLS.Conn or *tlcp.Conn, both of which implement net.Conn.
type Listener struct {
	inner    net.Listener
	eTLSConf *eTLS.Config
	tlcpConf *tlcp.Config
}

// NewListener creates a port-sharing listener that dispatches to
// eTLS or TLCP based on the client's protocol version.  At least one config
// must be non-nil.
func NewListener(inner net.Listener, eTLSConf *eTLS.Config, tlcpConf *tlcp.Config) net.Listener {
	return &Listener{
		inner:    inner,
		eTLSConf: eTLSConf,
		tlcpConf: tlcpConf,
	}
}

// Accept waits for the next raw TCP connection, peeks at the record layer
// header to determine the protocol, completes the appropriate handshake,
// and returns the wrapped connection.
func (l *Listener) Accept() (net.Conn, error) {
	rawConn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}

	dc := &detectConn{Conn: rawConn}
	if err := dc.readHeader(); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("shared: %w", err)
	}

	switch shared.ClassifyRecordHeader(dc.header) {
	case shared.VersionTLCP:
		if l.tlcpConf == nil {
			_ = rawConn.Close()
			return nil, errors.New("shared: TLCP connection but no TLCP config")
		}
		return tlcp.Server(dc, l.tlcpConf), nil

	case shared.VersionTLS:
		if l.eTLSConf == nil {
			_ = rawConn.Close()
			return nil, errors.New("shared: TLS connection but no TLS config")
		}
		return eTLS.Server(dc, l.eTLSConf), nil

	default:
		// Unknown protocol — return the raw connection with the peeked
		// bytes replayed.  This allows DNSCrypt-TCP and other non-TLS
		// protocols to share the port.
		log.Debugf("SHARED: unknown protocol major 0x%02x, returning raw connection from %s", dc.major, rawConn.RemoteAddr())
		return dc, nil
	}
}

// Close closes the underlying raw listener.
func (l *Listener) Close() error {
	return l.inner.Close()
}

// Addr returns the underlying listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}
