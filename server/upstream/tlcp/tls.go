package tlcp

import (
	"context"
	"io"
	"net"
	"zjdns/config"
	"zjdns/internal/log"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
)

// ExecuteTLCP performs a DoT-over-TLCP query.
func (c *Client) ExecuteTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	tlcpCfg := c.tlcpClientConfig(server).Clone()
	tlcpCfg.NextProtos = config.NextProtoDOT
	response, err := c.exchangeOverTLCP(ctx, msg, server.Address, tlcpCfg, c.getProxy(server))
	if err != nil {
		log.Debugf("UPSTREAM: TLCP query to %s failed: %v", server.Address, err)
	}
	return response, err
}

// dialTLCPConn establishes a TCP connection (optionally proxied), performs a
// TLCP handshake, and returns the resulting TLCP connection.
func (c *Client) dialTLCPConn(ctx context.Context, addr string, tlcpConfig *tlcp.Config, proxyDialer *socks5.Dialer) (net.Conn, error) {
	var tcpConn net.Conn
	var err error
	if proxyDialer != nil {
		tcpConn, err = proxyDialer.DialContext(ctx, "tcp", addr)
	} else {
		var d net.Dialer
		tcpConn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	if tc, ok := tcpConn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
	}
	tlcpConn := tlcp.Client(tcpConn, tlcpConfig)
	if err := tlcpConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return tlcpConn, nil
}

// exchangeOverTLCP dials a TLCP connection and performs a single DNS exchange.
func (c *Client) exchangeOverTLCP(ctx context.Context, msg *dns.Msg, addr string, tlcpConfig *tlcp.Config, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	tlcpConn, err := c.dialTLCPConn(ctx, addr, tlcpConfig, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tlcpConn.Close() }()
	if err := writeTCPMsg(tlcpConn, msg); err != nil {
		return nil, err
	}
	response, err := readTCPMsg(tlcpConn)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// writeTCPMsg writes a DNS message with a 2-byte big-endian length prefix.
func writeTCPMsg(conn net.Conn, msg *dns.Msg) error {
	if err := msg.Pack(); err != nil {
		return err
	}
	length := uint16(len(msg.Data))                    //nolint:gosec // G115: DNS TCP message — protocol-bounded uint16
	prefix := [2]byte{byte(length >> 8), byte(length)} //nolint:gosec // G115: DNS wire format — protocol-bounded byte
	if _, err := conn.Write(prefix[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg.Data)
	return err
}

// readTCPMsg reads a DNS message prefixed with a 2-byte big-endian length.
func readTCPMsg(conn net.Conn) (*dns.Msg, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		return nil, err
	}
	length := int(prefix[0])<<8 | int(prefix[1])
	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	msg := new(dns.Msg)
	msg.Data = buf
	if err := msg.Unpack(); err != nil {
		return nil, err
	}
	return msg, nil
}
