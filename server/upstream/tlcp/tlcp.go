package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
)

// ExecuteTLCP performs a DoT-over-TLCP query.
func (c *Client) ExecuteTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("tlcp: nil query message")
	}
	if server == nil {
		return nil, errors.New("tlcp: nil server config")
	}
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
	// Restore ctx-bound deadlines: ReadTCPMsg's contract requires the
	// caller to set a read deadline ("caller MUST set ... to prevent
	// goroutine leaks on unresponsive peers") and the proxy path clears
	// the dial deadline.
	stop := context.AfterFunc(ctx, func() { _ = tlcpConn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlcpConn.SetDeadline(deadline)
	}
	// RFC 7858 §4.1: only proceed when "dot" was negotiated — a server that
	// silently ignores ALPN (negotiates none, or an unexpected protocol)
	// would otherwise proceed without the DoT guarantee. Checked on the DoT
	// path only (dialTLCPConn also serves DoH-over-TLCP with a "h2" ALPN).
	if tc, ok := tlcpConn.(*tlcp.Conn); ok {
		if got := tc.ConnectionState().NegotiatedProtocol; got != config.NextProtoDOT[0] {
			return nil, fmt.Errorf("tlcp: server %s negotiated ALPN %q, expected %q", addr, got, config.NextProtoDOT[0])
		}
	}
	if err := zdnsutil.WriteTCPMsg(tlcpConn, msg); err != nil {
		return nil, err
	}
	response, err := zdnsutil.ReadTCPMsg(tlcpConn)
	if err != nil {
		return nil, err
	}
	// Reject ID mismatches like the TLS/plain-TCP paths (M7) — the response
	// was read on a fresh per-query connection, but a misbehaving or
	// intercepted server may still echo a stale datagram.
	if response.ID != msg.ID {
		pool.DefaultMessage.Put(response)
		return nil, fmt.Errorf("tlcp: response id mismatch: expected %d, got %d", msg.ID, response.ID)
	}
	return response, nil
}
