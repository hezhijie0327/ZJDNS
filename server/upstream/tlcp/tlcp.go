package tlcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
)

// ExecuteTLCP performs a DoT-over-TLCP query, using the pipelined connection
// pool when available.
func (c *Client) ExecuteTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	if msg == nil {
		return nil, errors.New("tlcp: nil query message")
	}
	if server == nil {
		return nil, errors.New("tlcp: nil server config")
	}
	proxyDialer := c.getProxy(server)

	if c.tlcpPool != nil {
		pc, err := c.tlcpPool.Acquire(ctx, tlcpPoolKey(server), server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			// Config built only on dial — the pool-hit path skips the
			// per-query SystemCertPool Clone (M-3-6).
			tlcpCfg := c.tlcpClientConfig(server).Clone()
			tlcpCfg.NextProtos = config.NextProtoDOT
			return c.dialTLCPConnForDOT(dialCtx, addr, tlcpCfg, proxyDialer)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.tlcpPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined TLCP query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Non-pooled fallback: manual dial + TLCP handshake + DNS exchange.
	tlcpCfg := c.tlcpClientConfig(server).Clone()
	tlcpCfg.NextProtos = config.NextProtoDOT
	response, err := c.exchangeOverTLCP(ctx, msg, server.Address, tlcpCfg, proxyDialer)
	if err != nil {
		log.Debugf("UPSTREAM: TLCP query to %s failed: %v", server.Address, err)
	}
	return response, err
}

// tlcpPoolKey groups pooled TLCP connections by the parameters that shape the
// handshake: address, server name, verification policy and proxy.  Mixing
// them in one pool would reuse a connection negotiated under the wrong config.
func tlcpPoolKey(server *config.UpstreamServer) string {
	return server.Address + "|" + server.ServerName + "|" + strconv.FormatBool(server.SkipTLSVerify) + "|" + server.Proxy
}

// dialTLCPConnForDOT dials a TLCP connection and enforces the DoT ALPN: a
// server that silently ignores ALPN (negotiates none, or an unexpected
// protocol) would otherwise proceed without the DoT guarantee (RFC 7858
// §4.1).  The check runs at dial time because it is a per-connection
// property — pooled connections must be verified once, at handshake.
func (c *Client) dialTLCPConnForDOT(ctx context.Context, addr string, tlcpConfig *tlcp.Config, proxyDialer *socks5.Dialer) (net.Conn, error) {
	tlcpConn, err := c.dialTLCPConn(ctx, addr, tlcpConfig, proxyDialer)
	if err != nil {
		return nil, err
	}
	if tc, ok := tlcpConn.(*tlcp.Conn); ok {
		if got := tc.ConnectionState().NegotiatedProtocol; got != config.NextProtoDOT[0] {
			_ = tlcpConn.Close()
			return nil, fmt.Errorf("tlcp: server %s negotiated ALPN %q, expected %q", addr, got, config.NextProtoDOT[0])
		}
	}
	return tlcpConn, nil
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

// exchangeOverTLCP dials a TLCP connection (enforcing the DoT ALPN) and
// performs a single DNS exchange.
func (c *Client) exchangeOverTLCP(ctx context.Context, msg *dns.Msg, addr string, tlcpConfig *tlcp.Config, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	tlcpConn, err := c.dialTLCPConnForDOT(ctx, addr, tlcpConfig, proxyDialer)
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
