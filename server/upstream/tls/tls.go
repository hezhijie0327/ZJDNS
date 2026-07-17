package tls

import (
	"context"
	"net"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	socks5 "zjdns/server/upstream/socks5"

	"codeberg.org/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"
)

// ExecuteTLS performs a DNS-over-TLS query, using the pipelined connection
// pool when available.
func (c *Client) ExecuteTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	proxyDialer := c.getProxy(server)

	dotConfig := c.eTLSClientConfig(server).Clone()
	dotConfig.NextProtos = config.NextProtoDOT

	if c.dotPool != nil {
		pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			return c.dialTLSConn(dialCtx, addr, dotConfig, proxyDialer)
		})
		if err == nil {
			response, err := pc.Exchange(ctx, msg)
			if err == nil {
				return response, nil
			}
			if pc.IsDead() {
				c.dotPool.Remove(pc)
			}
			log.Debugf("UPSTREAM: pipelined DoT query to %s failed: %v, falling back", server.Address, err)
		}
	}

	// Non-pooled fallback: manual dial + TLS + DNS exchange.
	return c.exchangeOverTLS(ctx, msg, server.Address, dotConfig, proxyDialer)
}

// dialTLSConn establishes a TCP connection (optionally proxied), performs a
// TLS handshake over it, and returns the resulting TLS connection.
func (c *Client) dialTLSConn(ctx context.Context, addr string, tlsConfig *eTLS.Config, proxyDialer *socks5.Dialer) (net.Conn, error) {
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
	tlsConn := eTLS.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// exchangeOverTLS dials a TLS connection and performs a single DNS exchange.
func (c *Client) exchangeOverTLS(ctx context.Context, msg *dns.Msg, addr string, tlsConfig *eTLS.Config, proxyDialer *socks5.Dialer) (*dns.Msg, error) {
	tlsConn, err := c.dialTLSConn(ctx, addr, tlsConfig, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tlsConn.Close() }()
	if _, err := msg.WriteTo(tlsConn); err != nil {
		return nil, err
	}
	response := pool.DefaultMessage.Get()
	if _, err := response.ReadFrom(tlsConn); err != nil {
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	if err := response.Unpack(); err != nil {
		pool.DefaultMessage.Put(response)
		return nil, err
	}
	return response, nil
}
