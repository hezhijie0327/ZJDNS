package client

import (
	"context"
	"net"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/smx509"
)

// tlcpClientConfig builds a gotlcp/tlcp Config for upstream TLCP connections.
// TLCP clients do not need certificates; CurveSM2 and the default TLCP cipher
// suites (ECC/ECDHE_SM4_GCM/CBC_SM3) are used.
func (c *Client) tlcpClientConfig(server *config.UpstreamServer) *tlcp.Config {
	return &tlcp.Config{
		CurvePreferences:   []tlcp.CurveID{tlcp.CurveSM2},
		InsecureSkipVerify: server.SkipTLSVerify,
		ServerName:         server.ServerName,
		RootCAs:            smx509.NewCertPool(), // prevent fallback to system pool (cannot parse SM2 certs)
	}
}

// dialTLCPConn establishes a TCP connection (optionally proxied), performs a
// TLCP handshake, and returns the resulting TLCP connection.
func (c *Client) dialTLCPConn(ctx context.Context, addr string, tlcpConfig *tlcp.Config, proxyDialer *SOCKS5Dialer) (net.Conn, error) {
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
func (c *Client) exchangeOverTLCP(ctx context.Context, msg *dns.Msg, addr string, tlcpConfig *tlcp.Config, proxyDialer *SOCKS5Dialer) (*dns.Msg, error) {
	tlcpConn, err := c.dialTLCPConn(ctx, addr, tlcpConfig, proxyDialer)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tlcpConn.Close() }()
	if _, err := msg.WriteTo(tlcpConn); err != nil {
		return nil, err
	}
	response := pool.DefaultMessagePool.Get()
	if _, err := response.ReadFrom(tlcpConn); err != nil {
		pool.DefaultMessagePool.Put(response)
		return nil, err
	}
	if err := response.Unpack(); err != nil {
		pool.DefaultMessagePool.Put(response)
		return nil, err
	}
	return response, nil
}

// executeTLCP performs a DoT-over-TLCP query. Uses a simple dial+exchange
// pattern without connection pooling in the MVP.
func (c *Client) executeTLCP(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlcpConfig *tlcp.Config) (*dns.Msg, error) {
	tlcpCfg := tlcpConfig.Clone()
	tlcpCfg.NextProtos = config.NextProtoDOT
	response, err := c.exchangeOverTLCP(ctx, msg, server.Address, tlcpCfg, c.getProxyDialer(server))
	if err != nil {
		log.Debugf("UPSTREAM: TLCP query to %s failed: %v", server.Address, err)
	}
	return response, err
}
