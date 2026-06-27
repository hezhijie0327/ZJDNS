package client

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
)

func (c *Client) executeTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
	proxyDialer := c.getProxyDialer(server)

	if c.dotPool != nil {
		pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			dialTLS := tlsConfig.Clone()
			dialTLS.NextProtos = []string{"dot"}

			// Establish the underlying TCP connection, optionally through a proxy.
			var tcpConn net.Conn
			var dialErr error
			if proxyDialer != nil {
				tcpConn, dialErr = proxyDialer.DialContext(dialCtx, "tcp", addr)
			} else {
				var nd net.Dialer
				tcpConn, dialErr = nd.DialContext(dialCtx, "tcp", addr)
			}
			if dialErr != nil {
				return nil, dialErr
			}

			// TLS handshake over the (possibly proxied) TCP connection.
			tlsConn := tls.Client(tcpConn, dialTLS)
			if err := tlsConn.HandshakeContext(dialCtx); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			return tlsConn, nil
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

	// Non-pooled fallback.
	dialTLS := tlsConfig.Clone()
	dialTLS.NextProtos = []string{"dot"}

	if proxyDialer != nil {
		tcpConn, err := proxyDialer.DialContext(ctx, "tcp", server.Address)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(tcpConn, dialTLS)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
		dnsConn := new(dns.Conn)
		dnsConn.Conn = tlsConn
		if err := dnsConn.WriteMsg(msg); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		return dnsConn.ReadMsg()
	}

	client := *c.tlsClient
	client.TLSConfig = dialTLS
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}
