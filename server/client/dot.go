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
	key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify)

	if c.dotPool != nil {
		pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			dialer := tls.Dialer{Config: tlsConfig.Clone()}
			return dialer.DialContext(dialCtx, "tcp", addr)
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

	client := *c.tlsClient
	client.TLSConfig = tlsConfig
	response, _, err := client.ExchangeContext(ctx, msg, server.Address)
	return response, err
}
