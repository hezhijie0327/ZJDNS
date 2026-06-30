package client

import (
	"context"
	"net"

	"github.com/miekg/dns"
	eTLS "gitlab.com/go-extension/tls"

	"zjdns/config"
	"zjdns/internal/log"
)

func (c *Client) executeTLS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *eTLS.Config) (*dns.Msg, error) {
	key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify)

	// Clone once for this call — the pooled closure and fallback path share it.
	dotConfig := tlsConfig.Clone()
	dotConfig.NextProtos = []string{"dot"}

	if c.dotPool != nil {
		pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
			return c.dialTLSConn(dialCtx, addr, dotConfig)
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
	return c.exchangeOverTLS(ctx, msg, server.Address, dotConfig)
}
