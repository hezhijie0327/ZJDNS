package upstream

import (
	"context"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"
	socks5 "zjdns/server/upstream/socks5"
)

// getProxyDialer returns a cached SOCKS5Dialer for the server's proxy URL.
func (c *Client) getProxyDialer(server *config.UpstreamServer) *socks5.Dialer {
	if server.Proxy == "" {
		return nil
	}

	c.proxyMu.Lock()
	defer c.proxyMu.Unlock()

	if c.proxyDialers == nil {
		return nil
	}

	if d, ok := c.proxyDialers[server.Proxy]; ok {
		return d
	}

	if len(c.proxyDialers) >= config.DefaultTransportMax {
		for k, d := range c.proxyDialers {
			if d != nil {
				_ = d.Close()
			}
			delete(c.proxyDialers, k)
			break
		}
	}

	d, err := socks5.New(server.Proxy, c.timeout)
	if err != nil {
		log.Warnf("UPSTREAM: invalid proxy %s for %s: %v", d.SafeURL(), server.Address, err)
		c.proxyDialers[server.Proxy] = nil
		return nil
	}
	c.proxyDialers[server.Proxy] = d
	return d
}

// WarmUpConnections asynchronously pre-establishes transport-level connections
// to all configured secure upstream servers.
func (c *Client) WarmUpConnections(servers []config.UpstreamServer) {
	for _, server := range servers {
		if server.IsRecursive() {
			continue
		}
		protocol := strings.ToLower(server.Protocol)
		if !zdnsutil.IsSecureProtocol(protocol) && protocol != config.ProtoDNSCrypt && protocol != config.ProtoDNSCryptTCP {
			continue
		}
		s := server
		c.warmWg.Go(func() {
			defer zdnsutil.HandlePanic("connection pre-warm")
			warmCtx, cancel := context.WithTimeout(context.Background(), c.timeout)
			defer cancel()
			c.warmUpConnection(warmCtx, &s, protocol)
		})
	}
}

func (c *Client) warmUpConnection(ctx context.Context, server *config.UpstreamServer, protocol string) {
	switch protocol {
	case config.ProtoTLS:
		c.tlsClient.WarmUpTLS(ctx, server)
	case config.ProtoQUIC:
		c.tlsClient.WarmUpQUIC(ctx, server)
	case config.ProtoHTTP:
		c.tlsClient.WarmUpDOH(ctx, server)
	case config.ProtoHTTP3:
		c.tlsClient.WarmUpDOH3(ctx, server)
	case config.ProtoDNSCrypt, config.ProtoDNSCryptTCP:
		c.dnscrypt.WarmUp(ctx, server)
	}
}
