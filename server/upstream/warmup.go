package upstream

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"
	socks5 "zjdns/server/upstream/socks5"
)

// proxyErrorWarned deduplicates the invalid-proxy warning: the failure is
// deliberately not cached (see proxyDialer), so without a per-address gate
// every query under a bad proxy configuration would print a Warn.
var proxyErrorWarned sync.Map // address → struct{}{}

// proxyDialer returns a cached SOCKS5Dialer for the server's proxy URL.
func (c *Client) proxyDialer(server *config.UpstreamServer) *socks5.Dialer {
	if server.Proxy == "" {
		return nil
	}

	if c.proxyDialers == nil {
		return nil
	}

	if d, ok := c.proxyDialers.Get(server.Proxy); ok {
		return d
	}

	d, err := socks5.New(server.Proxy, c.timeout)
	if err != nil {
		// Redact credentials: the URL may contain socks5://user:pass@host.
		if u, parseErr := url.Parse(server.Proxy); parseErr == nil {
			logProxyError(server.Address, fmt.Sprintf("invalid proxy %s: %v", "socks5://"+u.Host, err))
		} else {
			logProxyError(server.Address, fmt.Sprintf("invalid proxy: %v", err))
		}
		// Do NOT cache the failure: a nil dialer in the LRU would poison the
		// entry (and its OnEvict close would be skipped), blocking later
		// retries if the proxy URL is fixed.
		return nil
	}
	c.proxyDialers.Set(server.Proxy, d)
	return d
}

// logProxyError warns about an invalid proxy once per upstream address;
// subsequent failures degrade to Debug.
func logProxyError(serverAddr, msg string) {
	if _, loaded := proxyErrorWarned.LoadOrStore(serverAddr, struct{}{}); !loaded {
		log.Warnf("UPSTREAM: %s (for %s)", msg, serverAddr)
	} else {
		log.Debugf("UPSTREAM: %s (for %s)", msg, serverAddr)
	}
}

// WarmUpConnections asynchronously pre-establishes transport-level connections
// to all configured secure upstream servers.
func (c *Client) WarmUpConnections(ctx context.Context, servers []config.UpstreamServer) {
	for i := range servers {
		if servers[i].IsRecursive() {
			continue
		}
		protocol := strings.ToLower(servers[i].Protocol)
		if !zdnsutil.IsSecureProtocol(protocol) {
			continue
		}
		// Copy the element: the goroutine must own its data — a pointer into
		// the caller's backing array races with any later mutation/append of
		// that slice by the caller.
		s := servers[i]
		c.warmWg.Go(func() {
			defer zdnsutil.HandlePanic("connection pre-warm")
			warmCtx, cancel := context.WithTimeout(ctx, c.timeout)
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
	case config.ProtoHTTPS:
		c.tlsClient.WarmUpHTTPS(ctx, server)
	case config.ProtoHTTP3:
		c.tlsClient.WarmUpHTTP3(ctx, server)
	case config.ProtoDNSCrypt, config.ProtoDNSCryptTCP:
		c.dnscryptClient.WarmUp(ctx, server)
	default:
		// DTLS / DTLCP / TLCP / HTTP-TLCP have no pre-warm implementation
		// yet — their first query pays the full handshake. Named explicitly
		// so the warm-up claim does not silently no-op for them.
		log.Debugf("UPSTREAM: no warm-up implemented for %s (%s)", server.Address, protocol)
	}
}
