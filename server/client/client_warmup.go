package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"github.com/quic-go/quic-go"
)

// getQUICConfig returns a cached QUIC config for the given upstream key, creating
// one with a TokenStore if none exists.
func (c *Client) getQUICConfig(key string, skipVerify bool) *quic.Config {
	c.quicConfigsMu.Lock()
	defer c.quicConfigsMu.Unlock()
	if cfg, ok := c.quicConfigs[key]; ok {
		return cfg
	}
	if len(c.quicConfigs) >= config.DefaultTransportMax {
		for k := range c.quicConfigs {
			delete(c.quicConfigs, k)
			break
		}
	}
	cfg := &quic.Config{
		MaxIdleTimeout:        config.DefaultQUICClientIdleTimeout,
		MaxIncomingStreams:    config.DefaultMaxIncomingStreams,
		MaxIncomingUniStreams: config.DefaultMaxIncomingStreams,
		EnableDatagrams:       true,
		Allow0RTT:             !skipVerify,
		KeepAlivePeriod:       config.DefaultQUICKeepAlive,
		TokenStore:            quic.NewLRUTokenStore(config.DefaultTokenStoreCapacity, config.DefaultTokenStoreMaxEntries),
	}
	c.quicConfigs[key] = cfg
	return cfg
}

// resetQUICConfig recreates the TokenStore for the given upstream key on
// 0-RTT rejection.
func (c *Client) resetQUICConfig(key string) {
	c.quicConfigsMu.Lock()
	defer c.quicConfigsMu.Unlock()
	cfg, ok := c.quicConfigs[key]
	if !ok {
		return
	}
	cfg = cfg.Clone()
	cfg.TokenStore = quic.NewLRUTokenStore(config.DefaultTokenStoreCapacity, config.DefaultTokenStoreMaxEntries)
	c.quicConfigs[key] = cfg
}

// getProxyDialer returns a cached SOCKS5Dialer for the server's proxy URL.
func (c *Client) getProxyDialer(server *config.UpstreamServer) *SOCKS5Dialer {
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

	d, err := NewSOCKS5Dialer(server.Proxy, c.timeout)
	if err != nil {
		log.Warnf("UPSTREAM: invalid proxy %s for %s: %v", d.SafeURL(), server.Address, err)
		c.proxyDialers[server.Proxy] = nil
		return nil
	}
	c.proxyDialers[server.Proxy] = d
	return d
}

// proxyPoolKey returns a pool key that isolates proxied and non-proxied
// connections to the same upstream.
func proxyPoolKey(baseKey, proxyURL string) string {
	if proxyURL == "" {
		return baseKey
	}
	return baseKey + "|" + proxyURL
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
	case config.ProtoDOT, config.ProtoTLS:
		key := transportKey(server.Address, server.ServerName, server.SkipTLSVerify, server.Proxy)
		proxyDialer := c.getProxyDialer(server)
		dotConfig := c.eTLSClientConfig(server).Clone()
		dotConfig.NextProtos = config.NextProtoDOT
		if c.dotPool != nil {
			pc, err := c.dotPool.Acquire(ctx, key, server.Address, func(dialCtx context.Context, addr string) (net.Conn, error) {
				return c.dialTLSConn(dialCtx, addr, dotConfig, proxyDialer)
			})
			if err != nil {
				log.Debugf("UPSTREAM: pre-warm DoT to %s: %v", server.Address, err)
				return
			}
			_ = pc
			log.Debugf("UPSTREAM: pre-warmed DoT connection to %s", server.Address)
		}

	case config.ProtoDOQ, config.ProtoQUIC:
		poolKey := proxyPoolKey(server.Address, server.Proxy)
		proxyDialer := c.getProxyDialer(server)
		dialTLS := c.stdTLSConfig(server).Clone()
		dialTLS.NextProtos = config.NextProtoDOQ
		if c.quicPool != nil {
			_, err := c.quicPool.Acquire(ctx, poolKey, func(dialCtx context.Context, addr string) (*quic.Conn, error) {
				timeoutCtx, cancel := context.WithTimeout(dialCtx, config.DefaultDNSQueryTimeout)
				defer cancel()
				if proxyDialer != nil {
					pconn, err := proxyDialer.ListenPacket(timeoutCtx)
					if err != nil {
						return nil, fmt.Errorf("proxy ListenPacket: %w", err)
					}
					remoteAddr, err := net.ResolveUDPAddr("udp", addr)
					if err != nil {
						return nil, fmt.Errorf("resolve %s: %w", addr, err)
					}
					return quic.Dial(timeoutCtx, pconn, remoteAddr, dialTLS, c.getQUICConfig("doq:"+addr, dialTLS.InsecureSkipVerify))
				}
				return quic.DialAddrEarly(timeoutCtx, addr, dialTLS, c.getQUICConfig("doq:"+addr, dialTLS.InsecureSkipVerify))
			})
			if err != nil {
				log.Debugf("UPSTREAM: pre-warm DoQ to %s: %v", server.Address, err)
				return
			}
			log.Debugf("UPSTREAM: pre-warmed DoQ connection to %s", server.Address)
		}

	case config.ProtoDOH, config.ProtoHTTP:
		parsedURL, err := url.Parse(server.Address)
		if err != nil {
			log.Debugf("UPSTREAM: pre-warm DoH parse %s: %v", server.Address, err)
			return
		}
		if parsedURL.Port() == "" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
		}
		key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
		tlsConfig := c.eTLSClientConfig(server)
		c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
		log.Debugf("UPSTREAM: pre-warmed DoH transport for %s (key=%s)", server.Address, key)

	case config.ProtoDOH3, config.ProtoHTTP3:
		parsedURL, err := url.Parse(server.Address)
		if err != nil {
			log.Debugf("UPSTREAM: pre-warm DoH3 parse %s: %v", server.Address, err)
			return
		}
		if parsedURL.Port() == "" {
			parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
		}
		key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
		tlsConfig := c.stdTLSConfig(server)
		c.createDOH3Client(key, parsedURL.Host, server.Proxy, tlsConfig)
		log.Debugf("UPSTREAM: pre-warmed DoH3 transport for %s (key=%s)", server.Address, key)

	case config.ProtoDNSCrypt, config.ProtoDNSCryptTCP:
		warmCtx, cancel := context.WithTimeout(context.Background(), c.timeout)
		defer cancel()
		c.warmUpDNSCrypt(warmCtx, server)
	}
}
