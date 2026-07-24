package tls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

// ExecuteHTTPS performs a DNS-over-HTTPS query (HTTP/2), using cached
// transports with automatic retry on connection failure.
func (c *Client) ExecuteHTTPS(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultHTTPSPort)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)
	tlsConfig := c.eTLSClientConfig(server)

	client, isCached := c.getDOHClient(key)
	if !isCached {
		client = c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
	}

	resp, err := zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http.MethodGet)
	if err == nil {
		return resp, nil
	}

	if isCached {
		for i := 0; shouldRetryHTTP(err) && i < config.DefaultSecureTransportRetries; i++ {
			c.dohTransportMu.Lock()
			if old, ok := c.dohTransports[key]; ok && old == client {
				if ct, ok := old.Transport.(*eHTTP.CompatableTransport); ok {
					ct.CloseIdleConnections()
				}
				delete(c.dohTransports, key)
			}
			c.dohTransportMu.Unlock()

			client = c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
			resp, err = zdnsutil.ExecuteDoHRequest(ctx, msg, parsedURL, client, http.MethodGet)
			if err == nil {
				return resp, nil
			}
		}
	}

	if err != nil {
		c.dohTransportMu.Lock()
		if old, ok := c.dohTransports[key]; ok && old == client {
			if ct, ok := old.Transport.(*eHTTP.CompatableTransport); ok {
				ct.CloseIdleConnections()
			}
			delete(c.dohTransports, key)
		}
		c.dohTransportMu.Unlock()
	}

	return resp, err
}

// transportKey builds a cache key for transport-level connection pools
// (DoH, DoH3, DoT). The key combines host, server name, TLS verification
// setting, and optional proxy URL.
func transportKey(host, serverName string, skipVerify bool, proxyURL string) string {
	var b strings.Builder
	b.Grow(len(host) + len(serverName) + len(proxyURL) + 16)
	b.WriteString(host)
	b.WriteByte('|')
	b.WriteString(serverName)
	b.WriteByte('|')
	if skipVerify {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	if proxyURL != "" {
		b.WriteByte('|')
		b.WriteString(proxyURL)
	}
	return b.String()
}

func (c *Client) getDOHClient(key string) (*http.Client, bool) {
	c.dohTransportMu.RLock()
	defer c.dohTransportMu.RUnlock()
	client, ok := c.dohTransports[key]
	return client, ok
}

// shouldRetryHTTP checks whether an HTTP/2 error warrants recreating the client
// and retrying.
func shouldRetryHTTP(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Also retry on transient operation errors (connection reset, etc.).
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Temporary() {
		return true
	}
	return false
}

func (c *Client) createDOHClient(host, serverName string, skipVerify bool, proxyURL string, tlsConfig *eTLS.Config) *http.Client {
	c.dohTransportMu.Lock()
	defer c.dohTransportMu.Unlock()

	if c.dohTransports == nil {
		return &http.Client{Timeout: c.dohClient.Timeout, Transport: &eHTTP.CompatableTransport{Transport: c.dohClient.Transport.(*eHTTP.Transport)}}
	}

	key := transportKey(host, serverName, skipVerify, proxyURL)
	if client, ok := c.dohTransports[key]; ok {
		return client
	}

	if len(c.dohTransports) >= config.DefaultTransportMax*2 {
		// Evict one entry when over threshold.  Under concurrent access the map
		// may temporarily exceed the limit, which is acceptable.
		for k := range c.dohTransports {
			if ct, ok := c.dohTransports[k].Transport.(*eHTTP.CompatableTransport); ok {
				ct.CloseIdleConnections()
			}
			delete(c.dohTransports, k)
			break
		}
	}

	transport := c.dohClient.Transport.(*eHTTP.Transport).Clone()
	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = config.NextProtoDOH
	tlsCfg.ServerName = serverName
	transport.TLSClientConfig = tlsCfg

	if proxyURL != "" {
		proxyDialer := c.getProxy(&config.UpstreamServer{Proxy: proxyURL})
		if proxyDialer != nil {
			transport.DialContext = proxyDialer.DialContext
		}
	} else {
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetKeepAlive(true)
				_ = tc.SetKeepAlivePeriod(config.DefaultTCPKeepAlivePeriod)
			}
			return conn, nil
		}
	}

	client := &http.Client{
		Timeout:   c.dohClient.Timeout,
		Transport: &eHTTP.CompatableTransport{Transport: transport},
	}
	c.dohTransports[key] = client
	return client
}
