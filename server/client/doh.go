package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"zjdns/config"

	"codeberg.org/miekg/dns"
	eHTTP "gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
)

func (c *Client) executeDOH(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *eTLS.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)

	client, isCached := c.getDOHClient(key)
	if !isCached {
		client = c.createDOHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
	}

	// First attempt with the cached client.
	resp, err := executeDOHHTTPRequest(ctx, msg, parsedURL, client)
	if err == nil {
		return resp, nil
	}

	// If the cached client failed, recreate and retry up to 2 times.
	// This handles cases where idle connections were closed by the server
	// or a network change broke the existing H2 connection.
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
			resp, err = executeDOHHTTPRequest(ctx, msg, parsedURL, client)
			if err == nil {
				return resp, nil
			}
		}
	}

	if err != nil {
		// Clean up the failed transport so the next query starts fresh.
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
// and retrying. Timeout errors often indicate a network change that broke the
// keep-alive connection.
func shouldRetryHTTP(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func (c *Client) createDOHClient(host, serverName string, skipVerify bool, proxyURL string, tlsConfig *eTLS.Config) *http.Client {
	c.dohTransportMu.Lock()
	defer c.dohTransportMu.Unlock()

	// Guard against concurrent Close() which sets dohTransports to nil.
	if c.dohTransports == nil {
		return &http.Client{Timeout: c.dohClient.Timeout, Transport: &eHTTP.CompatableTransport{Transport: c.dohClient.Transport.(*eHTTP.Transport)}}
	}

	key := transportKey(host, serverName, skipVerify, proxyURL)
	if client, ok := c.dohTransports[key]; ok {
		return client
	}

	// Evict oldest entry when at capacity.
	if len(c.dohTransports) >= config.DefaultTransportMax {
		for k := range c.dohTransports {
			if ct, ok := c.dohTransports[k].Transport.(*eHTTP.CompatableTransport); ok {
				ct.CloseIdleConnections()
			}
			delete(c.dohTransports, k)
			break
		}
	}

	// Extension http's Transport uses eTLS natively — we set TLSClientConfig
	// instead of wiring up DialTLSContext manually.
	transport := c.dohClient.Transport.(*eHTTP.Transport).Clone()
	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = config.NextProtoDOH
	tlsCfg.ServerName = serverName
	transport.TLSClientConfig = tlsCfg

	// Route through SOCKS5 proxy when configured. When no proxy, set up
	// DialContext with TCP keep-alive to detect dead connections.
	if proxyURL != "" {
		proxyDialer := c.getProxyDialer(&config.UpstreamServer{Proxy: proxyURL})
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

	// Wrap in CompatibleTransport so the client exposes net/http.RoundTripper
	// for the shared executeDOHHTTPRequest.
	client := &http.Client{
		Timeout:   c.dohClient.Timeout,
		Transport: &eHTTP.CompatableTransport{Transport: transport},
	}
	c.dohTransports[key] = client
	return client
}
