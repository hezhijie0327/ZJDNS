package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"

	"zjdns/config"
)

func (c *Client) executeDoH(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify)

	client, isCached := c.getDoHClient(key)
	if !isCached {
		client = c.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
	}

	// First attempt with the cached client.
	resp, err := executeDoHHTTPRequest(ctx, msg, parsedURL, client)
	if err == nil {
		return resp, nil
	}

	// If the cached client failed, recreate and retry up to 2 times.
	// This handles cases where idle connections were closed by the server
	// or a network change broke the existing H2 connection.
	if isCached {
		for i := 0; shouldRetryHTTP(err) && i < 2; i++ {
			c.dohTransportMu.Lock()
			if old, ok := c.dohTransports[key]; ok && old == client {
				if t, ok := old.Transport.(*http.Transport); ok {
					t.CloseIdleConnections()
				}
				delete(c.dohTransports, key)
			}
			c.dohTransportMu.Unlock()

			client = c.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
			resp, err = executeDoHHTTPRequest(ctx, msg, parsedURL, client)
			if err == nil {
				return resp, nil
			}
		}
	}

	if err != nil {
		// Clean up the failed transport so the next query starts fresh.
		c.dohTransportMu.Lock()
		if old, ok := c.dohTransports[key]; ok && old == client {
			if t, ok := old.Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			delete(c.dohTransports, key)
		}
		c.dohTransportMu.Unlock()
	}

	return resp, err
}

func transportKey(host, serverName string, skipVerify bool) string {
	return fmt.Sprintf("%s|%s|%t", host, serverName, skipVerify)
}

func (c *Client) getDoHClient(key string) (*http.Client, bool) {
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

func (c *Client) createDoHClient(host, serverName string, skipVerify bool, tlsConfig *tls.Config) *http.Client {
	c.dohTransportMu.Lock()
	defer c.dohTransportMu.Unlock()

	key := transportKey(host, serverName, skipVerify)
	if client, ok := c.dohTransports[key]; ok {
		return client
	}

	// Evict oldest entry when at capacity (32).
	const transportMax = 32
	if len(c.dohTransports) >= transportMax {
		for k := range c.dohTransports {
			if t, ok := c.dohTransports[k].Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			delete(c.dohTransports, k)
			break
		}
	}

	transport := c.dohClient.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig.Clone()
	h2Transport, err := http2.ConfigureTransports(transport)
	if err == nil {
		// Send HTTP/2 pings on idle connections to keep NAT bindings alive
		// and detect dead peers early.
		h2Transport.ReadIdleTimeout = 30 * time.Second
	}

	client := &http.Client{
		Timeout:   c.dohClient.Timeout,
		Transport: transport,
	}
	c.dohTransports[key] = client
	return client
}
