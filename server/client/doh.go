package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	eTLS "gitlab.com/go-extension/tls"

	"github.com/miekg/dns"

	"zjdns/config"
)

func (c *Client) executeDoH(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *eTLS.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	key := transportKey(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy)

	client, isCached := c.getDoHClient(key)
	if !isCached {
		client = c.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
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
		for i := 0; shouldRetryHTTP(err) && i < config.DefaultSecureTransportRetries; i++ {
			c.dohTransportMu.Lock()
			if old, ok := c.dohTransports[key]; ok && old == client {
				if t, ok := old.Transport.(*http.Transport); ok {
					t.CloseIdleConnections()
				}
				delete(c.dohTransports, key)
			}
			c.dohTransportMu.Unlock()

			client = c.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, server.Proxy, tlsConfig)
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

func transportKey(host, serverName string, skipVerify bool, proxyURL string) string {
	key := fmt.Sprintf("%s|%s|%t", host, serverName, skipVerify)
	if proxyURL != "" {
		key += "|" + proxyURL
	}
	return key
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

func (c *Client) createDoHClient(host, serverName string, skipVerify bool, proxyURL string, tlsConfig *eTLS.Config) *http.Client {
	c.dohTransportMu.Lock()
	defer c.dohTransportMu.Unlock()

	key := transportKey(host, serverName, skipVerify, proxyURL)
	if client, ok := c.dohTransports[key]; ok {
		return client
	}

	// Evict oldest entry when at capacity.
	if len(c.dohTransports) >= config.DefaultTransportMax {
		for k := range c.dohTransports {
			if t, ok := c.dohTransports[k].Transport.(*http.Transport); ok {
				t.CloseIdleConnections()
			}
			delete(c.dohTransports, k)
			break
		}
	}

	transport := c.dohClient.Transport.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		tcpConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cfg := tlsConfig.Clone()
		cfg.ServerName = serverName
		eTLSConn := eTLS.Client(tcpConn, cfg)
		if err := eTLSConn.HandshakeContext(ctx); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
		return eTLSConn, nil
	}

	// Route through SOCKS5 proxy when configured.
	if proxyURL != "" {
		proxyDialer := c.getProxyDialer(&config.UpstreamServer{Proxy: proxyURL})
		if proxyDialer != nil {
			transport.DialContext = proxyDialer.DialContext
		}
	}

	client := &http.Client{
		Timeout:   c.dohClient.Timeout,
		Transport: transport,
	}
	c.dohTransports[key] = client
	return client
}
