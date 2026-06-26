package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

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

	client := c.getDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify)
	if client == nil {
		client = c.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
	}

	return executeDoHHTTPRequest(ctx, msg, parsedURL, client)
}

func transportKey(host, serverName string, skipVerify bool) string {
	return fmt.Sprintf("%s|%s|%t", host, serverName, skipVerify)
}

func (c *Client) getDoHClient(host, serverName string, skipVerify bool) *http.Client {
	c.dohTransportMu.RLock()
	defer c.dohTransportMu.RUnlock()
	return c.dohTransports[transportKey(host, serverName, skipVerify)]
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
	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Timeout:   c.dohClient.Timeout,
		Transport: transport,
	}
	c.dohTransports[key] = client
	return client
}
