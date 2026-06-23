package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
)

func (c *Client) executeDoH3(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	client := c.getDoH3Client(parsedURL.Host, server.ServerName, server.SkipTLSVerify)
	if client == nil {
		client = c.createDoH3Client(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
	}

	return executeDoHHTTPRequest(ctx, msg, parsedURL, client)
}

func (c *Client) getDoH3Client(host, serverName string, skipVerify bool) *http.Client {
	c.doh3TransportMu.RLock()
	defer c.doh3TransportMu.RUnlock()
	return c.doh3Transports[transportKey(host, serverName, skipVerify)]
}

func (c *Client) createDoH3Client(host, serverName string, skipVerify bool, tlsConfig *tls.Config) *http.Client {
	c.doh3TransportMu.Lock()
	defer c.doh3TransportMu.Unlock()

	key := transportKey(host, serverName, skipVerify)
	if client, ok := c.doh3Transports[key]; ok {
		return client
	}

	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = config.NextProtoDoH3

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        config.Timeout,
			MaxIncomingStreams:    MaxIncomingStreams,
			MaxIncomingUniStreams: MaxIncomingStreams,
			EnableDatagrams:       true,
			Allow0RTT:             true,
		},
	}

	client := &http.Client{
		Timeout:   c.doh3Client.Timeout,
		Transport: transport,
	}
	c.doh3Transports[key] = client
	return client
}
