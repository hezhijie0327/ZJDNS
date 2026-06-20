package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
	"zjdns/internal/pool"
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

	originalID := msg.Id
	msg.Id = 0

	buf, err := msg.Pack()
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	u := url.URL{
		Scheme:   parsedURL.Scheme,
		Host:     parsedURL.Host,
		Path:     parsedURL.Path,
		RawQuery: q.Encode(),
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := client.Do(httpReq)
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.Id = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, dns.MaxMsgSize))
	if err != nil {
		msg.Id = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	if err := response.Unpack(body); err != nil {
		msg.Id = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.Id = originalID
	response.Id = originalID

	return response, nil
}

func (c *Client) getDoH3Client(host, serverName string, skipVerify bool) *http.Client {
	c.doh3TransportMu.Lock()
	defer c.doh3TransportMu.Unlock()
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
	tlsCfg.NextProtos = NextProtoDoH3

	transport := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        config.IdleTimeout,
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
