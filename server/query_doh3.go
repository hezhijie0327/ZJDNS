package server

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

// executeDoH3 executes a DNS query over DNS over HTTPS/3 (DoH3/HTTP3).
// Uses a cached transport pool to avoid per-query transport creation.
func (qc *QueryClient) executeDoH3(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	client := qc.getDoH3Client(parsedURL.Host, server.ServerName, server.SkipTLSVerify)
	if client == nil {
		client = qc.createDoH3Client(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
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

// getDoH3Client retrieves a cached DoH3 HTTP client, or nil if not present.
func (qc *QueryClient) getDoH3Client(host, serverName string, skipVerify bool) *http.Client {
	qc.doh3TransportMu.Lock()
	defer qc.doh3TransportMu.Unlock()
	return qc.doh3Transports[dohTransportKey(host, serverName, skipVerify)]
}

// createDoH3Client builds and caches a DoH3 HTTP client for the given parameters.
func (qc *QueryClient) createDoH3Client(host, serverName string, skipVerify bool, tlsConfig *tls.Config) *http.Client {
	qc.doh3TransportMu.Lock()
	defer qc.doh3TransportMu.Unlock()

	key := dohTransportKey(host, serverName, skipVerify)
	if client, ok := qc.doh3Transports[key]; ok {
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
		Timeout:   qc.doh3Client.Timeout,
		Transport: transport,
	}
	qc.doh3Transports[key] = client
	return client
}
