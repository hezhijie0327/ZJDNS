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
	"golang.org/x/net/http2"

	"zjdns/config"
	"zjdns/internal/pool"
)

// executeDoH executes a DNS query over DNS over HTTPS (DoH/HTTP2).
// Uses a cached transport pool keyed by (address, serverName, skipVerify) to avoid
// per-query transport cloning.
func (qc *QueryClient) executeDoH(ctx context.Context, msg *dns.Msg, server *config.UpstreamServer, tlsConfig *tls.Config) (*dns.Msg, error) {
	parsedURL, err := url.Parse(server.Address)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}

	if parsedURL.Port() == "" {
		parsedURL.Host = net.JoinHostPort(parsedURL.Host, config.DefaultDOHPort)
	}

	client := qc.getDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify)
	if client == nil {
		client = qc.createDoHClient(parsedURL.Host, server.ServerName, server.SkipTLSVerify, tlsConfig)
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

// dohTransportKey builds a cache key for DoH transport pooling.
func dohTransportKey(host, serverName string, skipVerify bool) string {
	return fmt.Sprintf("%s|%s|%t", host, serverName, skipVerify)
}

// getDoHClient retrieves a cached DoH HTTP client, or nil if not present.
func (qc *QueryClient) getDoHClient(host, serverName string, skipVerify bool) *http.Client {
	qc.dohTransportMu.Lock()
	defer qc.dohTransportMu.Unlock()
	return qc.dohTransports[dohTransportKey(host, serverName, skipVerify)]
}

// createDoHClient builds and caches a DoH HTTP client for the given parameters.
func (qc *QueryClient) createDoHClient(host, serverName string, skipVerify bool, tlsConfig *tls.Config) *http.Client {
	qc.dohTransportMu.Lock()
	defer qc.dohTransportMu.Unlock()

	key := dohTransportKey(host, serverName, skipVerify)
	if client, ok := qc.dohTransports[key]; ok {
		return client
	}

	transport := qc.dohClient.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig.Clone()
	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Timeout:   qc.dohClient.Timeout,
		Transport: transport,
	}
	qc.dohTransports[key] = client
	return client
}
