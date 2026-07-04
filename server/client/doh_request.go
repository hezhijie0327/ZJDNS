package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	"zjdns/config"
	"zjdns/internal/pool"
)

// executeDOHHTTPRequest is the shared DoH/DoH3 request logic.
// Both executeDOH and executeDOH3 differ only in which *http.Client they
// construct (HTTP/2 vs HTTP/3 transport); the HTTP request/response dance
// is identical. This function factors out that common body.
func executeDOHHTTPRequest(ctx context.Context, msg *dns.Msg, u *url.URL, httpClient *http.Client) (*dns.Msg, error) {
	originalID := msg.ID
	msg.ID = 0

	err := msg.Pack()
	buf := msg.Data
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	q := url.Values{"dns": []string{base64.RawURLEncoding.EncodeToString(buf)}}
	requestURL := url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: q.Encode(),
	}

	// Use http3.MethodGet0RTT for HTTP/3 transports so the request is sent as
	// 0-RTT early data, skipping a round-trip on reconnections.
	method := http.MethodGet
	if _, ok := httpClient.Transport.(*http3Transport); ok {
		method = http3.MethodGet0RTT
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, requestURL.String(), nil)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", config.DOHContentType)
	httpReq.Header.Set("User-Agent", "")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		msg.ID = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(httpResp.Body, dns.MaxMsgSize))
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("read body: %w", err)
	}

	response := pool.DefaultMessagePool.Get()
	response.Data = body
	if err := response.Unpack(); err != nil {
		msg.ID = originalID
		pool.DefaultMessagePool.Put(response)
		return nil, fmt.Errorf("unpack: %w", err)
	}

	msg.ID = originalID
	response.ID = originalID

	return response, nil
}
