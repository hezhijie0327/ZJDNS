package tls

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"zjdns/config"
	"zjdns/internal/pool"

	"codeberg.org/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

// ExecuteDOHHTTPRequest is the shared DoH/DoH3 request logic. Both ExecuteDOH
// and ExecuteDOH3 differ only in which *http.Client they construct (HTTP/2 vs
// HTTP/3 transport); the HTTP request/response dance is identical.
func ExecuteDOHHTTPRequest(ctx context.Context, msg *dns.Msg, u *url.URL, httpClient *http.Client) (*dns.Msg, error) {
	originalID := msg.ID
	msg.ID = 0

	err := msg.Pack()
	buf := msg.Data
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Build the DoH GET URL manually with strings.Builder.
	encLen := base64.RawURLEncoding.EncodedLen(len(buf))
	var urlBuf strings.Builder
	urlBuf.Grow(len(u.Scheme) + 3 + len(u.Host) + len(u.Path) + 5 + encLen)
	urlBuf.WriteString(u.Scheme)
	urlBuf.WriteString("://")
	urlBuf.WriteString(u.Host)
	urlBuf.WriteString(u.Path)
	urlBuf.WriteString("?dns=")
	urlBuf.WriteString(base64.RawURLEncoding.EncodeToString(buf))

	method := http.MethodGet
	if _, ok := httpClient.Transport.(*http3Transport); ok {
		method = http3.MethodGet0RTT
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, urlBuf.String(), http.NoBody)
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
