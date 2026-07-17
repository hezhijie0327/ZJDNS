package dnsutil

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

// ExecuteDoHRequest sends a DNS query via DoH GET and returns the response.
// It is shared by the TLS and TLCP upstream clients.  The httpMethod parameter
// allows callers to use GET (HTTP/2) or GET0RTT (HTTP/3).
func ExecuteDoHRequest(ctx context.Context, msg *dns.Msg, u *url.URL, httpClient *http.Client, httpMethod string) (*dns.Msg, error) {
	originalID := msg.ID
	msg.ID = 0

	err := msg.Pack()
	buf := msg.Data
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}

	// Build the DoH GET URL manually — dnshttp.NewRequest appends /dns-query
	// unconditionally, but ZJDNS URLs already include the full path.  Also
	// dnshttp.NewRequest only supports GET/POST, not GET0RTT (HTTP/3).
	encLen := base64.RawURLEncoding.EncodedLen(len(buf))
	var urlBuf strings.Builder
	urlBuf.Grow(len(u.Scheme) + 3 + len(u.Host) + len(u.Path) + 5 + encLen)
	urlBuf.WriteString(u.Scheme)
	urlBuf.WriteString("://")
	urlBuf.WriteString(u.Host)
	urlBuf.WriteString(u.Path)
	urlBuf.WriteString("?dns=")
	urlBuf.WriteString(base64.RawURLEncoding.EncodeToString(buf))

	httpReq, err := http.NewRequestWithContext(ctx, httpMethod, urlBuf.String(), http.NoBody)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Accept", dnshttp.MimeType)
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

	// Use LimitReader to cap response body size, then delegate to the library.
	httpResp.Body = io.NopCloser(io.LimitReader(httpResp.Body, dns.MaxMsgSize))

	response, err := dnshttp.Response(httpResp)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("parse response: %w", err)
	}

	msg.ID = originalID
	response.ID = originalID

	return response, nil
}

// ServerDOHMsgAccept is a drop-in for dnshttp.MsgAcceptFunc that accepts
// non-zero DNS message IDs.  The library default rejects queries with non-zero
// IDs (designed for proxy/forwarder use per RFC 8484 §7), but real DNS clients
// always generate legitimate IDs — rejecting them would break server-side DoH.
func ServerDOHMsgAccept(m *dns.Msg) dns.MsgAcceptAction {
	if m.Response {
		return dns.MsgIgnore
	}
	if _, ok := dns.OpcodeToString[m.Opcode]; !ok {
		return dns.MsgRejectNotImplemented
	}
	if len(m.Question) != 1 {
		return dns.MsgReject
	}
	for _, o := range m.Pseudo {
		if _, ok := o.(*dns.TCPKEEPALIVE); ok {
			return dns.MsgReject
		}
	}
	return dns.MsgAccept
}
