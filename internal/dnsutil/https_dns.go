package dnsutil

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
)

// bodyCloser wraps a LimitReader while preserving the original body Close
// so deferred cleanup drains the HTTP connection for keep-alive reuse.
type bodyCloser struct {
	io.Reader
	io.Closer
}

// ExecuteDoHRequest sends a DNS query via DoH GET and returns the response.
// It is shared by the TLS and TLCP upstream clients.  The httpMethod parameter
// allows callers to use GET (HTTP/2) or GET0RTT (HTTP/3).
func ExecuteDoHRequest(ctx context.Context, msg *dns.Msg, u *url.URL, httpClient *http.Client, httpMethod string) (*dns.Msg, error) {
	originalID := msg.ID
	msg.ID = 0

	err := msg.Pack()
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("pack: %w", err)
	}
	buf := append([]byte{}, msg.Data...) // copy to break aliasing with pooled msg.Data

	// Build the DoH GET URL by cloning the upstream URL and setting the dns
	// query parameter — dnshttp.NewRequest appends /dns-query unconditionally,
	// but ZJDNS URLs already include the full path; it also only supports
	// GET/POST, not GET0RTT (HTTP/3). NOTE: the caller's own RawQuery (e.g.
	// "?param=value" on the upstream URL) is replaced, not merged — the dns
	// parameter is the DoH query.
	q := *u // shallow copy — caller's URL must not be mutated
	q.RawQuery = "dns=" + base64.RawURLEncoding.EncodeToString(buf)

	httpReq, err := http.NewRequestWithContext(ctx, httpMethod, q.String(), http.NoBody)
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
	defer func() { _ = httpResp.Body.Close() }() // _ = error: body close after read, best-effort

	if httpResp.StatusCode != http.StatusOK {
		msg.ID = originalID
		return nil, fmt.Errorf("HTTP status: %d", httpResp.StatusCode)
	}

	// Use LimitReader to cap response body size, then delegate to the library.
	// Wrap the original body so Close() drains the connection — NopCloser alone
	// would leak HTTP/1.x keep-alive connections because Close() is a no-op.
	httpResp.Body = &bodyCloser{Reader: io.LimitReader(httpResp.Body, dns.MaxMsgSize), Closer: httpResp.Body}

	response, err := dnshttp.Response(httpResp)
	if err != nil {
		msg.ID = originalID
		return nil, fmt.Errorf("parse response: %w", err)
	}

	msg.ID = originalID
	// RFC 8484 §5.1: subtract Age header from DNS TTLs.
	if ageStr := httpResp.Header.Get("Age"); ageStr != "" {
		if age, err := strconv.Atoi(ageStr); err == nil && age > 0 {
			age32 := uint32(age) //nolint:gosec // G115: Age header — HTTP protocol value
			for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, rr := range section {
					if rr != nil {
						if rr.Header().TTL > age32 {
							rr.Header().TTL -= age32
						} else {
							rr.Header().TTL = 0
						}
					}
				}
			}
		}
	}
	response.ID = originalID

	return response, nil
}

// ServerDOHMsgAccept is a drop-in for dnshttp.MsgAcceptFunc that accepts
// non-zero DNS message IDs.  The library default rejects queries with non-zero
// IDs (designed for proxy/forwarder use per RFC 8484 §4.1), but real DNS clients
// always generate legitimate IDs — rejecting them would break server-side DoH.
func ServerDOHMsgAccept(m *dns.Msg) dns.MsgAcceptAction {
	if m.Response {
		return dns.MsgIgnore
	}
	// RFC 8484 §4.1: DoH serves only standard DNS QUERY semantics — reject
	// IQUERY/STATUS/NOTIFY/UPDATE/DSO instead of accepting every known opcode.
	if m.Opcode != dns.OpcodeQuery {
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
