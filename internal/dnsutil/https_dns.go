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

	// Build the DoH GET URL by cloning the upstream URL and setting the dns
	// query parameter — dnshttp.NewRequest appends /dns-query unconditionally,
	// but ZJDNS URLs already include the full path; it also only supports
	// GET/POST, not GET0RTT (HTTP/3). NOTE: the caller's own RawQuery (e.g.
	// "?param=value" on the upstream URL) is replaced, not merged — the dns
	// parameter is the DoH query.  The wire is encoded straight from
	// msg.Data: the base64 string owns its bytes, and nothing mutates
	// msg.Data between Pack and encoding, so no defensive copy is needed.
	q := *u // shallow copy — caller's URL must not be mutated
	q.RawQuery = "dns=" + base64.RawURLEncoding.EncodeToString(msg.Data)

	// The request is built literally instead of via http.NewRequestWithContext,
	// which would re-parse q.String() (a url.Parse + several allocations per
	// request).  Field parity with NewRequestWithContext: HTTP/1.1 proto
	// defaults (transports rewrite it for h2/h3), empty body, no Host
	// override — the transport derives :authority from q.Host.
	httpReq := &http.Request{
		Method:     httpMethod,
		URL:        &q,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		Header:     make(http.Header, 2),
		Body:       http.NoBody,
	}
	httpReq = httpReq.WithContext(ctx)

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
	// RFC 8484 §5.1: subtract Age header from DNS TTLs. This fork's Unpack
	// strips the OPT RR from Extra and promotes its flags to message fields
	// (Security/Rcode/UDPSize), so no section TTL can corrupt EDNS metadata.
	if ageStr := httpResp.Header.Get("Age"); ageStr != "" {
		if age, err := strconv.Atoi(ageStr); err == nil && age > 0 {
			age32 := uint32(age) //nolint:gosec // G115: Age header — HTTP protocol value
			for _, section := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, rr := range section {
					if rr == nil {
						continue
					}
					if rr.Header().TTL > age32 {
						rr.Header().TTL -= age32
					} else {
						rr.Header().TTL = 0
					}
				}
			}
		}
	}
	response.ID = originalID

	return response, nil
}

// DOHCacheControl computes the RFC 8484 §5.1 Cache-Control value for a DNS
// response. The freshness lifetime MUST NOT exceed the smallest TTL in the
// Answer section (equal is RECOMMENDED — a zero-TTL record therefore clamps
// to max-age=0). With an empty Answer section (NXDOMAIN/NODATA), it MUST
// NOT exceed the MINIMUM field of an Authority-section SOA (RFC 2308
// negative caching); without one, max-age=0.
func DOHCacheControl(response *dns.Msg) string {
	if response == nil {
		return "max-age=0"
	}
	if len(response.Answer) > 0 {
		minTTL := -1
		for _, rr := range response.Answer {
			if rr == nil {
				continue
			}
			if t := int(rr.Header().TTL); minTTL < 0 || t < minTTL { //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
				minTTL = t
			}
		}
		if minTTL <= 0 {
			return "max-age=0"
		}
		return "max-age=" + strconv.Itoa(minTTL)
	}
	for _, rr := range response.Ns {
		if soa, ok := rr.(*dns.SOA); ok && soa.Minttl > 0 {
			return "max-age=" + strconv.Itoa(int(soa.Minttl)) //nolint:gosec // G115: SOA MINIMUM — protocol-bounded uint32
		}
	}
	return "max-age=0"
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
	// An EDNS TCP Keepalive option in a DoH query is ignored, not rejected:
	// the option is TCP-session-scoped (RFC 7828 §3.3.1 — a server MUST
	// ignore it outside TCP), and DoH manages idle at its HTTP layer.
	// Processing the query normally avoids a pointless FORMERR round-trip
	// for clients that pin the option on every transport.
	return dns.MsgAccept
}
