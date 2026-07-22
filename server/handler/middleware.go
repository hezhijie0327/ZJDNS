// Package handler provides the DNS query processing pipeline: query context,
// middleware interfaces, and the central Handler that dispatches queries
// through the assembled middleware chain.
package handler

import (
	"context"
	"errors"
	"net"
	"zjdns/edns"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// QueryHandler resolves a DNS query carried in the QueryContext.
// Implementations may short-circuit the chain by setting qctx.Res and
// returning nil, or delegate to the next handler.  Returning ErrDrop
// discards the query silently.  Any other error produces a SERVFAIL.
//
// NOTE: Renamed from Handler to avoid collision with the existing Handler
// struct.  Will be renamed back to Handler in Phase 3 when the old struct
// is removed.
type QueryHandler interface {
	ServeDNS(ctx context.Context, qctx *QueryContext) error
}

// QueryHandlerFunc adapts a plain function to the QueryHandler interface.
type QueryHandlerFunc func(ctx context.Context, qctx *QueryContext) error

// ZoneEvaluator is the subset of *zone.Evaluator used by the middleware
// chain, defined in the consumer package per the project's interface discipline.
type ZoneEvaluator interface {
	HasRules() bool
	Bypass(matchedTags map[string]bool) bool
	Evaluate(qname string, qtype, qclass uint16, matchedTags map[string]bool) zone.Result
}

// Middleware wraps a QueryHandler, returning a new QueryHandler that adds
// pre- or post-processing logic.  Implementations should delegate to
// next.ServeDNS when they choose not to short-circuit.
type Wrapper interface {
	Wrap(next QueryHandler) QueryHandler
}

// EDNSHandler is the subset of *edns.Handler used by the middleware chain,
// defined in the consumer package per the project's interface discipline.
type EDNSHandler interface {
	ParseFromDNS(req *dns.Msg) *edns.ECSOption
	ParseCookie(req *dns.Msg) *edns.CookieOption
	ECSForQType(qtype uint16) *edns.ECSOption
	ApplyToMessage(msg *dns.Msg, ecs *edns.ECSOption, isSecure bool, cookieStr string, ede *dns.EDE, isRequest, wantsPadding bool, tcpKeepalive uint16)
	GenerateServerCookie(clientIP net.IP, clientCookie []byte) []byte
	IsServerCookieValid(clientIP net.IP, clientCookie, serverCookie []byte) edns.CookieValStatus
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrDrop is returned by a Handler to signal that no response should be sent
// to the client (e.g. rate-limit or hijack detection drops the query silently).
var ErrDrop = errors.New("drop: no response")

// ---------------------------------------------------------------------------
// QueryHandlerFunc method
// ---------------------------------------------------------------------------

// ServeDNS implements QueryHandler.
func (f QueryHandlerFunc) ServeDNS(ctx context.Context, qctx *QueryContext) error {
	return f(ctx, qctx)
}
