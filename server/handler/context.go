package handler

import (
	"net"
	"strings"
	"zjdns/edns"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// QueryContext carries the full state of a single DNS query through the
// middleware chain.  It is a single mutable struct — each middleware reads
// fields set by upstream middlewares and writes fields consumed by downstream
// middlewares.  The contract: once a middleware sets a field, later
// middlewares read but do not overwrite it (unless explicitly documented).
type QueryContext struct {
	// ── Immutable: set by the protocol listener, never modified ──

	Req      *dns.Msg // incoming DNS request (never nil after validation)
	ClientIP net.IP   // client address (nil for unix-domain / internal)
	IsSecure bool     // true for encrypted transports (DoT, DoQ, DoH, DNSCrypt, TLCP, DTLS)
	Protocol string   // config.ProtoUDP, config.ProtoTCP, config.ProtoTLS, etc.

	// ── EDNS state: populated by EDNS ──

	ClientRequestedDNSSEC bool            // DNSSEC OK (DO) bit from the request
	ECSOpt                *edns.ECSOption // parsed EDNS Client Subnet (nil if absent)
	CookieOpt             *edns.CookieOption
	ClientWantsPadding    bool     // true if the request included EDNS padding option
	EDE                   *dns.EDE // EDE code set by error-producing middlewares

	// EDNSParsed is set by the EDNS middleware once it has run: the Response
	// middleware then skips its fallback re-parse of req.Pseudo (ECS /
	// padding detection) — ECSOpt == nil then definitively means "no ECS",
	// not "EDNS hasn't run yet".
	EDNSParsed bool
	// CookieStr caches the response COOKIE string computed during EDNS
	// validation — the Response middleware reuses it instead of running the
	// server-cookie HMAC a second time per query.
	CookieStr string

	// ── Cache state: populated by CacheLookup ──

	// ResHasDNSSEC mirrors Entry.HasDNSSEC for the pre-packed response —
	// lets the Response serve gate skip the per-hit wire scan.
	ResHasDNSSEC bool

	// ── Resolution: populated by Resolution ──

	ResolutionResult *resolver.QueryResult // set after resolver.Query completes
	Resolved         bool                  // true after Resolution ran

	// ── Response: built stepwise through the chain ──

	Res *dns.Msg // final response (nil until built); non-nil = short-circuit signal

	// ── Coordination ──

	StartTime int64 // log.NowUnixNano() — zero-alloc timestamp for response-time calculation

	// ── Pre-extracted question fields (set once in ServeDNS) ──
	//
	// The single source of truth for the question: middleware MUST read these
	// instead of re-extracting qctx.Req.Question[0].  Qname is the canonical
	// (lowercased, FQDN) form — the form cache keys, zone evaluation and
	// pending dedup require.  The raw wire case is only echoed via
	// BuildResponseMsg/SetReply, never by middleware logic.

	Qname  string // canonical question name (lowercased FQDN)
	Qtype  uint16 // question type (A, AAAA, etc.)
	Qclass uint16 // question class (IN, CHAOS, ...)
}

// InitQuestion pre-extracts the canonical question fields from Req.  It is
// the constructor contract of QueryContext: ServeDNS performs the equivalent
// inline on entry (pool reuse — zero extra calls on the hot path), and any
// code that hand-builds a QueryContext — tests — must call it after setting
// Req.  Each field is derived independently when unset (Qname "" / Qtype 0 /
// Qclass 0 are never valid question values); a Req without a question is a
// no-op.
func (qctx *QueryContext) InitQuestion() *QueryContext {
	if qctx.Req == nil || len(qctx.Req.Question) == 0 {
		return qctx
	}
	qd := qctx.Req.Question[0]
	if qctx.Qname == "" {
		qctx.Qname = strings.ToLower(qd.Header().Name)
	}
	if qctx.Qtype == 0 {
		qctx.Qtype = dns.RRToType(qd)
	}
	if qctx.Qclass == 0 {
		qctx.Qclass = qd.Header().Class
	}
	return qctx
}
