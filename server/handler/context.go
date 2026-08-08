package handler

import (
	"net"
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

	// ── Cache state: populated by CacheLookup ──

	CacheHit    bool // true when cache.Get found an entry (fresh or expired)
	CacheServed bool // true when the response was built from cache (for logging)

	// ── Resolution: populated by Resolution ──

	ResolutionResult *resolver.QueryResult // set after resolver.Query completes
	Resolved         bool                  // true after Resolution ran

	// ── Response: built stepwise through the chain ──

	Res *dns.Msg // final response (nil until built); non-nil = short-circuit signal

	// ── Coordination ──

	TCPKeepalive uint16
	StartTime    int64 // log.NowUnixNano() — zero-alloc timestamp for response-time calculation

	// ── Pre-extracted question fields (set once in ServeDNS) ──

	Qname string // canonical question name (already FQDN)
	Qtype uint16 // question type (A, AAAA, etc.)
}
