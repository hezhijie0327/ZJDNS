package handler

import (
	"net"
	"time"
	"zjdns/cache"
	"zjdns/edns"
	"zjdns/server/resolver"
	"zjdns/zone"

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

	// ── EDNS state: populated by EDNSMiddleware ──

	ClientRequestedDNSSEC bool            // DNSSEC OK (DO) bit from the request
	ECSOpt                *edns.ECSOption // parsed EDNS Client Subnet (nil if absent)
	CookieOpt             *edns.CookieOption
	ClientWantsPadding    bool            // true if the request included EDNS padding option
	EDE                   *edns.EDEOption // EDE code set by error-producing middlewares

	// ── Zone match: populated by ZoneMiddleware ──

	ZoneMatched bool         // true when a zone rule matched
	ZoneResult  *zone.Result // non-nil when ZoneMatched

	// ── Cache state: populated by CacheLookupMiddleware ──

	CacheHit     bool         // true when cache.Get found an entry (fresh or expired)
	CacheEntry   *cache.Entry // the entry returned by cache.Get (nil if miss)
	CacheIsStale bool         // true when the cached entry has expired
	CacheServed  bool         // true when the response was built from cache (for logging)

	// ── Resolution: populated by ResolutionMiddleware ──

	ResolutionResult *resolver.QueryResult // set after resolver.Query completes
	Resolved         bool                  // true after ResolutionMiddleware ran
	ResolutionError  bool                  // true when resolver.Query returned an error

	// ── Post-resolution transforms ──

	DNS64Applied bool // true when DNS64Middleware synthesised AAAA records
	CIDRFiltered bool // true when RulesetMiddleware filtered A/AAAA records

	// ── Response: built stepwise through the chain ──

	Res *dns.Msg // final response (nil until built); non-nil = short-circuit signal

	// ── Coordination ──

	Dropped      bool // true when ErrDrop was returned (no response will be sent)
	OriginalName string
	TCPKeepalive uint16
	StartTime    time.Time
}
