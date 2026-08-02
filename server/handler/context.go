package handler

import (
	"net"
	"sync"
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
	// ── Set by the protocol listener; pointer is never reassigned ──
	// (Unpack() may be called to re-parse EDNS pseudo-sections)

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

	// ── Zone match: populated by Zone ──

	ZoneResult *zone.Result // non-nil when a zone rule matched (nil = no match)

	// ── Cache state: populated by CacheLookup ──

	CacheEntry   *cache.Entry // the entry returned by cache.Get (nil = miss)
	CacheIsStale bool         // true when the cached entry has expired
	CacheServed  bool         // true when the response was built from cache (for logging)

	// ── Resolution: populated by Resolution ──

	ResolutionResult *resolver.QueryResult // nil until Resolution ran
	ResolutionError  bool                  // true when resolver.Query returned an error

	// ── Response: built stepwise through the chain ──

	Res *dns.Msg // final response (nil until built)
	// Responded is true only when Res is the FINAL response and the chain
	// must stop. A middleware that wants to set a partial response (to be
	// completed by later middlewares) sets Res WITHOUT Responded — the chain
	// keeps running and the Response middleware finalizes it.
	Responded bool

	// ── Coordination ──

	Dropped       bool   // true when ErrDrop was returned (no response will be sent)
	OriginalName  string // original qname before zone rewrite (set by Zone)
	RewrittenName string // rewritten qname after zone rewrite (set by Zone)
	TCPKeepalive  uint16
	StartTime     int64 // log.NowUnixNano() — zero-alloc timestamp for response-time calculation

	// ── Pre-extracted question fields (set once in ServeDNS) ──

	Qname  string // canonical question name (already FQDN)
	Qtype  uint16 // question type (A, AAAA, etc.)
	Qclass uint16 // question class (IN, CHAOS)
}

// queryContextPool is a sync.Pool for QueryContext values to reduce per-query
// heap allocations. QueryContext is the single most-allocated type on the hot
// path (~1.8 GB in a 3s zone-match benchmark).
var queryContextPool = sync.Pool{
	New: func() any { return &QueryContext{} },
}

// NewQueryContext returns a zeroed QueryContext from the pool.
func NewQueryContext() *QueryContext {
	return queryContextPool.Get().(*QueryContext)
}

// ReleaseQueryContext returns a QueryContext to the pool. The caller must
// ensure no references to qctx or its fields are retained.
func ReleaseQueryContext(qctx *QueryContext) {
	if qctx == nil {
		return
	}
	*qctx = QueryContext{}
	queryContextPool.Put(qctx)
}

// EffectiveName returns the name that should be used AFTER the zone rewrite:
// RewrittenName when a rewrite happened, otherwise Qname. Consumers must use
// this instead of Qname so rewritten queries use the correct cache keys,
// logging names, and answers.
func (c *QueryContext) EffectiveName() string {
	if c.RewrittenName != "" {
		return c.RewrittenName
	}
	return c.Qname
}

// ClientAddr returns the client IP, or a non-nil zero-length IP for
// unix-domain/internal queries — callers can index or format it without
// panicking on the documented-nil contract.
func (c *QueryContext) ClientAddr() net.IP {
	if c.ClientIP == nil {
		return net.IP{}
	}
	return c.ClientIP
}
