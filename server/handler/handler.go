// Package handler provides the DNS query processing pipeline: a composable
// middleware chain that validates, evaluates zone rules, parses EDNS, checks
// the cache, resolves via upstream/recursive, filters, and finalises responses.
package handler

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

// Question is a type alias for resolver.Question.
type Question = resolver.Question

// Resolver is the interface for DNS query resolution.
type Resolver interface {
	Query(ctx context.Context, question Question, ecs *edns.ECSOption) *resolver.QueryResult
	UpstreamServers() []*config.UpstreamServer
}

// LatencyProber is the interface for latency-probing cache entries.
type LatencyProber interface {
	Start(qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	Close()
}

// Handler processes DNS queries by delegating to the assembled middleware
// chain.  It is a thin adapter between protocol listeners and the chain.
type Handler struct {
	closed atomic.Int32 // hot-path: checked on every query via atomic load

	chain             QueryHandler
	edns              *edns.Handler
	cache             cache.Store
	prober            LatencyProber
	resolver          Resolver
	cacheRefreshGroup *errgroup.Group
	prefetchCooldown  *PrefetchCooldown
	ctx               context.Context
}

// HandlerDeps carries the Handler's collaborators as named fields —
// positional parameters are easy to transpose at the wiring site (2026-09 E1).
type HandlerDeps struct {
	Chain            QueryHandler
	EDNS             *edns.Handler
	CacheStore       cache.Store
	Prober           LatencyProber
	Resolver         Resolver
	RefreshGroup     *errgroup.Group
	PrefetchCooldown *PrefetchCooldown
	Ctx              context.Context
}

// qctxPool reuses QueryContext structs — one is allocated per query.  The
// full-field literal in ServeDNS overwrites every pooled field, so stale
// values can never leak into a new query.  Safe to reuse on return: all
// middleware chain execution is synchronous, and refresh goroutines capture
// only values (qname/qtype/ecs), never the QueryContext itself.
var qctxPool = sync.Pool{New: func() any { return new(QueryContext) }}

// NewHandler creates a Handler from the assembled middleware chain and
// essential dependencies.
func NewHandler(deps *HandlerDeps) *Handler {
	return &Handler{
		chain:             deps.Chain,
		edns:              deps.EDNS,
		cache:             deps.CacheStore,
		prober:            deps.Prober,
		resolver:          deps.Resolver,
		cacheRefreshGroup: deps.RefreshGroup,
		prefetchCooldown:  deps.PrefetchCooldown,
		ctx:               deps.Ctx,
	}
}

// ── Lifecycle ────────────────────────────────────────────────────────────

// IsClosed reports whether the handler has been shut down.
func (h *Handler) IsClosed() bool { return h.closed.Load() != 0 }

// MarkClosed signals the handler to stop accepting new work.
func (h *Handler) MarkClosed() { h.closed.Store(1) }

// ── Accessors ────────────────────────────────────────────────────────────

// Edns returns the EDNS handler.
func (h *Handler) EDNS() *edns.Handler { return h.edns }

// CacheStore returns the cache store.
func (h *Handler) CacheStore() cache.Store { return h.cache }

// Prober returns the latency prober.
func (h *Handler) Prober() LatencyProber { return h.prober }

// PrefetchCooldown returns the prefetch cooldown tracker.
func (h *Handler) PrefetchCooldown() *PrefetchCooldown { return h.prefetchCooldown }

// CacheRefreshGroup returns the errgroup for cache refresh goroutines.
func (h *Handler) CacheRefreshGroup() *errgroup.Group { return h.cacheRefreshGroup }

// UpstreamServers returns the configured upstream servers.
func (h *Handler) UpstreamServers() []*config.UpstreamServer { return h.resolver.UpstreamServers() }

// ── Query entry point ────────────────────────────────────────────────────

// ServeDNS handles an incoming DNS query from any protocol listener.
// It creates a QueryContext and delegates to the middleware chain.
func (h *Handler) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	if h.closed.Load() != 0 {
		msg := BuildResponseMsg(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	if req == nil || len(req.Question) == 0 {
		msg := pool.DefaultMessage.Get()
		if req != nil {
			dnsutil.SetReply(msg, req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	// RFC 1035 §4.1.1: a message with the QR (response) bit set is not a
	// query — silently drop it.  Replying would answer to a spoofed source
	// (reflection) and miekg's UDP listener already skips these; the
	// hand-rolled TCP-family listeners funneled them into the chain.
	if req.Response {
		return nil
	}

	if log.IsDebug() {
		qname := req.Question[0].Header().Name
		qtype := dns.RRToType(req.Question[0])
		if clientIP != nil {
			if log.IsDebug() {
				log.Debugf("QUERY: client IP=%s query=%s type=%s", clientIP.String(), qname, dns.TypeToString[qtype])
			}
		} else {
			if log.IsDebug() {
				log.Debugf("QUERY: client IP=<unknown> query=%s type=%s", qname, dns.TypeToString[qtype])
			}
		}
	}

	qd := req.Question[0]
	qctx := qctxPool.Get().(*QueryContext)
	// Full-field literal: zeroes every pooled field not listed here.
	// Qname is an already-FQDN unpacked name, so strings.ToLower is exactly
	// dnsutil.Canonical minus the always-allocating strings.Map.
	*qctx = QueryContext{
		Req:       req,
		ClientIP:  clientIP,
		IsSecure:  isSecure,
		Protocol:  protocol,
		StartTime: log.NowUnixNano(),
		Qname:     strings.ToLower(qd.Header().Name),
		Qtype:     dns.RRToType(qd),
	}
	defer qctxPool.Put(qctx)

	err := h.chain.ServeDNS(h.ctx, qctx)

	if err != nil && qctx.Res == nil {
		msg := BuildResponseMsg(req)
		msg.Rcode = dns.RcodeServerFailure
		rec := cache.AcquireRequestRecord()
		rec.Result = "error"
		rec.Protocol = protocol
		rec.Rcode = dns.RcodeServerFailure
		// Full identification, matching every other error record (H-L8).
		if qd := req.Question[0]; qd != nil {
			rec.Qname = strings.ToLower(qd.Header().Name)
			rec.Qtype = dns.RRToType(qd)
		}
		rec.ResponseTime = ElapsedMS(qctx.StartTime)
		h.cache.RecordRequest(rec)
		cache.ReleaseRequestRecord(rec)
		return msg
	}

	// BADCOOKIE responses are short-circuited by the EDNS middleware before
	// any stats-recording middleware; record them here so the badcookie
	// result class is populated (RFC 7873 §5.2).
	if qctx.Res != nil && qctx.Res.Rcode == dns.RcodeBadCookie {
		rec := cache.AcquireRequestRecord()
		rec.Result = "badcookie"
		rec.Protocol = protocol
		rec.Rcode = dns.RcodeBadCookie
		h.cache.RecordRequest(rec)
		cache.ReleaseRequestRecord(rec)
	}

	if qctx.Res != nil && log.IsDebug() {
		qname := qctx.Qname
		qtype := qctx.Qtype
		if log.IsDebug() {
			log.Debugf("RESULT: %s %s | rcode=%s time=%v answer=%d authority=%d additional=%d ad=%t\n%s",
				qname, dns.TypeToString[qtype], dns.RcodeToString[qctx.Res.Rcode],
				time.Duration(log.NowUnixNano()-qctx.StartTime).Truncate(time.Microsecond), len(qctx.Res.Answer), len(qctx.Res.Ns),
				len(qctx.Res.Extra), qctx.Res.AuthenticatedData,
				qctx.Res.String())
		}
	}

	return qctx.Res
}

// ElapsedMS returns the elapsed time in milliseconds since startNs
// (a log.NowUnixNano() timestamp).
func ElapsedMS(startNs int64) int64 {
	return (log.NowUnixNano() - startNs) / int64(time.Millisecond)
}

// BuildQueryMsg constructs a DNS query message for upstream/recursive resolution.
func BuildQueryMsg(ednsH *edns.Handler, question Question, ecs *edns.ECSOption, recursionDesired, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessage.Get()

	dnsutil.SetQuestion(msg, dnsutil.Fqdn(question.Name), question.Qtype, question.Qclass)
	msg.RecursionDesired = recursionDesired
	// RFC 6840 §5.9: a validating resolver SHOULD set CD on every
	// upstream query so the upstream returns DNSSEC proofs even for
	// bogus data, letting us validate independently.
	msg.CheckingDisabled = true

	if ednsH != nil {
		ednsH.ApplyToMessage(msg, ecs, isSecureConnection, "", nil, true, true, 0)
	}

	return msg
}
