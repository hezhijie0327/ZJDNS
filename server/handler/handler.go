// Package handler provides the DNS query processing pipeline: a composable
// middleware chain that validates, evaluates zone rules, parses EDNS, checks
// the cache, resolves via upstream/recursive, filters, and finalises responses.
package handler

import (
	"context"
	"errors"
	"net"
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
	DNSSECEDECode() uint16
	UpstreamEDEOption() *dns.EDE
	UpstreamServers() []*config.UpstreamServer
	FallbackServers() []*config.UpstreamServer
}

// LatencyProber is the interface for latency-probing cache entries.
type LatencyProber interface {
	Start(qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	Close()
}

// Handler processes DNS queries by delegating to the assembled middleware
// chain.  It is a thin adapter between protocol listeners and the chain.
type Handler struct {
	closed int32 // hot-path: checked on every query via atomic load

	chain             QueryHandler
	edns              *edns.Handler
	cache             cache.Store
	prober            LatencyProber
	resolver          Resolver
	cacheRefreshGroup *errgroup.Group
	prefetchCooldown  *PrefetchCooldown
	ctx               context.Context
}

// NewHandler creates a Handler from the assembled middleware chain and
// essential dependencies.
func NewHandler(chain QueryHandler, ednsH *edns.Handler, cacheStore cache.Store, prober LatencyProber, dnsResolver Resolver, refreshGroup *errgroup.Group, pfCooldown *PrefetchCooldown, ctx context.Context) *Handler {
	return &Handler{
		chain:             chain,
		edns:              ednsH,
		cache:             cacheStore,
		prober:            prober,
		resolver:          dnsResolver,
		cacheRefreshGroup: refreshGroup,
		prefetchCooldown:  pfCooldown,
		ctx:               ctx,
	}
}

// ── Lifecycle ────────────────────────────────────────────────────────────

// IsClosed reports whether the handler has been shut down.
func (h *Handler) IsClosed() bool { return atomic.LoadInt32(&h.closed) != 0 }

// MarkClosed signals the handler to stop accepting new work.
func (h *Handler) MarkClosed() { atomic.StoreInt32(&h.closed, 1) }

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

// FallbackServers returns the configured fallback servers.
func (h *Handler) FallbackServers() []*config.UpstreamServer { return h.resolver.FallbackServers() }

// ── Query entry point ────────────────────────────────────────────────────

// ServeDNS handles an incoming DNS query from any protocol listener.
// It creates a QueryContext and delegates to the middleware chain.
func (h *Handler) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	if atomic.LoadInt32(&h.closed) != 0 {
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

	if log.IsDebug() {
		qname := req.Question[0].Header().Name
		qtype := dns.RRToType(req.Question[0])
		if clientIP != nil {
			log.Debugf("QUERY: client IP=%s query=%s type=%s", clientIP.String(), qname, dns.TypeToString[qtype])
		} else {
			log.Debugf("QUERY: client IP=<unknown> query=%s type=%s", qname, dns.TypeToString[qtype])
		}
	}

	qd := req.Question[0]
	qctx := &QueryContext{
		Req:       req,
		ClientIP:  clientIP,
		IsSecure:  isSecure,
		Protocol:  protocol,
		StartTime: log.NowUnixNano(),
		Qname:     dnsutil.Fqdn(qd.Header().Name),
		Qtype:     dns.RRToType(qd),
	}

	err := h.chain.ServeDNS(h.ctx, qctx)

	if errors.Is(err, ErrDrop) || qctx.Dropped {
		// NOTE: Do NOT Put(req) here — the protocol caller owns the
		// request message lifecycle and will Put it after ServeDNS returns.
		// Putting here would cause a double-put race with the caller.
		return nil
	}

	if err != nil && qctx.Res == nil {
		msg := BuildResponseMsg(req)
		msg.Rcode = dns.RcodeServerFailure
		h.cache.RecordRequest(&cache.RequestRecord{
			Result: "error", Protocol: protocol, Rcode: dns.RcodeServerFailure,
		})
		return msg
	}

	if qctx.Res != nil && log.IsDebug() {
		qname := req.Question[0].Header().Name
		qtype := dns.RRToType(req.Question[0])
		log.Debugf("RESULT: %s %s | rcode=%s time=%v answer=%d authority=%d additional=%d ad=%t\n%s",
			qname, dns.TypeToString[qtype], dns.RcodeToString[qctx.Res.Rcode],
			time.Duration(log.NowUnixNano()-qctx.StartTime).Truncate(time.Microsecond), len(qctx.Res.Answer), len(qctx.Res.Ns),
			len(qctx.Res.Extra), qctx.Res.AuthenticatedData,
			qctx.Res.String())
	}

	return qctx.Res
}

// ElapsedMS returns the elapsed time in milliseconds since startNs
// (a log.NowUnixNano() timestamp).
func ElapsedMS(startNs int64) int64 {
	return (log.NowUnixNano() - startNs) / int64(time.Millisecond)
}

// BuildQueryMsg constructs an outbound DNS query message for the resolver.
// It is a standalone function (not a method) so it can be used before the
// Handler is created.

// BuildQueryMsg constructs a DNS query message for upstream/recursive resolution.
func BuildQueryMsg(ednsH *edns.Handler, question Question, ecs *edns.ECSOption, recursionDesired, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessage.Get()

	dnsutil.SetQuestion(msg, dnsutil.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if ednsH != nil {
		ednsH.ApplyToMessage(msg, ecs, isSecureConnection, "", nil, true, true, 0)
	}

	return msg
}
