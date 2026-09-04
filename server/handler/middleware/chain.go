package middleware

import (
	"context"
	"net"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// Dependencies bundles every dependency needed by the middleware chain.
// It is constructed once at startup in server.New() and passed to
// AssembleChain, which distributes the individual fields to each middleware.
//
// Required fields (must be non-nil):
//   - Config, Cache, EDNS, Resolver
//
// Optional fields (nil-checked before use):
//   - ZoneEvaluator, TagMatcher, Prober, PendingReqs, PendingRefrs,
//     DNS64, Closed, RefreshGroup, RefreshCtx, Ctx, PrefetchCooldown
type Dependencies struct {
	// Core
	Config        *config.ServerConfig
	Cache         cache.Store
	EDNS          handler.EDNSHandler
	ZoneEvaluator handler.ZoneEvaluator
	TagMatcher    func(qname string, ip net.IP) map[string]bool

	// Resolution
	Resolver     handler.Resolver
	Prober       handler.LatencyProber
	PendingReqs  *handler.PendingRequests
	PendingRefrs *pending.Group[handler.PendingKey]

	// Optional features
	DNS64 *dns64.Synthesizer

	// Lifecycle
	Closed           func() bool
	RefreshGroup     *errgroup.Group
	RefreshCtx       context.Context
	Ctx              context.Context
	PrefetchCooldown *handler.PrefetchCooldown
}

// AssembleChain builds the middleware chain from the given dependencies.
// The returned handler.QueryHandler is the outermost wrapper; calling ServeDNS on it
// runs the full pipeline.
//
// Execution order (outermost → innermost):
//
//	Response      — EDNS / cookie / EDE application
//	EDNS          — ECS + cookie parsing (full unpack of plain transport msgs)
//	MQTYPE        — RFC 10029 multi-QTYPE merge (recursive mode)
//	CacheStore    — cache write + request logging + latency probe
//	Validation    — domain length / label / NXNAME-AXFR-IXFR rejection
//	Zone          — zone rule evaluation (short-circuit on match)
//	Any           — RFC 8482 minimal ANY response (HINFO)
//	CacheLookup   — cache lookup (short-circuit on hit)
//	DNS64         — AAAA synthesis
//	Resolution    — terminal: upstream / recursive resolution
func AssembleChain(deps *Dependencies) handler.QueryHandler {
	if deps == nil {
		panic("middleware: nil Dependencies — programming error")
	}
	// Innermost: no-op terminal stub — not reached in normal operation
	// (Resolution is always configured).  Resolution is the real terminal
	// — it ignores next and never calls this stub.
	var h handler.QueryHandler = handler.QueryHandlerFunc(func(_ context.Context, qctx *handler.QueryContext) error {
		if log.IsDebug() {
			log.Debugf("QUERY: terminal stub reached — not reached in normal operation (Resolution is always configured)")
		}
		qctx.Res = handler.BuildResponseMsg(qctx.Req)
		qctx.Res.Rcode = dns.RcodeServerFailure
		return nil
	})

	// Wrap the terminal handler with Resolution.
	h = (&Resolution{
		resolver: deps.Resolver,
		pending:  deps.PendingReqs,
	}).Wrap(h)

	// Post-resolution transforms: wrap resolution from inside out so they
	// execute after Resolution returns.
	if deps.DNS64 != nil {
		h = (&DNS64{
			synthesizer: deps.DNS64,
			resolver:    deps.Resolver,
			pending:     deps.PendingReqs,
			store:       deps.Cache,
		}).Wrap(h)
	}

	// Cache lookup: short-circuits on fresh/stale hit.
	h = (&CacheLookup{
		store:            deps.Cache,
		closed:           deps.Closed,
		prefetchCooldown: deps.PrefetchCooldown,
		pendingRefreshes: deps.PendingRefrs,
		refreshGroup:     deps.RefreshGroup,
		refreshCtx:       deps.RefreshCtx,
		preferStale:      deps.Config.Server.Features.Cache.Entries.PreferStale,
		resolver:         deps.Resolver,
	}).Wrap(h)

	// RFC 8482 minimal ANY response — wrapped INSIDE Zone (earlier Wrap call
	// = inner layer), so operator-defined zone rules for ANY queries run
	// first and take precedence; only unmatched ANY queries reach Any.
	h = (&Any{store: deps.Cache}).Wrap(h)

	// Zone rule evaluation (short-circuit on match). The evaluator is
	// always wired by server.New, but guard for tests and embedded use.
	if deps.ZoneEvaluator != nil && deps.ZoneEvaluator.HasRules() {
		h = (&Zone{
			evaluator:  deps.ZoneEvaluator,
			tagMatcher: deps.TagMatcher,
			cache:      deps.Cache,
		}).Wrap(h)
	}

	// Request validation — reject malformed queries early.
	h = (&Validation{}).Wrap(h)

	// Cache storage: runs after resolution, writes to cache + starts probes.
	h = (&CacheStore{
		store:    deps.Cache,
		prober:   deps.Prober,
		resolver: deps.Resolver,
	}).Wrap(h)

	// RFC 10029 MQTYPE-Query: merges additional QTYPE responses into the
	// primary reply (recursive mode).  In forwarding mode the option is
	// passed through to the upstream by Resolution.
	//
	// Positioned outside CacheStore so its post-phase runs after CacheStore
	// has built qctx.Res from ResolutionResult (miss path), and inside EDNS
	// so the MQTYPE-Query option is visible in Pseudo before pre runs.
	h = (&MQTYPE{
		store:    deps.Cache,
		resolver: deps.Resolver,
		pending:  deps.PendingReqs,
	}).Wrap(h)

	// EDNS parsing + cookie validation — outside MQTYPE: EDNS.pre performs
	// the full request unpack (plain UDP/TCP listeners deliver question-only
	// messages), populating Pseudo before MQTYPE.pre's findMQQUERY.
	h = (&EDNS{
		edns: deps.EDNS,
	}).Wrap(h)

	// Response finalization: always runs, applies EDNS + restores domain.
	h = (&Response{edns: deps.EDNS}).Wrap(h)

	return h
}
