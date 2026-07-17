package middleware

import (
	"context"
	"net"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/dns64"
	"zjdns/internal/pending"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"golang.org/x/sync/errgroup"
)

// Dependencies bundles every dependency needed by the middleware chain.
// It is constructed once at startup in server.New() and passed to
// AssembleChain, which distributes the individual fields to each middleware.
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
	DNS64         *dns64.Synthesizer
	RulesetEngine resolver.CIDRMatcher

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
//	CacheStore    — cache write + request logging + latency probe
//	Validation    — domain length / label / ANY-AXFR-IXFR
//	Zone          — zone rule evaluation (short-circuit on match)
//	EDNS          — ECS + cookie parsing
//	CacheLookup   — cache lookup (short-circuit on hit)
//	PTR           — reverse PTR from cache (cache-miss only)
//	Ruleset       — CIDR-based A/AAAA filtering
//	DNS64         — AAAA synthesis
//	Resolution    — terminal: upstream / recursive resolution
func AssembleChain(deps *Dependencies) handler.QueryHandler {
	// Innermost: no-op terminal.  Resolution is the real terminal —
	// it ignores next and never calls this stub.
	var h handler.QueryHandler = handler.QueryHandlerFunc(func(_ context.Context, _ *handler.QueryContext) error {
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
		}).Wrap(h)
	}
	if deps.RulesetEngine != nil {
		h = (&Ruleset{cidrMatcher: deps.RulesetEngine}).Wrap(h)
	}

	// PTR reverse lookup only fires on cache miss.
	h = (&PTR{store: deps.Cache}).Wrap(h)

	// Cache lookup: short-circuits on fresh/stale hit.
	h = (&CacheLookup{
		store:            deps.Cache,
		closed:           deps.Closed,
		prefetchCooldown: deps.PrefetchCooldown,
		pendingRefreshes: deps.PendingRefrs,
		refreshGroup:     deps.RefreshGroup,
		refreshCtx:       deps.RefreshCtx,
		preferStale:      deps.Config.Server.Features.Cache.PreferStale,
		resolver:         deps.Resolver,
	}).Wrap(h)

	// EDNS parsing + cookie validation.
	h = (&EDNS{
		edns:   deps.EDNS,
		config: deps.Config,
	}).Wrap(h)

	// Zone rule evaluation (short-circuit on match).
	if deps.ZoneEvaluator.HasRules() {
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

	// Response finalization: always runs, applies EDNS + restores domain.
	h = (&Response{edns: deps.EDNS}).Wrap(h)

	return h
}
