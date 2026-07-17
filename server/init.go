package server

import (
	"context"
	"fmt"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/hijack"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
)

// initResolver creates the upstream query client and DNS resolver from the
// given configuration.  The resolver is created before the handler so it can
// be injected into the middleware chain without two-phase init.
func initResolver(
	cfg *config.ServerConfig,
	queryClient *upstream.Client,
	cryptoValidator *dnssec.CryptoValidator,
	hijackDetector *hijack.Detector,
	ednsHandler *edns.Handler,
	cidrMatcher resolver.CIDRMatcher,
	cacheStore cache.Store,
	buildMsg func(q resolver.Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg,
	backgroundCtx context.Context,
) *resolver.Resolver {
	r := resolver.New(&resolver.Config{
		QueryClient:   queryClient,
		Crypto:        cryptoValidator,
		Hijack:        hijackDetector,
		EDNS:          ednsHandler,
		CIDRMatcher:   cidrMatcher,
		BuildMsg:      buildMsg,
		Cache:         cacheStore,
		DNSSECEnforce: cfg.Server.Features.DNSSECEnforce,
		Ctx:           backgroundCtx,
	})
	r.ConfigureServers(cfg.Upstream, cfg.Fallback)
	return r
}

// makeFlushFunc returns a closure that calls op() and formats the result as a
// single-element []string suitable for DynamicContent in CHAOS zone rules.
func makeFlushFunc(op func() (int64, error), verb string) func() []string {
	return func() []string {
		n, err := op()
		if err != nil {
			return []string{fmt.Sprintf("error=%v", err)}
		}
		return []string{fmt.Sprintf("%s=%d", verb, n)}
	}
}

// wireZoneDynamicContent assigns dynamic content functions to zone rules that
// reference .stats, .db.clear, and related CHAOS names.
func wireZoneDynamicContent(store cache.Store, rules []config.ZoneRule) {
	for i := range rules {
		switch rules[i].Name {
		case config.DefaultProjectName + ".stats":
			rules[i].DynamicContent = store.Stats
		case config.DefaultProjectName + ".db.clear":
			rules[i].DynamicContent = makeFlushFunc(store.Clear, "flushed")
		case config.DefaultProjectName + ".db.clear.cache":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("cache") }, "flushed")
		case config.DefaultProjectName + ".db.clear.stats":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("stats") }, "reset")
		case config.DefaultProjectName + ".db.clear.querylog":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("querylog") }, "flushed")
		case config.DefaultProjectName + ".db.clear.latency":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("latency") }, "flushed")
		case config.DefaultProjectName + ".db.clear.zone":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("zone") }, "flushed")
		case config.DefaultProjectName + ".db.clear.ruleset":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("ruleset") }, "flushed")
		}
	}
}
