package server

import (
	"context"
	"fmt"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/defense"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
)

// initResolver creates the upstream query client and DNS resolver from the
// given configuration.  The resolver is created before the handler so it can
// be injected into the middleware chain without two-phase init.
func initResolver(
	cfg *config.ServerConfig,
	queryClient *upstream.Client,
	cryptoValidator *dnssec.CryptoValidator,
	poisonDetector defense.Detector,
	ednsHandler *edns.Handler,
	cidrMatcher resolver.CIDRMatcher,
	cacheStore cache.Store,
	buildMsg func(q resolver.Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg,
	backgroundCtx context.Context,
) (*resolver.Resolver, error) {
	r, err := resolver.New(&resolver.Config{
		QueryClient:    queryClient,
		Crypto:         cryptoValidator,
		PoisonDetector: poisonDetector,
		EDNS:           ednsHandler,
		CIDRMatcher:    cidrMatcher,
		BuildMsg:       buildMsg,
		Cache:          cacheStore,
		DNSSECEnforce:  cfg.Server.Features.DNSSECEnforce,
		Ctx:            backgroundCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("create resolver: %w", err)
	}
	r.ConfigureServers(cfg.Upstream)
	return r, nil
}

// makeFlushFunc returns a closure that calls op() and formats the result as a
// single-element []string suitable for DynamicContent in CHAOS zone rules.
func makeFlushFunc(op func() (int64, error), verb string) func() []string {
	return func() []string {
		n, err := op()
		if err != nil {
			// Log the detailed error server-side; the TXT answer stays
			// generic — FlushDB errors can expose persist-file internals
			// to any client able to query these CHAOS names.
			log.Errorf("SERVER: %s failed: %v", verb, err)
			return []string{"error=flush-failed"}
		}
		return []string{fmt.Sprintf("%s=%d", verb, n)}
	}
}

// wireZoneDynamicContent assigns dynamic content functions to zone rules that
// reference .stats, .cache, and related CHAOS names.
func wireZoneDynamicContent(store cache.Store, statsCollector *stats.Collector, rules []config.ZoneRule) {
	for i := range rules {
		switch rules[i].Name {
		case config.DefaultProjectName + ".stats":
			rules[i].DynamicContent = statsCollector.Stats
		case config.DefaultProjectName + ".stats.clear":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { statsCollector.Reset(); return int64(0), nil }, "reset")
		case config.DefaultProjectName + ".cache.clear":
			// cache.clear only flushes the cache; it must not wipe query
			// statistics as a side effect (use .stats.clear for that).
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
				return store.FlushDB("cache")
			}, "flushed")
		}
	}
}
