package server

import (
	"context"
	"fmt"
	"net"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/server/defense"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
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
		QueryClient:          queryClient,
		Crypto:               cryptoValidator,
		PoisonDetector:       poisonDetector,
		EDNS:                 ednsHandler,
		CIDRMatcher:          cidrMatcher,
		BuildMsg:             buildMsg,
		Cache:                cacheStore,
		DNSSECEnforce:        cfg.Server.Features.DNSSECEnforce,
		AddressFamily:        cfg.Server.Features.AddressFamily,
		DelegationMaxEntries: cfg.Server.Features.Cache.Delegation.Limit.Mem,
		DelegationSpillPath:  cfg.Server.Features.DelegationStateFile(),
		DelegationSpillLimit: cfg.Server.Features.Cache.Delegation.Limit.Disk,
		FallbackTimeout:      time.Duration(cfg.Server.Features.FallbackTimeout) * time.Millisecond,
		Ctx:                  backgroundCtx,
	})
	if err != nil {
		return nil, fmt.Errorf("create resolver: %w", err)
	}
	r.ConfigureServers(cfg.Upstream)
	return r, nil
}

// makeFlushFunc returns a closure that calls op() and formats the result as a
// single-element []string suitable for DynamicContent in CHAOS zone rules.
func makeFlushFunc(op func() (int64, error), verb string) func(net.IP) []string {
	return func(net.IP) []string {
		n, err := op()
		if err != nil {
			return []string{fmt.Sprintf("error=%v", err)}
		}
		return []string{fmt.Sprintf("%s=%d", verb, n)}
	}
}

// wireZoneDynamicContent assigns dynamic content functions to zone rules that
// reference .stats, .*.clear, and related CHAOS names.
// resetDNSCrypt is the DNSCrypt key-reset callback (nil when the DNSCrypt
// server is not enabled); it is resolved lazily because the DNSCrypt server
// is constructed after the zone rules are wired.
func wireZoneDynamicContent(store cache.Store, rules []config.ZoneRule, resetDNSCrypt func() error) {
	for i := range rules {
		// Canonicalize both sides: zone.LoadRules stores canonical names,
		// but the raw config rule may carry case variants or omit the
		// trailing dot — an exact-string match silently never wired the
		// dynamic function (R3-M19).
		switch dnsutil.Canonical(rules[i].Name) {
		case dnsutil.Canonical(config.DefaultProjectName + ".stats"):
			rules[i].DynamicContent = func(net.IP) []string { return store.Stats() }
		case dnsutil.Canonical(config.DefaultProjectName + ".stats.rcode"):
			rules[i].DynamicContent = func(net.IP) []string { return store.StatsRcode() }
		case dnsutil.Canonical(config.DefaultProjectName + ".whoami"):
			rules[i].DynamicContent = func(clientIP net.IP) []string {
				if clientIP == nil {
					return nil
				}
				return []string{clientIP.String()}
			}
		case dnsutil.Canonical(config.DefaultProjectName + ".cache.clear"):
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("cache") }, "flushed")
		case dnsutil.Canonical(config.DefaultProjectName + ".stats.clear"):
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("stats") }, "reset")
		case dnsutil.Canonical(config.DefaultProjectName + ".latency.clear"):
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("latency") }, "flushed")
		// zjdns.delegation.clear was removed: FlushDB has no delegation
		// branch (the cache store does not own the delegation cache), so the
		// endpoint always replied a false "flushed" (L2).
		case dnsutil.Canonical(config.DefaultProjectName + ".querylog.clear"):
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) { return store.FlushDB("querylog") }, "flushed")
		case dnsutil.Canonical(config.DefaultProjectName + ".dnscrypt.clear"):
			rules[i].DynamicContent = func(net.IP) []string {
				if resetDNSCrypt == nil {
					return []string{"error=dnscrypt not enabled"}
				}
				if err := resetDNSCrypt(); err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{"reset=1"}
			}
		}
	}
}
