// Package server — construction of the query-processing collaborators:
// EDNS handler, zone/ruleset engines, upstream client, resolver, and the
// middleware chain.  Protocol listener construction lives in protocols.go;
// lifecycle (start/stop/display) stays in server.go.
package server

import (
	"context"
	"errors"
	_ "expvar" // /debug/vars: runtime MemStats for RSS diagnosis (served only when pprof is enabled)
	"fmt"
	"net"
	_ "net/http/pprof" //nolint:gosec // G108: pprof is off unless configured
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/ruleset"
	"zjdns/server/defense"
	"zjdns/server/handler"
	"zjdns/server/handler/middleware"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/probe"
	"zjdns/server/upstream"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"

	zdnsutil "zjdns/internal/dnsutil"
)

// initEDNS creates the EDNS handler and auto-detects ECS subnets.
func (s *Server) initEDNS(cfg *config.ServerConfig) (*edns.Handler, error) {
	return edns.NewHandler(cfg.Server.Features.ECS)
}

// initZoneAndRulesets loads zone-file rules and CIDR/domain matching rulesets
// from config.  Returns the ruleset engine (nil if none configured) and any
// fatal error from loading.
func (s *Server) initZoneAndRulesets(cfg *config.ServerConfig, cacheStore cache.Store, zoneEvaluator *zone.Evaluator) (*ruleset.Engine, error) {
	wireZoneDynamicContent(cacheStore, cfg.Zone, func() error {
		// Resolved lazily: the DNSCrypt server is constructed after zone wiring.
		if s.dnscryptServer == nil {
			return errors.New("dnscrypt server not enabled")
		}
		return s.dnscryptServer.ResetKeys()
	})

	if len(cfg.Zone) > 0 {
		if err := zoneEvaluator.LoadRules(cfg.Zone); err != nil {
			return nil, fmt.Errorf("load zone rules: %w", err)
		}
	}

	var engine *ruleset.Engine
	if len(cfg.RuleSet) > 0 {
		engine = ruleset.New()
		if err := engine.LoadRules(cfg.RuleSet); err != nil {
			return nil, fmt.Errorf("load ruleset: %w", err)
		}
	}
	return engine, nil
}

// initQueryClient creates the upstream query client with transport pools
// and optional KTLS offload.
func (s *Server) initQueryClient(cfg *config.ServerConfig) *upstream.Client {
	client := upstream.New()
	if cfg.Server.Features.KTLS != nil {
		client.SetKTLS(cfg.Server.Features.KTLS.KernelTX, cfg.Server.Features.KTLS.KernelRX)
	}
	s.queryClient = client
	return client
}

// SetRootFilesDir sets the directory where root data files (named.root,
// root-anchors.xml) are looked up. Call before New() to place root files
// alongside the config file instead of the binary.
func SetRootFilesDir(dir string) {
	zdnsutil.SetRootFilesDir(dir)
}

// Go implements shared.Host: schedules f on the background errgroup.
func (s *Server) Go(f func() error) { s.backgroundGroup.Go(f) }

// Ctx implements shared.Host: returns the background context.
func (s *Server) Ctx() context.Context { return s.backgroundCtx }

// isRecursiveMode reports whether any upstream server uses the built-in
// recursive resolver.  Recursion is explicit-only: an empty upstream list
// does not imply recursion (queries then resolve to SERVFAIL).
func isRecursiveMode(cfg *config.ServerConfig) bool {
	for i := range cfg.Upstream {
		if cfg.Upstream[i].IsRecursive() {
			return true
		}
	}
	return false
}

// initDNSResolver wires together the recursive/forward resolver, security
// validators, and CIDR matcher.
func (s *Server) initDNSResolver(cfg *config.ServerConfig, queryClient *upstream.Client, ednsH *edns.Handler, cacheStore cache.Store, rulesetEngine *ruleset.Engine) (*resolver.Resolver, error) {
	cryptoValidator := dnssec.NewCryptoValidator(cacheStore)

	// Load root files only when recursive resolution is configured.
	if isRecursiveMode(cfg) {
		cryptoValidator.LoadTrustAnchors()
		resolver.LoadRootHints()
	}

	poisonDetector := defense.Detector{} // gated per-query by Recursive.poisonguard

	var cidrMatcher resolver.CIDRMatcher
	if rulesetEngine != nil {
		cidrMatcher = rulesetEngine
	}

	r, err := initResolver(cfg, queryClient, cryptoValidator, poisonDetector, ednsH, cidrMatcher, cacheStore,
		func(q resolver.Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
			return handler.BuildQueryMsg(ednsH, q, ecs, rd, secure)
		}, s.backgroundCtx)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// warmUpConnections pre-establishes transport connections to all configured
// secure upstream servers.
func (s *Server) warmUpConnections(cfg *config.ServerConfig, queryClient *upstream.Client) {
	if len(cfg.Upstream) == 0 {
		return
	}
	queryClient.WarmUpConnections(s.backgroundCtx, cfg.Upstream)
}

// initHandler builds the middleware chain and returns the assembled handler.
func (s *Server) initHandler(cfg *config.ServerConfig, cacheStore cache.Store, ednsH *edns.Handler, zoneEvaluator *zone.Evaluator, dnsResolver *resolver.Resolver, rulesetEngine *ruleset.Engine, cacheRefreshGroup *errgroup.Group, cacheRefreshCtx, backgroundCtx context.Context) *handler.Handler {
	var prober handler.LatencyProber
	if len(cfg.Server.Features.LatencyProbe) > 0 {
		prober = probe.New(
			cacheStore,
			func(fn func() error) { s.backgroundGroup.Go(fn) },
			backgroundCtx,
			cfg.Server.Features.LatencyProbe,
		)
	}

	prefetchCooldown := handler.NewPrefetchCooldown()
	// The Server owns the shared collaborators; background tasks (tasks.go)
	// read them from here rather than through Handler accessors.
	s.cacheStore = cacheStore
	s.ednsHandler = ednsH
	s.prober = prober
	s.prefetchCooldown = prefetchCooldown
	s.cacheRefreshGroup = cacheRefreshGroup
	ctx := s.ctx

	// isClosed is a forward-reference trick: the closure below captures the
	// variable isClosed, not its value. After h is created, isClosed is
	// updated to h.IsClosed so CacheLookup sees the real health check.
	isClosed := func() bool { return false }

	deps := &middleware.Dependencies{
		Config:           cfg,
		Cache:            cacheStore,
		EDNS:             ednsH,
		ZoneEvaluator:    zoneEvaluator,
		TagMatcher:       nil,
		Resolver:         dnsResolver,
		Prober:           prober,
		PendingReqs:      handler.NewPendingRequests(),
		PendingRefrs:     handler.NewRefreshGroup(),
		DNS64:            nil,
		Closed:           func() bool { return isClosed() },
		RefreshGroup:     cacheRefreshGroup,
		RefreshCtx:       cacheRefreshCtx,
		Ctx:              ctx,
		PrefetchCooldown: prefetchCooldown,
	}

	if rulesetEngine != nil {
		deps.TagMatcher = func(qname string, ip net.IP) map[string]bool {
			return rulesetEngine.Match(qname, ip.String())
		}
	}

	// DNS64 synthesizer.
	if cfg.Server.Features.DNS64 != nil && cfg.Server.Features.DNS64.Prefix != "" {
		synth, err := dns64.New(cfg.Server.Features.DNS64.Prefix)
		if err != nil {
			log.Warnf("DNS64: %v, using default prefix", err)
			var fallbackErr error
			synth, fallbackErr = dns64.New(config.DefaultDNS64Prefix)
			if fallbackErr != nil {
				log.Warnf("DNS64: default prefix also failed: %v", fallbackErr)
			}
		}
		if synth != nil {
			deps.DNS64 = synth
			log.Infof("DNS64: enabled with prefix %s", synth.Prefix())
		}
	}

	chain := middleware.AssembleChain(deps)

	h := handler.NewHandler(chain, ctx)
	isClosed = h.IsClosed

	return h
}
