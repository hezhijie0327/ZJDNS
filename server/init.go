package server

import (
	"context"
	"fmt"
	"path/filepath"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/persist"
	"zjdns/server/defense"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/upstream"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
)

// cachePersister is the slice of the cache needed by the CHAOS clear
// endpoints: flush the in-memory state, then persist the cleared state
// immediately (see wireZoneDynamicContent).
type cachePersister interface {
	FlushDB(target string) (int64, error)
	Save() error
	SavePtrIndex() error
	SaveLatency() error
	ClearPtrIndex() error
	ClearLatency() error
}

// statsSaver adapts the stats collector (fixed-layout counter snapshot, not a
// key-value LRU) to the persist Saver interface so it shares the unified
// periodic + shutdown flush.
type statsSaver struct {
	c    *stats.Collector
	file string
}

func (s *statsSaver) Save() error { return s.c.SavePersist(s.file) }

// initPersistManager registers every subsystem with persistent state on the
// unified persist manager. Subsystems whose file paths are empty (persistence
// disabled) are simply not registered; the Manager no-ops when empty.
func (s *Server) initPersistManager(cacheStore *cache.Cache, statsCollector *stats.Collector, persistDir string) {
	s.persistManager = persist.NewManager()
	if persistDir == "" {
		return
	}
	s.persistManager.Register("cache", cacheStore)
	s.persistManager.Register("cache-ptr", persist.SaverFunc(cacheStore.SavePtrIndex))
	s.persistManager.Register("cache-latency", persist.SaverFunc(cacheStore.SaveLatency))
	s.persistManager.Register("stats", &statsSaver{c: statsCollector, file: filepath.Join(persistDir, "stats.zst")})
	if s.dnscryptServer != nil {
		s.persistManager.Register("dnscrypt", s.dnscryptServer)
	}
}

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
// reference .stats, .cache, and related CHAOS names. dnscryptReset is bound
// late (the DNSCrypt server is created after zone wiring) and must be safe to
// call once the server is running.
func wireZoneDynamicContent(store cachePersister, statsCollector *stats.Collector, statsFile string, dnscryptReset func() error, rules []config.ZoneRule) {
	for i := range rules {
		switch rules[i].Name {
		case config.DefaultProjectName + ".stats":
			rules[i].DynamicContent = statsCollector.Stats
		case config.DefaultProjectName + ".stats.clear":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
				statsCollector.Reset()
				// Persist the reset immediately: otherwise a crash before the
				// next periodic flush restores the cleared totals from stats.zst.
				if statsFile != "" {
					if err := statsCollector.SavePersist(statsFile); err != nil {
						return int64(0), err
					}
				}
				return int64(0), nil
			}, "reset")
		case config.DefaultProjectName + ".cache.clear":
			// cache.clear only flushes the cache; it must not wipe query
			// statistics as a side effect (use .stats.clear for that).
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
				n, err := store.FlushDB("cache")
				if err != nil {
					return n, err
				}
				// Persist the cleared state immediately (cache.zst, ptr.zst,
				// latency.zst) — a crash before the next periodic flush would
				// otherwise restore the cleared entries on restart.
				if err := store.Save(); err != nil {
					return n, err
				}
				if err := store.SavePtrIndex(); err != nil {
					return n, err
				}
				return n, store.SaveLatency()
			}, "flushed")
		case config.DefaultProjectName + ".ptr.clear":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
				return 0, store.ClearPtrIndex()
			}, "flushed")
		case config.DefaultProjectName + ".latency.clear":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
				return 0, store.ClearLatency()
			}, "flushed")
		case config.DefaultProjectName + ".dnscrypt.clear":
			rules[i].DynamicContent = makeFlushFunc(func() (int64, error) {
				return 0, dnscryptReset()
			}, "rotated")
		}
	}
}
