// Package server implements the core DNS server, coordinating query processing, protocol listeners, and lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/cache"
	"zjdns/cidr"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/rewrite"
	"zjdns/server/client"
	"zjdns/server/latency"
	"zjdns/server/ratelimit"
	"zjdns/server/resolver"
	"zjdns/server/security"
	servertls "zjdns/server/tls"
	"zjdns/stats"
)

// Server-level timeouts and intervals.
const (
	DefaultTimeout   = 2 * time.Second
	OperationTimeout = 3 * time.Second

	PrefetchThrottleInterval = 3 * time.Second
	PrefetchThresholdPercent = 25

	ServeExpiredClientTimeout = 1800 * time.Millisecond

	DefaultCookieSecretRotationInterval = 1 * time.Hour
	DefaultECSRefreshInterval           = 15 * time.Minute

	PprofPath = "/debug/pprof/"
)

// Server is the core DNS server handling query processing, protocol listeners, and lifecycle.
type Server struct {
	config            *config.ServerConfig
	cacheMgr          cache.Store
	queryClient       *client.Client
	guard             *security.Guard
	tls               *servertls.Server
	ednsMgr           *edns.Handler
	rewriteMgr        *rewrite.Evaluator
	cidrMgr           *cidr.Filter
	statsMgr          *stats.Collector
	pprofServer       *http.Server
	ctx               context.Context
	cancel            context.CancelCauseFunc
	shutdown          chan struct{}
	backgroundGroup   *errgroup.Group
	backgroundCtx     context.Context
	cacheRefreshGroup *errgroup.Group
	cacheRefreshCtx   context.Context
	prefetchCooldown  sync.Map
	closed            int32
	resolver          *resolver.Resolver
	limiter           *ratelimit.Limiter
	prober            *latency.Prober
	semaphore         chan struct{}
	udpServer         *dns.Server
	tcpServer         *dns.Server
	tcpWriteMu        sync.Map
}

type tcpWriteEntry struct {
	mu           sync.Mutex
	lastAccess   atomic.Int64
	capacity     chan struct{}
	capacityOnce sync.Once
}

type queryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *edns.ECSOption
	fallback   bool
	err        error
}

// New creates and initializes a Server from the given configuration.
func New(cfg *config.ServerConfig) (*Server, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	ednsHandler, err := edns.NewHandler(cfg.Server.Features.ECS)
	if err != nil {
		cancel(fmt.Errorf("EDNS handler init: %w", err))
		return nil, fmt.Errorf("EDNS handler init: %w", err)
	}

	rewriteEvaluator := rewrite.New()
	if len(cfg.Rewrite) > 0 {
		if err := rewriteEvaluator.LoadRules(cfg.Rewrite); err != nil {
			cancel(fmt.Errorf("load rewrite rules: %w", err))
			return nil, fmt.Errorf("load rewrite rules: %w", err)
		}
	}

	var cidrFilter *cidr.Filter
	if len(cfg.CIDR) > 0 {
		cidrFilter, err = cidr.New(cfg.CIDR)
		if err != nil {
			cancel(fmt.Errorf("CIDR filter init: %w", err))
			return nil, fmt.Errorf("CIDR filter init: %w", err)
		}
	}

	cache := cache.New(cfg.Server.Features.Cache)

	server := &Server{
		config:            cfg,
		ednsMgr:           ednsHandler,
		rewriteMgr:        rewriteEvaluator,
		cidrMgr:           cidrFilter,
		statsMgr:          stats.New(cfg, cache),
		cacheMgr:          cache,
		limiter:           ratelimit.New(cfg.Server.RateLimit, cfg.Server.RateBurst),
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		backgroundGroup:   backgroundGroup,
		backgroundCtx:     backgroundCtx,
		cacheRefreshGroup: cacheRefreshGroup,
		cacheRefreshCtx:   cacheRefreshCtx,
	}

	if cfg.Server.MaxConcurrent > 0 {
		server.semaphore = make(chan struct{}, cfg.Server.MaxConcurrent)
	}

	server.guard = security.New(cfg.Server.Features.HijackProtection)

	if cfg.Server.TLS.SelfSigned || (cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "") {
		tlsCfg := servertls.Config{Port: cfg.Server.TLS.Port, HTTPSPort: cfg.Server.TLS.HTTPS.Port, HTTPSEndpoint: cfg.Server.TLS.HTTPS.Endpoint, SelfSigned: cfg.Server.TLS.SelfSigned, CertFile: cfg.Server.TLS.CertFile, KeyFile: cfg.Server.TLS.KeyFile, Domain: cfg.Server.Features.DDR.Domain}
		tlsSrv, err := servertls.New(server, tlsCfg, OperationTimeout)
		if err != nil {
			cancel(fmt.Errorf("TLS server init: %w", err))
			return nil, fmt.Errorf("TLS server init: %w", err)
		}
		server.tls = tlsSrv
	}

	queryClient := client.New()
	server.queryClient = queryClient

	server.resolver = resolver.New(
		queryClient,
		server.guard,
		ednsHandler,
		cidrFilter,
		server.buildQueryMessage,
	)
	server.resolver.InitServers(cfg.Upstream, cfg.Fallback)

	if len(cfg.Server.Features.LatencyProbe) > 0 {
		server.prober = latency.New(
			cache,
			func(fn func() error) { server.backgroundGroup.Go(fn) },
			backgroundCtx,
			cfg.Server.Features.LatencyProbe,
		)
	}

	if cfg.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              "127.0.0.1:" + cfg.Server.Pprof,
			ReadHeaderTimeout: OperationTimeout,
			ReadTimeout:       OperationTimeout,
			IdleTimeout:       config.IdleTimeout,
		}

		// Never share the DNS TLS certificate with pprof — pprof exposes
		// heap dumps, goroutine stacks, and other sensitive runtime data.
	}

	if server.ednsMgr != nil && server.ednsMgr.CookieGenerator != nil {
		server.backgroundGroup.Go(func() error {
			defer dnsutil.HandlePanic("DNS cookie secret rotation")
			ticker := time.NewTicker(DefaultCookieSecretRotationInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					server.ednsMgr.CookieGenerator.RotateSecret()
					log.Debugf("EDNS: rotated DNS cookie secret")
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	if server.ednsMgr != nil && server.ednsMgr.ShouldRefreshDefaultECS() {
		server.backgroundGroup.Go(func() error {
			defer dnsutil.HandlePanic("EDNS default ECS refresh")

			if ecsList, changed, err := server.ednsMgr.RefreshDefaultECS(); err != nil {
				log.Warnf("EDNS: initial default ECS refresh failed: %v", err)
			} else if changed {
				for _, ecs := range ecsList {
					if ecs != nil {
						log.Infof("EDNS: initial default ECS refreshed: %s/%d", ecs.Address, ecs.SourcePrefix)
					}
				}
			}

			ticker := time.NewTicker(DefaultECSRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if ecsList, changed, err := server.ednsMgr.RefreshDefaultECS(); err != nil {
						log.Warnf("EDNS: default ECS refresh failed: %v", err)
					} else if changed {
						for _, ecs := range ecsList {
							if ecs != nil {
								log.Infof("EDNS: refreshed default ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
							}
						}
					}
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	server.backgroundGroup.Go(func() error {
		defer dnsutil.HandlePanic("prefetch cooldown cleanup")
		ticker := time.NewTicker(PrefetchThrottleInterval * 10)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now().UnixNano()
				server.prefetchCooldown.Range(func(key, value any) bool {
					if ts, ok := value.(int64); ok && now > ts {
						server.prefetchCooldown.Delete(key)
					}
					return true
				})
			case <-server.backgroundCtx.Done():
				return nil
			}
		}
	})

	if statsInterval := server.config.Server.StatsInterval(); statsInterval > 0 && server.statsMgr != nil {
		interval := time.Duration(statsInterval) * time.Second
		server.backgroundGroup.Go(func() error {
			defer dnsutil.HandlePanic("stats logger")
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					server.logStatsNow("interval")
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	if statsResetInterval := server.config.Server.StatsResetInterval(); statsResetInterval > 0 && server.statsMgr != nil {
		resetInterval := time.Duration(statsResetInterval) * time.Second
		server.backgroundGroup.Go(func() error {
			defer dnsutil.HandlePanic("stats reset")
			ticker := time.NewTicker(resetInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					server.statsMgr.Reset()
					log.Infof("STATS: counters reset")
					server.logStatsNow("reset")
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	server.backgroundGroup.Go(func() error {
		defer dnsutil.HandlePanic("tcpWriteMu sweep")
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-10 * time.Minute).UnixNano()
				server.tcpWriteMu.Range(func(key, value any) bool {
					if value.(*tcpWriteEntry).lastAccess.Load() < cutoff {
						server.tcpWriteMu.Delete(key)
					}
					return true
				})
			case <-server.backgroundCtx.Done():
				return nil
			}
		}
	})

	server.setupSignalHandling()

	return server, nil
}

func (s *Server) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer dnsutil.HandlePanic("Signal handler")
		defer signal.Stop(sigChan)
		select {
		case sig := <-sigChan:
			log.Infof("SIGNAL: Received signal %v, starting graceful shutdown", sig)
			s.shutdownServer()
		case <-s.ctx.Done():
		}
	}()
}

func (s *Server) logStatsNow(trigger string) {
	if s == nil || s.statsMgr == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), OperationTimeout)
	defer cancel()

	snapshot, err := s.statsMgr.FetchStats(ctx)
	if err != nil {
		log.Warnf("STATS: fetch failed: %v", err)
		return
	}

	payload, err := stats.BuildStatsLogJSON(snapshot)
	if err != nil {
		log.Errorf("STATS: build payload failed: %v", err)
		return
	}

	if strings.TrimSpace(trigger) == "" {
		trigger = "unknown"
	}

	log.Infof("STATS: trigger=%s payload=%s", trigger, payload)

	s.statsMgr.Persist(s.cacheMgr)
}

func (s *Server) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	log.Infof("SERVER: Starting DNS server shutdown")
	if s.statsMgr != nil {
		s.logStatsNow("shutdown")
	}

	if s.cancel != nil {
		s.cancel(errors.New("server shutdown"))
	}

	// Cache is intentionally closed AFTER background tasks and cache-refresh
	// goroutines finish, so that inflight cache writes during shutdown are
	// completed rather than silently dropped.

	if s.limiter != nil {
		s.limiter.Shutdown()
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer shutdownCancel()
	if s.udpServer != nil {
		if err := s.udpServer.ShutdownContext(shutdownCtx); err != nil {
			log.Errorf("SERVER: UDP server shutdown failed: %v", err)
		} else {
			log.Infof("SERVER: UDP server shut down")
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.ShutdownContext(shutdownCtx); err != nil {
			log.Errorf("SERVER: TCP server shutdown failed: %v", err)
		} else {
			log.Infof("SERVER: TCP server shut down")
		}
	}

	if s.tls != nil {
		if err := s.tls.Shutdown(); err != nil {
			log.Errorf("TLS: TLS server shutdown failed: %v", err)
		}
	}

	// Close pooled connections and transports to release file descriptors
	// and goroutines before waiting for background tasks.
	if s.queryClient != nil {
		s.queryClient.Close()
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		defer cancel()
		if err := s.pprofServer.Shutdown(ctx); err != nil {
			log.Errorf("PPROF: pprof server shutdown failed: %v", err)
		} else {
			log.Infof("PPROF: pprof server shut down successfully")
		}
	}

	bgDone := make(chan error, 1)
	go func() {
		defer dnsutil.HandlePanic("Background group wait")
		bgDone <- s.backgroundGroup.Wait()
	}()

	select {
	case err := <-bgDone:
		if err != nil {
			log.Errorf("SERVER: Background goroutines finished with error: %v", err)
		}
		log.Infof("SERVER: All background tasks shut down")
	case <-time.After(DefaultTimeout):
		log.Errorf("SERVER: Background tasks shutdown timeout")
	}

	refreshDone := make(chan error, 1)
	go func() {
		defer dnsutil.HandlePanic("Cache refresh group wait")
		refreshDone <- s.cacheRefreshGroup.Wait()
	}()

	select {
	case err := <-refreshDone:
		if err != nil {
			log.Errorf("SERVER: Cache refresh goroutines finished with error: %v", err)
		}
		log.Infof("SERVER: All cache refresh tasks shut down")
	case <-time.After(DefaultTimeout):
		log.Errorf("SERVER: Cache refresh tasks shutdown timeout")
	}

	if s.cacheMgr != nil {
		dnsutil.CloseWithLog(s.cacheMgr, "Cache store")
	}

	log.DefaultTimeCache.Stop()

	if s.shutdown != nil {
		close(s.shutdown)
	}

	log.Infof("SERVER: Shutdown complete")
}

// Start runs the DNS server and blocks until shutdown is triggered.
func (s *Server) Start() error {
	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server is closed")
	}

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancelCause(context.Background())
	defer serverCancel(errors.New("server startup completed"))

	log.Infof("SERVER: Starting ZJDNS Server %s", config.Version)
	log.Infof("SERVER: Log level: %s", log.Default.Level().String())
	log.Infof("SERVER: Listening on port: %s", s.config.Server.Port)

	s.displayInfo()
	if s.config.Server.StatsInterval() > 0 {
		s.logStatsNow("startup")
	}

	g, ctx := errgroup.WithContext(serverCtx)

	g.Go(func() error {
		defer dnsutil.HandlePanic("UDP server")
		s.udpServer = &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
			UDPSize: pool.UDPBufferSize,
		}
		log.Infof("SERVER: UDP server started on port %s", s.config.Server.Port)
		err := s.udpServer.ListenAndServe()
		if err != nil {
			return fmt.Errorf("UDP startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	if s.pprofServer != nil {
		g.Go(func() error {
			defer dnsutil.HandlePanic("pprof server")
			log.Infof("PPROF: pprof server started on port %s", s.config.Server.Pprof)
			var err error
			if s.pprofServer.TLSConfig != nil {
				err = s.pprofServer.ListenAndServeTLS("", "")
			} else {
				err = s.pprofServer.ListenAndServe()
			}

			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("pprof startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	g.Go(func() error {
		defer dnsutil.HandlePanic("TCP server")
		s.tcpServer = &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
		}
		log.Infof("SERVER: TCP server started on port %s", s.config.Server.Port)
		err := s.tcpServer.ListenAndServe()
		if err != nil {
			return fmt.Errorf("TCP startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	if s.tls != nil {
		g.Go(func() error {
			defer dnsutil.HandlePanic("Secure DNS server")
			httpsPort := s.config.Server.TLS.HTTPS.Port
			err := s.tls.Start(httpsPort)
			if err != nil {
				return fmt.Errorf("secure DNS startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	go func() {
		defer dnsutil.HandlePanic("Server coordinator")
		if err := g.Wait(); err != nil {
			select {
			case errChan <- err:
			default:
			}
		}
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	<-s.shutdown
	return nil
}

func (s *Server) displayInfo() {
	servers := s.resolver.UpstreamServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				info := fmt.Sprintf("Upstream server: %s", server.Address)
				if len(server.Match) > 0 {
					info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				log.Infof("UPSTREAM: %s", info)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
				}
				serverInfo := fmt.Sprintf("%s (%s)", server.Address, protocol)
				if server.SkipTLSVerify && dnsutil.IsSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [Skip TLS verification]"
				}
				if len(server.Match) > 0 {
					serverInfo += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				log.Infof("UPSTREAM: Upstream server: %s", serverInfo)
			}
		}
		log.Infof("UPSTREAM: Upstream mode: total %d servers", len(servers))
	} else {
		log.Infof("RECURSION: Recursive mode")
	}

	if s.cidrMgr != nil && len(s.config.CIDR) > 0 {
		log.Infof("CIDR: CIDR Filter: enabled (%d rules)", len(s.config.CIDR))
	}

	if s.pprofServer != nil {
		log.Infof("PPROF: pprof server enabled on: %s, via: %s, tls: %t", s.config.Server.Pprof, PprofPath, s.pprofServer.TLSConfig != nil)
	}

	if s.tls != nil {
		log.Infof("TLS: Listening on port: %s (DoT/DoQ)", s.config.Server.TLS.Port)
		httpsPort := s.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := s.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(config.DefaultQueryPath, "/")
			}
			log.Infof("TLS: Listening on port: %s (DoH/DoH3, endpoint: %s)", httpsPort, endpoint)
		}
	}

	if s.rewriteMgr.HasRules() {
		log.Infof("REWRITE: DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	log.Infof("CACHE: Serve expired enabled (ttl=%d, client timeout=%s, prefer_stale=%t)", cache.StaleMaxAge, ServeExpiredClientTimeout.String(), s.config.Server.Features.Cache.PreferStale)
	if s.config.Server.Features.HijackProtection {
		log.Infof("SECURITY: DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.DefaultECS(); defaultECS != nil {
		log.Infof("EDNS: Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
}
