// Package main implements ZJDNS - High Performance DNS Server
// This file contains the main DNS server functionality including lifecycle
// management, signal handling, query processing, and response building.
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
	"zjdns/stats"
)

const (
	DefaultTimeout   = 2 * time.Second // Timeout for various operations like shutdown and cache refresh
	OperationTimeout = 3 * time.Second // Timeout for individual operations like upstream queries

	PrefetchThrottleInterval = 3 * time.Second // Minimum interval between prefetches for the same cache key to prevent thundering herd
	PrefetchThresholdPercent = 25              // Prefetch window threshold in percent of original TTL

	ServeExpiredClientTimeout = 1800 * time.Millisecond // Maximum client timeout for serving expired cache entries in seconds. RFC 8767 recommends 1.8 seconds

	DefaultCookieSecretRotationInterval = 1 * time.Hour    // Interval for rotating DNS cookie secrets
	DefaultECSRefreshInterval           = 15 * time.Minute // Interval for refreshing auto-configured ECS public IPs

	PprofPath = "/debug/pprof/" // Path prefix for pprof endpoints
)

// DNSServer is the core server coordinating query processing and protocol handlers.
type DNSServer struct {
	config            *config.ServerConfig
	cacheMgr          cache.Manager
	queryClient       *QueryClient
	securityMgr       *SecurityManager
	ednsMgr           *edns.Manager
	rewriteMgr        *rewrite.Manager
	cidrMgr           *cidr.Manager
	statsMgr          *stats.Manager
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
	queryMgr          *QueryManager
	limiter           *Limiter
	semaphore         chan struct{} // Admission control semaphore
	udpServer         *dns.Server   // stored for graceful shutdown
	tcpServer         *dns.Server   // stored for graceful shutdown
	tcpWriteMu        sync.Map      // key: RemoteAddr string → *tcpWriteEntry (TCP pipelining)
}

// tcpWriteEntry wraps per-connection state: a write serialization mutex,
// a last-access timestamp for periodic cleanup, and an in-flight capacity
// semaphore to bound concurrent queries per TCP connection (RFC 7766).
type tcpWriteEntry struct {
	mu           sync.Mutex
	lastAccess   atomic.Int64 // UnixNano
	capacity     chan struct{}
	capacityOnce sync.Once
}

// queryResult encapsulates the result of a DNS query, including the answer, authority, additional sections, validation status, ECS information, fallback status, and any error that occurred during processing.
type queryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *edns.ECSOption
	fallback   bool
	err        error
}

// NewDNSServer creates a new DNS server instance with all required managers.
// It initializes the cache, security, EDNS, rewrite, CIDR, and query managers.
func New(cfg *config.ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	ednsManager, err := edns.NewManager(cfg.Server.Features.ECS)
	if err != nil {
		cancel(fmt.Errorf("EDNS manager init: %w", err))
		return nil, fmt.Errorf("EDNS manager init: %w", err)
	}

	rewriteManager := rewrite.New()
	if len(cfg.Rewrite) > 0 {
		if err := rewriteManager.LoadRules(cfg.Rewrite); err != nil {
			cancel(fmt.Errorf("load rewrite rules: %w", err))
			return nil, fmt.Errorf("load rewrite rules: %w", err)
		}
	}

	var cidrManager *cidr.Manager
	if len(cfg.CIDR) > 0 {
		cidrManager, err = cidr.New(cfg.CIDR)
		if err != nil {
			cancel(fmt.Errorf("CIDR manager init: %w", err))
			return nil, fmt.Errorf("CIDR manager init: %w", err)
		}
	}

	cache := cache.New(cfg.Server.Features.Cache)

	server := &DNSServer{
		config:            cfg,
		ednsMgr:           ednsManager,
		rewriteMgr:        rewriteManager,
		cidrMgr:           cidrManager,
		statsMgr:          stats.New(cfg, cache),
		cacheMgr:          cache,
		limiter:           NewLimiter(cfg.Server.RateLimit, cfg.Server.RateBurst),
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

	securityManager, err := NewSecurityManager(cfg, server)
	if err != nil {
		cancel(fmt.Errorf("security manager init: %w", err))
		return nil, fmt.Errorf("security manager init: %w", err)
	}
	server.securityMgr = securityManager

	queryClient := NewQueryClient()
	server.queryClient = queryClient

	queryManager := NewQueryManager(server)
	if err := queryManager.Initialize(cfg.Upstream, cfg.Fallback); err != nil {
		cancel(fmt.Errorf("query manager init: %w", err))
		return nil, fmt.Errorf("query manager init: %w", err)
	}
	server.queryMgr = queryManager

	if cfg.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              ":" + cfg.Server.Pprof,
			ReadHeaderTimeout: OperationTimeout,
			ReadTimeout:       OperationTimeout,
			IdleTimeout:       config.IdleTimeout,
		}

		if server.securityMgr != nil && server.securityMgr.tls != nil {
			server.pprofServer.TLSConfig = server.securityMgr.tls.tlsConfig
		}
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

	// Background cleanup of prefetch cooldown map.
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

	// Periodic cleanup of stale TCP write mutex entries (idle > 10 min).
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

// setupSignalHandling configures signal handlers for graceful shutdown.
// It listens for SIGINT and SIGTERM signals to initiate server shutdown.
// Runs in its own goroutine (not added to backgroundGroup) to avoid a
// self-wait deadlock: shutdownServer() waits for backgroundGroup.Wait(),
// and if the signal handler were a member of that group, it would wait
// on itself.
func (s *DNSServer) setupSignalHandling() {
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

// logStatsNow fetches current statistics, logs them in JSON format, and persists them via the cache manager.
func (s *DNSServer) logStatsNow(trigger string) {
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

// shutdownServer performs graceful server shutdown, closing all connections
// and waiting for background tasks to complete.
func (s *DNSServer) shutdownServer() {
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

	if s.cacheMgr != nil {
		dnsutil.CloseWithLog(s.cacheMgr, "Cache manager")
	}

	if s.limiter != nil {
		s.limiter.Shutdown()
	}

	// Gracefully shut down UDP/TCP listeners so ListenAndServe goroutines return.
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

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(DefaultTimeout); err != nil {
			log.Errorf("SECURITY: Security manager shutdown failed: %v", err)
		}
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		if err := s.pprofServer.Shutdown(ctx); err != nil {
			log.Errorf("PPROF: pprof server shutdown failed: %v", err)
		} else {
			log.Infof("PPROF: pprof server shut down successfully")
		}
		cancel()
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

	log.DefaultTimeCache.Stop()

	if s.shutdown != nil {
		close(s.shutdown)
	}

	log.Infof("SERVER: Shutdown complete")
}

// Start starts the DNS server, including UDP, TCP, and secure protocol handlers
// (DoT, DoQ, DoH, DoH3) if configured.
func (s *DNSServer) Start() error {
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

	if s.securityMgr.tls != nil {
		g.Go(func() error {
			defer dnsutil.HandlePanic("Secure DNS server")
			httpsPort := s.config.Server.TLS.HTTPS.Port
			err := s.securityMgr.tls.Start(httpsPort)
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

// displayInfo logs server configuration information including upstream servers,
// cache settings, security features, and protocol listeners.
func (s *DNSServer) displayInfo() {
	servers := s.queryMgr.upstream.getServers()
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
		log.Infof("CIDR: CIDR Manager: enabled (%d rules)", len(s.config.CIDR))
	}

	if s.pprofServer != nil {
		log.Infof("PPROF: pprof server enabled on: %s, via: %s, tls: %t", s.config.Server.Pprof, PprofPath, s.pprofServer.TLSConfig != nil)
	}

	if s.securityMgr.tls != nil {
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
