// Package server implements the core DNS server, coordinating query processing, protocol listeners, and lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" // register pprof handlers on http.DefaultServeMux
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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
	"zjdns/server/resolver"
	"zjdns/server/security"
	servertls "zjdns/server/tls"
	"zjdns/stats"
)

const nanosPerSecond = int64(time.Second)

// Server is the core DNS server handling query processing, protocol listeners, and lifecycle.
type Server struct {
	closed int32 // hot-path: checked on every query via atomic load

	config       *config.ServerConfig
	cacheMgr     cache.Store
	reverseCache interface {
		ReverseLookup(net.IP) []cache.LookupResult
	}
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
	resolver          *resolver.Resolver
	prober            *latency.Prober
	semaphore         chan struct{}
	udpServer         *dns.Server
	tcpServer         *dns.Server
	tcpWriteMu        sync.Map
	udpRateLimiter    *rateLimiter
}

type rateLimitEntry struct {
	tokens     atomic.Int64
	lastRefill atomic.Int64 // unix nano
}

type rateLimiter struct {
	mu         sync.Mutex
	entries    map[string]*rateLimitEntry
	rate       int64 // tokens per second
	burst      int64 // max tokens
	maxEntries int   // max unique client IPs before rejecting new entries
}

func newRateLimiter(rate, burst int) *rateLimiter {
	return &rateLimiter{
		entries:    make(map[string]*rateLimitEntry),
		maxEntries: config.DefaultRateLimiterMaxEntries,
		rate:       int64(rate),
		burst:      int64(burst),
	}
}

// allow reports whether a request from the given key is allowed under the
// token-bucket rate limit. Returns true if allowed, false if rate-limited.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now().UnixNano()
	rl.mu.Lock()
	e, ok := rl.entries[key]
	if !ok {
		if len(rl.entries) >= rl.maxEntries {
			rl.mu.Unlock()
			return false
		}

		e = &rateLimitEntry{}
		e.tokens.Store(rl.burst - 1)
		e.lastRefill.Store(now)
		rl.entries[key] = e
		rl.mu.Unlock()
		return true
	}
	rl.mu.Unlock()

	last := e.lastRefill.Load()
	elapsed := now - last
	if elapsed < 0 {
		elapsed = 0
	}
	newTokens := elapsed * rl.rate / nanosPerSecond
	if newTokens > 0 {
		e.lastRefill.Store(now)
	}

	tokens := e.tokens.Add(newTokens)
	if tokens > rl.burst {
		e.tokens.Store(rl.burst)
		tokens = rl.burst
	}

	if tokens <= 0 {
		return false
	}
	e.tokens.Add(-1)
	return true
}

// sweep removes entries that haven't been accessed recently to prevent
// unbounded map growth.
func (rl *rateLimiter) sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge).UnixNano()
	rl.mu.Lock()
	for k, e := range rl.entries {
		if e.lastRefill.Load() < cutoff {
			delete(rl.entries, k)
		}
	}
	rl.mu.Unlock()
}

type tcpWriteEntry struct {
	writeMu      chan struct{} // buffered size 1, acts as timeout-capable mutex
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

	cacheStore := cache.New(cfg.Server.Features.Cache)

	server := &Server{
		config:            cfg,
		ednsMgr:           ednsHandler,
		rewriteMgr:        rewriteEvaluator,
		cidrMgr:           cidrFilter,
		statsMgr:          stats.New(cfg, cacheStore),
		cacheMgr:          cacheStore,
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
		server.udpRateLimiter = newRateLimiter(config.DefaultUDPRateLimit, config.DefaultUDPRateBurst)
	}

	server.guard = security.New(cacheStore, cfg.Server.Features.HijackProtection)
	// Cache the reverse lookup capability once — avoids a type assertion
	// on every PTR query.
	server.reverseCache, _ = server.cacheMgr.(interface {
		ReverseLookup(net.IP) []cache.LookupResult
	})

	if cfg.Server.TLS.SelfSigned || (cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "") {
		tlsCfg := servertls.Config{Port: cfg.Server.TLS.Port, HTTPSPort: cfg.Server.TLS.HTTPS.Port, HTTPSEndpoint: cfg.Server.TLS.HTTPS.Endpoint, SelfSigned: cfg.Server.TLS.SelfSigned, CertFile: cfg.Server.TLS.CertFile, KeyFile: cfg.Server.TLS.KeyFile, Domain: cfg.Server.Features.DDR.Domain}
		if cfg.Server.TLS.KTLS != nil {
			tlsCfg.KTLS = &servertls.KTLSSettings{
				KernelTX: cfg.Server.TLS.KTLS.KernelTX,
				KernelRX: cfg.Server.TLS.KTLS.KernelRX,
			}
		}
		tlsSrv, err := servertls.New(server, tlsCfg, config.DefaultBackgroundTimeout)
		if err != nil {
			cancel(fmt.Errorf("TLS server init: %w", err))
			return nil, fmt.Errorf("TLS server init: %w", err)
		}
		server.tls = tlsSrv
	}

	queryClient := client.New()
	if cfg.Server.TLS.KTLS != nil {
		queryClient.SetKTLS(cfg.Server.TLS.KTLS.KernelTX, cfg.Server.TLS.KTLS.KernelRX)
	}
	server.queryClient = queryClient

	server.resolver = resolver.New(
		queryClient,
		server.guard,
		ednsHandler,
		cidrFilter,
		server.buildQueryMessage,
		cacheStore,
	)
	server.resolver.DNSSECEnforce = cfg.Server.Features.DNSSECEnforce
	server.resolver.InitServers(cfg.Upstream, cfg.Fallback)
	server.resolver.SetBackgroundContext(backgroundCtx)

	// Initialize the infrastructure-level latency prober for root/NS
	// server reordering. This is independent of the user-facing
	// latency_probe configuration.
	latency.InitInfraProber(backgroundCtx)

	if len(cfg.Server.Features.LatencyProbe) > 0 {
		server.prober = latency.New(
			cacheStore,
			func(fn func() error) { server.backgroundGroup.Go(fn) },
			backgroundCtx,
			cfg.Server.Features.LatencyProbe,
		)
	}

	if cfg.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              "127.0.0.1:" + cfg.Server.Pprof,
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			ReadTimeout:       0, // Disabled: pprof endpoints (profile, trace, heap) take >10s
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
		}
	}

	server.startBackgroundTasks()

	return server, nil
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
			Net:     config.ProtoUDP,
			Handler: dns.HandlerFunc(s.handleDNSRequest),
			UDPSize: pool.UDPBufferSize,
		}
		log.Infof("SERVER: UDP server started on port %s", s.config.Server.Port)
		err := s.udpServer.ListenAndServe()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("UDP startup: %w", err)
			}
		}
		<-ctx.Done()
		return nil
	})

	if s.pprofServer != nil {
		g.Go(func() error {
			defer dnsutil.HandlePanic("pprof server")
			log.Infof("PPROF: pprof server started on port %s", s.config.Server.Pprof)
			err := s.pprofServer.ListenAndServe()

			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("pprof startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	g.Go(func() error {
		defer dnsutil.HandlePanic("TCP server")
		listener, err := net.Listen("tcp", ":"+s.config.Server.Port)
		if err != nil {
			return fmt.Errorf("TCP listen: %w", err)
		}
		s.tcpServer = &dns.Server{
			Listener: listener,
			Handler:  dns.HandlerFunc(s.handleDNSRequest),
		}
		log.Infof("SERVER: TCP server started on port %s", s.config.Server.Port)
		err = s.tcpServer.ListenAndServe()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("TCP startup: %w", err)
			}
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
		log.Infof("PPROF: pprof server enabled on: %s, via: %s", s.config.Server.Pprof, config.DefaultPprofPath)
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
		if runtime.GOOS == "linux" {
			ktlsTX, ktlsRX := false, false
			if s.config.Server.TLS.KTLS != nil {
				ktlsTX, ktlsRX = s.config.Server.TLS.KTLS.KernelTX, s.config.Server.TLS.KTLS.KernelRX
			}
			if _, err := os.Stat("/sys/module/tls"); err == nil {
				log.Infof("TLS: kTLS available, TX=%t RX=%t", ktlsTX, ktlsRX)
			} else {
				log.Infof("TLS: kTLS unavailable (load with: modprobe tls)")
			}
		}
	}

	if s.rewriteMgr.HasRules() {
		log.Infof("REWRITE: DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	log.Infof("CACHE: Serve expired enabled (ttl=%d, client timeout=%s, prefer_stale=%t)", config.DefaultStaleMaxAge, config.DefaultServeExpiredClientTimeout.String(), s.config.Server.Features.Cache.PreferStale)
	if s.config.Server.Features.HijackProtection {
		log.Infof("SECURITY: DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.DefaultECS(); defaultECS != nil {
		log.Infof("EDNS: Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
}
