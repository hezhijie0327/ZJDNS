// Package server implements the core DNS server, coordinating query processing, protocol listeners, and lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/cache"
	"zjdns/cidr"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/rewrite"
	"zjdns/server/latency"
	"zjdns/server/resolver"
	"zjdns/server/security"
	"zjdns/stats"
)

// Server is the core DNS server handling query processing, protocol listeners, and lifecycle.
type Server struct {
	closed int32

	config       *config.ServerConfig
	cacheMgr     cache.Store
	reverseCache interface {
		ReverseLookup(net.IP) []cache.LookupResult
	}
	guard      *security.Guard
	ednsMgr    *edns.Handler
	rewriteMgr *rewrite.Evaluator
	cidrMgr    *cidr.Filter
	statsMgr   *stats.Collector

	dnsProxy    *proxy.Proxy
	pprofServer *http.Server

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

// ServeDNS implements proxy.Handler for dnsproxy integration.
func (s *Server) ServeDNS(ctx context.Context, p *proxy.Proxy, dctx *proxy.DNSContext) error {
	clientIP := clientIPFromAddr(dctx.Addr)
	proto := string(dctx.Proto)
	response := s.processDNSQuery(dctx.Req, clientIP, protoIsSecure(proto), proto)
	if response != nil {
		dctx.Res = response
	}
	return nil
}

func clientIPFromAddr(addr netip.AddrPort) net.IP {
	if !addr.Addr().IsValid() || addr.Addr().IsUnspecified() {
		return nil
	}
	ip := addr.Addr().AsSlice()
	return net.IP(ip)
}

func protoIsSecure(proto string) bool {
	switch proto {
	case "tls", "quic", "https", "dnscrypt":
		return true
	}
	return false
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
	}

	server.guard = security.New(cacheStore, cfg.Server.Features.HijackProtection)
	server.reverseCache, _ = server.cacheMgr.(interface {
		ReverseLookup(net.IP) []cache.LookupResult
	})

	// Build dnsproxy config and create the proxy.
	pc, err := server.buildProxyConfig()
	if err != nil {
		cancel(fmt.Errorf("proxy config: %w", err))
		return nil, fmt.Errorf("proxy config: %w", err)
	}
	dnsProxy, err := proxy.New(pc)
	if err != nil {
		cancel(fmt.Errorf("proxy init: %w", err))
		return nil, fmt.Errorf("proxy init: %w", err)
	}
	server.dnsProxy = dnsProxy

	// Initialize the resolver with a client wrapper that uses dnsproxy's upstream.
	server.resolver = resolver.New(
		nil, // client — replaced by dnsproxy upstream resolution
		server.guard,
		ednsHandler,
		cidrFilter,
		server.buildQueryMessage,
		cacheStore,
	)
	server.resolver.DNSSECEnforce = cfg.Server.Features.DNSSECEnforce
	server.resolver.SetBackgroundContext(backgroundCtx)

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

	log.Infof("SERVER: Starting ZJDNS Server %s", config.Version)
	log.Infof("SERVER: Log level: %s", log.Default.Level().String())

	s.displayInfo()
	if s.config.Server.StatsInterval() > 0 {
		s.logStatsNow("startup")
	}

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancelCause(context.Background())
	defer serverCancel(errors.New("server startup completed"))

	g, ctx := errgroup.WithContext(serverCtx)

	// dnsproxy handles all DNS listeners (UDP, TCP, DoT, DoQ, DoH, DoH3, DNSCrypt).
	g.Go(func() error {
		defer dnsutil.HandlePanic("DNS proxy")
		log.Infof("SERVER: Starting DNS proxy")
		if err := s.dnsProxy.Start(ctx); err != nil {
			return fmt.Errorf("DNS proxy: %w", err)
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

	// Log listener addresses from dnsproxy.
	for _, addr := range s.dnsProxy.Addrs(proxy.ProtoUDP) {
		log.Infof("SERVER: Listening on %s (UDP)", addr)
	}
	for _, addr := range s.dnsProxy.Addrs(proxy.ProtoTCP) {
		log.Infof("SERVER: Listening on %s (TCP)", addr)
	}
	for _, addr := range s.dnsProxy.Addrs(proxy.ProtoTLS) {
		log.Infof("TLS: Listening on %s (DoT)", addr)
	}
	for _, addr := range s.dnsProxy.Addrs(proxy.ProtoQUIC) {
		log.Infof("TLS: Listening on %s (DoQ)", addr)
	}
	for _, addr := range s.dnsProxy.Addrs(proxy.ProtoHTTPS) {
		log.Infof("TLS: Listening on %s (DoH)", addr)
	}
	for _, addr := range s.dnsProxy.Addrs(proxy.ProtoDNSCrypt) {
		log.Infof("DNSCRYPT: Listening on %s (DNSCrypt)", addr)
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
