// Package server provides the core DNS server: lifecycle management,
// dependency wiring, and background task scheduling.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/database"
	"zjdns/edns"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/ruleset"
	"zjdns/server/handler"
	"zjdns/server/handler/middleware"
	"zjdns/server/protocol/tls"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/hijack"
	"zjdns/server/resolver/probe"
	"zjdns/server/upstream"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"

	zdnsutil "zjdns/internal/dnsutil"

	serverdnscrypt "zjdns/server/protocol/dnscrypt"
	serverplain "zjdns/server/protocol/plain"
	servertlcp "zjdns/server/protocol/tlcp"
)

// Server orchestrates the DNS server lifecycle: dependency wiring, protocol
// listener startup/shutdown, and background task scheduling.
type Server struct {
	config      *config.ServerConfig
	handler     *handler.Handler
	queryClient *upstream.Client

	tls             *tls.Server
	tlcpServer      *servertlcp.Server
	dnscryptServer  *serverdnscrypt.Server
	plain           *serverplain.Server
	pprofServer     *http.Server
	shutdown        chan struct{}
	tcpSem          chan struct{}
	tcpWriteMu      sync.Map
	ctx             context.Context
	cancel          context.CancelCauseFunc
	backgroundGroup *errgroup.Group
	backgroundCtx   context.Context
}

// New creates a fully-wired Server from the given configuration.  Database
// setup, cache, zone rules, the resolver, the middleware chain, and all
// protocol listeners are constructed and connected.
func New(cfg *config.ServerConfig) (*Server, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	s := &Server{
		config:          cfg,
		ctx:             ctx,
		cancel:          cancel,
		shutdown:        make(chan struct{}),
		backgroundGroup: backgroundGroup,
		backgroundCtx:   backgroundCtx,
		tcpSem:          make(chan struct{}, config.DefaultServerGoroutineLimit),
	}

	db, err := s.initDatabase(cfg)
	if err != nil {
		cancel(err)
		return nil, fmt.Errorf("database init: %w", err)
	}

	cacheStore := cache.New(db)
	zoneEvaluator := zone.New(db)

	ednsH, err := s.initEDNS(cfg)
	if err != nil {
		cancel(err)
		return nil, fmt.Errorf("EDNS handler init: %w", err)
	}

	rulesetEngine, err := s.initZoneAndRulesets(cfg, cacheStore, zoneEvaluator, db)
	if err != nil {
		cancel(err)
		return nil, err
	}

	queryClient := s.initQueryClient(cfg)

	dnsResolver := s.initDNSResolver(cfg, queryClient, ednsH, cacheStore, rulesetEngine)

	s.warmUpConnections(cfg, queryClient)

	h := s.initHandler(cfg, cacheStore, ednsH, zoneEvaluator, dnsResolver, rulesetEngine, cacheRefreshGroup, cacheRefreshCtx, backgroundCtx)

	s.handler = h

	if err := s.initProtocolListeners(cfg, h); err != nil {
		cancel(err)
		return nil, err
	}

	s.initPprof(cfg)

	s.startBackgroundTasks()

	return s, nil
}

// initDatabase opens the SQLite database with configured pragmas.
func (s *Server) initDatabase(cfg *config.ServerConfig) (*database.DB, error) {
	return database.Open(
		cfg.Server.Features.Database.DBPath,
		cfg.Server.Features.Cache.MaxEntries,
		database.Options{
			MMapSizeMB:  cfg.Server.Features.Database.MMapSizeMB,
			CacheSizeMB: cfg.Server.Features.Database.CacheSizeMB,
		})
}

// initEDNS creates the EDNS handler and auto-detects ECS subnets.
func (s *Server) initEDNS(cfg *config.ServerConfig) (*edns.Handler, error) {
	return edns.NewHandler(cfg.Server.Features.ECS)
}

// initZoneAndRulesets loads zone-file rules and CIDR/domain matching rulesets
// from config.  Returns the ruleset engine (nil if none configured) and any
// fatal error from loading.
func (s *Server) initZoneAndRulesets(cfg *config.ServerConfig, cacheStore cache.Store, zoneEvaluator *zone.Evaluator, db *database.DB) (*ruleset.Engine, error) {
	wireZoneDynamicContent(cacheStore, cfg.Zone.Rules)

	if len(cfg.Zone.Rules) > 0 {
		if err := zoneEvaluator.LoadRules(cfg.Zone.Rules); err != nil {
			return nil, fmt.Errorf("load zone rules: %w", err)
		}
		if len(cfg.Zone.BypassTags) > 0 {
			zoneEvaluator.SetBypassTags(cfg.Zone.BypassTags)
		}
	}

	var engine *ruleset.Engine
	if len(cfg.RuleSet) > 0 {
		engine = ruleset.New(db)
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

// isRecursiveMode reports whether any upstream or fallback server uses the
// built-in recursive resolver, or whether no servers are configured (pure
// recursive mode).
func isRecursiveMode(cfg *config.ServerConfig) bool {
	if len(cfg.Upstream) == 0 && len(cfg.Fallback) == 0 {
		return true
	}
	for i := range cfg.Upstream {
		if cfg.Upstream[i].IsRecursive() {
			return true
		}
	}
	for i := range cfg.Fallback {
		if cfg.Fallback[i].IsRecursive() {
			return true
		}
	}
	return false
}

// initDNSResolver wires together the recursive/forward resolver, security
// validators, and CIDR matcher.
func (s *Server) initDNSResolver(cfg *config.ServerConfig, queryClient *upstream.Client, ednsH *edns.Handler, cacheStore cache.Store, rulesetEngine *ruleset.Engine) *resolver.Resolver {
	cryptoValidator := dnssec.NewCryptoValidator(cacheStore)

	// Load root files only when recursive resolution is configured.
	if isRecursiveMode(cfg) {
		cryptoValidator.LoadTrustAnchors()
		resolver.LoadRootHints()
	}

	hijackDetector := &hijack.Detector{}
	hijackDetector.Enable(cfg.Server.Features.HijackProtection)

	var cidrMatcher resolver.CIDRMatcher
	if rulesetEngine != nil {
		cidrMatcher = rulesetEngine
	}

	return initResolver(cfg, queryClient, cryptoValidator, hijackDetector, ednsH, cidrMatcher, cacheStore,
		func(q resolver.Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
			return handler.BuildQueryMsg(ednsH, q, ecs, rd, secure)
		}, s.backgroundCtx)
}

// warmUpConnections pre-establishes transport connections to all configured
// secure upstream servers.
func (s *Server) warmUpConnections(cfg *config.ServerConfig, queryClient *upstream.Client) {
	if len(cfg.Upstream) == 0 && len(cfg.Fallback) == 0 {
		return
	}
	allServers := make([]config.UpstreamServer, 0, len(cfg.Upstream)+len(cfg.Fallback))
	allServers = append(allServers, cfg.Upstream...)
	allServers = append(allServers, cfg.Fallback...)
	queryClient.WarmUpConnections(allServers)
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
	ctx := s.ctx

	deps := &middleware.Dependencies{
		Config:           cfg,
		Cache:            cacheStore,
		EDNS:             ednsH,
		ZoneEvaluator:    zoneEvaluator, // set below
		TagMatcher:       nil,
		Resolver:         dnsResolver,
		Prober:           prober,
		PendingReqs:      handler.NewPendingRequests(),
		PendingRefrs:     handler.NewRefreshGroup(),
		DNS64:            nil,
		RulesetEngine:    nil,
		Closed:           func() bool { return false },
		RefreshGroup:     cacheRefreshGroup,
		RefreshCtx:       cacheRefreshCtx,
		Ctx:              ctx,
		PrefetchCooldown: prefetchCooldown,
	}

	if rulesetEngine != nil {
		deps.RulesetEngine = rulesetEngine
		deps.TagMatcher = func(qname string, ip net.IP) map[string]bool {
			return rulesetEngine.Match(qname, ip.String())
		}
	}

	// DNS64 synthesizer.
	if cfg.Server.Features.DNS64 != nil && cfg.Server.Features.DNS64.Prefix != "" {
		synth, err := dns64.New(cfg.Server.Features.DNS64.Prefix)
		if err != nil {
			log.Warnf("DNS64: %v, using default prefix", err)
			synth, _ = dns64.New(config.DefaultDNS64Prefix)
		}
		deps.DNS64 = synth
		log.Infof("DNS64: enabled with prefix %s", synth.Prefix())
	}

	chain := middleware.AssembleChain(deps)

	h := handler.NewHandler(
		chain, ednsH, cacheStore, prober, dnsResolver,
		cacheRefreshGroup, prefetchCooldown, ctx,
	)
	deps.Closed = h.IsClosed

	return h
}

// initProtocolListeners creates and wires all protocol servers (TLS, TLCP,
// DNSCrypt, Plain) into the Server struct.  Errors are non-fatal — the
// server starts with the protocols that initialised successfully.
func (s *Server) initProtocolListeners(cfg *config.ServerConfig, h *handler.Handler) error {
	if cfg.Server.Certificate.TLS.IsEnabled() {
		tlsCfg := tls.Config{
			TLSPort:       cfg.Server.Protocol.TLS,
			QUICPort:      cfg.Server.Protocol.QUIC,
			DTLSPort:      cfg.Server.Protocol.DTLS,
			HTTPSPort:     cfg.Server.Protocol.HTTPS.Port,
			HTTP3Port:     cfg.Server.Protocol.HTTP3.Port,
			HTTPSEndpoint: cfg.Server.Protocol.HTTPS.Endpoint,
			HTTP3Endpoint: cfg.Server.Protocol.HTTP3.Endpoint,
			SelfSigned:    cfg.Server.Certificate.TLS.SelfSigned,
			CertFile:      cfg.Server.Certificate.TLS.CertFile,
			KeyFile:       cfg.Server.Certificate.TLS.KeyFile,
			Domain:        cfg.Server.Certificate.Domain,
		}
		if cfg.Server.Features.KTLS != nil {
			tlsCfg.KTLS = &tls.KTLSSettings{KernelTX: cfg.Server.Features.KTLS.KernelTX, KernelRX: cfg.Server.Features.KTLS.KernelRX}
		}
		tlsSrv, err := tls.New(h, &tlsCfg, config.DefaultBackgroundTimeout)
		if err != nil {
			return fmt.Errorf("TLS server init: %w", err)
		}
		s.tls = tlsSrv
	}

	if cfg.Server.Protocol.DNSCrypt != "" {
		providerName := cfg.Server.Certificate.DNSCrypt.ProviderName(cfg.Server.Certificate.Domain)
		dnscryptSrv, err := serverdnscrypt.New(&cfg.Server.Certificate.DNSCrypt, cfg.Server.Protocol.DNSCrypt, providerName)
		if err != nil {
			return fmt.Errorf("DNSCrypt server init: %w", err)
		}
		s.dnscryptServer = dnscryptSrv
	}

	if cfg.Server.Certificate.TLCP.IsEnabled() && (cfg.Server.Protocol.TLCP != "" || cfg.Server.Protocol.HTTPTLCP.Port != "" || cfg.Server.Protocol.DTLCP != "") {
		tlcpSrv, err := servertlcp.New(&cfg.Server.Certificate.TLCP, cfg.Server.Protocol.TLCP, cfg.Server.Protocol.HTTPTLCP.Port, cfg.Server.Protocol.HTTPTLCP.Endpoint, cfg.Server.Protocol.DTLCP)
		if err != nil {
			return fmt.Errorf("TLCP server init: %w", err)
		}
		s.tlcpServer = tlcpSrv
	}

	s.plain = serverplain.New(cfg)
	return nil
}

// initPprof starts the optional pprof HTTP listener on 127.0.0.1.
func (s *Server) initPprof(cfg *config.ServerConfig) {
	if cfg.Server.Pprof == "" {
		return
	}
	if err := zdnsutil.TryBind("tcp", "127.0.0.1:"+cfg.Server.Pprof); err != nil {
		log.Warnf("PPROF: skipping — 127.0.0.1:%s unavailable: %v", cfg.Server.Pprof, err)
		return
	}
	s.pprofServer = &http.Server{
		Addr:              "127.0.0.1:" + cfg.Server.Pprof,
		ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
		ReadTimeout:       0,
		IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
	}
}

// ServeDNS delegates to the query handler. Required by server/tls.DNSHandler
// interface and external benchmarks.
func (s *Server) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	return s.handler.ServeDNS(req, clientIP, isSecure, protocol)
}

// Start runs the DNS server and blocks until shutdown is triggered.
func (s *Server) Start() error {
	if s.handler.IsClosed() {
		return errors.New("server is closed")
	}

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancelCause(s.ctx)
	defer serverCancel(errors.New("server startup completed"))

	s.displayInfo()

	g, ctx := errgroup.WithContext(serverCtx)

	if s.pprofServer != nil {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("pprof server")
			log.Infof("PPROF: pprof server started on port %s", s.config.Server.Pprof)
			err := s.pprofServer.ListenAndServe()

			if err != nil && err != http.ErrServerClosed {
				return fmt.Errorf("pprof startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if err := s.plain.Start(g, ctx, dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) { s.handleDNSRequest(w, r) })); err != nil {
		return err
	}

	if s.tls != nil {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("Secure DNS server")
			err := s.tls.Start()
			if err != nil {
				return fmt.Errorf("secure DNS startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.dnscryptServer != nil {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("DNSCrypt server")
			if err := s.dnscryptServer.Start(s); err != nil {
				return fmt.Errorf("DNSCrypt startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	if s.tlcpServer != nil {
		g.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP server")
			if err := s.tlcpServer.Start(s); err != nil {
				return fmt.Errorf("TLCP startup: %w", err)
			}
			<-ctx.Done()
			_ = s.tlcpServer.Shutdown()
			return nil
		})
	}

	go func() {
		defer zdnsutil.HandlePanic("Server coordinator")
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
	up := s.handler.UpstreamServers()
	fb := s.handler.FallbackServers()

	if len(up) == 0 && len(fb) == 0 {
		log.Infof("RECURSION: Recursive mode")
		return
	}

	for _, server := range up {
		s.logServer("UPSTREAM", server)
	}
	if len(fb) > 0 {
		for _, server := range fb {
			s.logServer("FALLBACK", server)
		}
		log.Infof("UPSTREAM: %d upstream + %d fallback servers", len(up), len(fb))
	} else {
		log.Infof("UPSTREAM: %d servers", len(up))
	}
	s.displayExtras()
}

func (s *Server) logServer(role string, server *config.UpstreamServer) {
	if server.IsRecursive() {
		info := server.Address
		if len(server.Match) > 0 {
			info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
		}
		log.Infof("%s: %s", role, info)
		return
	}
	protocol := strings.ToUpper(server.Protocol)
	if protocol == "" {
		protocol = "UDP"
	}
	info := fmt.Sprintf("%s (%s)", server.Address, protocol)
	if server.SkipTLSVerify && zdnsutil.IsSecureProtocol(strings.ToLower(server.Protocol)) {
		info += " [Skip TLS verification]"
	}
	if len(server.Match) > 0 {
		info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
	}
	log.Infof("%s: %s", role, info)
}

func (s *Server) displayExtras() {
	if s.pprofServer != nil {
		log.Infof("PPROF: pprof server enabled on: %s, via: %s", s.config.Server.Pprof, config.DefaultPprofPath)
	}

	if s.tls != nil {
		if runtime.GOOS == "linux" {
			ktlsTX, ktlsRX := false, false
			if s.config.Server.Features.KTLS != nil {
				ktlsTX, ktlsRX = s.config.Server.Features.KTLS.KernelTX, s.config.Server.Features.KTLS.KernelRX
			}
			if _, err := os.Stat("/sys/module/tls"); err == nil {
				log.Infof("TLS: kTLS available, TX=%t RX=%t", ktlsTX, ktlsRX)
			} else {
				log.Infof("TLS: kTLS unavailable (load with: modprobe tls)")
			}
		}
	}

	if s.config.Server.Features.HijackProtection {
		log.Infof("SECURITY: DNS hijacking prevention: enabled")
	}
}
