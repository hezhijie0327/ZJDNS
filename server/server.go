// Package server implements the core DNS server, coordinating query processing, protocol listeners, and lifecycle.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: profiling endpoint is opt-in // register pprof handlers on http.DefaultServeMux
	"os"
	"runtime"
	"strings"
	"sync"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/database"
	"zjdns/edns"
	"zjdns/internal/dns64"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/ruleset"
	"zjdns/server/handler"
	serverdnscrypt "zjdns/server/protocol/dnscrypt"
	serverplain "zjdns/server/protocol/plain"
	servertlcp "zjdns/server/protocol/tlcp"
	"zjdns/server/protocol/tls"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/hijack"
	"zjdns/server/resolver/probe"
	"zjdns/server/upstream"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// Server is the core DNS server handling lifecycle, protocol listeners, and background tasks.
type Server struct {
	config          *config.ServerConfig
	handler         *handler.Handler
	queryClient     *upstream.Client
	tls             *tls.Server
	dnscryptServer  *serverdnscrypt.Server
	tlcpServer      *servertlcp.Server
	plain           *serverplain.Server
	pprofServer     *http.Server
	ctx             context.Context
	cancel          context.CancelCauseFunc
	shutdown        chan struct{}
	backgroundGroup *errgroup.Group
	backgroundCtx   context.Context
	tcpWriteMu      sync.Map
	tcpSem          chan struct{} // bounds concurrent TCP query goroutines
}

// New creates and initializes a Server from the given configuration.
func New(cfg *config.ServerConfig) (*Server, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	server := &Server{
		config:          cfg,
		ctx:             ctx,
		cancel:          cancel,
		shutdown:        make(chan struct{}),
		backgroundGroup: backgroundGroup,
		backgroundCtx:   backgroundCtx,
		tcpSem:          make(chan struct{}, config.DefaultServerGoroutineLimit),
	}

	// ── Foundation: database ──────────────────────────────────────────────

	db, err := database.Open(
		cfg.Server.Features.Database.DBPath,
		cfg.Server.Features.Cache.MaxEntries,
		database.Options{
			MMapSizeMB:  cfg.Server.Features.Database.MMapSizeMB,
			CacheSizeMB: cfg.Server.Features.Database.CacheSizeMB,
		})
	if err != nil {
		cancel(fmt.Errorf("database init: %w", err))
		return nil, fmt.Errorf("database init: %w", err)
	}
	cacheStore := cache.New(db)
	zoneEvaluator := zone.New(db)

	ednsHandler, err := edns.NewHandler(cfg.Server.Features.ECS)
	if err != nil {
		cancel(fmt.Errorf("EDNS handler init: %w", err))
		return nil, fmt.Errorf("EDNS handler init: %w", err)
	}

	// Wire up DynamicContent for zone rules.
	for i := range cfg.Zone.Rules {
		switch cfg.Zone.Rules[i].Name {
		case config.DefaultProjectName + ".stats":
			cfg.Zone.Rules[i].DynamicContent = cacheStore.Stats
		case config.DefaultProjectName + ".db.clear":
			cfg.Zone.Rules[i].DynamicContent = func() []string {
				n, err := cacheStore.Clear()
				if err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{fmt.Sprintf("flushed=%d", n)}
			}
		case config.DefaultProjectName + ".db.clear.cache":
			cfg.Zone.Rules[i].DynamicContent = func() []string {
				n, err := cacheStore.FlushDB("cache")
				if err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{fmt.Sprintf("flushed=%d", n)}
			}
		case config.DefaultProjectName + ".db.clear.stats":
			cfg.Zone.Rules[i].DynamicContent = func() []string {
				n, err := cacheStore.FlushDB("stats")
				if err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{fmt.Sprintf("reset=%d", n)}
			}
		case config.DefaultProjectName + ".db.clear.latency":
			cfg.Zone.Rules[i].DynamicContent = func() []string {
				n, err := cacheStore.FlushDB("latency")
				if err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{fmt.Sprintf("flushed=%d", n)}
			}
		case config.DefaultProjectName + ".db.clear.zone":
			cfg.Zone.Rules[i].DynamicContent = func() []string {
				n, err := cacheStore.FlushDB("zone")
				if err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{fmt.Sprintf("flushed=%d", n)}
			}
		case config.DefaultProjectName + ".db.clear.ruleset":
			cfg.Zone.Rules[i].DynamicContent = func() []string {
				n, err := cacheStore.FlushDB("ruleset")
				if err != nil {
					return []string{fmt.Sprintf("error=%v", err)}
				}
				return []string{fmt.Sprintf("flushed=%d", n)}
			}
		}
	}

	if len(cfg.Zone.Rules) > 0 {
		if err := zoneEvaluator.LoadRules(cfg.Zone.Rules); err != nil {
			cancel(fmt.Errorf("load zone rules: %w", err))
			return nil, fmt.Errorf("load zone rules: %w", err)
		}
		if len(cfg.Zone.BypassTags) > 0 {
			zoneEvaluator.SetBypassTags(cfg.Zone.BypassTags)
		}
	}

	var rulesetEngine *ruleset.Engine
	if len(cfg.RuleSet) > 0 {
		rulesetEngine = ruleset.New(db)
		if err := rulesetEngine.LoadRules(cfg.RuleSet); err != nil {
			cancel(fmt.Errorf("ruleset init: %w", err))
			return nil, fmt.Errorf("ruleset init: %w", err)
		}
	}

	// ── Core: security ────────────────────────────────────────────────────

	cryptoValidator := dnssec.NewCryptoValidator(cacheStore)
	hijackDetector := &hijack.Detector{}
	hijackDetector.Enable(cfg.Server.Features.HijackProtection)

	// ── Outbound: query client ────────────────────────────────────────────

	queryClient := upstream.New()
	if cfg.Server.Features.KTLS != nil {
		queryClient.SetKTLS(cfg.Server.Features.KTLS.KernelTX, cfg.Server.Features.KTLS.KernelRX)
	}
	server.queryClient = queryClient

	// ── Resolution: resolver + upstream config (created before handler) ───

	var cidrMatcher resolver.CIDRMatcher
	if rulesetEngine != nil {
		cidrMatcher = rulesetEngine
	}
	dnsResolver := resolver.New(&resolver.Config{
		QueryClient: queryClient,
		Crypto:      cryptoValidator,
		Hijack:      hijackDetector,
		EDNS:        ednsHandler,
		CIDRMatcher: cidrMatcher,
		BuildMsg: func(q resolver.Question, ecs *edns.ECSOption, rd, secure bool) *dns.Msg {
			return handler.BuildQueryMsg(ednsHandler, q, ecs, rd, secure)
		},
		Cache:         cacheStore,
		DNSSECEnforce: cfg.Server.Features.DNSSECEnforce,
	})
	dnsResolver.ConfigureServers(cfg.Upstream, cfg.Fallback)

	if len(cfg.Upstream) > 0 || len(cfg.Fallback) > 0 {
		allServers := make([]config.UpstreamServer, 0, len(cfg.Upstream)+len(cfg.Fallback))
		allServers = append(allServers, cfg.Upstream...)
		allServers = append(allServers, cfg.Fallback...)
		server.queryClient.WarmUpConnections(allServers)
	}

	// ── Middleware chain assembly ─────────────────────────────────────────

	// Latency prober — created before handler so it can be injected.
	var prober handler.LatencyProber
	if len(cfg.Server.Features.LatencyProbe) > 0 {
		prober = probe.New(
			cacheStore,
			func(fn func() error) { server.backgroundGroup.Go(fn) },
			backgroundCtx,
			cfg.Server.Features.LatencyProbe,
		)
	}

	prefetchCooldown := handler.NewPrefetchCooldown()

	deps := &handler.Dependencies{
		Config:           cfg,
		Cache:            cacheStore,
		EDNS:             ednsHandler,
		ZoneEvaluator:    zoneEvaluator,
		TagMatcher:       nil,
		Resolver:         dnsResolver,
		Prober:           prober,
		PendingReqs:      handler.NewPendingRequests(),
		PendingRefrs:     handler.NewRefreshGroup(),
		DNS64:            nil, // set below if enabled
		RulesetEngine:    cidrMatcher,
		Closed:           func() bool { return false }, // updated after handler creation
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
			synth, _ = dns64.New(config.DefaultDNS64Prefix)
		}
		deps.DNS64 = synth
		log.Infof("DNS64: enabled with prefix %s", synth.Prefix())
	}

	chain := handler.AssembleChain(deps)

	h := handler.NewHandler(
		chain, ednsHandler, cacheStore, prober, dnsResolver,
		cacheRefreshGroup, prefetchCooldown, ctx,
	)
	server.handler = h

	// Wire the closed-check callback after handler is created.
	deps.Closed = h.IsClosed

	// ── Transport listeners ───────────────────────────────────────────────

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
			cancel(fmt.Errorf("TLS server init: %w", err))
			return nil, fmt.Errorf("TLS server init: %w", err)
		}
		server.tls = tlsSrv
	}

	if cfg.Server.Protocol.DNSCrypt != "" {
		providerName := cfg.Server.Certificate.DNSCrypt.ProviderName(cfg.Server.Certificate.Domain)
		dnscryptSrv, err := serverdnscrypt.New(&cfg.Server.Certificate.DNSCrypt, cfg.Server.Protocol.DNSCrypt, providerName)
		if err != nil {
			cancel(fmt.Errorf("DNSCrypt server init: %w", err))
			return nil, fmt.Errorf("DNSCrypt server init: %w", err)
		}
		server.dnscryptServer = dnscryptSrv
	}

	if cfg.Server.Certificate.TLCP.IsEnabled() && (cfg.Server.Protocol.TLCP != "" || cfg.Server.Protocol.HTTPTLCP.Port != "" || cfg.Server.Protocol.DTLCP != "") {
		tlcpSrv, err := servertlcp.New(&cfg.Server.Certificate.TLCP, cfg.Server.Protocol.TLCP, cfg.Server.Protocol.HTTPTLCP.Port, cfg.Server.Protocol.HTTPTLCP.Endpoint, cfg.Server.Protocol.DTLCP)
		if err != nil {
			cancel(fmt.Errorf("TLCP server init: %w", err))
			return nil, fmt.Errorf("TLCP server init: %w", err)
		}
		server.tlcpServer = tlcpSrv
	}

	server.plain = serverplain.New(cfg)

	// ── Observability: pprof ──────────────────────────────────────────────

	if cfg.Server.Pprof != "" {
		if err := zdnsutil.TryBind("tcp", "127.0.0.1:"+cfg.Server.Pprof); err != nil {
			log.Warnf("PPROF: skipping — address 127.0.0.1:%s is unavailable: %v", cfg.Server.Pprof, err)
		} else {
			server.pprofServer = &http.Server{
				Addr:              "127.0.0.1:" + cfg.Server.Pprof,
				ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
				ReadTimeout:       0,
				IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			}
		}
	}

	// ── Background tasks ──────────────────────────────────────────────────

	server.startBackgroundTasks()

	return server, nil
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
	serverCtx, serverCancel := context.WithCancelCause(context.Background())
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
	servers := s.handler.UpstreamServers()
	if len(servers) > 0 {
		for _, server := range servers {
			if server.IsRecursive() {
				info := "Upstream server: " + server.Address
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
				if server.SkipTLSVerify && zdnsutil.IsSecureProtocol(strings.ToLower(server.Protocol)) {
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
