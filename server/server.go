// Package server provides the core DNS server: lifecycle management,
// dependency wiring, and background task scheduling.
package server

import (
	"context"
	"errors"
	_ "expvar" // /debug/vars: runtime MemStats for RSS diagnosis (served only when pprof is enabled)
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // G108: pprof is off unless configured
	"os"
	"runtime"
	"strings"
	"sync"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/ruleset"
	"zjdns/server/defense"
	"zjdns/server/handler"
	"zjdns/server/handler/middleware"
	"zjdns/server/protocol/shared"
	"zjdns/server/protocol/tls"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/server/resolver/probe"
	"zjdns/server/upstream"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnshttp"
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
	dnsResolver *resolver.Resolver

	tls            *tls.Server
	tlcpServer     *servertlcp.Server
	dnscryptServer *serverdnscrypt.Server
	plain          *serverplain.Server
	sharedManager  *shared.Manager
	pprofServers   []*http.Server
	shutdown       chan struct{}
	shutdownOnce   sync.Once // guards close(shutdown) — a second shutdownServer call would double-close (M-3-6)
	tcpSem         chan struct{}
	// tcpWriteShards is the per-connection TCP write-serialization registry,
	// sharded by client address so concurrent connections never contend on a
	// global lock.  Each shard's mutex serializes the entry lifecycle (see
	// tcpWriteShard in bridge.go).
	tcpWriteShards  [tcpWriteShardCount]tcpWriteShard
	ctx             context.Context
	cancel          context.CancelCauseFunc
	backgroundGroup *errgroup.Group
	backgroundCtx   context.Context
}

// New creates a fully-wired Server from the given configuration.  Database
// setup, cache, zone rules, the resolver, the middleware chain, and all
// protocol listeners are constructed and connected.
func New(cfg *config.ServerConfig) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("server: nil config")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup.SetLimit(config.DefaultCacheRefreshConcurrency)

	s := &Server{
		config:          cfg,
		ctx:             ctx,
		cancel:          cancel,
		shutdown:        make(chan struct{}),
		backgroundGroup: backgroundGroup,
		backgroundCtx:   backgroundCtx,
		tcpSem:          make(chan struct{}, config.DefaultServerGoroutineLimit),
	}

	// Two-tier cache: the spill files ARE the persistence — opened (and
	// warmed with the hottest entries) inside New, no separate snapshot load.
	cacheStore := cache.New(
		cfg.Server.Features.Cache.Entries.Limit, cfg.Server.Features.Cache.Latency.Limit,
		cfg.Server.Features.CacheStateFile(), cfg.Server.Features.LatencyStateFile(),
	)
	zoneEvaluator := zone.New()

	ednsH, err := s.initEDNS(cfg)
	if err != nil {
		cancel(err)
		return nil, fmt.Errorf("EDNS handler init: %w", err)
	}

	rulesetEngine, err := s.initZoneAndRulesets(cfg, cacheStore, zoneEvaluator)
	if err != nil {
		cancel(err)
		return nil, err
	}

	queryClient := s.initQueryClient(cfg)

	dnsResolver, err := s.initDNSResolver(cfg, queryClient, ednsH, cacheStore, rulesetEngine)
	if err != nil {
		cancel(err)
		return nil, fmt.Errorf("resolver init: %w", err)
	}
	s.dnsResolver = dnsResolver

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

	h := handler.NewHandler(
		chain, ednsH, cacheStore, prober, dnsResolver,
		cacheRefreshGroup, prefetchCooldown, ctx,
	)
	isClosed = h.IsClosed

	return h
}

// initProtocolListeners creates and wires all protocol servers (TLS, TLCP,
// DNSCrypt, Plain) into the Server struct.  The first error is returned and
// fails New() — a configured protocol that cannot initialise (bad
// certificate, invalid port) is a configuration error, not something to
// silently skip (M-low).
func (s *Server) initProtocolListeners(cfg *config.ServerConfig, h *handler.Handler) error {
	// Detect shared ports early so protocol servers can coordinate:
	//   - TCP 443: HTTPS + HTTPoverTLCP (record-layer demux)
	//   - TCP 853: TLS(DoT) + TLCP(DoT) (record-layer demux)
	//   - UDP 853: any combination of QUIC(DoQ), DTLS, DTLCP (first-datagram demux)
	wantShared := cfg.Server.Protocol.HTTPS.Port != "" &&
		cfg.Server.Protocol.HTTPS.Port == cfg.Server.Protocol.HTTPTLCP.Port &&
		cfg.Server.Certificate.TLS.IsEnabled() &&
		cfg.Server.Certificate.TLCP.IsEnabled()
	wantSharedDOT := cfg.Server.Protocol.TLS != "" &&
		cfg.Server.Protocol.TLS == cfg.Server.Protocol.TLCP &&
		cfg.Server.Certificate.TLS.IsEnabled() &&
		cfg.Server.Certificate.TLCP.IsEnabled()
	// UDP port sharing: detect per-protocol-pair sharing.
	certsReady := cfg.Server.Certificate.TLS.IsEnabled() && cfg.Server.Certificate.TLCP.IsEnabled()
	dtlsDTLCPShare := cfg.Server.Protocol.DTLS != "" &&
		cfg.Server.Protocol.DTLS == cfg.Server.Protocol.DTLCP && certsReady
	quicDTLSShare := cfg.Server.Protocol.QUIC != "" &&
		cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DTLS && certsReady
	quicDTLCPShare := cfg.Server.Protocol.QUIC != "" &&
		cfg.Server.Protocol.QUIC == cfg.Server.Protocol.DTLCP && certsReady
	wantSharedUDP := dtlsDTLCPShare || quicDTLSShare || quicDTLCPShare

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
		if wantShared {
			tlsCfg.SkipHTTPS = true
		}
		if wantSharedDOT {
			tlsCfg.SkipDOT = true
		}
		if dtlsDTLCPShare || quicDTLSShare {
			tlsCfg.SkipDTLS = true
		}
		if quicDTLSShare || quicDTLCPShare {
			tlsCfg.SkipDOQ = true
		}
		tlsSrv, err := tls.New(h, &tlsCfg)
		if err != nil {
			return fmt.Errorf("TLS server init: %w", err)
		}
		s.tls = tlsSrv
	}

	// Create the TLCP server before the shared Manager so that TLCP-side
	// handlers can be wired into the shared config.
	if cfg.Server.Certificate.TLCP.IsEnabled() && (cfg.Server.Protocol.TLCP != "" || cfg.Server.Protocol.HTTPTLCP.Port != "" || cfg.Server.Protocol.DTLCP != "" || wantSharedUDP) {
		tlcpSrv, err := servertlcp.New(&cfg.Server.Certificate.TLCP, cfg.Server.Protocol.TLCP, cfg.Server.Protocol.HTTPTLCP.Port, cfg.Server.Protocol.HTTPTLCP.Endpoint, cfg.Server.Protocol.DTLCP)
		if err != nil {
			return fmt.Errorf("TLCP server init: %w", err)
		}
		s.tlcpServer = tlcpSrv
	}

	// Build the shared-port Manager now that both protocol servers exist.
	if (wantShared || wantSharedDOT || wantSharedUDP) && s.tls != nil {
		sharedCfg := shared.Config{}
		if wantShared {
			sharedCfg.Port = cfg.Server.Protocol.HTTPS.Port
			sharedCfg.TLSCfg = s.tls.ETLSConfigForDOH()
			sharedCfg.DOHHandler = s.tls.DOHHandler()
			sharedCfg.DOHTLCP = http.HandlerFunc(s.tlcpServer.ServeDOH)
		}
		if wantSharedDOT {
			sharedCfg.DOTPort = cfg.Server.Protocol.TLS
			sharedCfg.DOTHandler = s.tls.HandleDOTFromListener
			sharedCfg.DOTTLCP = s.tlcpServer.ServeDOT
		}
		if wantSharedUDP {
			sharedCfg.DTLSPort = cfg.Server.Protocol.DTLS
			if sharedCfg.DTLSPort == "" {
				sharedCfg.DTLSPort = cfg.Server.Protocol.DTLCP
			}
		}
		if dtlsDTLCPShare || quicDTLSShare {
			sharedCfg.DTLSHandler = s.tls.HandleDTLSFromPacketListener
		}
		if quicDTLSShare || quicDTLCPShare {
			sharedCfg.DOQHandler = s.tls.HandleDOQFromPacketConn
		}
		if s.tlcpServer != nil {
			sharedCfg.ServeDTLCP = s.tlcpServer.ServeDTLCPClient
			sharedCfg.WrapConn = func(c net.Conn, nextProtos []string) net.Conn {
				return s.tlcpServer.WrapTLCPConn(c, nextProtos)
			}
		}
		s.sharedManager = shared.New(s, &sharedCfg)
	}

	if cfg.Server.Protocol.DNSCrypt != "" {
		providerName := cfg.Server.Certificate.DNSCrypt.ProviderName(cfg.Server.Certificate.Domain)
		stateStore := serverdnscrypt.NewFileStore(cfg.Server.Certificate.DNSCrypt.StateFile)
		dnscryptSrv, err := serverdnscrypt.New(&cfg.Server.Certificate.DNSCrypt, cfg.Server.Protocol.DNSCrypt, providerName, stateStore)
		if err != nil {
			return fmt.Errorf("DNSCrypt server init: %w", err)
		}
		s.dnscryptServer = dnscryptSrv
	}

	s.plain = serverplain.New(cfg)
	return nil
}

// initPprof starts the optional pprof HTTP listener on all interfaces.
func (s *Server) initPprof(cfg *config.ServerConfig) {
	if cfg.Server.Pprof == "" {
		return
	}
	addrs, err := zdnsutil.ResolveBindAddrs("tcp", cfg.Server.Pprof)
	if err != nil {
		log.Warnf("PPROF: skipping — no available bind address for port %s: %v", cfg.Server.Pprof, err)
		return
	}
	s.pprofServers = make([]*http.Server, 0, len(addrs))
	for _, addr := range addrs {
		s.pprofServers = append(s.pprofServers, &http.Server{
			Addr:              addr,
			ReadHeaderTimeout: config.DefaultHTTPReadHeaderTimeout,
			ReadTimeout:       0,
			IdleTimeout:       config.DefaultHTTPServerIdleTimeout,
			// net/http/pprof's init registers /debug/pprof/ here; without a
			// handler every pprof path would 404.
			Handler: http.DefaultServeMux,
		})
	}
}

// ServeDNS delegates to the query handler. Required by server/tls.DNSHandler
// interface and external benchmarks.
func (s *Server) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	return s.handler.ServeDNS(req, clientIP, isSecure, protocol)
}

// Start runs the DNS server and blocks until shutdown is triggered.
func (s *Server) Start() error {
	log.Infof("SERVER: Starting DNS server")
	if s.handler.IsClosed() {
		return errors.New("server is closed")
	}

	// Set DoH message acceptance function globally before any protocol servers
	// start. The individual protocol start functions previously set this, but
	// since it's a global variable it must be set only once.
	dnshttp.MsgAcceptFunc = zdnsutil.ServerDOHMsgAccept

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancelCause(s.ctx)
	defer serverCancel(errors.New("server startup completed"))

	s.displayInfo()

	g, ctx := errgroup.WithContext(serverCtx)

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
		if s.sharedManager != nil {
			if err := s.sharedManager.Start(); err != nil {
				return fmt.Errorf("shared port startup: %w", err)
			}
		}
		g.Go(func() error {
			defer zdnsutil.HandlePanic("TLCP server")
			if err := s.tlcpServer.Start(s); err != nil {
				return fmt.Errorf("TLCP startup: %w", err)
			}
			<-ctx.Done()
			return nil
		})
	}

	// Pprof must be registered AFTER all error-returning init calls above.
	// If plain.Start() or other inits fail, Start() returns before the
	// coordinator goroutine calls g.Wait(), and the pprof goroutine would
	// be orphaned in the errgroup.
	if len(s.pprofServers) > 0 {
		// Aggregated one-line startup log, matching the protocol listeners
		// (PLAIN/DNSCRYPT print all bound addresses in a single line).
		addrs := make([]string, 0, len(s.pprofServers))
		for _, p := range s.pprofServers {
			addrs = append(addrs, p.Addr)
		}
		log.Infof("PPROF: pprof server started on %s", strings.Join(addrs, " "))
		for _, p := range s.pprofServers {
			g.Go(func() error {
				defer zdnsutil.HandlePanic("pprof server")
				err := p.ListenAndServe()

				if err != nil && err != http.ErrServerClosed {
					// Optional diagnostics listener: a bind failure (port in
					// use) must not take the DNS server down — log and keep
					// serving (M-3-6).
					log.Warnf("PPROF: pprof listener on %s failed: %v", p.Addr, err)
				}
				<-ctx.Done()
				return nil
			})
		}
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

	if len(up) == 0 {
		// Recursion is explicit-only — an empty upstream list resolves to
		// SERVFAIL, not implicit recursion.
		log.Warnf("SERVER: no upstream servers configured")
		return
	}

	for _, server := range up {
		s.logServer("UPSTREAM", server)
	}
	log.Infof("UPSTREAM: %d servers", len(up))
	s.displayExtras()
}

func (s *Server) logServer(role string, server *config.UpstreamServer) {
	if server.IsRecursive() {
		info := "built-in recursive"
		if server.Address != "" {
			info = server.Address
		}
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
	if server.SkipTLSVerify && zdnsutil.IsSecureProtocol(strings.ToLower(server.Protocol)) &&
		server.Protocol != config.ProtoDNSCrypt && server.Protocol != config.ProtoDNSCryptTCP {
		info += " [Skip TLS verification]"
	}
	if len(server.Match) > 0 {
		info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
	}
	log.Infof("%s: %s", role, info)
}

func (s *Server) displayExtras() {
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
}
