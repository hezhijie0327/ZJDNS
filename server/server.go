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
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/protocol/shared"
	"zjdns/server/protocol/tls"
	"zjdns/server/resolver"
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

	// Shared collaborators owned here (NOT re-exposed through Handler):
	// background tasks in tasks.go read them directly.
	cacheStore        cache.Store
	ednsHandler       *edns.Handler
	prober            handler.LatencyProber
	prefetchCooldown  *handler.PrefetchCooldown
	cacheRefreshGroup *errgroup.Group

	tls             *tls.Server
	tlcpServer      *servertlcp.Server
	dnscryptServer  *serverdnscrypt.Server
	plain           *serverplain.Server
	sharedManager   *shared.Mux
	pprofServers    []*http.Server
	shutdown        chan struct{}
	shutdownOnce    sync.Once // guards close(shutdown) — a second shutdownServer call would double-close (M-3-6)
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

func (s *Server) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	return s.handler.ServeDNS(req, clientIP, isSecure, protocol)
}

// Start runs the DNS server and blocks until shutdown is triggered.
func (s *Server) Start() error {
	log.Infof("SERVER: Starting DNS server")
	if s.handler.IsClosed() {
		return errors.New("server is closed")
	}

	// Set DoH message acceptance function globally before any protocol
	// servers start — it is a global, so it must be set exactly once.
	dnshttp.MsgAcceptFunc = zdnsutil.ServerDOHMsgAccept

	errChan := make(chan error, 1)
	serverCtx, serverCancel := context.WithCancelCause(s.ctx)
	defer serverCancel(errors.New("server startup completed"))

	s.displayInfo()

	g, ctx := errgroup.WithContext(serverCtx)

	if err := s.plain.Start(g, ctx,
		dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) { s.handleDNSRequest(w, r) }),
		s.handler,
	); err != nil {
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
		proto := &s.config.Server.Protocol
		sharedDNSCrypt := (proto.DNSCrypt != "" && proto.DNSCrypt == proto.HTTPS.Port) ||
			(proto.DNSCrypt != "" && (proto.DNSCrypt == proto.QUIC ||
				proto.DNSCrypt == proto.HTTP3.Port ||
				proto.DNSCrypt == proto.DTLS ||
				proto.DNSCrypt == proto.DTLCP))
		if sharedDNSCrypt {
			// Shared-port mode: the shared Manager routes packets
			// to the DNSCrypt server; only start the key renewal loop.
			s.dnscryptServer.SetHandler(s)
			s.dnscryptServer.StartBackground()
		} else {
			g.Go(func() error {
				defer zdnsutil.HandlePanic("DNSCrypt server")
				if err := s.dnscryptServer.Start(s); err != nil {
					return fmt.Errorf("DNSCrypt startup: %w", err)
				}
				<-ctx.Done()
				return nil
			})
		}
	}

	if s.sharedManager != nil {
		if err := s.sharedManager.Start(); err != nil {
			return fmt.Errorf("shared port startup: %w", err)
		}
	}

	if s.tlcpServer != nil {
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
	up := s.dnsResolver.UpstreamServers()

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
