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

	"codeberg.org/miekg/dns"
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
	"zjdns/server/handler"
	"zjdns/server/probe"
	"zjdns/server/resolver"
	"zjdns/server/security"
	servertls "zjdns/server/tls"
)

// Server is the core DNS server handling lifecycle, protocol listeners, and background tasks.
type Server struct {
	config          *config.ServerConfig
	handler         *handler.Handler
	queryClient     *client.Client
	guard           *security.Guard
	tls             *servertls.Server
	cidrFilter      *cidr.Filter
	pprofServer     *http.Server
	ctx             context.Context
	cancel          context.CancelCauseFunc
	shutdown        chan struct{}
	backgroundGroup *errgroup.Group
	backgroundCtx   context.Context
	udpServers      []*dns.Server // per-address listeners
	tcpServers      []*dns.Server // per-address listeners
	tcpWriteMu      sync.Map
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
	}

	// ── Foundation: database ──────────────────────────────────────────────

	cacheStore, err := cache.NewSQLiteCache(
		cfg.Server.Features.Cache.DBPath,
		cfg.Server.Features.Cache.MaxEntries,
		cfg.Server.Features.Cache.MMapSizeMB,
		cfg.Server.Features.Cache.CacheSizeMB,
	)
	if err != nil {
		cancel(fmt.Errorf("cache init: %w", err))
		return nil, fmt.Errorf("cache init: %w", err)
	}

	// ── Domain services: EDNS, rewrite, CIDR ──────────────────────────────

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
	server.cidrFilter = cidrFilter

	// ── Core: handler + security ──────────────────────────────────────────

	h := handler.New(
		cfg, cacheStore, ednsHandler, rewriteEvaluator,
		handler.BackgroundConfig{
			RefreshGroup: cacheRefreshGroup,
			RefreshCtx:   cacheRefreshCtx,
			Ctx:          ctx,
		},
	)
	server.handler = h

	guard := security.New(cacheStore, cfg.Server.Features.HijackProtection)
	server.guard = guard

	// ── Outbound: query client ────────────────────────────────────────────

	queryClient := client.New()
	if cfg.Server.TLS.KTLS != nil {
		queryClient.SetKTLS(cfg.Server.TLS.KTLS.KernelTX, cfg.Server.TLS.KTLS.KernelRX)
	}
	server.queryClient = queryClient

	// ── Resolution: resolver + upstream config ────────────────────────────

	resolver := resolver.New(
		queryClient, guard, ednsHandler, cidrFilter,
		func(q resolver.Question, ecs *edns.ECSOption, rd bool, secure bool) *dns.Msg {
			return h.BuildQueryMessage(q, ecs, rd, secure)
		},
		cacheStore,
	)
	resolver.DNSSECEnforce = cfg.Server.Features.DNSSECEnforce
	resolver.ConfigureServers(cfg.Upstream, cfg.Fallback)
	h.SetResolver(resolver)

	if len(cfg.Upstream) > 0 || len(cfg.Fallback) > 0 {
		allServers := make([]config.UpstreamServer, 0, len(cfg.Upstream)+len(cfg.Fallback))
		allServers = append(allServers, cfg.Upstream...)
		allServers = append(allServers, cfg.Fallback...)
		server.queryClient.WarmUpConnections(allServers)
	}

	// ── Transport listeners ───────────────────────────────────────────────

	if cfg.Server.TLS.SelfSigned || (cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "") {
		tlsCfg := servertls.Config{Port: cfg.Server.TLS.Port, HTTPSPort: cfg.Server.TLS.HTTPS.Port, HTTPSEndpoint: cfg.Server.TLS.HTTPS.Endpoint, SelfSigned: cfg.Server.TLS.SelfSigned, CertFile: cfg.Server.TLS.CertFile, KeyFile: cfg.Server.TLS.KeyFile, Domain: cfg.Server.Features.DDR.Domain}
		if cfg.Server.TLS.KTLS != nil {
			tlsCfg.KTLS = &servertls.KTLSSettings{KernelTX: cfg.Server.TLS.KTLS.KernelTX, KernelRX: cfg.Server.TLS.KTLS.KernelRX}
		}
		tlsSrv, err := servertls.New(h, tlsCfg, config.DefaultBackgroundTimeout)
		if err != nil {
			cancel(fmt.Errorf("TLS server init: %w", err))
			return nil, fmt.Errorf("TLS server init: %w", err)
		}
		server.tls = tlsSrv
	}

	// ── Observability: probes + pprof ─────────────────────────────────────

	if len(cfg.Server.Features.LatencyProbe) > 0 {
		prober := probe.New(
			cacheStore,
			func(fn func() error) { server.backgroundGroup.Go(fn) },
			backgroundCtx,
			cfg.Server.Features.LatencyProbe,
		)
		h.SetProber(prober)
	}

	if cfg.Server.Pprof != "" {
		if err := dnsutil.TryBind("tcp", "127.0.0.1:"+cfg.Server.Pprof); err != nil {
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
	s.logSummary("startup")

	g, ctx := errgroup.WithContext(serverCtx)

	udpAddrs, err := dnsutil.ResolveBindAddrs(config.ProtoUDP, s.config.Server.Port)
	if err != nil {
		return fmt.Errorf("UDP address resolution: %w", err)
	}
	for _, addr := range udpAddrs {
		addr := addr
		srv := &dns.Server{
			Addr:    addr,
			Net:     config.ProtoUDP,
			Handler: dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) { s.handleDNSRequest(w, r) }),
			UDPSize: pool.UDPBufferSize,
		}
		s.udpServers = append(s.udpServers, srv)
		g.Go(func() error {
			defer dnsutil.HandlePanic("UDP server")
			log.Infof("SERVER: UDP server started on %s", addr)
			err := srv.ListenAndServe()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					return fmt.Errorf("UDP startup on %s: %w", addr, err)
				}
			}
			<-ctx.Done()
			return nil
		})
	}

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

	tcpAddrs, err := dnsutil.ResolveBindAddrs("tcp", s.config.Server.Port)
	if err != nil {
		return fmt.Errorf("TCP address resolution: %w", err)
	}
	for _, addr := range tcpAddrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP listen on %s: %w", addr, err)
		}
		addr := addr
		srv := &dns.Server{
			Listener: &servertls.TCPKeepAliveListener{Listener: listener},
			Handler:  dns.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) { s.handleDNSRequest(w, r) }),
		}
		s.tcpServers = append(s.tcpServers, srv)
		g.Go(func() error {
			defer dnsutil.HandlePanic("TCP server")
			log.Infof("SERVER: TCP server started on %s", addr)
			err := srv.ListenAndServe()
			if err != nil {
				select {
				case <-ctx.Done():
					return nil
				default:
					return fmt.Errorf("TCP startup on %s: %w", addr, err)
				}
			}
			<-ctx.Done()
			return nil
		})
	}

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
	servers := s.handler.UpstreamServers()
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

	if s.pprofServer != nil {
		log.Infof("PPROF: pprof server enabled on: %s, via: %s", s.config.Server.Pprof, config.DefaultPprofPath)
	}

	if s.tls != nil {
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

	if s.config.Server.Features.HijackProtection {
		log.Infof("SECURITY: DNS hijacking prevention: enabled")
	}
}
