// Package main implements ZJDNS - High Performance DNS Server
// This file contains the main DNS server functionality including lifecycle
// management, signal handling, query processing, and response building.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	tcpWriteMu        sync.Map      // key: RemoteAddr string → *sync.Mutex (TCP pipelining)
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

// handleDNSRequest handles incoming DNS requests from UDP and TCP listeners.
// TCP queries are processed asynchronously for RFC 7766 pipelining support;
// responses may complete out of order. Writes are serialized via per-connection mutex.
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer dnsutil.HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	// TCP: spawn goroutine for concurrent pipelined processing.
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		addr := w.RemoteAddr().String()
		muI, _ := s.tcpWriteMu.LoadOrStore(addr, &sync.Mutex{})
		mu := muI.(*sync.Mutex)

		go func() {
			defer dnsutil.HandlePanic("TCP query handler")
			response := s.processDNSQuery(req, dnsutil.ClientIP(w), false, "TCP")
			if response != nil {
				response.Compress = true
				mu.Lock()
				_ = w.WriteMsg(response)
				mu.Unlock()
				pool.DefaultMessagePool.Put(response)
			}
		}()
		return
	}

	// UDP: synchronous processing (current behavior).
	response := s.processDNSQuery(req, dnsutil.ClientIP(w), false, detectRequestProtocol(w))
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
		pool.DefaultMessagePool.Put(response)
	}
}

// processDNSQuery processes a DNS query, checking rewrites, cache, and
// performing upstream or recursive resolution as needed.
func (s *DNSServer) processDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool, requestProtocol string) *dns.Msg {
	if atomic.LoadInt32(&s.closed) != 0 {
		msg := s.buildResponse(req)
		if msg != nil {
			msg.Rcode = dns.RcodeServerFailure
		}
		return msg
	}

	if s.semaphore != nil {
		select {
		case s.semaphore <- struct{}{}:
			defer func() { <-s.semaphore }()
		default:
			log.Debugf("QUERY: max concurrent reached, returning SERVFAIL")
			msg := s.buildResponse(req)
			if msg != nil {
				msg.Rcode = dns.RcodeServerFailure
			}
			return msg
		}
	}

	if !s.limiter.Allow(clientIP) {
		msg := s.buildResponse(req)
		msg.Rcode = dns.RcodeRefused
		return msg
	}

	if req == nil || len(req.Question) == 0 {
		msg := pool.DefaultMessagePool.Get()
		if req != nil {
			msg.SetReply(req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := req.Question[0]

	if clientIP != nil {
		log.Debugf("QUERY: client IP=%s query=%s type=%s", clientIP.String(), question.Name, dns.TypeToString[question.Qtype])
	} else {
		log.Debugf("QUERY: client IP=<unknown> query=%s type=%s", question.Name, dns.TypeToString[question.Qtype])
	}

	if len(question.Name) > config.MaxDomainLength || question.Qtype == dns.TypeANY {
		msg := pool.DefaultMessagePool.Get()
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused
		// Add EDE for invalid queries
		var ede *edns.EDEOption
		if len(question.Name) > config.MaxDomainLength {
			ede = edns.NewEDEOption(edns.EDECodeInvalidData, fmt.Sprintf("Domain name too long: %d characters (max %d)", len(question.Name), config.MaxDomainLength))
		} else {
			ede = edns.NewEDEOption(edns.EDECodeNotSupported, "ANY queries are not supported")
		}
		s.addEDNS(msg, req, isSecureConnection, clientIP, nil, ede)
		return msg
	}

	startTime := time.Now()
	cacheHit := false
	hadError := false
	rewrote := false
	hijackDetected := false
	staleServed := false
	prefetchTriggered := false
	var responseMsg *dns.Msg
	fallbackUsed := false
	defer func() {
		responseTime := time.Since(startTime)
		if log.Default.Level() >= log.Debug && responseMsg != nil {
			log.Debugf("Query completed: %s %s | rcode=%s | Time:%v | answer=%d, authority=%d, additional=%d, ad=%t%s", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[responseMsg.Rcode], responseTime.Truncate(time.Microsecond), len(responseMsg.Answer), len(responseMsg.Ns), len(responseMsg.Extra), responseMsg.AuthenticatedData, dnsutil.FormatRecords(responseMsg.Answer, responseMsg.Ns, responseMsg.Extra))
		}
		if s.statsMgr != nil {
			s.statsMgr.RecordRequest(responseTime, cacheHit, hadError, requestProtocol, rewrote, hijackDetected, staleServed, fallbackUsed, prefetchTriggered)
		}
	}()

	if s.rewriteMgr.HasRules() {
		log.Debugf("REWRITE: evaluating rules for %s qtype=%s client=%s", question.Name, dns.TypeToString[question.Qtype], clientIP)
		rewriteResult := s.rewriteMgr.Evaluate(question.Name, question.Qtype, question.Qclass, clientIP)

		if rewriteResult.ShouldRewrite {
			rewrote = true
			log.Debugf("REWRITE: matched rule for %s -> domain=%s responseCode=%d records=%d additional=%d", question.Name, rewriteResult.Domain, rewriteResult.ResponseCode, len(rewriteResult.Records), len(rewriteResult.Additional))
			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				log.Debugf("RESULT: %s %s | rcode=%s, blocked by rewrite rule", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[rewriteResult.ResponseCode])
				response := s.buildResponse(req)
				response.Rcode = rewriteResult.ResponseCode
				// Add EDE for rewrite-based blocks
				ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "Response code modified by rewrite rule")
				s.addEDNS(response, req, isSecureConnection, clientIP, nil, ede)
				responseMsg = response
				return responseMsg
			}

			if len(rewriteResult.Records) > 0 {
				response := s.buildResponse(req)
				response.Answer = rewriteResult.Records
				response.Rcode = dns.RcodeSuccess
				if len(rewriteResult.Additional) > 0 {
					response.Extra = rewriteResult.Additional
				}
				// Add EDE for rewrite-based response
				ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "Response modified by rewrite rule")
				s.addEDNS(response, req, isSecureConnection, clientIP, nil, ede)
				log.Debugf("RESULT: %s %s | rcode=NOERROR (rewrite), answer=%d, additional=%d", question.Name, dns.TypeToString[question.Qtype], len(rewriteResult.Records), len(rewriteResult.Additional))
				responseMsg = response
				return responseMsg
			}
			if rewriteResult.Domain != question.Name {
				question.Name = rewriteResult.Domain
			}
		}
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption
	var cookieOpt *edns.CookieOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
		cookieOpt = s.ednsMgr.ParseCookie(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.DefaultECSForQType(question.Qtype)
	}

	cacheKey := cache.BuildCacheKey(question, ecsOpt, clientRequestedDNSSEC)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		log.Debugf("CACHE: hit key=%s expired=%t for %s, ttl=%d, validated=%t, answer=%d", cacheKey, isExpired, question.Name, entry.GetRemainingTTL(), entry.Validated, len(entry.Answer))
		cacheHit = true
		if !isExpired {
			responseMsg = s.processCacheHit(req, entry, false, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &prefetchTriggered)
			return responseMsg
		}

		if entry.CanServeExpired(cache.StaleMaxAge) {
			responseMsg = s.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &staleServed, &fallbackUsed)
			return responseMsg
		}

		responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &hadError, &fallbackUsed)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer := s.lookupReversePTR(question, ecsOpt); len(ptrAnswer) > 0 {
			log.Debugf("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := s.buildResponse(req)
			response.Answer = ptrAnswer
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "Response generated by reverse PTR lookup")
			s.addEDNS(response, req, isSecureConnection, clientIP, cookieOpt, ede)
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &hadError, &fallbackUsed)
	return responseMsg
}

// lookupReversePTR performs a reverse DNS lookup for PTR queries using the cache manager.
func (s *DNSServer) lookupReversePTR(question dns.Question, ecsOpt *edns.ECSOption) []dns.RR {
	ip := dnsutil.ParseReverseDNSName(question.Name)
	if ip == nil {
		return nil
	}

	reverseCache, ok := s.cacheMgr.(interface {
		ReverseLookup(net.IP) []cache.LookupResult
	})
	if !ok {
		return nil
	}

	results := reverseCache.ReverseLookup(ip)
	if len(results) == 0 {
		return nil
	}

	records := make([]dns.RR, 0, len(results))
	for _, result := range results {
		records = append(records, dnsutil.BuildPTRRecord(question.Name, result.Name, config.DefaultTTL, question.Qclass))
	}

	return records
}

// processCacheHit handles DNS queries that have a cache hit, returning cached
// responses and optionally refreshing stale entries or near-expiry entries in the background.
func (s *DNSServer) processCacheHit(req *dns.Msg, entry *cache.CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, prefetchTriggered *bool) *dns.Msg {
	msg := s.buildCacheResponse(req, entry, isExpired, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)

	if isExpired && entry.ShouldRefresh() {
		s.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, OperationTimeout)
			defer cancel()
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	if !isExpired && entry.ShouldPrefetch(PrefetchThresholdPercent) && s.shouldStartPrefetch(cacheKey) {
		if prefetchTriggered != nil {
			*prefetchTriggered = true
		}
		s.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache prefetch")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, OperationTimeout)
			defer cancel()
			log.Debugf("CACHE: prefetch triggered for %s (threshold=%d%%)", question.Name, PrefetchThresholdPercent)
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	return msg
}

// shouldStartPrefetch applies lightweight per-key throttling to avoid repeated
// prefetch attempts for hot keys within a short interval.
func (s *DNSServer) shouldStartPrefetch(cacheKey string) bool {
	if s == nil || cacheKey == "" {
		return false
	}

	now := time.Now().UnixNano()
	nextAllowed, ok := s.prefetchCooldown.Load(cacheKey)
	if ok {
		if nextTs, typeOK := nextAllowed.(int64); typeOK && now < nextTs {
			return false
		}
	}

	s.prefetchCooldown.Store(cacheKey, now+PrefetchThrottleInterval.Nanoseconds())
	return true
}

// buildCacheResponse constructs a DNS response message based on a cache entry, including
func (s *DNSServer) buildCacheResponse(req *dns.Msg, entry *cache.CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)

	responseTTL := entry.GetRemainingTTL()
	elapsed := int64(entry.TTL) - int64(responseTTL)
	if elapsed < 0 {
		elapsed = 0
	}
	msg.Answer = cache.ProcessRecords(cache.ExpandRecords(entry.Answer), elapsed, true, clientRequestedDNSSEC)
	msg.Ns = cache.ProcessRecords(cache.ExpandRecords(entry.Authority), elapsed, true, clientRequestedDNSSEC)
	msg.Extra = cache.ProcessRecords(cache.ExpandRecords(entry.Additional), elapsed, true, clientRequestedDNSSEC)

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	if isExpired {
		ede := edns.NewEDEOption(edns.EDECodeStaleAnswer, "Serving expired cache entry")
		s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	} else {
		s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, nil)
	}

	s.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

// canServeExpiredEntry checks if an expired cache entry can be served based on its age and the configured stale max age.
func (s *DNSServer) canServeExpiredEntry(entry *cache.CacheEntry) bool {
	if entry == nil || !entry.IsExpired() {
		return false
	}
	return entry.CanServeExpired(cache.StaleMaxAge)
}

// processExpiredCacheHit handles cache hits for expired entries, serving stale
// responses and refreshing in the background. When prefer_stale is disabled,
// it still waits briefly for a fresh upstream answer before falling back.
func (s *DNSServer) processExpiredCacheHit(req *dns.Msg, entry *cache.CacheEntry, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, staleServed *bool, fallbackUsed *bool) *dns.Msg {
	if s.config.Server.Features.Cache.PreferStale {
		if staleServed != nil {
			*staleServed = true
		}
		s.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("expired cache refresh")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, OperationTimeout)
			defer cancel()
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}

	resultChan := make(chan queryResult, 1)
	go func() {
		defer dnsutil.HandlePanic("expired cache fallback query")
		answer, authority, additional, validated, ecsResponse, _, fallbackUsed, err := s.queryMgr.Query(question, ecsOpt)
		resultChan <- queryResult{
			answer:     answer,
			authority:  authority,
			additional: additional,
			validated:  validated,
			ecs:        ecsResponse,
			fallback:   fallbackUsed,
			err:        err,
		}
	}()

	timer := time.NewTimer(ServeExpiredClientTimeout)
	defer timer.Stop()

	select {
	case res := <-resultChan:
		if res.err == nil {
			if fallbackUsed != nil && res.fallback {
				*fallbackUsed = true
			}
			return s.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs, res.fallback, clientIP, isSecureConnection)
		}
		if staleServed != nil {
			*staleServed = true
		}
		return s.processCacheHit(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, nil)
	case <-timer.C:
		if staleServed != nil {
			*staleServed = true
		}
		go func() {
			res := <-resultChan
			if res.err != nil || res.fallback {
				return
			}
			log.Debugf("CACHE: background refresh completed for slow expired query %s", question.Name)
			s.cacheMgr.Set(cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
			s.startLatencyProbe(question, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
		}()
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}
}

// processCacheMiss handles DNS queries that do not have a cache hit,
// performing upstream or recursive resolution.
func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, clientIP net.IP, isSecureConnection bool, hadError *bool, fallbackUsed *bool) *dns.Msg {
	log.Debugf("CACHE: miss key=%s for %s, querying upstream/recursive", cacheKey, question.Name)
	answer, authority, additional, validated, ecsResponse, _, usedFallback, err := s.queryMgr.Query(question, ecsOpt)
	if fallbackUsed != nil && usedFallback {
		*fallbackUsed = true
	}

	if err != nil {
		// Check if it's a CIDR filter refusal
		if errors.Is(err, ErrCIDRFilterRefused) {
			return s.processCIDRRefused(req, question, cookieOpt, clientIP, isSecureConnection)
		}
		if hadError != nil {
			*hadError = true
		}
		return s.processQueryError(req, cacheKey, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
	}

	return s.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, answer, authority, additional, validated, ecsResponse, usedFallback, clientIP, isSecureConnection)
}

// processQueryError handles query failures, attempting to serve stale cache
// data if available, or returning a server failure response.
func (s *DNSServer) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found && s.canServeExpiredEntry(entry) {
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.GetRemainingTTL(), entry.Validated)
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", question.Name, dns.TypeToString[question.Qtype])
	msg := s.buildResponse(req)
	if msg == nil {
		msg = pool.DefaultMessagePool.Get()
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	// Add EDE for query error
	ede := edns.NewEDEOption(edns.EDECodeNetworkError, "All upstream queries failed")
	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	return msg
}

// detectRequestProtocol determines the protocol (UDP or TCP) used for the incoming DNS request based on the network type of the remote address.
func detectRequestProtocol(w dns.ResponseWriter) string {
	addr := w.RemoteAddr()
	if addr == nil {
		return "UDP"
	}

	network := strings.ToLower(addr.Network())
	switch {
	case strings.HasPrefix(network, "tcp"):
		return "TCP"
	case strings.HasPrefix(network, "udp"):
		return "UDP"
	default:
		return "UDP"
	}
}

// processCIDRRefused handles CIDR filtering rejections by returning REFUSED with EDE
func (s *DNSServer) processCIDRRefused(req *dns.Msg, question dns.Question, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg = pool.DefaultMessagePool.Get()
		msg.SetReply(req)
	}
	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := edns.NewEDEOption(edns.EDECodeBlocked, "Query blocked by CIDR filtering rule")
	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	return msg
}

// processQuerySuccess handles successful query results, building the DNS response message, populating the cache if applicable, and adding EDNS options.
func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption, skipCache bool, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg = pool.DefaultMessagePool.Get()
		msg.SetReply(req)
	}

	if validated {
		msg.AuthenticatedData = true
	}

	responseECS := ecsResponse
	if responseECS == nil && ecsOpt != nil {
		responseECS = &edns.ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      ecsOpt.Address,
		}
	}

	if !skipCache {
		log.Debugf("CACHE: populating cache key=%s for %s", cacheKey, question.Name)
		s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, responseECS)
		s.startLatencyProbe(question, cacheKey, answer, authority, additional, validated, responseECS)
	} else {
		log.Debugf("CACHE: fallback result, skipping cache population for %s", question.Name)
	}

	msg.Answer = cache.ProcessRecords(answer, 0, false, clientRequestedDNSSEC)
	msg.Ns = cache.ProcessRecords(authority, 0, false, clientRequestedDNSSEC)
	msg.Extra = cache.ProcessRecords(additional, 0, false, clientRequestedDNSSEC)
	log.Debugf("RESULT: %s %s | rcode=NOERROR, answer=%d, authority=%d, additional=%d, validated=%t, skipCache=%t, ecs=%t", question.Name, dns.TypeToString[question.Qtype], len(answer), len(authority), len(additional), validated, skipCache, responseECS != nil)
	log.Debugf("CACHE: served response for %s (skipCache=%t)", question.Name, skipCache)

	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, nil)
	s.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

// refreshCacheEntry refreshes a stale cache entry in the background.
func (s *DNSServer) refreshCacheEntry(_ context.Context, question dns.Question, ecs *edns.ECSOption, cacheKey string, _ *cache.CacheEntry) error {
	defer dnsutil.HandlePanic("cache refresh")

	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server closed")
	}

	answer, authority, additional, validated, ecsResponse, _, fallbackUsed, err := s.queryMgr.Query(question, ecs)
	if err != nil {
		return err
	}

	if !fallbackUsed {
		s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, ecsResponse)
		s.startLatencyProbe(question, cacheKey, answer, authority, additional, validated, ecsResponse)
	} else {
		log.Debugf("CACHE: refresh query used fallback for %s, skipping cache population", question.Name)
	}

	return nil
}

// addEDNS adds EDNS options to a DNS response message, including ECS,
// DNSSEC flags, cookie, EDE, and padding for secure connections.
func (s *DNSServer) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.DefaultECSForQType(req.Question[0].Qtype)
	}

	// Generate cookie response only when the client sent a cookie option.
	cookieStr := s.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection

	if shouldAddEDNS {
		s.ednsMgr.ApplyToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection, cookieStr, ede)
	}
}

// generateCookieResponse generates cookie string for response
// Returns client_cookie || server_cookie format only when the client sent a cookie option.
func (s *DNSServer) generateCookieResponse(cookieOpt *edns.CookieOption, clientIP net.IP) string {
	if s.ednsMgr == nil || s.ednsMgr.CookieGenerator == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}

	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		return ""
	}

	// Client sent a cookie - validate server cookie if present, then generate a new one.
	var serverCookie []byte
	if len(cookieOpt.ServerCookie) >= 16 {
		if s.ednsMgr.CookieGenerator.ValidateServerCookie(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			log.Debugf("EDNS: server cookie validated for %s", clientIP)
			serverCookie = s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		} else {
			log.Debugf("EDNS: server cookie invalid for %s, regenerating", clientIP)
			serverCookie = s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		}
	}

	if serverCookie == nil {
		log.Debugf("EDNS: generating new server cookie for %s", clientIP)
		serverCookie = s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	}

	return edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
}

// buildResponse creates a new DNS response message from a request.
// It sets the appropriate flags and initializes the message pool.
func (s *DNSServer) buildResponse(req *dns.Msg) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	if req != nil && len(req.Question) > 0 {
		msg.SetReply(req)
	} else if req != nil {
		msg.Response = true
		msg.Rcode = dns.RcodeFormatError
	}

	msg.Authoritative = false
	msg.RecursionAvailable = true
	msg.Compress = true
	return msg
}

// restoreOriginalDomain restores the original domain name in DNS response
// records when the query was rewritten. Returns early if no rewrite occurred.
func (s *DNSServer) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || strings.EqualFold(currentName, originalName) {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}

// buildQueryMessage creates a new DNS query message for the given question.
// It sets the recursion desired flag and adds EDNS options.
func (s *DNSServer) buildQueryMessage(question dns.Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.ApplyToMessage(msg, ecs, true, isSecureConnection, "", nil)
	}

	return msg
}
