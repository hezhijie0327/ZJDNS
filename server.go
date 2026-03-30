// Package main implements ZJDNS - High Performance DNS Server
// This file contains the main DNS server functionality including lifecycle
// management, signal handling, query processing, and response building.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

// =============================================================================
// DNSServer Implementation
// =============================================================================

// NewDNSServer creates a new DNS server instance with all required managers.
// It initializes the cache, security, EDNS, rewrite, CIDR, and query managers.
func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	ednsManager, err := NewEDNSManager(config.Server.DefaultECS)
	if err != nil {
		cancel(fmt.Errorf("EDNS manager init: %w", err))
		return nil, fmt.Errorf("EDNS manager init: %w", err)
	}

	rewriteManager := NewRewriteManager()
	if len(config.Rewrite) > 0 {
		if err := rewriteManager.LoadRules(config.Rewrite); err != nil {
			cancel(fmt.Errorf("load rewrite rules: %w", err))
			return nil, fmt.Errorf("load rewrite rules: %w", err)
		}
	}

	var cidrManager *CIDRManager
	if len(config.CIDR) > 0 {
		cidrManager, err = NewCIDRManager(config.CIDR)
		if err != nil {
			cancel(fmt.Errorf("CIDR manager init: %w", err))
			return nil, fmt.Errorf("CIDR manager init: %w", err)
		}
	}

	var redisClient *redis.Client
	var cache CacheManager
	if config.Redis.Address == "" {
		cache = NewNullCache()
	} else {
		redisCache, err := NewRedisCache(config)
		if err != nil {
			cancel(fmt.Errorf("redis cache init: %w", err))
			return nil, fmt.Errorf("redis cache init: %w", err)
		}
		cache = redisCache
		redisClient = redisCache.client
	}

	server := &DNSServer{
		config:            config,
		ednsMgr:           ednsManager,
		rewriteMgr:        rewriteManager,
		cidrMgr:           cidrManager,
		redisClient:       redisClient,
		cacheMgr:          cache,
		ctx:               ctx,
		cancel:            cancel,
		shutdown:          make(chan struct{}),
		backgroundGroup:   backgroundGroup,
		backgroundCtx:     backgroundCtx,
		cacheRefreshGroup: cacheRefreshGroup,
		cacheRefreshCtx:   cacheRefreshCtx,
	}

	securityManager, err := NewSecurityManager(config, server)
	if err != nil {
		cancel(fmt.Errorf("security manager init: %w", err))
		return nil, fmt.Errorf("security manager init: %w", err)
	}
	server.securityMgr = securityManager

	queryClient := NewQueryClient()
	server.queryClient = queryClient

	queryManager := NewQueryManager(server)
	if err := queryManager.Initialize(config.Upstream); err != nil {
		cancel(fmt.Errorf("query manager init: %w", err))
		return nil, fmt.Errorf("query manager init: %w", err)
	}
	server.queryMgr = queryManager

	if config.Server.Pprof != "" {
		server.pprofServer = &http.Server{
			Addr:              ":" + config.Server.Pprof,
			ReadHeaderTimeout: OperationTimeout,
			ReadTimeout:       OperationTimeout,
			IdleTimeout:       IdleTimeout,
		}

		if server.securityMgr != nil && server.securityMgr.tls != nil {
			server.pprofServer.TLSConfig = server.securityMgr.tls.tlsConfig
		}
	}

	server.setupSignalHandling()

	return server, nil
}

// =============================================================================
// DNSServer: Lifecycle Management
// =============================================================================

// setupSignalHandling configures signal handlers for graceful shutdown.
// It listens for SIGINT and SIGTERM signals to initiate server shutdown.
func (s *DNSServer) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	s.backgroundGroup.Go(func() error {
		defer HandlePanic("Signal handler")
		select {
		case sig := <-sigChan:
			LogInfo("SIGNAL: Received signal %v, starting graceful shutdown", sig)
			s.shutdownServer()
		case <-s.backgroundCtx.Done():
			return nil
		}
		return nil
	})
}

// shutdownServer performs graceful server shutdown, closing all connections
// and waiting for background tasks to complete.
func (s *DNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	LogInfo("SERVER: Starting DNS server shutdown")

	if s.cancel != nil {
		s.cancel(errors.New("server shutdown"))
	}

	if s.cacheMgr != nil {
		CloseWithLog(s.cacheMgr, "Cache manager")
	}

	if s.securityMgr != nil {
		if err := s.securityMgr.Shutdown(DefaultTimeout); err != nil {
			LogError("SECURITY: Security manager shutdown failed: %v", err)
		}
	}

	if s.pprofServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
		if err := s.pprofServer.Shutdown(ctx); err != nil {
			LogError("PPROF: pprof server shutdown failed: %v", err)
		} else {
			LogInfo("PPROF: pprof server shut down successfully")
		}
		cancel()
	}

	bgDone := make(chan error, 1)
	go func() {
		defer HandlePanic("Background group wait")
		bgDone <- s.backgroundGroup.Wait()
	}()

	select {
	case err := <-bgDone:
		if err != nil {
			LogError("SERVER: Background goroutines finished with error: %v", err)
		}
		LogInfo("SERVER: All background tasks shut down")
	case <-time.After(DefaultTimeout):
		LogWarn("SERVER: Background tasks shutdown timeout")
	}

	refreshDone := make(chan error, 1)
	go func() {
		defer HandlePanic("Cache refresh group wait")
		refreshDone <- s.cacheRefreshGroup.Wait()
	}()

	select {
	case err := <-refreshDone:
		if err != nil {
			LogError("SERVER: Cache refresh goroutines finished with error: %v", err)
		}
		LogInfo("SERVER: All cache refresh tasks shut down")
	case <-time.After(DefaultTimeout):
		LogWarn("SERVER: Cache refresh tasks shutdown timeout")
	}

	timeCache.Stop()

	if s.shutdown != nil {
		close(s.shutdown)
	}

	os.Exit(0)
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

	LogInfo("SERVER: Starting ZJDNS Server %s", getVersion())
	LogInfo("SERVER: Listening on port: %s", s.config.Server.Port)

	s.displayInfo()

	g, ctx := errgroup.WithContext(serverCtx)

	g.Go(func() error {
		defer HandlePanic("UDP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "udp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
			UDPSize: UDPBufferSize,
		}
		LogInfo("DNS: UDP server started on port %s", s.config.Server.Port)
		err := server.ListenAndServe()
		if err != nil {
			return fmt.Errorf("UDP startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	if s.pprofServer != nil {
		g.Go(func() error {
			defer HandlePanic("pprof server")
			LogInfo("PPROF: pprof server started on port %s", s.config.Server.Pprof)
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
		defer HandlePanic("TCP server")
		server := &dns.Server{
			Addr:    ":" + s.config.Server.Port,
			Net:     "tcp",
			Handler: dns.HandlerFunc(s.handleDNSRequest),
		}
		LogInfo("DNS: TCP server started on port %s", s.config.Server.Port)
		err := server.ListenAndServe()
		if err != nil {
			return fmt.Errorf("TCP startup: %w", err)
		}
		<-ctx.Done()
		return nil
	})

	if s.securityMgr.tls != nil {
		g.Go(func() error {
			defer HandlePanic("Secure DNS server")
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
		defer HandlePanic("Server coordinator")
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
				info := "Upstream server: recursive resolution"
				if len(server.Match) > 0 {
					info += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				LogInfo("UPSTREAM: %s", info)
			} else {
				protocol := strings.ToUpper(server.Protocol)
				if protocol == "" {
					protocol = "UDP"
				}
				serverInfo := fmt.Sprintf("%s (%s)", server.Address, protocol)
				if server.SkipTLSVerify && IsSecureProtocol(strings.ToLower(server.Protocol)) {
					serverInfo += " [Skip TLS verification]"
				}
				if len(server.Match) > 0 {
					serverInfo += fmt.Sprintf(" [CIDR match: %v]", server.Match)
				}
				LogInfo("UPSTREAM: Upstream server: %s", serverInfo)
			}
		}
		LogInfo("UPSTREAM: Upstream mode: total %d servers", len(servers))
	} else {
		if s.config.Redis.Address == "" {
			LogInfo("RECURSION: Recursive mode (no cache)")
		} else {
			LogInfo("RECURSION: Recursive mode + Redis cache: %s", s.config.Redis.Address)
		}
	}

	if s.cidrMgr != nil && len(s.config.CIDR) > 0 {
		LogInfo("CIDR: CIDR Manager: enabled (%d rules)", len(s.config.CIDR))
	}

	if s.pprofServer != nil {
		LogInfo("PPROF: pprof server enabled on: %s, via: %s, tls: %t", s.config.Server.Pprof, PprofPath, s.pprofServer.TLSConfig != nil)
	}

	if s.securityMgr.tls != nil {
		LogInfo("TLS: Listening on port: %s (DoT/DoQ)", s.config.Server.TLS.Port)
		httpsPort := s.config.Server.TLS.HTTPS.Port
		if httpsPort != "" {
			endpoint := s.config.Server.TLS.HTTPS.Endpoint
			if endpoint == "" {
				endpoint = strings.TrimPrefix(DefaultQueryPath, "/")
			}
			LogInfo("TLS: Listening on port: %s (DoH/DoH3, endpoint: %s)", httpsPort, endpoint)
		}
	}

	if s.rewriteMgr.hasRules() {
		LogInfo("REWRITE: DNS rewriter: enabled (%d rules)", len(s.config.Rewrite))
	}
	if s.config.Server.Features.HijackProtection {
		LogInfo("HIJACK: DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.GetDefaultECS(); defaultECS != nil {
		LogInfo("EDNS: Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
}

// =============================================================================
// DNSServer: Query Processing
// =============================================================================

// handleDNSRequest handles incoming DNS requests from UDP and TCP listeners.
// It performs panic recovery and writes responses back to the client.
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	response := s.processDNSQuery(req, GetClientIP(w), false)
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
		messagePool.Put(response)
	}
}

// processDNSQuery processes a DNS query, checking rewrites, cache, and
// performing upstream or recursive resolution as needed.
func (s *DNSServer) processDNSQuery(req *dns.Msg, _ net.IP, isSecureConnection bool) *dns.Msg {
	if atomic.LoadInt32(&s.closed) != 0 {
		msg := s.buildResponse(req)
		if msg != nil {
			msg.Rcode = dns.RcodeServerFailure
		}
		return msg
	}

	if req == nil || len(req.Question) == 0 {
		msg := &dns.Msg{}
		if req != nil && len(req.Question) > 0 {
			msg.SetReply(req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		return msg
	}

	question := req.Question[0]

	if len(question.Name) > MaxDomainLength || question.Qtype == dns.TypeANY {
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused
		return msg
	}

	startTime := time.Now()
	defer func() {
		if globalLog.GetLevel() >= Debug {
			responseTime := time.Since(startTime)
			LogDebug("Query completed: %s %s | Time:%v", question.Name, dns.TypeToString[question.Qtype], responseTime.Truncate(time.Microsecond))
		}
	}()

	if s.rewriteMgr.hasRules() {
		rewriteResult := s.rewriteMgr.RewriteWithDetails(question.Name, question.Qtype, question.Qclass)

		if rewriteResult.ShouldRewrite {
			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				response := s.buildResponse(req)
				response.Rcode = rewriteResult.ResponseCode
				s.addEDNS(response, req, isSecureConnection)
				return response
			}

			if len(rewriteResult.Records) > 0 {
				response := s.buildResponse(req)
				response.Answer = rewriteResult.Records
				response.Rcode = dns.RcodeSuccess
				if len(rewriteResult.Additional) > 0 {
					response.Extra = rewriteResult.Additional
				}
				s.addEDNS(response, req, isSecureConnection)
				return response
			}

			if rewriteResult.Domain != question.Name {
				question.Name = rewriteResult.Domain
			}
		}
	}

	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECS()
	}

	cacheKey := BuildCacheKey(question, ecsOpt, clientRequestedDNSSEC, s.config.Redis.KeyPrefix)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		return s.processCacheHit(req, entry, isExpired, question, clientRequestedDNSSEC, ecsOpt, cacheKey, isSecureConnection)
	}

	return s.processCacheMiss(req, question, ecsOpt, clientRequestedDNSSEC, cacheKey, isSecureConnection)
}

// processCacheHit handles DNS queries that have a cache hit, returning cached
// responses and optionally refreshing stale entries in the background.
func (s *DNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *ECSOption, cacheKey string, isSecureConnection bool) *dns.Msg {
	responseTTL := entry.GetRemainingTTL()

	msg := s.buildResponse(req)
	if msg == nil {
		msg := messagePool.Get()
		msg.SetReply(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	s.addEDNS(msg, req, isSecureConnection)

	if isExpired && entry.ShouldRefresh() {
		s.cacheRefreshGroup.Go(func() error {
			defer HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, OperationTimeout)
			defer cancel()
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)

	return msg
}

// processCacheMiss handles DNS queries that do not have a cache hit,
// performing upstream or recursive resolution.
func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, isSecureConnection bool) *dns.Msg {
	answer, authority, additional, validated, ecsResponse, _, err := s.queryMgr.Query(question, ecsOpt)

	if err != nil {
		return s.processQueryError(req, cacheKey, question, clientRequestedDNSSEC, ecsOpt, isSecureConnection)
	}

	return s.processQuerySuccess(req, question, ecsOpt, clientRequestedDNSSEC, cacheKey, answer, authority, additional, validated, ecsResponse, isSecureConnection)
}

// processQueryError handles query failures, attempting to serve stale cache
// data if available, or returning a server failure response.
func (s *DNSServer) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ *ECSOption, isSecureConnection bool) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found {
		msg := s.buildResponse(req)
		if msg == nil {
			msg := messagePool.Get()
			msg.SetReply(req)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}

		responseTTL := uint32(StaleTTL)
		msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), responseTTL, clientRequestedDNSSEC)
		msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), responseTTL, clientRequestedDNSSEC)
		msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), responseTTL, clientRequestedDNSSEC)

		if entry.Validated {
			msg.AuthenticatedData = true
		}

		s.addEDNS(msg, req, isSecureConnection)
		s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
		return msg
	}

	msg := s.buildResponse(req)
	if msg == nil {
		msg = messagePool.Get()
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	return msg
}

// processQuerySuccess handles successful query responses, caching the results
// and building the response message.
func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg := messagePool.Get()
		msg.SetReply(req)
	}

	if validated {
		msg.AuthenticatedData = true
	}

	responseECS := ecsResponse
	if responseECS == nil && ecsOpt != nil {
		responseECS = &ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      ecsOpt.Address,
		}
	}

	s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, responseECS)

	msg.Answer = ProcessRecords(answer, 0, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(authority, 0, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(additional, 0, clientRequestedDNSSEC)

	s.addEDNS(msg, req, isSecureConnection)
	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

// refreshCacheEntry refreshes a stale cache entry in the background.
func (s *DNSServer) refreshCacheEntry(_ context.Context, question dns.Question, ecs *ECSOption, cacheKey string, _ *CacheEntry) error {
	defer HandlePanic("cache refresh")

	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server closed")
	}

	answer, authority, additional, validated, ecsResponse, _, err := s.queryMgr.Query(question, ecs)

	if err != nil {
		return err
	}

	s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, ecsResponse)

	return nil
}

// =============================================================================
// DNSServer: Response Building Helpers
// =============================================================================

// addEDNS adds EDNS options to a DNS response message, including ECS,
// DNSSEC flags, and padding for secure connections.
func (s *DNSServer) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECS()
	}

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || true

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection)
	}
}

// buildResponse creates a new DNS response message from a request.
// It sets the appropriate flags and initializes the message pool.
func (s *DNSServer) buildResponse(req *dns.Msg) *dns.Msg {
	msg := messagePool.Get()

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
// records when the query was rewritten.
func (s *DNSServer) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil {
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
func (s *DNSServer) buildQueryMessage(question dns.Question, ecs *ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := messagePool.Get()

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.AddToMessage(msg, ecs, true, isSecureConnection)
	}

	return msg
}
