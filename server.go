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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/errgroup"
)

const (
	DefaultTimeout   = 2 * time.Second // Timeout for various operations like shutdown and cache refresh
	OperationTimeout = 3 * time.Second // Timeout for individual operations like upstream queries
	IdleTimeout      = 4 * time.Second // Idle timeout for servers

	PrefetchThrottleInterval = 3 * time.Second // Minimum interval between prefetches for the same cache key to prevent thundering herd
	PrefetchThresholdPercent = 10              // Prefetch window threshold in percent of original TTL

	ServeExpiredClientTimeout = 1800 * time.Millisecond // Maximum client timeout for serving expired cache entries in seconds. RFC 8767 recommends 1.8 seconds

	DefaultCookieSecretRotationInterval = 1 * time.Hour    // Interval for rotating DNS cookie secrets
	DefaultECSRefreshInterval           = 15 * time.Minute // Interval for refreshing auto-configured ECS public IPs

	MaxDomainLength = 253 // Maximum length of a fully qualified domain name

	PprofPath = "/debug/pprof/" // Path prefix for pprof endpoints
)

// DNSServer is the core server coordinating query processing and protocol handlers.
type DNSServer struct {
	config            *ServerConfig
	cacheMgr          CacheManager
	queryClient       *QueryClient
	securityMgr       *SecurityManager
	ednsMgr           *EDNSManager
	rewriteMgr        *RewriteManager
	cidrMgr           *CIDRManager
	statsMgr          *StatsManager
	pprofServer       *http.Server
	redisClient       *redis.Client
	redisCache        *RedisCache
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
}

// NewDNSServer creates a new DNS server instance with all required managers.
// It initializes the cache, security, EDNS, rewrite, CIDR, and query managers.
func NewDNSServer(config *ServerConfig) (*DNSServer, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
	cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)

	ednsManager, err := NewEDNSManager(config.Server.Features.ECS)
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
	var redisCacheObj *RedisCache
	var cache CacheManager
	if config.Server.Features.Cache.Redis.Address == "" {
		memoryCache := NewMemoryCache(config.Server.Features.Cache.Memory.Size)
		cache = memoryCache
	} else {
		redisCache, err := NewRedisCache(config)
		if err != nil {
			cancel(fmt.Errorf("redis cache init: %w", err))
			return nil, fmt.Errorf("redis cache init: %w", err)
		}
		memoryCache := NewMemoryCache(config.Server.Features.Cache.Memory.Size)
		cache = NewHybridCache(memoryCache, redisCache)
		redisClient = redisCache.client
		redisCacheObj = redisCache
	}

	server := &DNSServer{
		config:            config,
		ednsMgr:           ednsManager,
		rewriteMgr:        rewriteManager,
		cidrMgr:           cidrManager,
		statsMgr:          NewStatsManager(config, redisClient),
		redisClient:       redisClient,
		redisCache:        redisCacheObj,
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
	if err := queryManager.Initialize(config.Upstream, config.Fallback); err != nil {
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

	if server.ednsMgr != nil && server.ednsMgr.cookieGenerator != nil {
		server.backgroundGroup.Go(func() error {
			defer HandlePanic("DNS cookie secret rotation")
			ticker := time.NewTicker(DefaultCookieSecretRotationInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					server.ednsMgr.cookieGenerator.RotateSecret()
					LogDebug("EDNS: rotated DNS cookie secret")
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	if server.ednsMgr != nil && server.ednsMgr.shouldRefreshDefaultECS() {
		server.backgroundGroup.Go(func() error {
			defer HandlePanic("EDNS default ECS refresh")

			if ecsList, changed, err := server.ednsMgr.RefreshDefaultECS(); err != nil {
				LogWarn("EDNS: initial default ECS refresh failed: %v", err)
			} else if changed {
				for _, ecs := range ecsList {
					if ecs != nil {
						LogInfo("EDNS: initial default ECS refreshed: %s/%d", ecs.Address, ecs.SourcePrefix)
					}
				}
			}

			ticker := time.NewTicker(DefaultECSRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if ecsList, changed, err := server.ednsMgr.RefreshDefaultECS(); err != nil {
						LogWarn("EDNS: default ECS refresh failed: %v", err)
					} else if changed {
						for _, ecs := range ecsList {
							if ecs != nil {
								LogInfo("EDNS: refreshed default ECS: %s/%d", ecs.Address, ecs.SourcePrefix)
							}
						}
					}
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	if statsInterval := server.config.Server.GetStatsInterval(); statsInterval > 0 && server.statsMgr != nil {
		interval := time.Duration(statsInterval) * time.Second
		server.backgroundGroup.Go(func() error {
			defer HandlePanic("stats logger")
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					server.logStatsNow()
				case <-server.backgroundCtx.Done():
					return nil
				}
			}
		})
	}

	if statsResetInterval := server.config.Server.GetStatsResetInterval(); statsResetInterval > 0 && server.statsMgr != nil {
		resetInterval := time.Duration(statsResetInterval) * time.Second
		server.backgroundGroup.Go(func() error {
			defer HandlePanic("stats reset")
			ticker := time.NewTicker(resetInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					server.statsMgr.Reset()
					LogInfo("STATS: counters reset")
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

// logStatsNow fetches current statistics and logs them in JSON format.
func (s *DNSServer) logStatsNow() {
	if s == nil || s.statsMgr == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), OperationTimeout)
	defer cancel()

	snapshot, err := s.statsMgr.FetchStats(ctx)
	if err != nil {
		LogWarn("STATS: fetch failed: %v", err)
		return
	}

	payload, err := BuildStatsLogJSON(snapshot)
	if err != nil {
		LogError("STATS: build payload failed: %v", err)
		return
	}

	LogInfo("STATS: %s", payload)
}

// shutdownServer performs graceful server shutdown, closing all connections
// and waiting for background tasks to complete.
func (s *DNSServer) shutdownServer() {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return
	}

	LogInfo("SERVER: Starting DNS server shutdown")
	if s.config.Server.GetStatsInterval() > 0 {
		s.logStatsNow()
	}

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
	if s.config.Server.GetStatsInterval() > 0 {
		s.logStatsNow()
	}

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
				info := fmt.Sprintf("Upstream server: %s", server.Address)
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
		if s.config.Server.Features.Cache.Redis.Address == "" {
			LogInfo("RECURSION: Recursive mode (Memory cache)")
		} else {
			LogInfo("RECURSION: Recursive mode (Memory + Redis cache: %s)", s.config.Server.Features.Cache.Redis.Address)
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
	LogInfo("CACHE: Serve expired enabled (ttl=%d, client timeout=%dms)", StaleMaxAge, ServeExpiredClientTimeout)
	if s.config.Server.Features.HijackProtection {
		LogInfo("HIJACK: DNS hijacking prevention: enabled")
	}
	if defaultECS := s.ednsMgr.GetDefaultECS(); defaultECS != nil {
		LogInfo("EDNS: Default ECS: %s/%d", defaultECS.Address, defaultECS.SourcePrefix)
	}
}

// handleDNSRequest handles incoming DNS requests from UDP and TCP listeners.
// It performs panic recovery and writes responses back to the client.
func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	response := s.processDNSQuery(req, GetClientIP(w), false, detectRequestProtocol(w))
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
		messagePool.Put(response)
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

	if clientIP != nil {
		LogDebug("QUERY: client IP=%s query=%s type=%s", clientIP.String(), question.Name, dns.TypeToString[question.Qtype])
	} else {
		LogDebug("QUERY: client IP=<unknown> query=%s type=%s", question.Name, dns.TypeToString[question.Qtype])
	}

	if len(question.Name) > MaxDomainLength || question.Qtype == dns.TypeANY {
		msg := &dns.Msg{}
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused
		// Add EDE for invalid queries
		var ede *EDEOption
		if len(question.Name) > MaxDomainLength {
			ede = NewEDEOption(EDECodeInvalidData, fmt.Sprintf("Domain name too long: %d characters (max %d)", len(question.Name), MaxDomainLength))
		} else {
			ede = NewEDEOption(EDECodeNotSupported, "ANY queries are not supported")
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
		if globalLog.GetLevel() >= Debug && responseMsg != nil {
			LogDebug("Query completed: %s %s | rcode=%s | Time:%v | answer=%d, authority=%d, additional=%d, ad=%t%s", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[responseMsg.Rcode], responseTime.Truncate(time.Microsecond), len(responseMsg.Answer), len(responseMsg.Ns), len(responseMsg.Extra), responseMsg.AuthenticatedData, FormatAllRecords(responseMsg.Answer, responseMsg.Ns, responseMsg.Extra))
		}
		if s.statsMgr != nil {
			s.statsMgr.RecordRequest(responseTime, cacheHit, hadError, requestProtocol, rewrote, hijackDetected, staleServed, fallbackUsed, prefetchTriggered)
		}
	}()

	if s.rewriteMgr.hasRules() {
		LogDebug("REWRITE: evaluating rules for %s qtype=%s client=%s", question.Name, dns.TypeToString[question.Qtype], clientIP)
		rewriteResult := s.rewriteMgr.RewriteWithDetails(question.Name, question.Qtype, question.Qclass, clientIP)

		if rewriteResult.ShouldRewrite {
			rewrote = true
			LogDebug("REWRITE: matched rule for %s -> domain=%s responseCode=%d records=%d additional=%d", question.Name, rewriteResult.Domain, rewriteResult.ResponseCode, len(rewriteResult.Records), len(rewriteResult.Additional))
			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				LogDebug("RESULT: %s %s | rcode=%s, blocked by rewrite rule", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[rewriteResult.ResponseCode])
				response := s.buildResponse(req)
				response.Rcode = rewriteResult.ResponseCode
				// Add EDE for rewrite-based blocks
				ede := NewEDEOption(EDECodeForgedAnswer, "Response code modified by rewrite rule")
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
				ede := NewEDEOption(EDECodeForgedAnswer, "Response modified by rewrite rule")
				s.addEDNS(response, req, isSecureConnection, clientIP, nil, ede)
				LogDebug("RESULT: %s %s | rcode=NOERROR (rewrite), answer=%d, additional=%d", question.Name, dns.TypeToString[question.Qtype], len(rewriteResult.Records), len(rewriteResult.Additional))
				responseMsg = response
				return responseMsg
			}
			if rewriteResult.Domain != question.Name {
				question.Name = rewriteResult.Domain
			}
		}
	}

	clientRequestedDNSSEC := false
	var ecsOpt *ECSOption
	var cookieOpt *CookieOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
		cookieOpt = s.ednsMgr.ParseCookie(req)
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.GetDefaultECSForQType(question.Qtype)
	}

	cacheKey := BuildCacheKey(question, ecsOpt, clientRequestedDNSSEC, s.config.Server.Features.Cache.Redis.KeyPrefix)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		LogDebug("CACHE: hit key=%s expired=%t for %s, ttl=%d, validated=%t, answer=%d", cacheKey, isExpired, question.Name, entry.GetRemainingTTL(), entry.Validated, len(entry.Answer))
		cacheHit = true
		if !isExpired {
			responseMsg = s.processCacheHit(req, entry, false, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &prefetchTriggered)
			return responseMsg
		}

		if entry.CanServeExpired(StaleMaxAge) {
			responseMsg = s.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &staleServed, &fallbackUsed)
			return responseMsg
		}

		responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &hadError, &fallbackUsed)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer := s.lookupReversePTR(question, ecsOpt); len(ptrAnswer) > 0 {
			LogDebug("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := s.buildResponse(req)
			response.Answer = ptrAnswer
			ede := NewEDEOption(EDECodeForgedAnswer, "Response generated by reverse PTR lookup")
			s.addEDNS(response, req, isSecureConnection, clientIP, cookieOpt, ede)
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &hadError, &fallbackUsed)
	return responseMsg
}

// lookupReversePTR performs a reverse DNS lookup for PTR queries using the cache manager.
func (s *DNSServer) lookupReversePTR(question dns.Question, ecsOpt *ECSOption) []dns.RR {
	ip := ParseReverseDNSName(question.Name)
	if ip == nil {
		return nil
	}

	reverseCache, ok := s.cacheMgr.(interface {
		ReverseLookup(net.IP) []reverseLookupResult
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
		records = append(records, BuildPTRRecord(question.Name, result.Name, DefaultTTL, question.Qclass))
	}

	return records
}

// ParseReverseDNSName parses a PTR query name into an IP address.
// It supports IPv4 reverse names under in-addr.arpa and IPv6 reverse names under ip6.arpa.
func ParseReverseDNSName(name string) net.IP {
	fqdn := strings.TrimSuffix(dns.Fqdn(name), ".")
	lower := strings.ToLower(fqdn)

	if strings.HasSuffix(lower, ".in-addr.arpa") {
		octets := strings.Split(strings.TrimSuffix(strings.TrimSuffix(lower, ".in-addr.arpa"), "."), ".")
		if len(octets) != 4 {
			return nil
		}
		for i, j := 0, len(octets)-1; i < j; i, j = i+1, j-1 {
			octets[i], octets[j] = octets[j], octets[i]
		}
		return net.ParseIP(strings.Join(octets, "."))
	}

	if strings.HasSuffix(lower, ".ip6.arpa") {
		nibbles := strings.Split(strings.TrimSuffix(strings.TrimSuffix(lower, ".ip6.arpa"), "."), ".")
		if len(nibbles) != 32 {
			return nil
		}
		for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
			nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
		}
		var builder strings.Builder
		for i, nibble := range nibbles {
			builder.WriteString(nibble)
			if i%4 == 3 && i != len(nibbles)-1 {
				builder.WriteByte(':')
			}
		}
		return net.ParseIP(builder.String())
	}

	return nil
}

// BuildPTRRecord creates a PTR record for the given query name and target.
func BuildPTRRecord(name, target string, ttl uint32, qclass uint16) dns.RR {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	return &dns.PTR{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypePTR,
			Class:  qclass,
			Ttl:    ttl,
		},
		Ptr: dns.Fqdn(target),
	}
}

// GetClientIP extracts client IP from DNS response writer.
func GetClientIP(w dns.ResponseWriter) net.IP {
	if addr := w.RemoteAddr(); addr != nil {
		switch a := addr.(type) {
		case *net.UDPAddr:
			return a.IP
		case *net.TCPAddr:
			return a.IP
		}
	}
	return nil
}

// FormatAllRecords outputs raw DNS records with section headers for logging.
func FormatAllRecords(answers, authority, additional []dns.RR) string {
	var b strings.Builder
	if len(answers) > 0 {
		b.WriteString("\n  ;; ANSWER SECTION:")
		for _, rr := range answers {
			b.WriteString("\n  " + rr.String())
		}
	}
	if len(authority) > 0 {
		b.WriteString("\n  ;; AUTHORITY SECTION:")
		for _, rr := range authority {
			b.WriteString("\n  " + rr.String())
		}
	}
	if len(additional) > 0 {
		b.WriteString("\n  ;; ADDITIONAL SECTION:")
		for _, rr := range additional {
			b.WriteString("\n  " + rr.String())
		}
	}
	return b.String()
}

// processCacheHit handles DNS queries that have a cache hit, returning cached
// responses and optionally refreshing stale entries or near-expiry entries in the background.
func (s *DNSServer) processCacheHit(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *ECSOption, cookieOpt *CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, prefetchTriggered *bool) *dns.Msg {
	msg := s.buildCacheResponse(req, entry, isExpired, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)

	if isExpired && entry.ShouldRefresh() {
		s.cacheRefreshGroup.Go(func() error {
			defer HandlePanic("cache refresh")
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
			defer HandlePanic("cache prefetch")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, OperationTimeout)
			defer cancel()
			LogDebug("CACHE: prefetch triggered for %s (threshold=%d%%)", question.Name, PrefetchThresholdPercent)
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
func (s *DNSServer) buildCacheResponse(req *dns.Msg, entry *CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, cookieOpt *CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg := messagePool.Get()
		msg.SetReply(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	responseTTL := entry.GetRemainingTTL()
	elapsed := int64(entry.TTL) - int64(responseTTL)
	if elapsed < 0 {
		elapsed = 0
	}
	msg.Answer = ProcessRecords(ExpandRecords(entry.Answer), elapsed, true, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(ExpandRecords(entry.Authority), elapsed, true, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(ExpandRecords(entry.Additional), elapsed, true, clientRequestedDNSSEC)

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	if isExpired {
		ede := NewEDEOption(EDECodeStaleAnswer, "Serving expired cache entry")
		s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	} else {
		s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, nil)
	}

	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

// canServeExpiredEntry checks if an expired cache entry can be served based on its age and the configured stale max age.
func (s *DNSServer) canServeExpiredEntry(entry *CacheEntry) bool {
	if entry == nil || !entry.IsExpired() {
		return false
	}
	return entry.CanServeExpired(StaleMaxAge)
}

// processExpiredCacheHit handles cache hits for expired entries, attempting to refresh the data in the background while serving the stale response to the client. It waits for the refresh to complete or a timeout before returning the response.
func (s *DNSServer) processExpiredCacheHit(req *dns.Msg, entry *CacheEntry, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *ECSOption, cookieOpt *CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, staleServed *bool, fallbackUsed *bool) *dns.Msg {
	type queryResult struct {
		answer     []dns.RR
		authority  []dns.RR
		additional []dns.RR
		validated  bool
		ecs        *ECSOption
		fallback   bool
		err        error
	}

	resultChan := make(chan queryResult, 1)
	go func() {
		defer HandlePanic("expired cache fallback query")
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
			LogDebug("CACHE: background refresh completed for slow expired query %s", question.Name)
			s.cacheMgr.Set(cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
			s.startLatencyProbe(question, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
		}()
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}
}

// processCacheMiss handles DNS queries that do not have a cache hit,
// performing upstream or recursive resolution.
func (s *DNSServer) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, cookieOpt *CookieOption, clientRequestedDNSSEC bool, cacheKey string, clientIP net.IP, isSecureConnection bool, hadError *bool, fallbackUsed *bool) *dns.Msg {
	LogDebug("CACHE: miss key=%s for %s, querying upstream/recursive", cacheKey, question.Name)
	answer, authority, additional, validated, ecsResponse, _, usedFallback, err := s.queryMgr.Query(question, ecsOpt)
	if fallbackUsed != nil && usedFallback {
		*fallbackUsed = true
	}

	if err != nil {
		// Check if it's a CIDR filter refusal
		if err.Error() == "cidr_filter_refused" {
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
func (s *DNSServer) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ *ECSOption, cookieOpt *CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found && s.canServeExpiredEntry(entry) {
		LogDebug("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.GetRemainingTTL(), entry.Validated)
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}

	LogDebug("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", question.Name, dns.TypeToString[question.Qtype])
	msg := s.buildResponse(req)
	if msg == nil {
		msg = messagePool.Get()
		msg.SetReply(req)
	}
	msg.Rcode = dns.RcodeServerFailure
	// Add EDE for query error
	ede := NewEDEOption(EDECodeNetworkError, "All upstream queries failed")
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
func (s *DNSServer) processCIDRRefused(req *dns.Msg, question dns.Question, cookieOpt *CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg = messagePool.Get()
		msg.SetReply(req)
	}
	LogDebug("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := NewEDEOption(EDECodeBlocked, "Query blocked by CIDR filtering rule")
	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	return msg
}

// processQuerySuccess handles successful query results, building the DNS response message, populating the cache if applicable, and adding EDNS options.
func (s *DNSServer) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *ECSOption, cookieOpt *CookieOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *ECSOption, skipCache bool, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	if msg == nil {
		msg = messagePool.Get()
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

	if !skipCache {
		LogDebug("CACHE: populating cache key=%s for %s", cacheKey, question.Name)
		s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, responseECS)
		s.startLatencyProbe(question, cacheKey, answer, authority, additional, validated, responseECS)
	} else {
		LogDebug("CACHE: fallback result, skipping cache population for %s", question.Name)
	}

	msg.Answer = ProcessRecords(answer, 0, false, clientRequestedDNSSEC)
	msg.Ns = ProcessRecords(authority, 0, false, clientRequestedDNSSEC)
	msg.Extra = ProcessRecords(additional, 0, false, clientRequestedDNSSEC)
	LogDebug("RESULT: %s %s | rcode=NOERROR, answer=%d, authority=%d, additional=%d, validated=%t, skipCache=%t, ecs=%t", question.Name, dns.TypeToString[question.Qtype], len(answer), len(authority), len(additional), validated, skipCache, responseECS != nil)
	LogDebug("CACHE: served response for %s (skipCache=%t)", question.Name, skipCache)

	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, nil)
	s.restoreOriginalDomain(msg, req.Question[0].Name, question.Name)
	return msg
}

// refreshCacheEntry refreshes a stale cache entry in the background.
func (s *DNSServer) refreshCacheEntry(_ context.Context, question dns.Question, ecs *ECSOption, cacheKey string, _ *CacheEntry) error {
	defer HandlePanic("cache refresh")

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
		LogDebug("CACHE: refresh query used fallback for %s, skipping cache population", question.Name)
	}

	return nil
}

// addEDNS adds EDNS options to a DNS response message, including ECS,
// DNSSEC flags, cookie, EDE, and padding for secure connections.
func (s *DNSServer) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *CookieOption, ede *EDEOption) {
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
		ecsOpt = s.ednsMgr.GetDefaultECSForQType(req.Question[0].Qtype)
	}

	// Generate cookie response only when the client sent a cookie option.
	cookieStr := s.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection

	if shouldAddEDNS {
		s.ednsMgr.AddToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection, cookieStr, ede)
	}
}

// generateCookieResponse generates cookie string for response
// Returns client_cookie || server_cookie format only when the client sent a cookie option.
func (s *DNSServer) generateCookieResponse(cookieOpt *CookieOption, clientIP net.IP) string {
	if s.ednsMgr == nil || s.ednsMgr.cookieGenerator == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = net.ParseIP("0.0.0.0")
	}

	if len(cookieOpt.ClientCookie) != DefaultCookieClientLen {
		LogDebug("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), DefaultCookieClientLen)
		return ""
	}

	// Client sent a cookie - validate server cookie if present, then generate a new one.
	var serverCookie []byte
	if len(cookieOpt.ServerCookie) >= 16 {
		if s.ednsMgr.cookieGenerator.ValidateServerCookie(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			LogDebug("EDNS: server cookie validated for %s", clientIP)
			serverCookie = s.ednsMgr.cookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		} else {
			LogDebug("EDNS: server cookie invalid for %s, regenerating", clientIP)
			serverCookie = s.ednsMgr.cookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		}
	}

	if serverCookie == nil {
		LogDebug("EDNS: generating new server cookie for %s", clientIP)
		serverCookie = s.ednsMgr.cookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
	}

	return BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
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
		s.ednsMgr.AddToMessage(msg, ecs, true, isSecureConnection, "", nil)
	}

	return msg
}
