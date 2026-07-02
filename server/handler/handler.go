// Package handler provides the DNS query processing pipeline: cache lookup,
// rewrite evaluation, upstream/recursive resolution, and DNSSEC validation.
package handler

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/rewrite"
	"zjdns/server/latency"
	"zjdns/server/resolver"
	"zjdns/stats"
)

// queryMetrics bundles the per-query state needed for deferred metric
// recording. Using a struct avoids a 13-variable closure heap escape on every
// query (saves ~200-300 bytes per query).
type queryMetrics struct {
	cacheHit          bool
	hadError          bool
	rewrote           bool
	hijackDetected    bool
	staleServed       bool
	prefetchTriggered bool
	fallbackUsed      bool
	dnssecStatus      string
	startTime         time.Time
	requestProtocol   string
}

// queryResult holds the result of a resolver query for stale-cache fallback.
type queryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *edns.ECSOption
	fallback   bool
	err        error
}

// Handler processes DNS queries through the caching and resolution pipeline.
type Handler struct {
	closed int32 // hot-path: checked on every query via atomic load

	config            *config.ServerConfig
	cache             cache.Store
	reverseCache      interface{ ReverseLookup(net.IP) []cache.LookupResult }
	edns              *edns.Handler
	rewrite           *rewrite.Evaluator
	stats             *stats.Collector
	resolver          *resolver.Resolver
	prober            *latency.Prober
	prefetchCooldown  sync.Map
	semaphore         chan struct{}
	cacheRefreshGroup *errgroup.Group
	cacheRefreshCtx   context.Context
	ctx               context.Context
}

// New creates a Handler with the given dependencies. The resolver and prober
// are set later via SetResolver / SetProber after they are constructed.
func New(
	cfg *config.ServerConfig,
	cacheStore cache.Store,
	ednsHandler *edns.Handler,
	rewriteEvaluator *rewrite.Evaluator,
	statsCollector *stats.Collector,
	semaphore chan struct{},
	cacheRefreshGroup *errgroup.Group,
	cacheRefreshCtx context.Context,
	ctx context.Context,
) *Handler {
	h := &Handler{
		config:            cfg,
		cache:             cacheStore,
		edns:              ednsHandler,
		rewrite:           rewriteEvaluator,
		stats:             statsCollector,
		semaphore:         semaphore,
		cacheRefreshGroup: cacheRefreshGroup,
		cacheRefreshCtx:   cacheRefreshCtx,
		ctx:               ctx,
	}
	h.reverseCache, _ = cacheStore.(interface {
		ReverseLookup(net.IP) []cache.LookupResult
	})
	return h
}

// SetResolver sets the resolver after construction (two-phase init).
func (h *Handler) SetResolver(r *resolver.Resolver) { h.resolver = r }

// SetProber sets the latency prober after construction.
func (h *Handler) SetProber(p *latency.Prober) { h.prober = p }

// IsClosed reports whether the handler has been shut down.
func (h *Handler) IsClosed() bool { return atomic.LoadInt32(&h.closed) != 0 }

// MarkClosed signals the handler to stop accepting new work.
func (h *Handler) MarkClosed() { atomic.StoreInt32(&h.closed, 1) }

// Edns returns the EDNS handler.
func (h *Handler) Edns() *edns.Handler { return h.edns }

// Stats returns the stats collector.
func (h *Handler) Stats() *stats.Collector { return h.stats }

// CacheStore returns the cache store (used for persistence and shutdown).
func (h *Handler) CacheStore() cache.Store { return h.cache }

// Resolver returns the DNS resolver.
func (h *Handler) Resolver() *resolver.Resolver { return h.resolver }

// HasRewriteRules reports whether rewrite rules are configured.
func (h *Handler) HasRewriteRules() bool { return h.rewrite != nil && h.rewrite.HasRules() }

// PrefetchCooldown returns the prefetch throttle map (used by background cleanup).
func (h *Handler) PrefetchCooldown() *sync.Map { return &h.prefetchCooldown }

// UpstreamServers returns the configured upstream servers.
func (h *Handler) UpstreamServers() []*config.UpstreamServer { return h.resolver.UpstreamServers() }

// DefaultECS returns the default ECS option.
func (h *Handler) DefaultECS() *edns.ECSOption { return h.edns.DefaultECS() }

// CacheRefreshGroup returns the errgroup for cache refresh goroutines.
func (h *Handler) CacheRefreshGroup() *errgroup.Group { return h.cacheRefreshGroup }

// CacheRefreshCtx returns the context for cache refresh operations.
func (h *Handler) CacheRefreshCtx() context.Context { return h.cacheRefreshCtx }

// ServeDNS handles an incoming DNS query from a TLS/DoH/DoQ listener.
func (h *Handler) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	return h.processDNSQuery(req, clientIP, isSecure, protocol)
}

// BuildQueryMessage constructs an outbound DNS query message for the resolver.
func (h *Handler) BuildQueryMessage(question dns.Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if h.edns != nil {
		h.edns.ApplyToMessage(msg, ecs, isSecureConnection, "", nil, true, true)
	}

	return msg
}

func (h *Handler) processDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool, requestProtocol string) *dns.Msg {
	if atomic.LoadInt32(&h.closed) != 0 {
		msg := h.buildResponse(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	if h.semaphore != nil {
		select {
		case h.semaphore <- struct{}{}:
			defer func() { <-h.semaphore }()
		default:
			log.Debugf("QUERY: max concurrent reached, returning SERVFAIL")
			msg := h.buildResponse(req)
			msg.Rcode = dns.RcodeServerFailure
			return msg
		}
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

	if len(question.Name) > config.MaxDomainLength || question.Qtype == dns.TypeANY ||
		question.Qtype == dns.TypeAXFR || question.Qtype == dns.TypeIXFR ||
		!dnsutil.IsValidDomainLabels(question.Name) {
		msg := pool.DefaultMessagePool.Get()
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused

		var ede *edns.EDEOption
		if len(question.Name) > config.MaxDomainLength || !dnsutil.IsValidDomainLabels(question.Name) {
			ede = edns.NewEDEOption(edns.EDECodeInvalidData, "")
		} else {
			ede = edns.NewEDEOption(edns.EDECodeNotSupported, "")
		}
		h.addEDNS(msg, req, isSecureConnection, clientIP, nil, ede)
		return msg
	}

	startTime := time.Now()
	m := &queryMetrics{
		startTime:       startTime,
		requestProtocol: requestProtocol,
	}
	var responseMsg *dns.Msg
	defer h.recordQueryMetrics(m, &responseMsg, question)

	if h.rewrite.HasRules() {
		log.Debugf("REWRITE: evaluating rules for %s qtype=%s client=%s", question.Name, dns.TypeToString[question.Qtype], clientIP)
		rewriteResult := h.rewrite.Evaluate(question.Name, question.Qtype, question.Qclass, clientIP)

		if rewriteResult.ShouldRewrite {
			m.rewrote = true
			log.Debugf("REWRITE: matched rule for %s -> domain=%s responseCode=%d records=%d additional=%d", question.Name, rewriteResult.Domain, rewriteResult.ResponseCode, len(rewriteResult.Records), len(rewriteResult.Additional))
			if rewriteResult.ResponseCode != dns.RcodeSuccess {
				log.Debugf("RESULT: %s %s | rcode=%s, blocked by rewrite rule", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[rewriteResult.ResponseCode])
				response := h.buildResponse(req)
				response.Rcode = rewriteResult.ResponseCode

				ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
				h.addEDNS(response, req, isSecureConnection, clientIP, nil, ede)
				responseMsg = response
				return responseMsg
			}

			if len(rewriteResult.Records) > 0 {
				response := h.buildResponse(req)
				response.Answer = rewriteResult.Records
				response.Rcode = dns.RcodeSuccess
				if len(rewriteResult.Additional) > 0 {
					response.Extra = rewriteResult.Additional
				}

				ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
				h.addEDNS(response, req, isSecureConnection, clientIP, nil, ede)
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
		ecsOpt = h.edns.ParseFromDNS(req)
		cookieOpt = h.edns.ParseCookie(req)
	}

	// Early DNS Cookie validation (RFC 7873): reject queries with an invalid
	// server cookie before spending CPU on resolution. This prevents an attacker
	// from using spoofed source IPs to amplify traffic through the resolver.
	if cookieOpt != nil && len(cookieOpt.ServerCookie) >= edns.DefaultCookieServerLen {
		if !h.edns.CookieGenerator.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			log.Debugf("EDNS: bad server cookie from %s, returning BADCOOKIE", clientIP)
			msg := h.buildResponse(req)
			msg.Rcode = dns.RcodeFormatError
			// Generate a valid server cookie so the legitimate client can retry.
			serverCookie := h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
			cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
			h.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req))
			responseMsg = msg
			return responseMsg
		}
	}

	if ecsOpt == nil {
		ecsOpt = h.edns.ECSForQType(question.Qtype)
	}

	cacheKey := cache.BuildCacheKey(question, ecsOpt, clientRequestedDNSSEC)

	if entry, found, isExpired := h.cache.Get(cacheKey); found {
		log.Debugf("CACHE: hit key=%s expired=%t for %s, ttl=%d, validated=%t, answer=%d", cacheKey, isExpired, question.Name, entry.RemainingTTL(), entry.Validated, len(entry.Answer))
		m.cacheHit = true
		if !isExpired {
			responseMsg = h.processCacheHit(req, entry, false, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &m.prefetchTriggered, &m.dnssecStatus)
			return responseMsg
		}

		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			responseMsg = h.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &m.staleServed, &m.fallbackUsed, &m.dnssecStatus)
			return responseMsg
		}

		responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &m.hadError, &m.fallbackUsed, &m.dnssecStatus)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer := h.lookupReversePTR(question, ecsOpt); len(ptrAnswer) > 0 {
			log.Debugf("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := h.buildResponse(req)
			response.Answer = ptrAnswer
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			h.applyEDNS(response, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req))
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &m.hadError, &m.fallbackUsed, &m.dnssecStatus)
	return responseMsg
}

func (h *Handler) lookupReversePTR(question dns.Question, ecsOpt *edns.ECSOption) []dns.RR {
	ip := dnsutil.ParseReverseDNSName(question.Name)
	if ip == nil {
		return nil
	}

	if h.reverseCache == nil {
		return nil
	}

	results := h.reverseCache.ReverseLookup(ip)
	if len(results) == 0 {
		return nil
	}

	records := make([]dns.RR, 0, len(results))
	for _, result := range results {
		records = append(records, dnsutil.NewPTRRecord(question.Name, result.Name, config.DefaultTTL, question.Qclass))
	}

	return records
}

func (h *Handler) processCacheHit(req *dns.Msg, entry *cache.Entry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, prefetchTriggered *bool, dnssecStatus *string) *dns.Msg {
	if entry.Validated {
		*dnssecStatus = config.DNSSECStatusSecure
	} else {
		*dnssecStatus = config.DNSSECStatusInsecure
	}

	msg := h.buildCacheResponse(req, entry, isExpired, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)

	if isExpired && entry.ShouldRefresh() {
		h.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return h.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	if !isExpired && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) && h.shouldStartPrefetch(cacheKey) {
		if prefetchTriggered != nil {
			*prefetchTriggered = true
		}
		h.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache prefetch")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			log.Debugf("CACHE: prefetch triggered for %s (threshold=%d%%)", question.Name, config.DefaultPrefetchThresholdPercent)
			return h.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	return msg
}

func (h *Handler) shouldStartPrefetch(cacheKey string) bool {
	if h == nil || cacheKey == "" {
		return false
	}

	now := log.NowUnixNano()
	nextAllowed, ok := h.prefetchCooldown.Load(cacheKey)
	if ok {
		if nextTs, typeOK := nextAllowed.(int64); typeOK && now < nextTs {
			return false
		}
	}

	h.prefetchCooldown.Store(cacheKey, now+config.DefaultPrefetchThrottleInterval.Nanoseconds())
	return true
}

func (h *Handler) buildCacheResponse(req *dns.Msg, entry *cache.Entry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := h.buildResponse(req)

	responseTTL := entry.RemainingTTL()
	elapsed := int64(entry.TTL) - int64(responseTTL)
	if elapsed < 0 {
		elapsed = 0
	}
	msg.Answer = cache.ExpandAndProcessRecords(entry.Answer, elapsed, true, clientRequestedDNSSEC)
	msg.Ns = cache.ExpandAndProcessRecords(entry.Authority, elapsed, true, clientRequestedDNSSEC)
	msg.Extra = cache.ExpandAndProcessRecords(entry.Additional, elapsed, true, clientRequestedDNSSEC)

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	if isExpired {
		ede := edns.NewEDEOption(edns.EDECodeStaleAnswer, "")
		h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req))
	} else {
		h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, nil, edns.HasPaddingOption(req))
	}

	h.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

func (h *Handler) processExpiredCacheHit(req *dns.Msg, entry *cache.Entry, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, staleServed *bool, fallbackUsed *bool, dnssecStatus *string) *dns.Msg {
	if h.config.Server.Features.Cache.PreferStale {
		if staleServed != nil {
			*staleServed = true
		}
		if entry.Validated {
			*dnssecStatus = config.DNSSECStatusSecure
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
		h.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("expired cache refresh")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return h.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
	}

	var res queryResult
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer dnsutil.HandlePanic("expired cache fallback query")
		qr := h.resolver.Query(h.ctx, question, ecsOpt)
		res = queryResult{
			answer:     qr.Answer,
			authority:  qr.Authority,
			additional: qr.Additional,
			validated:  qr.Validated,
			ecs:        qr.ECS,
			fallback:   qr.Fallback,
			err:        qr.Err,
		}
	}()

	timer := time.NewTimer(config.DefaultServeExpiredClientTimeout)
	defer timer.Stop()

	select {
	case <-done:
		if res.err == nil {
			if fallbackUsed != nil && res.fallback {
				*fallbackUsed = true
			}
			return h.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs, clientIP, isSecureConnection, dnssecStatus)
		}
		if staleServed != nil {
			*staleServed = true
		}
		return h.processCacheHit(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, nil, dnssecStatus)
	case <-timer.C:
		if staleServed != nil {
			*staleServed = true
		}
		if entry.Validated {
			*dnssecStatus = config.DNSSECStatusSecure
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
		go func() {
			select {
			case <-done:
				if res.err != nil {
					return
				}
				log.Debugf("CACHE: background refresh completed for slow expired query %s", question.Name)
				h.cache.Set(cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
				if h.prober != nil {
					h.prober.Start(question, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
				}
			case <-h.ctx.Done():
			}
		}()
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
	}
}

func (h *Handler) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, clientIP net.IP, isSecureConnection bool, hadError *bool, fallbackUsed *bool, dnssecStatus *string) *dns.Msg {
	log.Debugf("CACHE: miss key=%s for %s, querying upstream/recursive", cacheKey, question.Name)
	qr := h.resolver.Query(h.ctx, question, ecsOpt)
	if fallbackUsed != nil && qr.Fallback {
		*fallbackUsed = true
	}

	if qr.Err != nil {

		if errors.Is(qr.Err, resolver.ErrCIDRFilterRefused) {
			return h.processCIDRRefused(req, question, ecsOpt, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
		}
		if hadError != nil {
			*hadError = true
		}
		return h.processQueryError(req, cacheKey, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, qr.Err, dnssecStatus)
	}

	return h.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS, clientIP, isSecureConnection, dnssecStatus)
}

func (h *Handler) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, queryErr error, dnssecStatus *string) *dns.Msg {
	if entry, found, _ := h.cache.Get(cacheKey); found && entry.IsExpired() && entry.CanServeExpired(config.DefaultStaleMaxAge) {
		if entry.Validated {
			*dnssecStatus = config.DNSSECStatusSecure
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.RemainingTTL(), entry.Validated)
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", question.Name, dns.TypeToString[question.Qtype])
	msg := h.buildResponse(req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := edns.EDECodeNetworkError
	if h.resolver != nil && h.resolver.Recursive() != nil && h.resolver.Recursive().DNSSECEDECode() != 0 {
		edeCode = h.resolver.Recursive().DNSSECEDECode()
		*dnssecStatus = config.DNSSECStatusBogus
		log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
	} else {
		var dnsErr *resolver.DNSSECError
		if errors.As(queryErr, &dnsErr) {
			edeCode = dnsErr.EDECode
			*dnssecStatus = config.DNSSECStatusBogus
			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		} else if queryErr != nil {
			log.Debugf("RESULT: non-DNSSEC error, using EDE %d: %v", edeCode, queryErr)
		}
	}
	ede := edns.NewEDEOption(edeCode, "")
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req))
	return msg
}

func (h *Handler) processCIDRRefused(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := h.buildResponse(req)
	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := edns.NewEDEOption(edns.EDECodeBlocked, "")
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req))
	return msg
}

func (h *Handler) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption, clientIP net.IP, isSecureConnection bool, dnssecStatus *string) *dns.Msg {
	msg := h.buildResponse(req)

	if validated {
		*dnssecStatus = config.DNSSECStatusSecure
	} else {
		if h.resolver != nil && h.resolver.Recursive() != nil && h.resolver.Recursive().DNSSECEDECode() != 0 {
			*dnssecStatus = config.DNSSECStatusBogus
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
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

	log.Debugf("CACHE: populating cache key=%s for %s", cacheKey, question.Name)
	h.cache.Set(cacheKey, answer, authority, additional, validated, responseECS)
	if h.prober != nil {
		h.prober.Start(question, cacheKey, answer, authority, additional, validated, responseECS)
	}

	msg.Answer = cache.ProcessRecords(answer, 0, false, clientRequestedDNSSEC)
	msg.Ns = cache.ProcessRecords(authority, 0, false, clientRequestedDNSSEC)
	msg.Extra = cache.ProcessRecords(additional, 0, false, clientRequestedDNSSEC)
	log.Debugf("RESULT: %s %s | rcode=NOERROR, answer=%d, authority=%d, additional=%d, validated=%t, ecs=%t", question.Name, dns.TypeToString[question.Qtype], len(answer), len(authority), len(additional), validated, responseECS != nil)
	log.Debugf("CACHE: served response for %s ", question.Name)

	var edeOpt *edns.EDEOption
	if *dnssecStatus == config.DNSSECStatusBogus && h.resolver != nil && h.resolver.Recursive() != nil {
		if code := h.resolver.Recursive().DNSSECEDECode(); code != 0 {
			edeOpt = edns.NewEDEOption(code, "")
		}
	}
	if edeOpt == nil && h.resolver != nil {
		if upstreamEDE := h.resolver.UpstreamEDEOption(); upstreamEDE != nil {
			edeOpt = upstreamEDE
			log.Debugf("UPSTREAM: passing through EDE %d (%s) from upstream", upstreamEDE.InfoCode, edns.EDECodeString(upstreamEDE.InfoCode))
		}
	}
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, edeOpt, edns.HasPaddingOption(req))
	h.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

func (h *Handler) refreshCacheEntry(ctx context.Context, question dns.Question, ecs *edns.ECSOption, cacheKey string, _ *cache.Entry) error {
	defer dnsutil.HandlePanic("cache refresh")

	if atomic.LoadInt32(&h.closed) != 0 {
		return errors.New("server closed")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	qr := h.resolver.Query(ctx, question, ecs)
	if qr.Err != nil {
		return qr.Err
	}

	h.cache.Set(cacheKey, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
	if h.prober != nil {
		h.prober.Start(question, cacheKey, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
	}

	return nil
}

func (h *Handler) recordQueryMetrics(m *queryMetrics, responseMsg **dns.Msg, question dns.Question) {
	responseTime := time.Since(m.startTime)
	rcode := dns.RcodeServerFailure
	if *responseMsg != nil {
		rcode = (*responseMsg).Rcode
		if log.Default.Level() >= log.Debug {
			log.Debugf("RESULT: %s %s | rcode=%s time=%v answer=%d authority=%d additional=%d ad=%t%s",
				question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[(*responseMsg).Rcode],
				responseTime.Truncate(time.Microsecond), len((*responseMsg).Answer), len((*responseMsg).Ns),
				len((*responseMsg).Extra), (*responseMsg).AuthenticatedData,
				dnsutil.FormatRecords((*responseMsg).Answer, (*responseMsg).Ns, (*responseMsg).Extra))
		}
	}
	if h.stats != nil {
		h.stats.RecordRequest(responseTime, m.cacheHit, m.hadError, m.requestProtocol,
			m.rewrote, m.hijackDetected, m.staleServed, m.fallbackUsed, m.prefetchTriggered,
			m.dnssecStatus, rcode)
	}
}

// ── Message helpers ───────────────────────────────────────────────────────────

func (h *Handler) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = h.edns.ParseFromDNS(req)
	}

	if ecsOpt == nil && len(req.Question) > 0 {
		ecsOpt = h.edns.ECSForQType(req.Question[0].Qtype)
	}

	clientWantsPadding := edns.HasPaddingOption(req)
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, clientWantsPadding)
}

func (h *Handler) applyEDNS(msg *dns.Msg, isSecureConnection bool, clientIP net.IP, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, ede *edns.EDEOption, clientWantsPadding bool) {
	cookieStr := h.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection

	if shouldAddEDNS {
		h.edns.ApplyToMessage(msg, ecsOpt, isSecureConnection, cookieStr, ede, false, clientWantsPadding)
	}
}

func (h *Handler) generateCookieResponse(cookieOpt *edns.CookieOption, clientIP net.IP) string {
	if h.edns == nil || h.edns.CookieGenerator == nil || cookieOpt == nil {
		return ""
	}

	if clientIP == nil {
		clientIP = net.ParseIP(config.FallbackClientIP)
	}

	if len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen {
		log.Debugf("EDNS: invalid client cookie length %d (expected %d)", len(cookieOpt.ClientCookie), edns.DefaultCookieClientLen)
		return ""
	}

	if len(cookieOpt.ServerCookie) >= edns.DefaultCookieServerLen {
		if h.edns.CookieGenerator.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			log.Debugf("EDNS: server cookie validated for %s", clientIP)
		} else {
			log.Debugf("EDNS: server cookie invalid for %s, regenerating", clientIP)
		}
	} else {
		log.Debugf("EDNS: generating new server cookie for %s", clientIP)
	}
	serverCookie := h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)

	return edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
}

func (h *Handler) buildResponse(req *dns.Msg) *dns.Msg {
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

func (h *Handler) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || strings.EqualFold(currentName, originalName) {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Ns {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
	for _, rr := range msg.Extra {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}
