package server

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/client"
	"zjdns/server/resolver"
)

// ServeDNS handles an incoming DNS query and returns a response.
func (s *Server) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	return s.processDNSQuery(req, clientIP, isSecure, protocol)
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, req *dns.Msg) {
	defer dnsutil.HandlePanic("DNS request processing")

	select {
	case <-s.ctx.Done():
		return
	default:
	}

	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		addr := w.RemoteAddr().String()
		entryI, _ := s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
		entry := entryI.(*tcpWriteEntry)
		entry.capacityOnce.Do(func() {
			entry.capacity = make(chan struct{}, client.DefaultMaxPipe)
		})

		select {
		case entry.capacity <- struct{}{}:
		default:
			return
		}

		go func() {
			defer func() { <-entry.capacity }()
			defer dnsutil.HandlePanic("TCP query handler")
			response := s.processDNSQuery(req, dnsutil.ClientIP(w), false, "TCP")
			if response != nil {
				response.Compress = true
				entry.lastAccess.Store(time.Now().UnixNano())
				entry.mu.Lock()
				if err := w.WriteMsg(response); err != nil {
					log.Debugf("SERVER: TCP write error for %s: %v", addr, err)
				}
				entry.mu.Unlock()
				pool.DefaultMessagePool.Put(response)
			}
		}()
		return
	}

	response := s.processDNSQuery(req, dnsutil.ClientIP(w), false, detectRequestProtocol(w))
	if response != nil {
		response.Compress = true
		_ = w.WriteMsg(response)
		pool.DefaultMessagePool.Put(response)
	}
}

func (s *Server) processDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool, requestProtocol string) *dns.Msg {
	if atomic.LoadInt32(&s.closed) != 0 {
		msg := s.buildResponse(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	if s.semaphore != nil {
		select {
		case s.semaphore <- struct{}{}:
			defer func() { <-s.semaphore }()
		default:
			log.Debugf("QUERY: max concurrent reached, returning SERVFAIL")
			msg := s.buildResponse(req)
			msg.Rcode = dns.RcodeServerFailure
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

		var ede *edns.EDEOption
		if len(question.Name) > config.MaxDomainLength {
			ede = edns.NewEDEOption(edns.EDECodeInvalidData, "")
		} else {
			ede = edns.NewEDEOption(edns.EDECodeNotSupported, "")
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

				ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
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

				ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
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
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			s.addEDNS(response, req, isSecureConnection, clientIP, cookieOpt, ede)
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &hadError, &fallbackUsed)
	return responseMsg
}

func (s *Server) lookupReversePTR(question dns.Question, ecsOpt *edns.ECSOption) []dns.RR {
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

func (s *Server) processCacheHit(req *dns.Msg, entry *cache.CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, prefetchTriggered *bool) *dns.Msg {
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

func (s *Server) shouldStartPrefetch(cacheKey string) bool {
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

func (s *Server) buildCacheResponse(req *dns.Msg, entry *cache.CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)

	responseTTL := entry.GetRemainingTTL()
	elapsed := int64(entry.TTL) - int64(responseTTL)
	if elapsed < 0 {
		elapsed = 0
	}
	msg.Answer = cache.ExpandAndProcessRecords(entry.Answer, elapsed, true, clientRequestedDNSSEC)
	msg.Ns = cache.ExpandAndProcessRecords(entry.Authority, elapsed, true, clientRequestedDNSSEC)
	msg.Extra = cache.ExpandAndProcessRecords(entry.Additional, elapsed, true, clientRequestedDNSSEC)

	// Restore AuthenticatedData if the entry was cryptographically validated
	// by the full DNSSEC chain-of-trust verification. The record-presence-only
	// Validator (entry.Validated) does NOT set AD — only CryptoValidator does.
	if entry.Validated {
		msg.AuthenticatedData = true
	}

	if isExpired {
		ede := edns.NewEDEOption(edns.EDECodeStaleAnswer, "")
		s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	} else {
		s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, nil)
	}

	s.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

func (s *Server) canServeExpiredEntry(entry *cache.CacheEntry) bool {
	if entry == nil || !entry.IsExpired() {
		return false
	}
	return entry.CanServeExpired(cache.StaleMaxAge)
}

func (s *Server) processExpiredCacheHit(req *dns.Msg, entry *cache.CacheEntry, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, staleServed *bool, fallbackUsed *bool) *dns.Msg {
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
		answer, authority, additional, validated, ecsResponse, _, fallbackUsed, err := s.resolver.Query(question, ecsOpt)
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
			select {
			case res := <-resultChan:
				if res.err != nil || res.fallback {
					return
				}
				log.Debugf("CACHE: background refresh completed for slow expired query %s", question.Name)
				s.cacheMgr.Set(cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
				if s.prober != nil {
					s.prober.Start(question, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs)
				}
			case <-s.ctx.Done():
			}
		}()
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}
}

func (s *Server) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, clientIP net.IP, isSecureConnection bool, hadError *bool, fallbackUsed *bool) *dns.Msg {
	log.Debugf("CACHE: miss key=%s for %s, querying upstream/recursive", cacheKey, question.Name)
	answer, authority, additional, validated, ecsResponse, _, usedFallback, err := s.resolver.Query(question, ecsOpt)
	if fallbackUsed != nil && usedFallback {
		*fallbackUsed = true
	}

	if err != nil {

		if errors.Is(err, resolver.ErrCIDRFilterRefused) {
			return s.processCIDRRefused(req, question, cookieOpt, clientIP, isSecureConnection)
		}
		if hadError != nil {
			*hadError = true
		}
		return s.processQueryError(req, cacheKey, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, err)
	}

	return s.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, answer, authority, additional, validated, ecsResponse, usedFallback, clientIP, isSecureConnection)
}

func (s *Server) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, _ *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, queryErr error) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found && s.canServeExpiredEntry(entry) {
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.GetRemainingTTL(), entry.Validated)
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", question.Name, dns.TypeToString[question.Qtype])
	msg := s.buildResponse(req)
	msg.Rcode = dns.RcodeServerFailure

	// Map error to appropriate RFC 8914 Extended DNS Error code.
	// Check the recursive resolver's DNSSEC state first (more reliable
	// than error type matching since the error can be lost in the chain).
	edeCode := edns.EDECodeNetworkError
	if s.resolver != nil && s.resolver.Recursive() != nil && s.resolver.Recursive().DNSSECEDECode() != 0 {
		edeCode = s.resolver.Recursive().DNSSECEDECode()
		log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
	} else {
		var dnsErr *resolver.DNSSECError
		if errors.As(queryErr, &dnsErr) {
			edeCode = dnsErr.EDECode
			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		} else if queryErr != nil {
			log.Debugf("RESULT: non-DNSSEC error, using EDE %d: %v", edeCode, queryErr)
		}
	}
	ede := edns.NewEDEOption(edeCode, "")
	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	return msg
}

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

func (s *Server) processCIDRRefused(req *dns.Msg, question dns.Question, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := edns.NewEDEOption(edns.EDECodeBlocked, "")
	s.addEDNS(msg, req, isSecureConnection, clientIP, cookieOpt, ede)
	return msg
}

func (s *Server) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption, skipCache bool, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)

	// Set AuthenticatedData when DNSSEC cryptographic validation passed.
	// DNSSEC is always enabled; CryptoValidator runs on every recursive query.
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
		if s.prober != nil {
			s.prober.Start(question, cacheKey, answer, authority, additional, validated, responseECS)
		}
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

func (s *Server) refreshCacheEntry(ctx context.Context, question dns.Question, ecs *edns.ECSOption, cacheKey string, _ *cache.CacheEntry) error {
	defer dnsutil.HandlePanic("cache refresh")

	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server closed")
	}

	// Check context before making an expensive query. Note: Resolver.Query
	// creates its own internal context; a future refactor should thread ctx
	// through the resolver chain for proper cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	answer, authority, additional, validated, ecsResponse, _, fallbackUsed, err := s.resolver.Query(question, ecs)
	if err != nil {
		return err
	}

	if !fallbackUsed {
		s.cacheMgr.Set(cacheKey, answer, authority, additional, validated, ecsResponse)
		if s.prober != nil {
			s.prober.Start(question, cacheKey, answer, authority, additional, validated, ecsResponse)
		}
	} else {
		log.Debugf("CACHE: refresh query used fallback for %s, skipping cache population", question.Name)
	}

	return nil
}

func (s *Server) addEDNS(msg *dns.Msg, req *dns.Msg, isSecureConnection bool, clientIP net.IP, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	if msg == nil || req == nil {
		return
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption

	if opt := req.IsEdns0(); opt != nil {
		clientRequestedDNSSEC = opt.Do()
		ecsOpt = s.ednsMgr.ParseFromDNS(req)
	}

	if ecsOpt == nil && len(req.Question) > 0 {
		ecsOpt = s.ednsMgr.DefaultECSForQType(req.Question[0].Qtype)
	}

	s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede)
}

// applyEDNS applies EDNS options to a response without re-parsing the request.
// It accepts already-parsed ECS and DNSSEC values to avoid redundant work on
// the hot path where these are already known from the initial request parse.
func (s *Server) applyEDNS(msg *dns.Msg, isSecureConnection bool, clientIP net.IP, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, ede *edns.EDEOption) {
	cookieStr := s.generateCookieResponse(cookieOpt, clientIP)

	shouldAddEDNS := ecsOpt != nil || clientRequestedDNSSEC || cookieStr != "" || ede != nil || isSecureConnection

	if shouldAddEDNS {
		s.ednsMgr.ApplyToMessage(msg, ecsOpt, clientRequestedDNSSEC, isSecureConnection, cookieStr, ede)
	}
}

func (s *Server) generateCookieResponse(cookieOpt *edns.CookieOption, clientIP net.IP) string {
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

func (s *Server) buildResponse(req *dns.Msg) *dns.Msg {
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

func (s *Server) restoreOriginalDomain(msg *dns.Msg, currentName, originalName string) {
	if msg == nil || strings.EqualFold(currentName, originalName) {
		return
	}
	for _, rr := range msg.Answer {
		if rr != nil && strings.EqualFold(rr.Header().Name, currentName) {
			rr.Header().Name = originalName
		}
	}
}

func (s *Server) buildQueryMessage(question dns.Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	msg.SetQuestion(dns.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if s.ednsMgr != nil {
		s.ednsMgr.ApplyToMessage(msg, ecs, true, isSecureConnection, "", nil)
	}

	return msg
}
