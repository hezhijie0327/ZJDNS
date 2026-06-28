package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/resolver"
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
			entry.capacity = make(chan struct{}, config.DefaultMaxPipe)
			entry.writeMu = make(chan struct{}, 1)
		})

		select {
		case entry.capacity <- struct{}{}:
		default:
			msg := pool.DefaultMessagePool.Get()
			msg.SetReply(req)
			msg.Rcode = dns.RcodeServerFailure
			if err := w.WriteMsg(msg); err != nil {
				log.Debugf("SERVER: TCP SERVFAIL write error for %s: %v", addr, err)
			}
			pool.DefaultMessagePool.Put(msg)
			return
		}

		go func() {
			defer func() { <-entry.capacity }()
			defer dnsutil.HandlePanic("TCP query handler")
			response := s.processDNSQuery(req, dnsutil.ClientIP(w), false, "TCP")
			if response != nil {
				response.Compress = true
				entry.lastAccess.Store(time.Now().UnixNano())
				writeTimer := time.NewTimer(config.DefaultDNSQueryTimeout)
				select {
				case entry.writeMu <- struct{}{}:
					writeTimer.Stop()
					defer func() { <-entry.writeMu }()
				case <-writeTimer.C:
					log.Debugf("SERVER: TCP write lock timeout for %s", addr)
					pool.DefaultMessagePool.Put(response)
					return
				}
				if err := w.WriteMsg(response); err != nil {
					log.Debugf("SERVER: TCP write error for %s: %v", addr, err)
				}
				pool.DefaultMessagePool.Put(response)
			}
		}()
		return
	}

	// UDP per-client rate limiting to prevent DoS via query flooding.
	clientIP := dnsutil.ClientIP(w)
	if s.udpRateLimiter != nil && clientIP != nil {
		if !s.udpRateLimiter.allow(clientIP.String()) {
			log.Debugf("QUERY: UDP rate limit exceeded for %s", clientIP.String())
			msg := pool.DefaultMessagePool.Get()
			msg.SetReply(req)
			msg.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(msg)
			pool.DefaultMessagePool.Put(msg)
			return
		}
	}

	response := s.processDNSQuery(req, clientIP, false, detectRequestProtocol(w))
	if response != nil {
		response.Compress = true
		if err := w.WriteMsg(response); err != nil {
			log.Debugf("SERVER: UDP write error for %s: %v", w.RemoteAddr().String(), err)
		}
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
		!dnsutil.ValidateDomainLabels(question.Name) {
		msg := pool.DefaultMessagePool.Get()
		msg.SetReply(req)
		msg.Rcode = dns.RcodeRefused

		var ede *edns.EDEOption
		if len(question.Name) > config.MaxDomainLength || !dnsutil.ValidateDomainLabels(question.Name) {
			ede = edns.NewEDEOption(edns.EDECodeInvalidData, "")
		} else {
			ede = edns.NewEDEOption(edns.EDECodeNotSupported, "")
		}
		s.addEDNS(msg, req, isSecureConnection, clientIP, nil, ede)
		return msg
	}

	startTime := time.Now()
	m := &queryMetrics{
		startTime:       startTime,
		requestProtocol: requestProtocol,
	}
	var responseMsg *dns.Msg
	defer s.recordQueryMetrics(m, &responseMsg, question)

	if s.rewriteMgr.HasRules() {
		log.Debugf("REWRITE: evaluating rules for %s qtype=%s client=%s", question.Name, dns.TypeToString[question.Qtype], clientIP)
		rewriteResult := s.rewriteMgr.Evaluate(question.Name, question.Qtype, question.Qclass, clientIP)

		if rewriteResult.ShouldRewrite {
			m.rewrote = true
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

	// Early DNS Cookie validation (RFC 7873): reject queries with an invalid
	// server cookie before spending CPU on resolution. This prevents an attacker
	// from using spoofed source IPs to amplify traffic through the resolver.
	if cookieOpt != nil && len(cookieOpt.ServerCookie) >= edns.DefaultCookieServerLen {
		if !s.ednsMgr.CookieGenerator.ValidateServerCookie(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
			log.Debugf("EDNS: bad server cookie from %s, returning BADCOOKIE", clientIP)
			msg := s.buildResponse(req)
			msg.Rcode = dns.RcodeFormatError
			// Generate a valid server cookie so the legitimate client can retry.
			serverCookie := s.ednsMgr.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
			cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
			s.ednsMgr.ApplyToMessage(msg, ecsOpt, clientRequestedDNSSEC, false, cookieStr, nil)
			responseMsg = msg
			return responseMsg
		}
	}

	if ecsOpt == nil {
		ecsOpt = s.ednsMgr.DefaultECSForQType(question.Qtype)
	}

	cacheKey := cache.BuildCacheKey(question, ecsOpt, clientRequestedDNSSEC)

	if entry, found, isExpired := s.cacheMgr.Get(cacheKey); found {
		log.Debugf("CACHE: hit key=%s expired=%t for %s, ttl=%d, validated=%t, answer=%d", cacheKey, isExpired, question.Name, entry.GetRemainingTTL(), entry.Validated, len(entry.Answer))
		m.cacheHit = true
		if !isExpired {
			responseMsg = s.processCacheHit(req, entry, false, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &m.prefetchTriggered, &m.dnssecStatus)
			return responseMsg
		}

		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			responseMsg = s.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, &m.staleServed, &m.fallbackUsed, &m.dnssecStatus)
			return responseMsg
		}

		responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &m.hadError, &m.fallbackUsed, &m.dnssecStatus)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer := s.lookupReversePTR(question, ecsOpt); len(ptrAnswer) > 0 {
			log.Debugf("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := s.buildResponse(req)
			response.Answer = ptrAnswer
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			s.applyEDNS(response, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede)
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = s.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, clientIP, isSecureConnection, &m.hadError, &m.fallbackUsed, &m.dnssecStatus)
	return responseMsg
}

func (s *Server) lookupReversePTR(question dns.Question, ecsOpt *edns.ECSOption) []dns.RR {
	ip := dnsutil.ParseReverseDNSName(question.Name)
	if ip == nil {
		return nil
	}

	if s.reverseCache == nil {
		return nil
	}

	results := s.reverseCache.ReverseLookup(ip)
	if len(results) == 0 {
		return nil
	}

	records := make([]dns.RR, 0, len(results))
	for _, result := range results {
		records = append(records, dnsutil.BuildPTRRecord(question.Name, result.Name, config.DefaultTTL, question.Qclass))
	}

	return records
}

func (s *Server) processCacheHit(req *dns.Msg, entry *cache.CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, prefetchTriggered *bool, dnssecStatus *string) *dns.Msg {
	// Record DNSSEC status for cache hits
	if entry.Validated {
		*dnssecStatus = config.DNSSECStatusSecure
	} else {
		*dnssecStatus = config.DNSSECStatusInsecure
	}

	msg := s.buildCacheResponse(req, entry, isExpired, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)

	if isExpired && entry.ShouldRefresh() {
		s.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
	}

	if !isExpired && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) && s.shouldStartPrefetch(cacheKey) {
		if prefetchTriggered != nil {
			*prefetchTriggered = true
		}
		s.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache prefetch")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			log.Debugf("CACHE: prefetch triggered for %s (threshold=%d%%)", question.Name, config.DefaultPrefetchThresholdPercent)
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

	s.prefetchCooldown.Store(cacheKey, now+config.DefaultPrefetchThrottleInterval.Nanoseconds())
	return true
}

func (s *Server) buildCacheResponse(req *dns.Msg, entry *cache.CacheEntry, isExpired bool, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
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
		s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede)
	} else {
		s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, nil)
	}

	s.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

func (s *Server) processExpiredCacheHit(req *dns.Msg, entry *cache.CacheEntry, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, cacheKey string, clientIP net.IP, isSecureConnection bool, staleServed *bool, fallbackUsed *bool, dnssecStatus *string) *dns.Msg {
	if s.config.Server.Features.Cache.PreferStale {
		if staleServed != nil {
			*staleServed = true
		}
		// Record DNSSEC status for stale cache hits
		if entry.Validated {
			*dnssecStatus = config.DNSSECStatusSecure
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
		s.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("expired cache refresh")
			ctx, cancel := context.WithTimeout(s.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return s.refreshCacheEntry(ctx, question, ecsOpt, cacheKey, entry)
		})
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
	}

	var res queryResult
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer dnsutil.HandlePanic("expired cache fallback query")
		qr := s.resolver.Query(s.ctx, question, ecsOpt)
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
			return s.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, res.answer, res.authority, res.additional, res.validated, res.ecs, res.fallback, clientIP, isSecureConnection, dnssecStatus)
		}
		if staleServed != nil {
			*staleServed = true
		}
		return s.processCacheHit(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, cacheKey, clientIP, isSecureConnection, nil, dnssecStatus)
	case <-timer.C:
		if staleServed != nil {
			*staleServed = true
		}
		// Record DNSSEC status for stale cache hit (timeout fallback)
		if entry.Validated {
			*dnssecStatus = config.DNSSECStatusSecure
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
		go func() {
			select {
			case <-done:
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
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
	}
}

func (s *Server) processCacheMiss(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, clientIP net.IP, isSecureConnection bool, hadError *bool, fallbackUsed *bool, dnssecStatus *string) *dns.Msg {
	log.Debugf("CACHE: miss key=%s for %s, querying upstream/recursive", cacheKey, question.Name)
	qr := s.resolver.Query(s.ctx, question, ecsOpt)
	if fallbackUsed != nil && qr.Fallback {
		*fallbackUsed = true
	}

	if qr.Err != nil {

		if errors.Is(qr.Err, resolver.ErrCIDRFilterRefused) {
			return s.processCIDRRefused(req, question, ecsOpt, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection)
		}
		if hadError != nil {
			*hadError = true
		}
		return s.processQueryError(req, cacheKey, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, qr.Err, dnssecStatus)
	}

	return s.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, cacheKey, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS, qr.Fallback, clientIP, isSecureConnection, dnssecStatus)
}

func (s *Server) processQueryError(req *dns.Msg, cacheKey string, question dns.Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, queryErr error, dnssecStatus *string) *dns.Msg {
	if entry, found, _ := s.cacheMgr.Get(cacheKey); found && entry.IsExpired() && entry.CanServeExpired(config.DefaultStaleMaxAge) {
		// Serving stale cache on error fallback
		if entry.Validated {
			*dnssecStatus = config.DNSSECStatusSecure
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.GetRemainingTTL(), entry.Validated)
		return s.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection)
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
	s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede)
	return msg
}

func detectRequestProtocol(w dns.ResponseWriter) string {
	addr := w.RemoteAddr()
	if addr == nil {
		return config.ProtoUDP
	}
	// Case-insensitive protocol detection without allocation:
	// check the first byte of the network string.
	network := addr.Network()
	if len(network) > 0 {
		switch network[0] {
		case 't', 'T':
			return config.ProtoTCP
		}
	}
	return config.ProtoUDP
}

func (s *Server) processCIDRRefused(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool) *dns.Msg {
	msg := s.buildResponse(req)
	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := edns.NewEDEOption(edns.EDECodeBlocked, "")
	s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede)
	return msg
}

func (s *Server) processQuerySuccess(req *dns.Msg, question dns.Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, cacheKey string, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption, skipCache bool, clientIP net.IP, isSecureConnection bool, dnssecStatus *string) *dns.Msg {
	msg := s.buildResponse(req)

	// Determine DNSSEC status for stats
	if validated {
		*dnssecStatus = config.DNSSECStatusSecure
	} else {
		// Distinguished bogus from insecure: if the recursive resolver set an
		// EDE code, validation was attempted and failed (bogus). Otherwise the
		// domain is unsigned (insecure delegation).
		if s.resolver != nil && s.resolver.Recursive() != nil && s.resolver.Recursive().DNSSECEDECode() != 0 {
			*dnssecStatus = config.DNSSECStatusBogus
		} else {
			*dnssecStatus = config.DNSSECStatusInsecure
		}
	}

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

	// When DNSSEC validation failed but enforcement is off (bogus + NOERROR),
	// include an EDE hint so clients can detect the bogus response.
	var edeOpt *edns.EDEOption
	if *dnssecStatus == config.DNSSECStatusBogus && s.resolver != nil && s.resolver.Recursive() != nil {
		if code := s.resolver.Recursive().DNSSECEDECode(); code != 0 {
			edeOpt = edns.NewEDEOption(code, "")
		}
	}
	// In upstream (forwarder) mode, pass through EDE from the upstream
	// resolver so downstream clients receive diagnostic codes (e.g. EDE 6
	// DNSSEC Bogus) instead of silently dropped EDE information.
	if edeOpt == nil && s.resolver != nil {
		if upstreamEDE := s.resolver.UpstreamEDEOption(); upstreamEDE != nil {
			edeOpt = upstreamEDE
			log.Debugf("UPSTREAM: passing through EDE %d (%s) from upstream", upstreamEDE.InfoCode, edns.EDECodeString(upstreamEDE.InfoCode))
		}
	}
	s.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, edeOpt)
	s.restoreOriginalDomain(msg, question.Name, req.Question[0].Name)
	return msg
}

func (s *Server) refreshCacheEntry(ctx context.Context, question dns.Question, ecs *edns.ECSOption, cacheKey string, _ *cache.CacheEntry) error {
	defer dnsutil.HandlePanic("cache refresh")

	if atomic.LoadInt32(&s.closed) != 0 {
		return errors.New("server closed")
	}

	// Check context before making an expensive query. The ctx is now threaded
	// through the resolver chain for proper cancellation of in-flight queries.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	qr := s.resolver.Query(ctx, question, ecs)
	if qr.Err != nil {
		return qr.Err
	}

	if !qr.Fallback {
		s.cacheMgr.Set(cacheKey, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
		if s.prober != nil {
			s.prober.Start(question, cacheKey, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
		}
	} else {
		log.Debugf("CACHE: refresh query used fallback for %s, skipping cache population", question.Name)
	}

	return nil
}

// recordQueryMetrics logs query completion and records stats. Accepts a
// pointer-to-pointer for responseMsg so the defer captures the final value
// rather than the nil it has at defer setup time.
func (s *Server) recordQueryMetrics(m *queryMetrics, responseMsg **dns.Msg, question dns.Question) {
	responseTime := time.Since(m.startTime)
	rcode := dns.RcodeServerFailure
	if *responseMsg != nil {
		rcode = (*responseMsg).Rcode
		if log.Default.Level() >= log.Debug {
			log.Debugf("Query completed: %s %s | rcode=%s | Time:%v | answer=%d, authority=%d, additional=%d, ad=%t%s",
				question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[(*responseMsg).Rcode],
				responseTime.Truncate(time.Microsecond), len((*responseMsg).Answer), len((*responseMsg).Ns),
				len((*responseMsg).Extra), (*responseMsg).AuthenticatedData,
				dnsutil.FormatRecords((*responseMsg).Answer, (*responseMsg).Ns, (*responseMsg).Extra))
		}
	}
	if s.statsMgr != nil {
		s.statsMgr.RecordRequest(responseTime, m.cacheHit, m.hadError, m.requestProtocol,
			m.rewrote, m.hijackDetected, m.staleServed, m.fallbackUsed, m.prefetchTriggered,
			m.dnssecStatus, rcode)
	}
}
