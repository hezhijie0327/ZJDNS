package handler

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

func (h *Handler) processCacheHit(req *dns.Msg, entry *cache.Entry, isExpired bool, question Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {
	msg := h.buildCacheResponse(req, entry, isExpired, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)

	if isExpired && !h.IsClosed() && h.tryStartRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt) {
		h.cacheRefreshGroup.Go(func() error {
			defer h.finishRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt)
			defer zdnsutil.HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return h.refreshCacheEntry(ctx, question, ecsOpt)
		})
	}

	if !isExpired && !h.IsClosed() && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) && h.shouldStartPrefetch(question.Name) && h.tryStartRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt) {
		h.cacheRefreshGroup.Go(func() error {
			defer h.finishRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt)
			defer zdnsutil.HandlePanic("cache prefetch")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			log.Debugf("CACHE: prefetch triggered for %s (threshold=%d%%)", question.Name, config.DefaultPrefetchThresholdPercent)
			return h.refreshCacheEntry(ctx, question, ecsOpt)
		})
	}

	return msg
}

func (h *Handler) shouldStartPrefetch(cacheKey string) bool {
	if h == nil || cacheKey == "" {
		return false
	}

	now := log.NowUnixNano()
	expireAt := now + config.DefaultPrefetchThrottleInterval.Nanoseconds()

	h.prefetchCooldownMu.RLock()
	nextAllowed, ok := h.prefetchCooldown[cacheKey]
	h.prefetchCooldownMu.RUnlock()
	if ok && now < nextAllowed {
		return false
	}

	h.prefetchCooldownMu.Lock()
	// Double-check after acquiring write lock.
	if nextAllowed2, ok2 := h.prefetchCooldown[cacheKey]; ok2 && now < nextAllowed2 {
		h.prefetchCooldownMu.Unlock()
		return false
	}
	h.prefetchCooldown[cacheKey] = expireAt
	h.prefetchCooldownMu.Unlock()
	return true
}

func (h *Handler) buildCacheResponse(req *dns.Msg, entry *cache.Entry, isExpired bool, question Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {
	msg := h.buildResponse(req)

	responseTTL := entry.RemainingTTL()

	if isExpired {
		// Stale: set all RR TTLs directly to the cyclical stale countdown.
		msg.Answer = cache.ProcessRecords(entry.Answer, int64(responseTTL), false, clientRequestedDNSSEC)
		msg.Ns = cache.ProcessRecords(entry.Authority, int64(responseTTL), false, clientRequestedDNSSEC)
		msg.Extra = cache.ProcessRecords(entry.Additional, int64(responseTTL), false, clientRequestedDNSSEC)
	} else {
		// Fresh: subtract actual elapsed time from each RR's original TTL.
		elapsed := ttl.Elapsed(entry.Timestamp)
		msg.Answer = cache.ProcessRecords(entry.Answer, elapsed, true, clientRequestedDNSSEC)
		msg.Ns = cache.ProcessRecords(entry.Authority, elapsed, true, clientRequestedDNSSEC)
		msg.Extra = cache.ProcessRecords(entry.Additional, elapsed, true, clientRequestedDNSSEC)
	}

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	if isExpired {
		ede := edns.NewEDEOption(edns.EDECodeStaleAnswer, "")
		h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	} else {
		h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, nil, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	}

	h.restoreOriginalDomain(msg, question.Name, req.Question[0].Header().Name)
	return msg
}

func (h *Handler) processExpiredCacheHit(req *dns.Msg, entry *cache.Entry, question Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {
	if h.config.Server.Features.Cache.PreferStale && !h.IsClosed() {
		if h.tryStartRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt) {
			h.cacheRefreshGroup.Go(func() error {
				defer h.finishRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt)
				defer zdnsutil.HandlePanic("expired cache refresh")
				ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
				defer cancel()
				return h.refreshCacheEntry(ctx, question, ecsOpt)
			})
		}
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}

	var qr *resolver.QueryResult
	done := make(chan struct{})
	refreshed := !h.IsClosed() && h.tryStartRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt)
	if !refreshed {
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}
	go func() {
		defer close(done)
		defer h.finishRefresh(question.Name, question.Qtype, question.Qclass, ecsOpt)
		defer zdnsutil.HandlePanic("expired cache fallback query")
		qr = h.resolver.Query(h.ctx, question, ecsOpt)
	}()

	timer := time.NewTimer(config.DefaultServeExpiredClientTimeout)
	defer timer.Stop()

	select {
	case <-done:
		if qr.Err == nil {
			return h.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS, clientIP, isSecureConnection, qr.Server, qr.Fallback, qr.Hijack, qr.Cacheable, time.Now(), "", tcpKeepaliveTimeout)
		}
		return h.processCacheHit(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	case <-timer.C:
		go func() {
			select {
			case <-done:
				if qr.Err != nil {
					return
				}
				log.Debugf("CACHE: background refresh completed for slow expired query %s", question.Name)
				if qr.Cacheable {
					h.cache.Set(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, qr.Answer, qr.Authority, qr.Additional, qr.Validated)
				}
				if h.prober != nil {
					h.prober.Start(question.Name, question.Qtype, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
				}
			case <-h.ctx.Done():
			}
		}()
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}
}

func (h *Handler) processCacheMiss(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, clientIP net.IP, isSecureConnection bool, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	// Guard against calling before SetResolver (two-phase initialization).
	if h.resolver == nil {
		msg := h.buildResponse(req)
		msg.Rcode = dns.RcodeServerFailure
		log.Warnf("CACHE: resolver not set — returning SERVFAIL for %s", question.Name)
		return msg
	}

	// Deduplicate concurrent identical queries.  If another goroutine is
	// already resolving the same (qname, qtype, qclass, ECS, DNSSEC), wait
	// for its result instead of sending a duplicate upstream query.
	if h.pending != nil {
		if qr, follower := h.pending.Join(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC); follower {
			return h.processCacheMissResult(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout, qr)
		}
	}

	log.Debugf("CACHE: miss for %s, querying upstream/recursive", question.Name)
	qr := h.resolver.Query(h.ctx, question, ecsOpt)

	// DNS64: if AAAA query returned no records, try synthesizing from A.
	if h.dns64 != nil && question.Qtype == dns.TypeAAAA &&
		qr.Err == nil && len(qr.Answer) == 0 {
		aQuestion := Question{Name: question.Name, Qtype: dns.TypeA, Qclass: question.Qclass}
		aqr := h.resolver.Query(h.ctx, aQuestion, ecsOpt)
		if aqr.Err == nil && len(aqr.Answer) > 0 {
			qr.Answer, qr.Authority, qr.Additional = h.dns64.Synthesize(
				qr.Answer, qr.Authority, qr.Additional,
				aqr.Answer, aqr.Authority, aqr.Additional, qr.Validated)
			log.Debugf("DNS64: synthesized %d AAAA records for %s", len(qr.Answer), question.Name)
		}
	}

	// Notify any followers that joined during this query.
	if h.pending != nil {
		h.pending.Done(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, qr)
	}

	return h.processCacheMissResult(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout, qr)
}

func (h *Handler) processCacheMissResult(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, clientIP net.IP, isSecureConnection bool, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16, qr *resolver.QueryResult) *dns.Msg {
	if qr.Err != nil {
		if errors.Is(qr.Err, resolver.ErrCIDRFilterRefused) {
			return h.processCIDRRefused(req, question, ecsOpt, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
		}
		return h.processQueryError(req, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, qr.Err, startTime, requestProtocol, tcpKeepaliveTimeout)
	}

	return h.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS, clientIP, isSecureConnection, qr.Server, qr.Fallback, qr.Hijack, qr.Cacheable, startTime, requestProtocol, tcpKeepaliveTimeout)
}

func (h *Handler) processQueryError(req *dns.Msg, question Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, queryErr error, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	if entry, found, _ := h.cache.Get(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC); found && entry.IsExpired() && entry.CanServeExpired(config.DefaultStaleMaxAge) {
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.RemainingTTL(), entry.Validated)
		h.cache.RecordRequest(&cache.RequestRecord{
			Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
			ECS: ecsOpt, DNSSECOK: clientRequestedDNSSEC,
			Protocol: requestProtocol, Result: "error", Rcode: dns.RcodeServerFailure,
			ResponseTime: time.Since(startTime).Milliseconds(),
		})
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", question.Name, dns.TypeToString[question.Qtype])
	msg := h.buildResponse(req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := edns.EDECodeNetworkError
	dnssecStatus := ""
	if h.resolver != nil && h.resolver.Recursive() != nil && h.resolver.Recursive().DNSSECEDECode() != 0 {
		edeCode = h.resolver.Recursive().DNSSECEDECode()
		dnssecStatus = config.DNSSECStatusBogus

		log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
	} else {
		var dnsErr *resolver.DNSSECError
		if errors.As(queryErr, &dnsErr) {
			edeCode = dnsErr.EDECode
			dnssecStatus = config.DNSSECStatusBogus

			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		} else if queryErr != nil {
			log.Debugf("RESULT: non-DNSSEC error, using EDE %d: %v", edeCode, queryErr)
		}
	}

	h.cache.RecordRequest(&cache.RequestRecord{
		Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
		ECS: ecsOpt, DNSSECOK: clientRequestedDNSSEC,
		Protocol: requestProtocol, Result: "error", Rcode: dns.RcodeServerFailure,
		ResponseTime: time.Since(startTime).Milliseconds(),
		DNSSECStatus: dnssecStatus,
	})
	ede := edns.NewEDEOption(edeCode, "")
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	return msg
}

func (h *Handler) processCIDRRefused(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	msg := h.buildResponse(req)
	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := edns.NewEDEOption(edns.EDECodeBlocked, "")
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	h.cache.RecordRequest(&cache.RequestRecord{
		Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
		ECS: ecsOpt, DNSSECOK: clientRequestedDNSSEC,
		Protocol: requestProtocol, Result: "blocked", Rcode: dns.RcodeRefused,
		ResponseTime: time.Since(startTime).Milliseconds(),
	})
	return msg
}

func (h *Handler) processQuerySuccess(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption, clientIP net.IP, isSecureConnection bool, server string, fallback, hijack, cacheable bool, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	msg := h.buildResponse(req)

	var dnssecStatus string
	switch {
	case validated:
		dnssecStatus = config.DNSSECStatusSecure
	case h.resolver != nil && h.resolver.Recursive() != nil && h.resolver.Recursive().DNSSECEDECode() != 0:
		dnssecStatus = config.DNSSECStatusBogus
	default:
		dnssecStatus = config.DNSSECStatusInsecure
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
			Address:      copyIP(ecsOpt.Address),
		}
	}

	if cacheable {
		log.Debugf("CACHE: populating cache for %s", question.Name)
		h.cache.Set(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, answer, authority, additional, validated)
	}
	h.cache.RecordRequest(&cache.RequestRecord{
		Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
		ECS: ecsOpt, DNSSECOK: clientRequestedDNSSEC,
		Protocol: requestProtocol, Result: "miss", ResponseTime: time.Since(startTime).Milliseconds(),
		Rcode: dns.RcodeSuccess, Server: server, Hijack: hijack, Fallback: fallback,
		DNSSECStatus: dnssecStatus,
	})
	if h.prober != nil {
		h.prober.Start(question.Name, question.Qtype, answer, authority, additional, validated, responseECS)
	}

	msg.Answer = cache.ProcessRecords(answer, 0, false, clientRequestedDNSSEC)
	msg.Ns = cache.ProcessRecords(authority, 0, false, clientRequestedDNSSEC)
	msg.Extra = cache.ProcessRecords(additional, 0, false, clientRequestedDNSSEC)

	log.Debugf("RESULT: %s %s | rcode=NOERROR, answer=%d, authority=%d, additional=%d, validated=%t, ecs=%t", question.Name, dns.TypeToString[question.Qtype], len(answer), len(authority), len(additional), validated, responseECS != nil)
	log.Debugf("CACHE: served response for %s ", question.Name)

	var edeOpt *edns.EDEOption
	if dnssecStatus == config.DNSSECStatusBogus && h.resolver != nil && h.resolver.Recursive() != nil {
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
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, edeOpt, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	h.restoreOriginalDomain(msg, question.Name, req.Question[0].Header().Name)
	return msg
}

func (h *Handler) refreshCacheEntry(ctx context.Context, question Question, ecs *edns.ECSOption) error {
	defer zdnsutil.HandlePanic("cache refresh")

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

	if qr.Cacheable {
		h.cache.Set(question.Name, question.Qtype, question.Qclass, ecs, false, qr.Answer, qr.Authority, qr.Additional, qr.Validated)
	}
	if h.prober != nil {
		h.prober.Start(question.Name, question.Qtype, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
	}

	return nil
}

// tryStartRefresh builds a pendingKey from the given parameters and attempts
// to register a cache refresh. Returns true if the caller should proceed
// (leader), false if a refresh is already in flight. All refresh paths use
// dnssecOK=false since refreshCacheEntry always caches with dnssecOK=false.
func (h *Handler) tryStartRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if h.pendingRefreshes == nil {
		return true
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	if !h.pendingRefreshes.Start(key) {
		log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		return false
	}
	return true
}

// finishRefresh removes the pending refresh key after the refresh goroutine
// completes (whether success or failure).
func (h *Handler) finishRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if h.pendingRefreshes == nil {
		return
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	h.pendingRefreshes.Done(key)
}

// copyIP returns a deep copy of ip, allocating a new backing array for the
// net.IP byte slice to prevent mutation of the original by downstream consumers.
func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}
