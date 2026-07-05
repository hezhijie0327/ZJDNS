package handler

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
	"zjdns/server/resolver"
)

func (h *Handler) processCacheHit(req *dns.Msg, entry *cache.Entry, isExpired bool, question Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {

	msg := h.buildCacheResponse(req, entry, isExpired, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)

	if isExpired {
		h.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache refresh")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return h.refreshCacheEntry(ctx, question, ecsOpt)
		})
	}

	if !isExpired && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) && h.shouldStartPrefetch(question.Name) {
		h.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("cache prefetch")
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
	nextAllowed, ok := h.prefetchCooldown.Load(cacheKey)
	if ok {
		if nextTs, typeOK := nextAllowed.(int64); typeOK && now < nextTs {
			return false
		}
	}

	h.prefetchCooldown.Store(cacheKey, now+config.DefaultPrefetchThrottleInterval.Nanoseconds())
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
	if h.config.Server.Features.Cache.PreferStale {
		h.cacheRefreshGroup.Go(func() error {
			defer dnsutil.HandlePanic("expired cache refresh")
			ctx, cancel := context.WithTimeout(h.cacheRefreshCtx, config.DefaultDNSQueryTimeout)
			defer cancel()
			return h.refreshCacheEntry(ctx, question, ecsOpt)
		})
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}

	var res queryResult
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer dnsutil.HandlePanic("expired cache fallback query")
		qr := h.resolver.Query(h.ctx, resolver.Question{Name: question.Name, Qtype: question.Qtype, Qclass: question.Qclass}, ecsOpt)
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
			return h.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, res.answer, res.authority, res.additional, res.validated, res.ecs, clientIP, isSecureConnection, time.Now(), "", tcpKeepaliveTimeout)
		}
		return h.processCacheHit(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	case <-timer.C:
		go func() {
			select {
			case <-done:
				if res.err != nil {
					return
				}
				log.Debugf("CACHE: background refresh completed for slow expired query %s", question.Name)
				h.cache.Set(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, res.answer, res.authority, res.additional, res.validated, cache.SetOptions{})
				if h.prober != nil {
					h.prober.Start(question.Name, question.Qtype, res.answer, res.authority, res.additional, res.validated, res.ecs)
				}
			case <-h.ctx.Done():
			}
		}()
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}
}

func (h *Handler) processCacheMiss(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, clientIP net.IP, isSecureConnection bool, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	log.Debugf("CACHE: miss for %s, querying upstream/recursive", question.Name)
	qr := h.resolver.Query(h.ctx, resolver.Question{Name: question.Name, Qtype: question.Qtype, Qclass: question.Qclass}, ecsOpt)

	if qr.Err != nil {

		if errors.Is(qr.Err, resolver.ErrCIDRFilterRefused) {
			return h.processCIDRRefused(req, question, ecsOpt, clientRequestedDNSSEC, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
		}
		return h.processQueryError(req, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, qr.Err, startTime, requestProtocol, tcpKeepaliveTimeout)
	}

	return h.processQuerySuccess(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
}

func (h *Handler) processQueryError(req *dns.Msg, question Question, clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, queryErr error, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	if entry, found, _ := h.cache.Get(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC); found && entry.IsExpired() && entry.CanServeExpired(config.DefaultStaleMaxAge) {
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d, validated=%t", question.Name, entry.RemainingTTL(), entry.Validated)
		return h.buildCacheResponse(req, entry, true, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", question.Name, dns.TypeToString[question.Qtype])
	msg := h.buildResponse(req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := edns.EDECodeNetworkError
	if h.resolver != nil && h.resolver.Recursive() != nil && h.resolver.Recursive().DNSSECEDECode() != 0 {
		edeCode = h.resolver.Recursive().DNSSECEDECode()

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
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	return msg
}

func (h *Handler) processCIDRRefused(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, clientRequestedDNSSEC bool, cookieOpt *edns.CookieOption, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {
	msg := h.buildResponse(req)
	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", question.Name, dns.TypeToString[question.Qtype])
	msg.Rcode = dns.RcodeRefused
	ede := edns.NewEDEOption(edns.EDECodeBlocked, "")
	h.applyEDNS(msg, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
	return msg
}

func (h *Handler) processQuerySuccess(req *dns.Msg, question Question, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, clientRequestedDNSSEC bool, answer, authority, additional []dns.RR, validated bool, ecsResponse *edns.ECSOption, clientIP net.IP, isSecureConnection bool, startTime time.Time, requestProtocol string, tcpKeepaliveTimeout uint16) *dns.Msg {
	msg := h.buildResponse(req)

	var dnssecStatus string
	if validated {
		dnssecStatus = config.DNSSECStatusSecure
	} else {
		if h.resolver != nil && h.resolver.Recursive() != nil && h.resolver.Recursive().DNSSECEDECode() != 0 {

		} else {
			dnssecStatus = config.DNSSECStatusInsecure
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

	log.Debugf("CACHE: populating cache for %s", question.Name)
	h.cache.Set(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, answer, authority, additional, validated, cache.SetOptions{Rcode: dns.RcodeSuccess, ResponseTime: int64(time.Since(startTime).Milliseconds())})
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
	defer dnsutil.HandlePanic("cache refresh")

	if atomic.LoadInt32(&h.closed) != 0 {
		return errors.New("server closed")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	qr := h.resolver.Query(ctx, resolver.Question{Name: question.Name, Qtype: question.Qtype, Qclass: question.Qclass}, ecs)
	if qr.Err != nil {
		return qr.Err
	}

	h.cache.Set(question.Name, question.Qtype, question.Qclass, ecs, false, qr.Answer, qr.Authority, qr.Additional, qr.Validated, cache.SetOptions{})
	if h.prober != nil {
		h.prober.Start(question.Name, question.Qtype, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.ECS)
	}

	return nil
}
