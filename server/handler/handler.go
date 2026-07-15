// Package handler provides the DNS query processing pipeline: cache lookup,
// zone evaluation, upstream/recursive resolution, and DNSSEC validation.
package handler

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dns64"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"
	"zjdns/server/resolver"
	"zjdns/zone"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

// Question is a type alias for resolver.Question to avoid duplicate definitions
// and conversion overhead at the handler↔resolver boundary.  The resolver owns the
// canonical Question type; the handler reuses it via this alias.
type Question = resolver.Question

// Resolver is the interface for DNS query resolution, defined in the consumer
// package so the handler depends on an abstraction rather than a concrete type.
type Resolver interface {
	Query(ctx context.Context, question Question, ecs *edns.ECSOption) *resolver.QueryResult
	DNSSECEDECode() uint16
	UpstreamEDEOption() *edns.EDEOption
	UpstreamServers() []*config.UpstreamServer
}

// LatencyProber is the interface for latency-probing cache entries after
// successful resolution.
type LatencyProber interface {
	Start(qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	Close()
}

// Handler processes DNS queries through the caching and resolution pipeline.
type Handler struct {
	closed int32 // hot-path: checked on every query via atomic load

	config             *config.ServerConfig
	cache              cache.Store
	edns               *edns.Handler
	zoneEvaluator      *zone.Evaluator
	tagMatcher         func(qname string, ip net.IP) map[string]bool // rule tag lookup for zone/upstream
	resolver           Resolver
	prober             LatencyProber
	dns64              *dns64.Synthesizer
	prefetchCooldown   map[string]int64
	prefetchCooldownMu sync.RWMutex
	cacheRefreshGroup  *errgroup.Group
	cacheRefreshCtx    context.Context
	ctx                context.Context
	pending            *PendingRequests
	pendingRefreshes   *pending.Group[pendingKey]
}

// BackgroundConfig groups lifecycle-related dependencies that the Handler
// uses for cache refresh scheduling and graceful shutdown coordination.
type BackgroundConfig struct {
	RefreshGroup *errgroup.Group
	RefreshCtx   context.Context
	Ctx          context.Context
}

// New creates a Handler with the given dependencies. The resolver and prober
// are set later via SetResolver / SetProber after they are constructed.
func New(
	cfg *config.ServerConfig,
	cacheStore cache.Store,
	ednsHandler *edns.Handler,
	zoneEval *zone.Evaluator,
	bg BackgroundConfig,
) *Handler {
	h := &Handler{
		config:            cfg,
		cache:             cacheStore,
		edns:              ednsHandler,
		zoneEvaluator:     zoneEval,
		prefetchCooldown:  make(map[string]int64),
		pending:           NewPendingRequests(),
		pendingRefreshes:  pending.NewGroup[pendingKey](),
		cacheRefreshGroup: bg.RefreshGroup,
		cacheRefreshCtx:   bg.RefreshCtx,
		ctx:               bg.Ctx,
	}
	// Initialize DNS64 synthesizer.
	if cfg.Server.Features.DNS64 != nil && cfg.Server.Features.DNS64.Prefix != "" {
		synth, err := dns64.New(cfg.Server.Features.DNS64.Prefix)
		if err != nil {
			log.Warnf("DNS64: %v, using default prefix", err)
			synth, _ = dns64.New(config.DefaultDNS64Prefix)
		}
		h.dns64 = synth
		log.Infof("DNS64: enabled with prefix %s", h.dns64.Prefix())
	}
	return h
}

// SetResolver sets the resolver after construction (two-phase init).
func (h *Handler) SetResolver(r Resolver) { h.resolver = r }

// SetProber sets the latency prober after construction.
func (h *Handler) SetProber(p LatencyProber) { h.prober = p }

// SetTagMatcher sets the CIDR tag matching function for zone bypass checks.
func (h *Handler) SetTagMatcher(fn func(qname string, ip net.IP) map[string]bool) { h.tagMatcher = fn }

// Prober returns the latency prober (for lifecycle cleanup).
func (h *Handler) Prober() LatencyProber { return h.prober }

// IsClosed reports whether the handler has been shut down.
func (h *Handler) IsClosed() bool { return atomic.LoadInt32(&h.closed) != 0 }

// MarkClosed signals the handler to stop accepting new work.
func (h *Handler) MarkClosed() { atomic.StoreInt32(&h.closed, 1) }

// Edns returns the EDNS handler.
func (h *Handler) Edns() *edns.Handler { return h.edns }

// CacheStore returns the cache store (used for persistence and shutdown).
func (h *Handler) CacheStore() cache.Store { return h.cache }

// CleanupPrefetchCooldown removes stale entries from the prefetch cooldown map.
// Entries with timestamp < now are evicted.
func (h *Handler) CleanupPrefetchCooldown(now int64) {
	h.prefetchCooldownMu.Lock()
	for key, ts := range h.prefetchCooldown {
		if now > ts {
			delete(h.prefetchCooldown, key)
		}
	}
	h.prefetchCooldownMu.Unlock()
}

// UpstreamServers returns the configured upstream servers.
func (h *Handler) UpstreamServers() []*config.UpstreamServer { return h.resolver.UpstreamServers() }

// CacheRefreshGroup returns the errgroup for cache refresh goroutines.
func (h *Handler) CacheRefreshGroup() *errgroup.Group { return h.cacheRefreshGroup }

// ServeDNS handles an incoming DNS query from any protocol listener (plain
// UDP/TCP or encrypted DoT/DoQ/DoH/DoH3/DNSCrypt).
func (h *Handler) ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg {
	return h.processDNSQuery(req, clientIP, isSecure, protocol)
}

// BuildQueryMessage constructs an outbound DNS query message for the resolver.
func (h *Handler) BuildQueryMessage(question Question, ecs *edns.ECSOption, recursionDesired, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	dnsutil.SetQuestion(msg, dnsutil.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if h.edns != nil {
		h.edns.ApplyToMessage(msg, ecs, isSecureConnection, "", nil, true, true, 0)
	}

	return msg
}

func (h *Handler) processDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool, requestProtocol string) *dns.Msg {
	if atomic.LoadInt32(&h.closed) != 0 {
		msg := h.buildResponse(req)
		msg.Rcode = dns.RcodeServerFailure
		h.cache.RecordRequest(&cache.RequestRecord{
			Result: "error", Protocol: requestProtocol, Rcode: dns.RcodeServerFailure,
		})
		return msg
	}

	if req == nil || len(req.Question) == 0 {
		msg := pool.DefaultMessagePool.Get()
		if req != nil {
			dnsutil.SetReply(msg, req)
		} else {
			msg.Response = true
		}
		msg.Rcode = dns.RcodeFormatError
		h.cache.RecordRequest(&cache.RequestRecord{
			Result: "error", Protocol: requestProtocol, Rcode: dns.RcodeFormatError,
		})
		return msg
	}

	question := Question{
		Name:   req.Question[0].Header().Name,
		Qtype:  dns.RRToType(req.Question[0]),
		Qclass: req.Question[0].Header().Class,
	}

	if log.IsDebug() {
		if clientIP != nil {
			log.Debugf("QUERY: client IP=%s query=%s type=%s", clientIP.String(), question.Name, dns.TypeToString[question.Qtype])
		} else {
			log.Debugf("QUERY: client IP=<unknown> query=%s type=%s", question.Name, dns.TypeToString[question.Qtype])
		}
	}

	tcpKeepaliveTimeout := tcpKeepaliveTimeoutForProtocol(requestProtocol)

	if resp := h.validateDNSQuery(req, &question, clientIP, isSecureConnection, tcpKeepaliveTimeout); resp != nil {
		h.cache.RecordRequest(&cache.RequestRecord{
			Result: "error", Protocol: requestProtocol, Rcode: int(resp.Rcode),
		})
		return resp
	}

	startTime := time.Now()
	var responseMsg *dns.Msg
	defer func() {
		if responseMsg != nil && log.IsDebug() {
			log.Debugf("RESULT: %s %s | rcode=%s time=%v answer=%d authority=%d additional=%d ad=%t%s",
				question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[responseMsg.Rcode],
				time.Since(startTime).Truncate(time.Microsecond), len(responseMsg.Answer), len(responseMsg.Ns),
				len(responseMsg.Extra), responseMsg.AuthenticatedData,
				zdnsutil.FormatRecords(responseMsg.Answer, responseMsg.Ns, responseMsg.Extra))
		}
	}()

	if resp, done := h.processZone(req, &question, clientIP, isSecureConnection, requestProtocol, tcpKeepaliveTimeout); done {
		responseMsg = resp
		return responseMsg
	}

	clientRequestedDNSSEC, ecsOpt, cookieOpt, resp := h.parseEDNSAndCookie(req, &question, clientIP, requestProtocol, tcpKeepaliveTimeout)
	if resp != nil {
		responseMsg = resp
		return responseMsg
	}

	if entry, found, isExpired := h.cache.Get(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC); found {
		log.Debugf("CACHE: hit expired=%t for %s, ttl=%d, validated=%t, answer=%d", isExpired, question.Name, entry.RemainingTTL(), entry.Validated, len(entry.Answer))
		if !isExpired {
			responseMsg = h.processCacheHit(req, entry, false, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
			h.cache.RecordRequest(&cache.RequestRecord{
				Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
				Protocol: requestProtocol, Result: "hit", Rcode: dns.RcodeSuccess,
				ResponseTime: time.Since(startTime).Milliseconds(),
				EntryID:      entry.ID,
			})
			return responseMsg
		}

		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			responseMsg = h.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
			h.cache.RecordRequest(&cache.RequestRecord{
				Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
				Protocol: requestProtocol, Result: "stale", Rcode: dns.RcodeSuccess,
				ResponseTime: time.Since(startTime).Milliseconds(),
				EntryID:      entry.ID,
			})
			return responseMsg
		}

		responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer, entryIDs := h.lookupReversePTR(question); len(ptrAnswer) > 0 {
			log.Debugf("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := h.buildResponse(req)
			response.Answer = ptrAnswer
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			h.applyEDNS(response, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
			entryID := int64(0)
			if len(entryIDs) > 0 {
				entryID = entryIDs[0]
			}
			h.cache.RecordRequest(&cache.RequestRecord{
				Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
				ECS: ecsOpt, DNSSECOK: clientRequestedDNSSEC,
				Protocol: requestProtocol, Result: "hit", Rcode: dns.RcodeSuccess,
				ResponseTime: time.Since(startTime).Milliseconds(),
				EntryID:      entryID,
			})
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
	return responseMsg
}

// parseEDNSAndCookie unpacks EDNS options, extracts ECS and Cookie, and validates
// the server cookie early (RFC 7873). Returns a non-nil *dns.Msg when the request
// should be rejected with BADCOOKIE.
func (h *Handler) parseEDNSAndCookie(req *dns.Msg, question *Question, clientIP net.IP, requestProtocol string, tcpKeepaliveTimeout uint16) (clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, reject *dns.Msg) {
	// Force a full unpack so EDNS flags (DO bit, ECS) are available.
	// edns handler is always set by the constructor — no nil check needed.
	req.Options = 0
	_ = req.Unpack()

	clientRequestedDNSSEC = req.Security
	ecsOpt = h.edns.ParseFromDNS(req)
	cookieOpt = h.edns.ParseCookie(req)

	// Early DNS Cookie validation (RFC 7873).
	//
	// Three cases for the ServerCookie length:
	//   0 bytes  — initial handshake, no cookie to validate (allow through)
	//   1-15     — truncated/tampered, reject with BADCOOKIE
	//   16 bytes — normal, validate cryptographically
	if cookieOpt != nil && len(cookieOpt.ServerCookie) > 0 && len(cookieOpt.ServerCookie) < edns.DefaultCookieServerLen {
		log.Debugf("EDNS: short server cookie (%d bytes) from %s, returning BADCOOKIE", len(cookieOpt.ServerCookie), clientIP)
		msg := h.buildResponse(req)
		msg.Rcode = dns.RcodeFormatError
		serverCookie := h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
		h.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
		h.cache.RecordRequest(&cache.RequestRecord{
			Result: "badcookie", Protocol: requestProtocol, Rcode: dns.RcodeFormatError,
		})
		return false, nil, nil, msg
	}
	if cookieOpt != nil && len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen {
		status := h.edns.CookieGenerator.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie)
		if status == edns.CookieExpired || status == edns.CookieFuture || status == edns.CookieInvalid {
			log.Debugf("EDNS: bad server cookie (status=%d) from %s, returning BADCOOKIE", status, clientIP)
			msg := h.buildResponse(req)
			msg.Rcode = dns.RcodeFormatError
			serverCookie := h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
			cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
			h.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
			h.cache.RecordRequest(&cache.RequestRecord{
				Result: "badcookie", Protocol: requestProtocol, Rcode: dns.RcodeFormatError,
			})
			return false, nil, nil, msg
		}
	}

	if ecsOpt == nil {
		ecsOpt = h.edns.ECSForQType(question.Qtype)
	}
	return clientRequestedDNSSEC, ecsOpt, cookieOpt, nil
}

func (h *Handler) lookupReversePTR(question Question) (records []dns.RR, entryIDs []int64) {
	ip := zdnsutil.ParseReverseDNSName(question.Name)
	if ip == nil {
		return nil, nil
	}

	results := h.cache.ReverseLookup(ip.String())
	if len(results) == 0 {
		return nil, nil
	}

	records = make([]dns.RR, 0, len(results))
	entryIDs = make([]int64, 0, len(results))
	for _, result := range results {
		records = append(records, zdnsutil.NewPTRRecord(question.Name, result.Name, result.TTL, question.Qclass))
		entryIDs = append(entryIDs, result.EntryID)
	}

	return records, entryIDs
}

// validateDNSQuery rejects queries with invalid domain names, label lengths,
// or unsupported query types (ANY, AXFR, IXFR). Returns nil if the query is valid.
func (h *Handler) validateDNSQuery(req *dns.Msg, question *Question, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {
	if len(question.Name) <= config.MaxDomainLength && question.Qtype != dns.TypeANY &&
		question.Qtype != dns.TypeAXFR && question.Qtype != dns.TypeIXFR &&
		zdnsutil.IsValidDomainLabels(question.Name) {
		return nil
	}
	msg := pool.DefaultMessagePool.Get()
	dnsutil.SetReply(msg, req)
	msg.Rcode = dns.RcodeRefused

	var ede *edns.EDEOption
	if len(question.Name) > config.MaxDomainLength || !zdnsutil.IsValidDomainLabels(question.Name) {
		ede = edns.NewEDEOption(edns.EDECodeInvalidData, "")
	} else {
		ede = edns.NewEDEOption(edns.EDECodeNotSupported, "")
	}
	h.addEDNS(msg, req, isSecureConnection, clientIP, nil, ede, tcpKeepaliveTimeout)
	return msg
}

// processZone evaluates zone rules and returns a synthetic response if a rule
// matches. The caller must return the response immediately when done=true.
func (h *Handler) processZone(req *dns.Msg, question *Question, clientIP net.IP, isSecureConnection bool, requestProtocol string, tcpKeepaliveTimeout uint16) (*dns.Msg, bool) {
	if !h.zoneEvaluator.HasRules() {
		return nil, false
	}
	log.Debugf("ZONE: evaluating rules for %s qtype=%s client=%s", question.Name, dns.TypeToString[question.Qtype], clientIP)

	var matchedTags map[string]bool
	if h.tagMatcher != nil {
		matchedTags = h.tagMatcher(question.Name, clientIP)
	}
	if h.zoneEvaluator.Bypass(matchedTags) {
		return nil, false
	}
	zoneResult := h.zoneEvaluator.Evaluate(question.Name, question.Qtype, question.Qclass, matchedTags)
	if !zoneResult.Matched {
		return nil, false
	}

	log.Debugf("ZONE: matched rule for %s -> domain=%s rcode=%d answer=%d authority=%d additional=%d",
		question.Name, zoneResult.Domain, zoneResult.Rcode, len(zoneResult.Answer), len(zoneResult.Authority), len(zoneResult.Additional))

	h.cache.RecordRequest(&cache.RequestRecord{
		Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
		Protocol: requestProtocol, Result: "zone", Rcode: zoneResult.Rcode,
	})

	if zoneResult.Rcode != dns.RcodeSuccess {
		log.Debugf("RESULT: %s %s | rcode=%s, blocked by zone rule", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[uint16(zoneResult.Rcode)]) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
		response := h.buildResponse(req)
		response.Rcode = uint16(zoneResult.Rcode) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
		if len(zoneResult.Authority) > 0 || len(zoneResult.Additional) > 0 {
			elapsed := ttl.Elapsed(zoneResult.CreatedAt)
			response.Ns = ttl.DeductElapsedCyclical(zoneResult.Authority, elapsed)
			response.Extra = ttl.DeductElapsedCyclical(zoneResult.Additional, elapsed)
		}
		ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
		h.addEDNS(response, req, isSecureConnection, clientIP, nil, ede, tcpKeepaliveTimeout)
		return response, true
	}

	hasRecords := len(zoneResult.Answer) > 0 || len(zoneResult.Authority) > 0 || len(zoneResult.Additional) > 0
	if hasRecords {
		elapsed := ttl.Elapsed(zoneResult.CreatedAt)
		response := h.buildResponse(req)
		response.Answer = ttl.DeductElapsedCyclical(zoneResult.Answer, elapsed)
		response.Ns = ttl.DeductElapsedCyclical(zoneResult.Authority, elapsed)
		response.Extra = ttl.DeductElapsedCyclical(zoneResult.Additional, elapsed)
		response.Rcode = dns.RcodeSuccess
		ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
		h.addEDNS(response, req, isSecureConnection, clientIP, nil, ede, tcpKeepaliveTimeout)
		log.Debugf("RESULT: %s %s | rcode=NOERROR (zone), answer=%d authority=%d additional=%d",
			question.Name, dns.TypeToString[question.Qtype], len(zoneResult.Answer), len(zoneResult.Authority), len(zoneResult.Additional))
		return response, true
	}

	if zoneResult.Domain != question.Name {
		question.Name = zoneResult.Domain
	}
	return nil, false
}

// tcpKeepaliveTimeoutForProtocol returns the EDNS TCP Keepalive timeout value
// (in 100ms units, RFC 7828) for responses sent over the given protocol.
// Returns 0 for protocols where TCP keepalive is not applicable (UDP, DoH, DoQ).
func tcpKeepaliveTimeoutForProtocol(protocol string) uint16 {
	switch protocol {
	case config.ProtoTCP, config.ProtoTLS:
		return uint16(config.DefaultEDNSTCPKeepaliveTimeout)
	default:
		return 0
	}
}
