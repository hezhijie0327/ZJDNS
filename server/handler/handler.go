// Package handler provides the DNS query processing pipeline: cache lookup,
// rewrite evaluation, upstream/recursive resolution, and DNSSEC validation.
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
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"
	"zjdns/rewrite"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"
)

// Question is a type alias for resolver.Question to avoid duplicate definitions.
type Question = resolver.Question

// LatencyProber is the interface for latency-probing cache entries after
// successful resolution.
type LatencyProber interface {
	Start(qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	Close()
}

// Handler processes DNS queries through the caching and resolution pipeline.
type Handler struct {
	closed int32 // hot-path: checked on every query via atomic load

	config       *config.ServerConfig
	cache        cache.Store
	reverseCache interface {
		ReverseLookup(string) []cache.LookupResult
	}
	edns               *edns.Handler
	rewrite            *rewrite.Evaluator
	resolver           *resolver.Resolver
	prober             LatencyProber
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

// queryResult holds the result of a resolver query for stale-cache fallback.
type queryResult struct {
	answer     []dns.RR
	authority  []dns.RR
	additional []dns.RR
	validated  bool
	ecs        *edns.ECSOption
	server     string
	fallback   bool
	hijack     bool
	err        error
}

// New creates a Handler with the given dependencies. The resolver and prober
// are set later via SetResolver / SetProber after they are constructed.
func New(
	cfg *config.ServerConfig,
	cacheStore cache.Store,
	ednsHandler *edns.Handler,
	rewriteEvaluator *rewrite.Evaluator,
	bg BackgroundConfig,
) *Handler {
	h := &Handler{
		config:            cfg,
		cache:             cacheStore,
		edns:              ednsHandler,
		rewrite:           rewriteEvaluator,
		prefetchCooldown:  make(map[string]int64),
		pending:           NewPendingRequests(),
		pendingRefreshes:  pending.NewGroup[pendingKey](),
		cacheRefreshGroup: bg.RefreshGroup,
		cacheRefreshCtx:   bg.RefreshCtx,
		ctx:               bg.Ctx,
	}
	h.reverseCache, _ = cacheStore.(interface {
		ReverseLookup(string) []cache.LookupResult
	})
	return h
}

// SetResolver sets the resolver after construction (two-phase init).
func (h *Handler) SetResolver(r *resolver.Resolver) { h.resolver = r }

// SetProber sets the latency prober after construction.
func (h *Handler) SetProber(p LatencyProber) { h.prober = p }

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

// Resolver returns the DNS resolver.
func (h *Handler) Resolver() *resolver.Resolver { return h.resolver }

// HasRewriteRules reports whether rewrite rules are configured.
func (h *Handler) HasRewriteRules() bool { return h.rewrite != nil && h.rewrite.HasRules() }

// PrefetchCooldown returns the prefetch throttle map and its mutex
// (used by background cleanup).
func (h *Handler) PrefetchCooldown() (map[string]int64, *sync.RWMutex) {
	return h.prefetchCooldown, &h.prefetchCooldownMu
}

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
		return resp
	}

	startTime := time.Now()
	var responseMsg *dns.Msg
	defer func() {
		if responseMsg != nil && log.Default.Level() >= log.Debug {
			log.Debugf("RESULT: %s %s | rcode=%s time=%v answer=%d authority=%d additional=%d ad=%t%s",
				question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[responseMsg.Rcode],
				time.Since(startTime).Truncate(time.Microsecond), len(responseMsg.Answer), len(responseMsg.Ns),
				len(responseMsg.Extra), responseMsg.AuthenticatedData,
				zdnsutil.FormatRecords(responseMsg.Answer, responseMsg.Ns, responseMsg.Extra))
		}
	}()

	if resp, done := h.processRewrite(req, &question, clientIP, isSecureConnection, tcpKeepaliveTimeout); done {
		responseMsg = resp
		return responseMsg
	}

	clientRequestedDNSSEC, ecsOpt, cookieOpt, resp := h.parseEDNSAndCookie(req, &question, clientIP, tcpKeepaliveTimeout)
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
			})
			return responseMsg
		}

		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			responseMsg = h.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
			h.cache.RecordRequest(&cache.RequestRecord{
				Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
				Protocol: requestProtocol, Result: "stale", Rcode: dns.RcodeSuccess,
				ResponseTime: time.Since(startTime).Milliseconds(),
			})
			return responseMsg
		}

		responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer := h.lookupReversePTR(question); len(ptrAnswer) > 0 {
			log.Debugf("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := h.buildResponse(req)
			response.Answer = ptrAnswer
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			h.applyEDNS(response, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
			h.cache.RecordRequest(&cache.RequestRecord{
				Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
				ECS: ecsOpt, DNSSECOK: clientRequestedDNSSEC,
				Protocol: requestProtocol, Result: "hit", Rcode: dns.RcodeSuccess,
				ResponseTime: time.Since(startTime).Milliseconds(),
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
func (h *Handler) parseEDNSAndCookie(req *dns.Msg, question *Question, clientIP net.IP, tcpKeepaliveTimeout uint16) (clientRequestedDNSSEC bool, ecsOpt *edns.ECSOption, cookieOpt *edns.CookieOption, reject *dns.Msg) {
	// Force a full unpack so EDNS flags (DO bit, ECS) are available.
	req.Options = 0
	if h.edns != nil {
		_ = req.Unpack()
	}

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
		return false, nil, nil, msg
	}
	if cookieOpt != nil && len(cookieOpt.ServerCookie) == edns.DefaultCookieServerLen && !h.edns.CookieGenerator.IsServerCookieValid(clientIP, cookieOpt.ClientCookie, cookieOpt.ServerCookie) {
		log.Debugf("EDNS: bad server cookie from %s, returning BADCOOKIE", clientIP)
		msg := h.buildResponse(req)
		msg.Rcode = dns.RcodeFormatError
		serverCookie := h.edns.CookieGenerator.GenerateServerCookie(clientIP, cookieOpt.ClientCookie)
		cookieStr := edns.BuildCookieResponse(cookieOpt.ClientCookie, serverCookie)
		h.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
		return false, nil, nil, msg
	}

	if ecsOpt == nil {
		ecsOpt = h.edns.ECSForQType(question.Qtype)
	}
	return clientRequestedDNSSEC, ecsOpt, cookieOpt, nil
}

func (h *Handler) lookupReversePTR(question Question) []dns.RR {
	ip := zdnsutil.ParseReverseDNSName(question.Name)
	if ip == nil {
		return nil
	}

	if h.reverseCache == nil {
		return nil
	}

	results := h.reverseCache.ReverseLookup(ip.String())
	if len(results) == 0 {
		return nil
	}

	records := make([]dns.RR, 0, len(results))
	for _, result := range results {
		records = append(records, zdnsutil.NewPTRRecord(question.Name, result.Name, result.TTL, question.Qclass))
	}

	return records
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

// processRewrite evaluates rewrite rules and returns a synthetic response if
// a rule matches. The caller must return the response immediately when done=true.
func (h *Handler) processRewrite(req *dns.Msg, question *Question, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) (*dns.Msg, bool) {
	if !h.rewrite.HasRules() {
		return nil, false
	}
	log.Debugf("REWRITE: evaluating rules for %s qtype=%s client=%s", question.Name, dns.TypeToString[question.Qtype], clientIP)
	rewriteResult := h.rewrite.Evaluate(question.Name, question.Qtype, question.Qclass, clientIP)
	if !rewriteResult.ShouldRewrite {
		return nil, false
	}

	log.Debugf("REWRITE: matched rule for %s -> domain=%s responseCode=%d records=%d additional=%d", question.Name, rewriteResult.Domain, uint16(rewriteResult.ResponseCode), len(rewriteResult.Records), len(rewriteResult.Additional)) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16

	h.cache.RecordRequest(&cache.RequestRecord{
		Qname: question.Name, Qtype: question.Qtype, Qclass: question.Qclass,
		Protocol: "", Result: "rewrite", Rcode: rewriteResult.ResponseCode,
	})

	if uint16(rewriteResult.ResponseCode) != dns.RcodeSuccess { //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
		log.Debugf("RESULT: %s %s | rcode=%s, blocked by rewrite rule", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[uint16(rewriteResult.ResponseCode)]) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
		response := h.buildResponse(req)
		response.Rcode = uint16(rewriteResult.ResponseCode) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
		ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
		h.addEDNS(response, req, isSecureConnection, clientIP, nil, ede, tcpKeepaliveTimeout)
		return response, true
	}

	if len(rewriteResult.Records) > 0 {
		elapsed := ttl.Elapsed(rewriteResult.CreatedAt)
		response := h.buildResponse(req)
		response.Answer = ttl.DeductElapsedCyclical(rewriteResult.Records, elapsed)
		response.Rcode = dns.RcodeSuccess
		if len(rewriteResult.Additional) > 0 {
			response.Extra = ttl.DeductElapsedCyclical(rewriteResult.Additional, elapsed)
		}
		ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
		h.addEDNS(response, req, isSecureConnection, clientIP, nil, ede, tcpKeepaliveTimeout)
		log.Debugf("RESULT: %s %s | rcode=NOERROR (rewrite), answer=%d, additional=%d", question.Name, dns.TypeToString[question.Qtype], len(rewriteResult.Records), len(rewriteResult.Additional))
		return response, true
	}

	if rewriteResult.Domain != question.Name {
		question.Name = rewriteResult.Domain
	}
	return nil, false
}

// tcpKeepaliveTimeoutForProtocol returns the EDNS TCP Keepalive timeout value
// (in 100ms units, RFC 7828) for responses sent over the given protocol.
// Returns 0 for protocols where TCP keepalive is not applicable (UDP, DoH, DoQ).
func tcpKeepaliveTimeoutForProtocol(protocol string) uint16 {
	switch protocol {
	case "TCP", "tcp", "DoT":
		return uint16(config.DefaultEDNSTCPKeepaliveTimeout)
	default:
		return 0
	}
}
