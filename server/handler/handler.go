// Package handler provides the DNS query processing pipeline: cache lookup,
// rewrite evaluation, upstream/recursive resolution, and DNSSEC validation.
package handler

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
	"golang.org/x/sync/errgroup"

	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"
	"zjdns/rewrite"
	"zjdns/server/resolver"
)

// Question is a DNS question compatible with both v1 and v2 dns packages.
type Question struct {
	Name   string
	Qtype  uint16
	Qclass uint16
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

// LatencyProber is the interface for latency-probing cache entries after
// successful resolution.
type LatencyProber interface {
	Start(qname string, qtype uint16, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
}

// Handler processes DNS queries through the caching and resolution pipeline.
type Handler struct {
	closed int32 // hot-path: checked on every query via atomic load

	config       *config.ServerConfig
	cache        cache.Store
	reverseCache interface {
		ReverseLookup(string) []cache.LookupResult
	}
	edns              *edns.Handler
	rewrite           *rewrite.Evaluator
	resolver          *resolver.Resolver
	prober            LatencyProber
	prefetchCooldown  sync.Map
	cacheRefreshGroup *errgroup.Group
	cacheRefreshCtx   context.Context
	ctx               context.Context
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
	rewriteEvaluator *rewrite.Evaluator,
	bg BackgroundConfig,
) *Handler {
	h := &Handler{
		config:            cfg,
		cache:             cacheStore,
		edns:              ednsHandler,
		rewrite:           rewriteEvaluator,
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
func (h *Handler) BuildQueryMessage(question Question, ecs *edns.ECSOption, recursionDesired bool, isSecureConnection bool) *dns.Msg {
	msg := pool.DefaultMessagePool.Get()

	dnsutilv2.SetQuestion(msg, dnsutilv2.Fqdn(question.Name), question.Qtype)
	msg.RecursionDesired = recursionDesired

	if h.edns != nil {
		h.edns.ApplyToMessage(msg, ecs, isSecureConnection, "", nil, true, true, 0)
	}

	return msg
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

func (h *Handler) processDNSQuery(req *dns.Msg, clientIP net.IP, isSecureConnection bool, requestProtocol string) *dns.Msg {
	if atomic.LoadInt32(&h.closed) != 0 {
		msg := h.buildResponse(req)
		msg.Rcode = dns.RcodeServerFailure
		return msg
	}

	if req == nil || len(req.Question) == 0 {
		msg := pool.DefaultMessagePool.Get()
		if req != nil {
			dnsutilv2.SetReply(msg, req)
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
				dnsutil.FormatRecords(responseMsg.Answer, responseMsg.Ns, responseMsg.Extra))
		}
	}()

	if resp, done := h.processRewrite(req, &question, clientIP, isSecureConnection, tcpKeepaliveTimeout); done {
		responseMsg = resp
		return responseMsg
	}

	// The library's serveDNS only unpacks to the question section for
	// early validation. Force a full unpack so EDNS flags (DO bit, ECS)
	// are available.
	req.Options = 0
	if h.edns != nil {
		_ = req.Unpack()
	}

	clientRequestedDNSSEC := false
	var ecsOpt *edns.ECSOption
	var cookieOpt *edns.CookieOption

	clientRequestedDNSSEC = req.Security
	ecsOpt = h.edns.ParseFromDNS(req)
	cookieOpt = h.edns.ParseCookie(req)

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
			h.edns.ApplyToMessage(msg, ecsOpt, false, cookieStr, nil, false, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
			responseMsg = msg
			return responseMsg
		}
	}

	if ecsOpt == nil {
		ecsOpt = h.edns.ECSForQType(question.Qtype)
	}

	if entry, found, isExpired := h.cache.Get(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC); found {
		log.Debugf("CACHE: hit expired=%t for %s, ttl=%d, validated=%t, answer=%d", isExpired, question.Name, entry.RemainingTTL(), entry.Validated, len(entry.Answer))
		if !isExpired {
			responseMsg = h.processCacheHit(req, entry, false, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
			h.cache.RecordHit(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, requestProtocol)
			return responseMsg
		}

		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			responseMsg = h.processExpiredCacheHit(req, entry, question, clientRequestedDNSSEC, ecsOpt, cookieOpt, clientIP, isSecureConnection, tcpKeepaliveTimeout)
			h.cache.RecordHit(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC, requestProtocol)
			h.cache.RecordStale(question.Name, question.Qtype, question.Qclass, ecsOpt, clientRequestedDNSSEC)
			return responseMsg
		}

		responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
		return responseMsg
	}

	if question.Qtype == dns.TypePTR {
		if ptrAnswer := h.lookupReversePTR(question, ecsOpt); len(ptrAnswer) > 0 {
			log.Debugf("PTR: cache hit for reverse lookup %s, found %d records", question.Name, len(ptrAnswer))
			response := h.buildResponse(req)
			response.Answer = ptrAnswer
			ede := edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			h.applyEDNS(response, isSecureConnection, clientIP, ecsOpt, clientRequestedDNSSEC, cookieOpt, ede, edns.HasPaddingOption(req), tcpKeepaliveTimeout)
			responseMsg = response
			return responseMsg
		}
	}

	responseMsg = h.processCacheMiss(req, question, ecsOpt, cookieOpt, clientRequestedDNSSEC, clientIP, isSecureConnection, startTime, requestProtocol, tcpKeepaliveTimeout)
	return responseMsg
}

func (h *Handler) lookupReversePTR(question Question, ecsOpt *edns.ECSOption) []dns.RR {
	ip := dnsutil.ParseReverseDNSName(question.Name)
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
		records = append(records, dnsutil.NewPTRRecord(question.Name, result.Name, result.TTL, question.Qclass))
	}

	return records
}

// validateDNSQuery rejects queries with invalid domain names, label lengths,
// or unsupported query types (ANY, AXFR, IXFR). Returns nil if the query is valid.
func (h *Handler) validateDNSQuery(req *dns.Msg, question *Question, clientIP net.IP, isSecureConnection bool, tcpKeepaliveTimeout uint16) *dns.Msg {
	if len(question.Name) <= config.MaxDomainLength && question.Qtype != dns.TypeANY &&
		question.Qtype != dns.TypeAXFR && question.Qtype != dns.TypeIXFR &&
		dnsutil.IsValidDomainLabels(question.Name) {
		return nil
	}
	msg := pool.DefaultMessagePool.Get()
	dnsutilv2.SetReply(msg, req)
	msg.Rcode = dns.RcodeRefused

	var ede *edns.EDEOption
	if len(question.Name) > config.MaxDomainLength || !dnsutil.IsValidDomainLabels(question.Name) {
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

	log.Debugf("REWRITE: matched rule for %s -> domain=%s responseCode=%d records=%d additional=%d", question.Name, rewriteResult.Domain, uint16(rewriteResult.ResponseCode), len(rewriteResult.Records), len(rewriteResult.Additional))

	h.cache.RecordRewrite(question.Name, question.Qtype, question.Qclass, nil, false)

	if uint16(rewriteResult.ResponseCode) != dns.RcodeSuccess {
		log.Debugf("RESULT: %s %s | rcode=%s, blocked by rewrite rule", question.Name, dns.TypeToString[question.Qtype], dns.RcodeToString[uint16(rewriteResult.ResponseCode)])
		response := h.buildResponse(req)
		response.Rcode = uint16(rewriteResult.ResponseCode)
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
