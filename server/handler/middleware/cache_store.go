package middleware

import (
	"context"
	"errors"
	"slices"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"
	"zjdns/server/resolver/dnssec"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
)

// CacheStore wraps the inner chain and handles all post-resolution
// processing: building the DNS response from the resolution result, writing
// to the cache, recording request statistics, and triggering latency probes.
// On resolution errors it attempts a stale-cache fallback.
type CacheStore struct {
	store    cache.Store
	stats    *stats.Collector
	prober   handler.LatencyProber
	resolver handler.Resolver
}

// Wrap implements Wrapper.
func (m *CacheStore) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		// Already handled by cache lookup or zone match — nothing to do.
		// Only a FINAL (Responded) response skips the cache write; a partial
		// response still needs building and caching.
		if qctx.CacheServed || qctx.ZoneResult != nil || qctx.Responded {
			return err
		}

		if qctx.ResolutionResult == nil {
			return err
		}

		qr := qctx.ResolutionResult
		if qr.Err != nil {
			if errors.Is(qr.Err, resolver.ErrCIDRFilterRefused) {
				qctx.Res = m.buildCIDRRefused(qctx)
				qctx.Responded = true
			} else {
				qctx.Res = m.buildError(qctx)
				qctx.Responded = true
			}
			return err
		}

		qctx.Res = m.buildSuccess(qctx)
		qctx.Responded = true
		return err
	})
}

func (m *CacheStore) buildSuccess(qctx *handler.QueryContext) *dns.Msg {
	qr := qctx.ResolutionResult
	qname := qctx.Qname
	qtype := qctx.Qtype
	qclass := qctx.Qclass
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	validated := qr.Validated
	cacheable := qr.Cacheable

	msg := handler.BuildResponseMsg(qctx.Req)
	// Preserve the resolution rcode (NXDOMAIN etc.) — BuildResponseMsg
	// defaults to NOERROR.
	if qr.Rcode != 0 {
		msg.Rcode = qr.Rcode
	}

	// Determine DNSSEC status and EDE code.
	var dnssecStatus string
	var dnssecEDECode uint16
	switch {
	case validated:
		dnssecStatus = config.DNSSECStatusSecure
	case qr.DNSSECEDE != 0:
		dnssecEDECode = qr.DNSSECEDE
		dnssecStatus = config.DNSSECStatusBogus
	default:
		dnssecStatus = config.DNSSECStatusInsecure
	}

	if validated {
		msg.AuthenticatedData = true
	}

	// ECS for the response.
	responseECS := qr.ECS
	// RFC 7871 §7.3/§11.2: verify response ECS matches query.
	if ecsOpt != nil && responseECS != nil && !edns.VerifyECSResponse(ecsOpt, responseECS) {
		log.Debugf("EDNS: ECS mismatch — returning SERVFAIL for spoofed response")
		msg := handler.BuildResponseMsg(qctx.Req)
		msg.Rcode = dns.RcodeServerFailure
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: "ECS response mismatch"}
		m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeServerFailure, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
		return msg
	}

	if responseECS == nil && ecsOpt != nil {
		responseECS = &edns.ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      slices.Clone(ecsOpt.Address),
		}
	}

	// Cache population.
	if cacheable {
		// RFC 4035 §5.3.3: cap TTL of authenticated RRsets.
		if validated {
			dnssec.CapValidatedTTL(qr.Answer, qr.Authority, qr.Additional)
		}

		log.Debugf("CACHE: populating cache for %s", qname)
		// RFC 7871 §7.3.1: when the authoritative response scope is 0,
		// the answer is suitable for all addresses — cache globally.
		cacheECS := ecsOpt
		if responseECS != nil && responseECS.ScopePrefix == 0 {
			cacheECS = nil
		}
		_ = m.store.Set(qname, qtype, qclass, cacheECS, dnssecOK, qr.Answer, qr.Authority, qr.Additional, validated, qr.Rcode)
	}

	// Request log.  Record the real rcode — negative responses (NXDOMAIN)
	// served here must not be counted as NOERROR, or the rcode distribution
	// skews availability metrics.
	m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "miss", ResponseTime: handler.ElapsedMS(qctx.StartTime), Rcode: int(qr.Rcode), Poisoned: qr.Poisoned, DNSSECStatus: dnssecStatus}) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16

	// Latency probe.
	if m.prober != nil {
		m.prober.Start(qname, qtype, qr.Answer, qr.Authority, qr.Additional, validated, responseECS)
	}

	// Build response records.
	msg.Answer = cache.ProcessRecords(qr.Answer, 0, false, dnssecOK)
	msg.Ns = cache.ProcessRecords(qr.Authority, 0, false, dnssecOK)
	msg.Extra = cache.ProcessRecords(qr.Additional, 0, false, dnssecOK)

	// RFC 8767 §4: clamp served TTLs to MaxCacheableTTL. ClampTTL clones, so
	// the records shared with the latency prober are never mutated.
	msg.Answer = cache.ClampTTL(msg.Answer, config.DefaultMaxCacheableTTL)
	msg.Ns = cache.ClampTTL(msg.Ns, config.DefaultMaxCacheableTTL)
	msg.Extra = cache.ClampTTL(msg.Extra, config.DefaultMaxCacheableTTL)

	log.Debugf("RESULT: %s %s | rcode=%s, answer=%d, validated=%t", qname, dns.TypeToString[qtype], dns.RcodeToString[qr.Rcode], len(qr.Answer), validated)

	// Set EDE from DNSSEC or upstream.
	if dnssecEDECode != 0 {
		qctx.EDE = &dns.EDE{InfoCode: dnssecEDECode, ExtraText: "DNSSEC validation failed"}
	}
	if qctx.EDE == nil && qr.UpstreamEDE != nil {
		qctx.EDE = &dns.EDE{InfoCode: qr.UpstreamEDE.InfoCode, ExtraText: "(from " + qr.Server + ") " + qr.UpstreamEDE.ExtraText}
		log.Debugf("UPSTREAM: passing through EDE %d (%s) from upstream", qr.UpstreamEDE.InfoCode, dns.ExtendedErrorToString[qr.UpstreamEDE.InfoCode])
	}

	return msg
}

func (m *CacheStore) buildError(qctx *handler.QueryContext) *dns.Msg {
	qr := qctx.ResolutionResult
	qname := qctx.Qname
	qtype := qctx.Qtype
	qclass := qctx.Qclass
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	queryErr := qr.Err

	// Try cache fallback — fresh or stale.
	if entry, found, isExpired := m.store.Get(qname, qtype, qclass, ecsOpt, dnssecOK); found {
		if !isExpired || entry.CanServeExpired(config.DefaultStaleMaxAge) {
			log.Debugf("CACHE: serving cached result for %s, ttl_remaining=%d", qname, entry.RemainingTTL())
			// The client gets a valid cached answer (NOERROR), not a
			// SERVFAIL — recording RcodeServerFailure here corrupted the
			// availability/error metrics.
			m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
			return m.buildFromCacheEntry(qctx, entry, isExpired)
		}
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", qname, dns.TypeToString[qtype])

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := dns.ExtendedErrorNetworkError
	dnssecStatus := ""
	if m.resolver != nil {
		if code := qr.DNSSECEDE; code != 0 {
			edeCode = code
			dnssecStatus = config.DNSSECStatusBogus
			log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
		}
	}
	if dnssecStatus == "" {
		var dnsErr *resolver.DNSSECError
		if errors.As(queryErr, &dnsErr) {
			edeCode = dnsErr.EDECode
			dnssecStatus = config.DNSSECStatusBogus
			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		}
	}

	m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeServerFailure, ResponseTime: handler.ElapsedMS(qctx.StartTime), DNSSECStatus: dnssecStatus})

	qctx.EDE = &dns.EDE{InfoCode: edeCode, ExtraText: "resolution error"}
	return msg
}

func (m *CacheStore) buildCIDRRefused(qctx *handler.QueryContext) *dns.Msg {
	qname := qctx.Qname
	qtype := qctx.Qtype

	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", qname, dns.TypeToString[qtype])

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeRefused

	qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: ""}

	m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "blocked", Rcode: dns.RcodeRefused, ResponseTime: handler.ElapsedMS(qctx.StartTime)})

	return msg
}

func (m *CacheStore) buildFromCacheEntry(qctx *handler.QueryContext, entry *cache.Entry, isExpired bool) *dns.Msg {
	msg := handler.BuildCacheEntryResponse(qctx.Req, entry, qctx.ClientRequestedDNSSEC, isExpired)
	if isExpired {
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorStaleAnswer, ExtraText: ""}
	}

	return msg
}
