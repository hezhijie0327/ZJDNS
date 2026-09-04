package middleware

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// CacheStore wraps the inner chain and handles all post-resolution
// processing: building the DNS response from the resolution result, writing
// to the cache, recording request statistics, and triggering latency probes.
// On resolution errors it attempts a stale-cache fallback.
type CacheStore struct {
	store    cache.Store
	prober   handler.LatencyProber
	resolver handler.Resolver
}

// ecsMismatchCount samples the ECS-mismatch Warn (C-M1) — atomic, hot path.
var ecsMismatchCount atomic.Uint64

// Wrap implements Wrapper.
func (m *CacheStore) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		// Already handled by an upstream middleware — nothing to do.
		// Gate on Res alone — markers like ZoneMatched were redundant here
		// (both are always accompanied by Res except the records-less zone
		// rule path, which must reach buildSuccess below or the query is
		// silently dropped — C3).
		if qctx.Res != nil {
			return err
		}

		if !qctx.Resolved {
			return err
		}

		qr := qctx.ResolutionResult
		if qr.Err != nil {
			if errors.Is(qr.Err, resolver.ErrCIDRFilterRefused) {
				qctx.Res = m.buildCIDRRefused(qctx)
			} else {
				qctx.Res = m.buildError(qctx)
			}
			return err
		}

		qctx.Res = m.buildSuccess(qctx)
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

	msg := handler.BuildResponseMsg(qctx.Req)

	// Propagate the resolution rcode (e.g. NXDOMAIN from the authoritative
	// server or a compact NODATA restored per RFC 9824 §5.1).  BuildResponseMsg
	// always starts NOERROR — without this every upstream/recursive NXDOMAIN
	// was served as NODATA, and the cached wire lost the rcode entirely.
	if qr.Rcode != 0 && qr.Rcode != dns.RcodeSuccess {
		msg.Rcode = qr.Rcode
	}

	// DNSSEC EDE for the response (the journal status is derived by the
	// Stats middleware from the resolution result).
	var dnssecEDECode uint16
	if !validated && qr.DNSSECEDE != 0 {
		dnssecEDECode = qr.DNSSECEDE
	}

	if validated {
		msg.AuthenticatedData = true
	}

	// ECS for the response.
	responseECS := qr.ECS
	// RFC 7871 §7.3/§11.2: verify response ECS matches query — a mismatched
	// family/prefix/address means the response is not for the queried subnet
	// (spoofed or misrouted); serving it would poison the client's cache.
	if ecsOpt != nil && responseECS != nil && !edns.VerifyECSResponse(ecsOpt, responseECS) {
		// Security-relevant event (spoofed or misrouted response) — sampled
		// Warn, not per-query: an upstream that consistently rewrites ECS
		// (or a spoofer) hits this branch at full query rate and would
		// flood the log otherwise (2026-09 C-M1).
		if n := ecsMismatchCount.Add(1); n%config.DefaultECSMismatchWarnEvery == 1 {
			log.Warnf("EDNS: ECS mismatch for %s — returning SERVFAIL (spoofed or misrouted response) [%dth]", qname, n)
		}
		// Reuse the pooled msg built above — allocating a second one would
		// leak the first to the GC.
		msg.Rcode = dns.RcodeServerFailure
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: "ECS response mismatch"}
		qctx.Result = "error"
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

	// Cache population — the single cacheability gate (bogus results never
	// cached; validated RRsets TTL-capped per RFC 4035 §5.3.3).
	if handler.StoreIfCacheable(m.store, qname, qtype, qclass, ecsOpt, qr) && log.IsDebug() {
		log.Debugf("CACHE: populating cache for %s", qname)
	}

	qctx.Result = "miss"

	// Latency probe.
	if m.prober != nil {
		m.prober.Start(qname, qtype, qr.Answer, qr.Authority, qr.Additional, validated, responseECS)
	}

	// Build response records.
	msg.Answer = cache.ProcessRecords(qr.Answer, 0, false, dnssecOK)
	msg.Ns = cache.ProcessRecords(qr.Authority, 0, false, dnssecOK)
	msg.Extra = cache.ProcessRecords(qr.Additional, 0, false, dnssecOK)

	if log.IsDebug() {
		log.Debugf("RESULT: %s %s | rcode=NOERROR, answer=%d, validated=%t", qname, dns.TypeToString[qtype], len(qr.Answer), validated)
	}

	// Set EDE from DNSSEC or upstream.
	if dnssecEDECode != 0 {
		qctx.EDE = &dns.EDE{InfoCode: dnssecEDECode, ExtraText: ""}
	}
	if qctx.EDE == nil && qr.UpstreamEDE != nil {
		qctx.EDE = &dns.EDE{InfoCode: qr.UpstreamEDE.InfoCode, ExtraText: qr.UpstreamEDE.ExtraText}
		if log.IsDebug() {
			log.Debugf("UPSTREAM: passing through EDE %d (%s) from upstream", qr.UpstreamEDE.InfoCode, dns.ExtendedErrorToString[qr.UpstreamEDE.InfoCode])
		}
	}

	return msg
}

func (m *CacheStore) buildError(qctx *handler.QueryContext) *dns.Msg {
	qr := qctx.ResolutionResult
	qname := qctx.Qname
	qtype := qctx.Qtype
	ecsOpt := qctx.ECSOpt
	queryErr := qr.Err

	// Try cache fallback — fresh or stale.
	if entry, found, isExpired := m.store.Get(qname, qtype, qctx.Qclass, ecsOpt); found {
		if !isExpired || entry.CanServeExpired(config.DefaultStaleMaxAge) {
			if log.IsDebug() {
				log.Debugf("CACHE: serving cached result for %s, ttl_remaining=%d", qname, entry.RemainingTTL())
			}
			qctx.Result = "error"
			return buildCacheResponse(qctx, entry, isExpired)
		}
		// Entry cannot serve stale and is dropped — return the pool-owned
		// TTL-offset slice (buildCacheResponse would have released it).
		cache.ReleaseTTLOffsets(entry.TTLOffsets)
	}

	if log.IsDebug() {
		log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", qname, dns.TypeToString[qtype])
	}

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := dns.ExtendedErrorNetworkError
	if qr.DNSSECEDE != 0 {
		edeCode = qr.DNSSECEDE
		if log.IsDebug() {
			log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
		}
	} else if dnsErr, ok := errors.AsType[*resolver.DNSSECError](queryErr); ok {
		edeCode = dnsErr.EDECode
		if log.IsDebug() {
			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		}
	}

	qctx.Result = "error"

	qctx.EDE = &dns.EDE{InfoCode: edeCode, ExtraText: ""}
	return msg
}

func (m *CacheStore) buildCIDRRefused(qctx *handler.QueryContext) *dns.Msg {
	qname := qctx.Qname
	qtype := qctx.Qtype

	if log.IsDebug() {
		log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", qname, dns.TypeToString[qtype])
	}

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeRefused

	qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: ""}
	qctx.Result = "blocked"

	return msg
}
