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

// dnssecCacheable reports whether a resolution result may be cached.
// A validated (AD=1) response is always cached — the trust chain has been
// verified and a bogus EDE that leaks through is a stale artifact from an
// earlier delegation level (sticky chain.lastEDECode), not a real failure.
// An unvalidated response carrying a bogus-class EDE (6/7/8/1/12) must
// never be cached: a dnssec_enforce instance reading a shared cache would
// otherwise serve the unauthenticated answer, bypassing the enforce gate.
// RRSIGs-missing keeps the existing insecure treatment and stays cacheable.
func dnssecCacheable(validated bool, ede uint16) bool {
	if validated {
		return true
	}
	return ede == 0 || ede == dns.ExtendedErrorRRSIGsMissing
}

// Wrap implements Wrapper.
func (m *CacheStore) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		// Already handled by an upstream middleware — nothing to do.
		// Gate on Res alone: CacheServed/ZoneMatched were redundant here
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
	qclass := qctx.Req.Question[0].Header().Class
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	validated := qr.Validated
	cacheable := qr.Cacheable

	msg := handler.BuildResponseMsg(qctx.Req)

	// Propagate the resolution rcode (e.g. NXDOMAIN from the authoritative
	// server or a compact NODATA restored per RFC 9824 §5.1).  BuildResponseMsg
	// always starts NOERROR — without this every upstream/recursive NXDOMAIN
	// was served as NODATA, and the cached wire lost the rcode entirely.
	if qr.Rcode != 0 && qr.Rcode != dns.RcodeSuccess {
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
	// RFC 7871 §7.3/§11.2: verify response ECS matches query — a mismatched
	// family/prefix/address means the response is not for the queried subnet
	// (spoofed or misrouted); serving it would poison the client's cache.
	if ecsOpt != nil && responseECS != nil && !edns.VerifyECSResponse(ecsOpt, responseECS) {
		// Rare security-relevant event (spoofed or misrouted response) —
		// Warn with the qname for correlation; not per-query spam.
		log.Warnf("EDNS: ECS mismatch for %s — returning SERVFAIL (spoofed or misrouted response)", qname)
		// Reuse the pooled msg built above — allocating a second one would
		// leak the first to the GC.
		msg.Rcode = dns.RcodeServerFailure
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: "ECS response mismatch"}
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

	// Cache population.  Bogus validation results are never cached — an
	// enforce instance sharing the DB must not serve them from cache.
	if cacheable && dnssecCacheable(validated, qr.DNSSECEDE) {
		// RFC 4035 §5.3.3: cap TTL of authenticated RRsets.
		if validated {
			dnssec.CapValidatedTTL(qr.Answer, qr.Authority, qr.Additional)
		}

		log.Debugf("CACHE: populating cache for %s", qname)
		m.store.Set(qname, qtype, qclass, ecsOpt, dnssecOK, qr.Answer, qr.Authority, qr.Additional, validated, qr.Rcode)
	}

	// Request log.
	rec := cache.AcquireRequestRecord()
	rec.Qname = qname
	rec.Qtype = qtype
	rec.Qclass = qclass
	rec.Protocol = qctx.Protocol
	rec.Result = "miss"
	rec.ResponseTime = handler.ElapsedMS(qctx.StartTime)
	rec.Rcode = dns.RcodeSuccess
	rec.Server = qr.Server
	rec.Poisoned = qr.Poisoned
	rec.DNSSECStatus = dnssecStatus
	m.store.RecordRequest(rec)
	cache.ReleaseRequestRecord(rec)

	// Latency probe.
	if m.prober != nil {
		m.prober.Start(qname, qtype, qr.Answer, qr.Authority, qr.Additional, validated, responseECS)
	}

	// Build response records.
	msg.Answer = cache.ProcessRecords(qr.Answer, 0, false, dnssecOK)
	msg.Ns = cache.ProcessRecords(qr.Authority, 0, false, dnssecOK)
	msg.Extra = cache.ProcessRecords(qr.Additional, 0, false, dnssecOK)

	log.Debugf("RESULT: %s %s | rcode=NOERROR, answer=%d, validated=%t", qname, dns.TypeToString[qtype], len(qr.Answer), validated)

	// Set EDE from DNSSEC or upstream.
	if dnssecEDECode != 0 {
		qctx.EDE = &dns.EDE{InfoCode: dnssecEDECode, ExtraText: ""}
	}
	if qctx.EDE == nil && qr.UpstreamEDE != nil {
		qctx.EDE = &dns.EDE{InfoCode: qr.UpstreamEDE.InfoCode, ExtraText: qr.UpstreamEDE.ExtraText}
		log.Debugf("UPSTREAM: passing through EDE %d (%s) from upstream", qr.UpstreamEDE.InfoCode, dns.ExtendedErrorToString[qr.UpstreamEDE.InfoCode])
	}

	return msg
}

func (m *CacheStore) buildError(qctx *handler.QueryContext) *dns.Msg {
	qr := qctx.ResolutionResult
	qname := qctx.Qname
	qtype := qctx.Qtype
	qclass := qctx.Req.Question[0].Header().Class
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	queryErr := qr.Err

	// Try cache fallback — fresh or stale.
	if entry, found, isExpired := m.store.Get(qname, qtype, qclass, ecsOpt, dnssecOK); found {
		if !isExpired || entry.CanServeExpired(config.DefaultStaleMaxAge) {
			log.Debugf("CACHE: serving cached result for %s, ttl_remaining=%d", qname, entry.RemainingTTL())
			rec := cache.AcquireRequestRecord()
			rec.Qname = qname
			rec.Qtype = qtype
			rec.Qclass = qclass
			rec.Protocol = qctx.Protocol
			rec.Result = "error"
			rec.Rcode = dns.RcodeServerFailure
			rec.ResponseTime = handler.ElapsedMS(qctx.StartTime)
			m.store.RecordRequest(rec)
			cache.ReleaseRequestRecord(rec)
			return buildCacheResponse(qctx, entry, isExpired)
		}
		// Entry cannot serve stale and is dropped — return the pool-owned
		// TTL-offset slice (buildCacheResponse would have released it).
		cache.ReleaseTTLOffsets(entry.TTLOffsets)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", qname, dns.TypeToString[qtype])

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := dns.ExtendedErrorNetworkError
	dnssecStatus := ""
	if qr.DNSSECEDE != 0 {
		edeCode = qr.DNSSECEDE
		dnssecStatus = config.DNSSECStatusBogus
		log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
	}
	if dnssecStatus == "" {
		var dnsErr *resolver.DNSSECError
		if errors.As(queryErr, &dnsErr) {
			edeCode = dnsErr.EDECode
			dnssecStatus = config.DNSSECStatusBogus
			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		}
	}

	rec := cache.AcquireRequestRecord()
	rec.Qname = qname
	rec.Qtype = qtype
	rec.Qclass = qclass
	rec.Protocol = qctx.Protocol
	rec.Result = "error"
	rec.Rcode = dns.RcodeServerFailure
	rec.ResponseTime = handler.ElapsedMS(qctx.StartTime)
	rec.DNSSECStatus = dnssecStatus
	m.store.RecordRequest(rec)
	cache.ReleaseRequestRecord(rec)

	qctx.EDE = &dns.EDE{InfoCode: edeCode, ExtraText: ""}
	return msg
}

func (m *CacheStore) buildCIDRRefused(qctx *handler.QueryContext) *dns.Msg {
	qname := qctx.Qname
	qtype := qctx.Qtype
	qclass := qctx.Req.Question[0].Header().Class

	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", qname, dns.TypeToString[qtype])

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeRefused

	qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: ""}

	rec := cache.AcquireRequestRecord()
	rec.Qname = qname
	rec.Qtype = qtype
	rec.Qclass = qclass
	rec.Protocol = qctx.Protocol
	rec.Result = "blocked"
	rec.Rcode = dns.RcodeRefused
	rec.ResponseTime = handler.ElapsedMS(qctx.StartTime)
	m.store.RecordRequest(rec)
	cache.ReleaseRequestRecord(rec)

	return msg
}
