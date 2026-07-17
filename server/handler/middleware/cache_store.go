package middleware

import (
	"context"
	"errors"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// CacheStoreMiddleware wraps the inner chain and handles all post-resolution
// processing: building the DNS response from the resolution result, writing
// to the cache, recording request statistics, and triggering latency probes.
// On resolution errors it attempts a stale-cache fallback.
type CacheStoreMiddleware struct {
	store    cache.Store
	prober   handler.LatencyProber
	resolver handler.Resolver
}

// Wrap implements Middleware.
func (m *CacheStoreMiddleware) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		err := next.ServeDNS(ctx, qctx)

		// Already handled by cache lookup or zone match — nothing to do.
		if qctx.CacheServed || qctx.ZoneMatched || qctx.Res != nil {
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

func (m *CacheStoreMiddleware) buildSuccess(qctx *handler.QueryContext) *dns.Msg {
	qr := qctx.ResolutionResult
	qd := qctx.Req.Question[0]
	qname := qd.Header().Name
	qtype := dns.RRToType(qd)
	qclass := qd.Header().Class
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	validated := qr.Validated
	cacheable := qr.Cacheable

	msg := handler.BuildResponseMsg(qctx.Req)

	// Determine DNSSEC status and EDE code.
	var dnssecStatus string
	var dnssecEDECode uint16
	switch {
	case validated:
		dnssecStatus = config.DNSSECStatusSecure
	case m.resolver != nil && m.resolver.DNSSECEDECode() != 0:
		dnssecEDECode = m.resolver.DNSSECEDECode()
		dnssecStatus = config.DNSSECStatusBogus
	default:
		dnssecStatus = config.DNSSECStatusInsecure
	}

	if validated {
		msg.AuthenticatedData = true
	}

	// ECS for the response.
	responseECS := qr.ECS
	if responseECS == nil && ecsOpt != nil {
		responseECS = &edns.ECSOption{
			Family:       ecsOpt.Family,
			SourcePrefix: ecsOpt.SourcePrefix,
			ScopePrefix:  ecsOpt.ScopePrefix,
			Address:      handler.CopyIP(ecsOpt.Address),
		}
	}

	// Cache population.
	var entryID int64
	if cacheable {
		log.Debugf("CACHE: populating cache for %s", qname)
		entryID = m.store.Set(qname, qtype, qclass, ecsOpt, dnssecOK, qr.Answer, qr.Authority, qr.Additional, validated)
	}

	// Request log.
	m.store.RecordRequest(&cache.RequestRecord{
		Qname: qname, Qtype: qtype, Qclass: qclass,
		ECS: ecsOpt, DNSSECOK: dnssecOK,
		Protocol: qctx.Protocol, Result: "miss", ResponseTime: time.Since(qctx.StartTime).Milliseconds(),
		Rcode: dns.RcodeSuccess, Server: qr.Server, Hijack: qr.Hijack, Fallback: qr.Fallback,
		DNSSECStatus: dnssecStatus,
		EntryID:      entryID,
	})

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
		qctx.EDE = edns.NewEDEOption(dnssecEDECode, "")
	}
	if qctx.EDE == nil && m.resolver != nil {
		if upstreamEDE := m.resolver.UpstreamEDEOption(); upstreamEDE != nil {
			qctx.EDE = upstreamEDE
			log.Debugf("UPSTREAM: passing through EDE %d (%s) from upstream", upstreamEDE.InfoCode, edns.EDECodeString(upstreamEDE.InfoCode))
		}
	}

	return msg
}

func (m *CacheStoreMiddleware) buildError(qctx *handler.QueryContext) *dns.Msg {
	qr := qctx.ResolutionResult
	qd := qctx.Req.Question[0]
	qname := qd.Header().Name
	qtype := dns.RRToType(qd)
	qclass := qd.Header().Class
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC
	queryErr := qr.Err

	// Try stale cache fallback.
	if entry, found, _ := m.store.Get(qname, qtype, qclass, ecsOpt, dnssecOK); found && entry.IsExpired() && entry.CanServeExpired(config.DefaultStaleMaxAge) {
		log.Debugf("CACHE: serving expired cached result for %s, ttl_remaining=%d", qname, entry.RemainingTTL())
		m.store.RecordRequest(&cache.RequestRecord{
			Qname: qname, Qtype: qtype, Qclass: qclass,
			ECS: ecsOpt, DNSSECOK: dnssecOK,
			Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeServerFailure,
			ResponseTime: time.Since(qctx.StartTime).Milliseconds(),
			EntryID:      entry.ID,
		})
		return m.buildFromCacheEntry(qctx, entry, true)
	}

	log.Debugf("RESULT: %s %s | rcode=SERVFAIL, no stale cache available", qname, dns.TypeToString[qtype])

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeServerFailure

	edeCode := edns.EDECodeNetworkError
	dnssecStatus := ""
	if code := m.resolver.DNSSECEDECode(); m.resolver != nil && code != 0 {
		edeCode = code
		dnssecStatus = config.DNSSECStatusBogus
		log.Debugf("SECURITY: using DNSSEC EDE %d from recursive resolver", edeCode)
	} else {
		var dnsErr *resolver.DNSSECError
		if errors.As(queryErr, &dnsErr) {
			edeCode = dnsErr.EDECode
			dnssecStatus = config.DNSSECStatusBogus
			log.Debugf("SECURITY: DNSSEC error mapped to EDE %d: %s", edeCode, dnsErr.Message)
		}
	}

	m.store.RecordRequest(&cache.RequestRecord{
		Qname: qname, Qtype: qtype, Qclass: qclass,
		ECS: ecsOpt, DNSSECOK: dnssecOK,
		Protocol: qctx.Protocol, Result: "error", Rcode: dns.RcodeServerFailure,
		ResponseTime: time.Since(qctx.StartTime).Milliseconds(),
		DNSSECStatus: dnssecStatus,
	})

	qctx.EDE = edns.NewEDEOption(edeCode, "")
	return msg
}

func (m *CacheStoreMiddleware) buildCIDRRefused(qctx *handler.QueryContext) *dns.Msg {
	qd := qctx.Req.Question[0]
	qname := qd.Header().Name
	qtype := dns.RRToType(qd)
	qclass := qd.Header().Class
	ecsOpt := qctx.ECSOpt
	dnssecOK := qctx.ClientRequestedDNSSEC

	log.Debugf("RESULT: %s %s | rcode=REFUSED, blocked by CIDR filtering", qname, dns.TypeToString[qtype])

	msg := handler.BuildResponseMsg(qctx.Req)
	msg.Rcode = dns.RcodeRefused

	qctx.EDE = edns.NewEDEOption(edns.EDECodeBlocked, "")

	m.store.RecordRequest(&cache.RequestRecord{
		Qname: qname, Qtype: qtype, Qclass: qclass,
		ECS: ecsOpt, DNSSECOK: dnssecOK,
		Protocol: qctx.Protocol, Result: "blocked", Rcode: dns.RcodeRefused,
		ResponseTime: time.Since(qctx.StartTime).Milliseconds(),
	})

	return msg
}

func (m *CacheStoreMiddleware) buildFromCacheEntry(qctx *handler.QueryContext, entry *cache.Entry, isExpired bool) *dns.Msg {
	msg := handler.BuildCacheEntryResponse(qctx.Req, entry, qctx.ClientRequestedDNSSEC, isExpired)
	if isExpired {
		qctx.EDE = edns.NewEDEOption(edns.EDECodeStaleAnswer, "")
	}

	return msg
}
