package middleware

import (
	"context"
	"net"
	"zjdns/cache"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// ZoneMiddleware evaluates zone rules against the incoming query.
// If a rule matches it short-circuits with a synthetic response
// (NXDOMAIN, REFUSED, or NOERROR with records).  If no rule matches,
// it delegates to the next handler.
type ZoneMiddleware struct {
	evaluator  handler.ZoneEvaluator
	tagMatcher func(qname string, ip net.IP) map[string]bool
	cache      cache.Store
}

// Wrap implements Middleware.
func (m *ZoneMiddleware) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		if !m.evaluator.HasRules() {
			return next.ServeDNS(ctx, qctx)
		}

		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)
		qclass := qd.Header().Class

		var matchedTags map[string]bool
		if m.tagMatcher != nil {
			matchedTags = m.tagMatcher(qname, qctx.ClientIP)
		}

		log.Debugf("ZONE: evaluating rules for %s qtype=%s client=%s tags=%v", qname, dns.TypeToString[qtype], qctx.ClientIP, matchedTags)

		if m.evaluator.Bypass(matchedTags) {
			return next.ServeDNS(ctx, qctx)
		}

		zoneResult := m.evaluator.Evaluate(qname, qtype, qclass, matchedTags)
		if !zoneResult.Matched {
			return next.ServeDNS(ctx, qctx)
		}

		log.Debugf("ZONE: matched rule for %s -> domain=%s rcode=%d", qname, zoneResult.Domain, zoneResult.Rcode)

		m.cache.RecordRequest(&cache.RequestRecord{
			Qname: qname, Qtype: qtype, Qclass: qclass,
			Protocol: qctx.Protocol, Result: "zone", Rcode: zoneResult.Rcode,
		})

		qctx.ZoneMatched = true
		qctx.ZoneResult = &zoneResult

		// Non-success rcode → build error response.
		if zoneResult.Rcode != dns.RcodeSuccess {
			log.Debugf("RESULT: %s %s | rcode=%s, blocked by zone rule", qname, dns.TypeToString[qtype], dns.RcodeToString[uint16(zoneResult.Rcode)]) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
			response := handler.BuildResponseMsg(qctx.Req)
			response.Rcode = uint16(zoneResult.Rcode) //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
			if len(zoneResult.Authority) > 0 || len(zoneResult.Additional) > 0 {
				elapsed := ttl.Elapsed(zoneResult.CreatedAt)
				response.Ns = ttl.DeductElapsedCyclical(zoneResult.Authority, elapsed)
				response.Extra = ttl.DeductElapsedCyclical(zoneResult.Additional, elapsed)
			}
			qctx.EDE = edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			qctx.Res = response
			return nil
		}

		// Successful zone response with records.
		hasRecords := len(zoneResult.Answer) > 0 || len(zoneResult.Authority) > 0 || len(zoneResult.Additional) > 0
		if hasRecords {
			elapsed := ttl.Elapsed(zoneResult.CreatedAt)
			response := handler.BuildResponseMsg(qctx.Req)
			response.Answer = ttl.DeductElapsedCyclical(zoneResult.Answer, elapsed)
			response.Ns = ttl.DeductElapsedCyclical(zoneResult.Authority, elapsed)
			response.Extra = ttl.DeductElapsedCyclical(zoneResult.Additional, elapsed)
			response.Rcode = dns.RcodeSuccess
			qctx.EDE = edns.NewEDEOption(edns.EDECodeForgedAnswer, "")
			qctx.Res = response
			log.Debugf("RESULT: %s %s | rcode=NOERROR (zone), answer=%d", qname, dns.TypeToString[qtype], len(zoneResult.Answer))
			return nil
		}

		// Zone rule matched but changed the domain (wildcard rewrite).
		if zoneResult.Domain != qname {
			qctx.OriginalName = qname
			qd.Header().Name = zoneResult.Domain
		}
		return next.ServeDNS(ctx, qctx)
	})
}
