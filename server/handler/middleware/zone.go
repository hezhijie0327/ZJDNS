package middleware

import (
	"context"
	"net"
	"strings"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
	"zjdns/server/handler"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Zone evaluates zone rules against the incoming query.
// If a rule matches it short-circuits with a synthetic response
// (NXDOMAIN, REFUSED, or NOERROR with records).  If no rule matches,
// it delegates to the next handler.
type Zone struct {
	evaluator  handler.ZoneEvaluator
	tagMatcher func(qname string, ip net.IP) map[string]bool
	stats      *stats.Collector
}

// isDestructiveChaosName reports whether the qname is one of the CHAOS
// control endpoints that mutate server state (cache/ptr/latency flush,
// stats reset, DNSCrypt key reset). Case-insensitive: zone-rule matching is
// case-insensitive too, so a case-variant query (e.g. "zjdns.cache.clear")
// would otherwise bypass the loopback gate below.
func isDestructiveChaosName(qname string) bool {
	c := strings.ToLower(dnsutil.Canonical(qname))
	switch c {
	case strings.ToLower(config.DefaultProjectName) + ".cache.clear.",
		strings.ToLower(config.DefaultProjectName) + ".stats.clear.",
		strings.ToLower(config.DefaultProjectName) + ".ptr.clear.",
		strings.ToLower(config.DefaultProjectName) + ".latency.clear.",
		strings.ToLower(config.DefaultProjectName) + ".dnscrypt.clear.":
		return true
	}
	return false
}

// Wrap implements Wrapper.
func (m *Zone) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)
		qclass := qd.Header().Class

		var matchedTags map[string]bool
		if m.tagMatcher != nil {
			matchedTags = m.tagMatcher(qname, qctx.ClientIP)
		}

		log.Debugf("ZONE: evaluating rules for %s qtype=%s client=%s tags=%v", qname, dns.TypeToString[qtype], qctx.ClientIP, matchedTags)

		zoneResult := m.evaluator.Evaluate(qname, qtype, qclass, matchedTags)
		if !zoneResult.Matched {
			return next.ServeDNS(ctx, qctx)
		}

		// Destructive CHAOS endpoints (.cache.clear / .stats.clear) flush the
		// cache and reset statistics — any client that can reach a listener
		// could otherwise trigger them remotely. Loopback-only.
		if isDestructiveChaosName(qname) && (qctx.ClientIP == nil || !qctx.ClientIP.IsLoopback()) {
			log.Warnf("SECURITY: denying destructive CHAOS query %s from non-loopback client %s", qname, qctx.ClientIP)
			response := handler.BuildResponseMsg(qctx.Req)
			response.Rcode = dns.RcodeRefused
			qctx.Res = response
			qctx.Responded = true
			return nil
		}

		log.Debugf("ZONE: matched rule for %s -> domain=%s rcode=%d", qname, zoneResult.Domain, zoneResult.Rcode)

		m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "zone", Rcode: zoneResult.Rcode, ResponseTime: handler.ElapsedMS(qctx.StartTime)})

		// ZoneResult is set ONLY on the branches that actually build a
		// synthetic response below: CacheStore uses it to skip building a
		// response, so setting it before the fall-through delegation would
		// silently drop the resolution result (the client gets nothing).
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
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorBlocked, ExtraText: ""}
			qctx.Res = response
			qctx.Responded = true
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
			// Operator-configured zone rules are legitimate policy, not
			// security forgeries — omit EDE so clients don't misclassify.
			qctx.Res = response
			qctx.Responded = true
			log.Debugf("RESULT: %s %s | rcode=NOERROR (zone), answer=%d", qname, dns.TypeToString[qtype], len(zoneResult.Answer))
			return nil
		}

		// Zone rule matched but changed the domain (wildcard rewrite).
		// qctx.RewrittenName is set so the Response middleware can restore
		// original owner names in the response rdata sections without mutating
		// the shared request message. Wildcard CNAME chains (where intermediate
		// targets differ from the original query name) are not restored — this
		// is an accepted limitation for zone rewrite.
		if zoneResult.Domain != qname {
			qctx.OriginalName = qname
			qctx.RewrittenName = zoneResult.Domain
		}
		return next.ServeDNS(ctx, qctx)
	})
}
