package middleware

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
	"zjdns/server/handler"

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
	cache      cache.Store
}

// wildcardPrefix is the zone-rule wildcard marker (matches zone package).
const wildcardPrefix = "*."

// chaosDenialCount samples the destructive-CHAOS denial Warn (C-M2).
var chaosDenialCount atomic.Uint64

// destructiveChaosNames are the CHAOS control endpoints that mutate server
// state, precomputed once (the former per-call ToLower+concat rebuilt five
// constant strings on every zone-matched query, H-L6).
var destructiveChaosNames = func() map[string]struct{} {
	base := strings.ToLower(config.DefaultProjectName)
	names := []string{"cache.clear.", "stats.clear.", "latency.clear.", "querylog.clear.", "dnscrypt.clear."}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[base+"."+n] = struct{}{}
	}
	return set
}()

// isDestructiveChaosName reports whether the qname is one of the CHAOS
// control endpoints that mutate server state (cache/latency flush, stats
// reset, DNSCrypt key reset). Case-insensitive: zone-rule matching is
// case-insensitive too, so a case-variant query (e.g. "zjdns.cache.clear")
// would otherwise bypass the loopback gate below.
func isDestructiveChaosName(qname string) bool {
	_, ok := destructiveChaosNames[strings.ToLower(dnsutil.Canonical(qname))]
	return ok
}

// rewriteOwnerNames rewrites RR owner names that exactly match from, setting
// them to the target name — wildcard zone rules store answers under
// "*.<domain>" and must serve them with the queried name as the owner
// (RFC 1034 §4.3.3, R3-M7).
// The RRs are freshly unpacked per query, so in-place mutation is safe.
func rewriteOwnerNames(rrs []dns.RR, from, to string) []dns.RR {
	for _, rr := range rrs {
		if rr != nil && dns.EqualName(rr.Header().Name, from) {
			rr.Header().Name = to
		}
	}
	return rrs
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

		zoneResult := m.evaluator.Evaluate(qname, qtype, qclass, matchedTags, qctx.ClientIP)
		if !zoneResult.Matched {
			return next.ServeDNS(ctx, qctx)
		}

		// Destructive CHAOS endpoints (.cache.clear / .dnscrypt.clear) flush
		// the cache and reset keys — any client that can reach a listener
		// could otherwise trigger them remotely. Loopback-only.
		if isDestructiveChaosName(qname) && (qctx.ClientIP == nil || !qctx.ClientIP.IsLoopback()) {
			// Sampled: any remote client can spam these names, each carrying
			// attacker-chosen context — a per-packet Warn is a log-flood
			// vector (2026-09 C-M2).
			if n := chaosDenialCount.Add(1); n%config.DefaultChaosDenialWarnEvery == 1 {
				log.Warnf("SECURITY: denying destructive CHAOS query %s from non-loopback client %s [%dth denial]", qname, qctx.ClientIP, n)
			}
			response := handler.BuildResponseMsg(qctx.Req)
			response.Rcode = dns.RcodeRefused
			qctx.Res = response
			return nil
		}

		log.Debugf("ZONE: matched rule for %s -> domain=%s rcode=%d", qname, zoneResult.Domain, zoneResult.Rcode)

		rec := cache.AcquireRequestRecord()
		rec.Qname = qname
		rec.Qtype = qtype
		rec.Qclass = qclass
		rec.Protocol = qctx.Protocol
		rec.Result = "zone"
		rec.Rcode = zoneResult.Rcode
		m.cache.RecordRequest(rec)
		cache.ReleaseRequestRecord(rec)

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
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorForgedAnswer, ExtraText: ""}
			qctx.Res = response
			return nil
		}

		// Successful zone response with records.
		hasRecords := len(zoneResult.Answer) > 0 || len(zoneResult.Authority) > 0 || len(zoneResult.Additional) > 0
		if hasRecords {
			elapsed := ttl.Elapsed(zoneResult.CreatedAt)
			response := handler.BuildResponseMsg(qctx.Req)
			// Zone rules are served authoritatively by this server — the AA
			// bit is required for RESINFO responses (RFC 9606 §3: AA MUST be
			// set on the resolver's own records) and matches the semantics
			// of local policy data (R2 finding).
			response.Authoritative = true
			response.Answer = ttl.DeductElapsedCyclical(zoneResult.Answer, elapsed)
			response.Ns = ttl.DeductElapsedCyclical(zoneResult.Authority, elapsed)
			response.Extra = ttl.DeductElapsedCyclical(zoneResult.Additional, elapsed)
			response.Rcode = dns.RcodeSuccess
			// RFC 1034 §4.3.3: a wildcard match serves the stored records
			// with the QUERIED name as owner — the wildcard rule's records
			// carry the literal "*.<domain>" owner (the stored Domain has no
			// "*." prefix — LoadRules strips it), which must be rewritten
			// before serving (R3-M7).
			if zoneResult.Wildcard {
				wildOwner := wildcardPrefix + zoneResult.Domain
				response.Answer = rewriteOwnerNames(response.Answer, wildOwner, qname)
				response.Ns = rewriteOwnerNames(response.Ns, wildOwner, qname)
				response.Extra = rewriteOwnerNames(response.Extra, wildOwner, qname)
			}
			// Operator-configured zone rules are legitimate policy, not
			// security forgeries — omit EDE so clients don't misclassify.
			qctx.Res = response
			log.Debugf("RESULT: %s %s | rcode=NOERROR (zone), answer=%d", qname, dns.TypeToString[qtype], len(zoneResult.Answer))
			return nil
		}

		// Records-less rule (Rcode=0): pass through to normal resolution.
		// The question is NOT rewritten here — the old wildcard-rewrite
		// branch set OriginalName/RewrittenName without ever mutating the
		// question, so the rewrite was dead code and the query was dropped
		// (CacheStore's ZoneMatched gate skipped response construction).
		// Records-less rules now behave as pure pass-through (C3).
		return next.ServeDNS(ctx, qctx)
	})
}
