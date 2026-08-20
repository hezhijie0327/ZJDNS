package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// DNS64 synthesises AAAA records from A-record answers when the
// original AAAA query returned no answer records and DNS64 is configured.
// It wraps the Resolution middleware — after resolution completes, it
// checks if DNS64 synthesis is needed and performs a secondary A lookup.
type DNS64 struct {
	synthesizer *dns64.Synthesizer
	resolver    handler.Resolver
	pending     *handler.PendingRequests
	store       cache.Store // response cache for the secondary A lookup
}

// Wrap implements Wrapper.
func (m *DNS64) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Let resolution complete first.
		err := next.ServeDNS(ctx, qctx)

		if m.synthesizer == nil || !qctx.Resolved {
			return err
		}

		qr := qctx.ResolutionResult
		if qr.Err != nil {
			return err
		}

		qd := qctx.Req.Question[0]
		qtype := dns.RRToType(qd)
		if qtype != dns.TypeAAAA || len(qr.Answer) > 0 {
			return err
		}

		// Canonicalize: cache.Get requires a canonical qname (Set stores the
		// canonical form) — the raw wire name may carry mixed case, which
		// would miss every time (regression of the removed internal
		// canonicalization).
		qname := dnsutil.Canonical(qd.Header().Name)
		qclass := qd.Header().Class
		ecsOpt := qctx.ECSOpt
		dnssecOK := qctx.ClientRequestedDNSSEC

		// Perform A-record lookup for DNS64 synthesis. Check the response
		// cache first: CacheLookup already ran upstream of this middleware,
		// and going straight to the resolver would bypass the cache — a full
		// upstream query per AAAA miss.
		var aqr *resolver.QueryResult
		if m.store != nil {
			// Skip expired entries: synthesizing from a stale A answer would
			// serve it with the full stored TTL and no stale-answer EDE
			// (M-cache).
			if entry, found, isExpired := m.store.Get(qname, dns.TypeA, qclass, ecsOpt); found && !isExpired {
				if entry.Unpack() == nil && len(entry.Answer) > 0 {
					cache.ReleaseTTLOffsets(entry.TTLOffsets)
					aqr = &resolver.QueryResult{
						Answer: entry.Answer, Authority: entry.Authority, Additional: entry.Additional,
						Validated: entry.Validated,
					}
				} else {
					// Unpack failed or empty answers — the entry is dropped;
					// still return the pool-owned TTL-offset slice (M-pool).
					cache.ReleaseTTLOffsets(entry.TTLOffsets)
				}
			}
		}
		if aqr == nil {
			if m.pending != nil {
				aqr = m.pending.DoJoin(qname, dns.TypeA, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
					aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
					return m.resolver.Query(ctx, aQuestion, ecsOpt)
				})
			} else {
				aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
				aqr = m.resolver.Query(ctx, aQuestion, ecsOpt)
			}
		}

		if aqr != nil && aqr.Err == nil && len(aqr.Answer) > 0 {
			qr.Answer, qr.Authority, qr.Additional = m.synthesizer.Synthesize(
				qr.Authority, aqr.Answer, aqr.Authority, aqr.Additional,
			)
			log.Debugf("DNS64: synthesized %d AAAA records for %s", len(qr.Answer), qname)
		} else {
			reason := "no A answers"
			if aqr == nil {
				reason = "A lookup unavailable"
			} else if aqr.Err != nil {
				reason = aqr.Err.Error()
			}
			log.Debugf("DNS64: skipping synthesis for %s (qtype=%d): %s", qname, qtype, reason)
		}

		return err
	})
}
