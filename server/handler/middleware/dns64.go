package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
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

		if qctx.Qtype != dns.TypeAAAA {
			return err
		}
		// RFC 6147 §5.1.5: synthesis is needed when the AAAA response
		// carries no AAAA record — including CNAME/DNAME chains without a
		// terminating AAAA (the common CDN/ALIAS shape); skipping those
		// leaves IPv6-only clients with NODATA (2026-09 H-M3).  A real
		// AAAA answer needs no synthesis; §5.1.2's "treat other rcodes as
		// empty answer" is left alone — SERVFAIL/timeout synthesis from a
		// failed lookup would mask genuine outages.
		if qr.Err != nil {
			return err
		}
		for _, rr := range qr.Answer {
			if _, ok := rr.(*dns.AAAA); ok {
				return err
			}
		}

		// qctx.Qname is canonical (the form cache keys require) — cache.Get
		// and store.Set both key on it directly.
		qname := qctx.Qname
		qclass := qctx.Qclass
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
			if entry, found, isExpired := m.store.Get(qname, dns.TypeA, qclass, ecsOpt); found {
				if !isExpired && entry.Unpack() == nil && len(entry.Answer) > 0 {
					aqr = &resolver.QueryResult{
						Answer: entry.Answer, Authority: entry.Authority, Additional: entry.Additional,
						Validated: entry.Validated,
					}
				}
				// Every found path — usable, empty, unpack failure or expired
				// — releases the pool-owned TTL-offset slice (H-L1).
				cache.ReleaseTTLOffsets(entry.TTLOffsets)
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
			// The served content now derives from the A lookup — the AAAA
			// response's AD assertion must not carry over to synthesized
			// records (RFC 6147: synthesized data is not validated as-is).
			qr.Validated = qr.Validated && aqr.Validated
			if log.IsDebug() {
				log.Debugf("DNS64: synthesized %d AAAA records for %s", len(qr.Answer), qname)
			}
		} else {
			reason := "no A answers"
			if aqr == nil {
				reason = "A lookup unavailable"
			} else if aqr.Err != nil {
				reason = aqr.Err.Error()
			}
			if log.IsDebug() {
				log.Debugf("DNS64: skipping synthesis for %s (qtype=%d): %s", qname, qctx.Qtype, reason)
			}
		}

		return err
	})
}
