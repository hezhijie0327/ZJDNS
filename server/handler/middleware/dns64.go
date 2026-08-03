package middleware

import (
	"context"
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
}

// hasAAAA reports whether the answer contains an AAAA record.
func hasAAAA(answer []dns.RR) bool {
	for _, rr := range answer {
		if rr != nil && dns.RRToType(rr) == dns.TypeAAAA {
			return true
		}
	}
	return false
}

// Wrap implements Wrapper.
func (m *DNS64) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Let resolution complete first.
		err := next.ServeDNS(ctx, qctx)

		if m.synthesizer == nil || qctx.ResolutionResult == nil {
			return err
		}

		qr := qctx.ResolutionResult
		if qr.Err != nil {
			return err
		}

		// The pre-extracted context fields are the single source of truth
		// for the question (qctx.Req.Question[0] is an RR in this fork).
		qtype := qctx.Qtype
		// Suppress synthesis only when the AAAA answer actually CONTAINS AAAA
		// records: a CNAME-only chain (final target without AAAA but with A)
		// is exactly the RFC 6147 §5.1.2 case DNS64 must handle.
		if qtype != dns.TypeAAAA || hasAAAA(qr.Answer) {
			return err
		}

		// RFC 6147 §5.5: with the CD bit set the client validates for
		// itself and synthesis MUST NOT happen — skip the A lookup entirely
		// instead of performing it only to have the synthesizer refuse.
		if qctx.Req.CheckingDisabled {
			return err
		}

		qname := qctx.Qname
		qclass := qctx.Req.Question[0].Header().Class
		ecsOpt := qctx.ECSOpt
		dnssecOK := qctx.ClientRequestedDNSSEC

		// Perform A-record lookup for DNS64 synthesis.
		var aqr *resolver.QueryResult
		if m.pending != nil {
			aqr = m.pending.DoJoin(ctx, qname, dns.TypeA, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
				aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
				return m.resolver.Query(ctx, aQuestion, ecsOpt)
			})
		} else {
			aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
			aqr = m.resolver.Query(ctx, aQuestion, ecsOpt)
		}

		if aqr != nil && aqr.Err == nil && len(aqr.Answer) > 0 {
			// RFC 6147 §5.5: with the CD bit set the client validates for
			// itself — the synthesizer refuses (it would destroy the
			// signature chain). Without CD, synthesis proceeds.
			//
			// Clone the QueryResult before mutating it: singleflight
			// followers share one cloned result across their chains, and a
			// concurrent follower's CacheStore reads qr.Answer/Validated
			// while this goroutine rewrites them.
			cloned := *qr
			cloned.Answer, cloned.Authority, cloned.Additional = m.synthesizer.Synthesize(
				qr.Answer, qr.Authority, qr.Additional,
				aqr.Answer, aqr.Authority, aqr.Additional, qctx.Req.CheckingDisabled)
			// RFC 6147 §5.5: the synthesized AAAA's DNSSEC status is that
			// of the A lookup it derives from — set AD only when those
			// records validated; never assert AD for unverified data.
			cloned.Validated = aqr.Validated
			qctx.ResolutionResult = &cloned
			log.Debugf("DNS64: synthesized %d AAAA records for %s", len(cloned.Answer), qname)
		} else if aqr != nil && aqr.Err != nil {
			// An upstream failure must not be masked as NODATA (and cached
			// as such). Debug: this fires on every AAAA query while the
			// upstream is down — per-query errors are recorded by the
			// resolver's own error paths.
			log.Debugf("DNS64: A lookup failed for %s: %v", qname, aqr.Err)
		}

		return err
	})
}
