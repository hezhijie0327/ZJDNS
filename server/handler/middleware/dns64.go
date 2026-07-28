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

		qname := qd.Header().Name
		qclass := qd.Header().Class
		ecsOpt := qctx.ECSOpt
		dnssecOK := qctx.ClientRequestedDNSSEC

		// Perform A-record lookup for DNS64 synthesis.
		var aqr *resolver.QueryResult
		if m.pending != nil {
			aqr = m.pending.DoJoin(qname, dns.TypeA, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
				aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
				return m.resolver.Query(ctx, aQuestion, ecsOpt)
			})
		} else {
			aQuestion := handler.Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
			aqr = m.resolver.Query(ctx, aQuestion, ecsOpt)
		}

		if aqr != nil && aqr.Err == nil && len(aqr.Answer) > 0 {
			qr.Answer, qr.Authority, qr.Additional = m.synthesizer.Synthesize(
				qr.Answer, qr.Authority, qr.Additional,
				aqr.Answer, aqr.Authority, aqr.Additional, qr.Validated)
			log.Debugf("DNS64: synthesized %d AAAA records for %s", len(qr.Answer), qname)
		}

		return err
	})
}
