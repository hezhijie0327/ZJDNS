package handler

import (
	"context"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// DNS64Middleware synthesises AAAA records from A-record answers when the
// original AAAA query returned no answer records and DNS64 is configured.
// It wraps the Resolution middleware — after resolution completes, it
// checks if DNS64 synthesis is needed and performs a secondary A lookup.
type DNS64Middleware struct {
	synthesizer *dns64.Synthesizer
	resolver    Resolver
	pending     *PendingRequests
}

// Wrap implements Middleware.
func (m *DNS64Middleware) Wrap(next QueryHandler) QueryHandler {
	return QueryHandlerFunc(func(ctx context.Context, qctx *QueryContext) error {
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
			if shared, follower := m.pending.Join(qname, dns.TypeA, qclass, ecsOpt, dnssecOK); follower {
				aqr = shared
			} else {
				aQuestion := Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
				aqr = m.resolver.Query(ctx, aQuestion, ecsOpt)
				m.pending.Done(qname, dns.TypeA, qclass, ecsOpt, dnssecOK, aqr)
			}
		} else {
			aQuestion := Question{Name: qname, Qtype: dns.TypeA, Qclass: qclass}
			aqr = m.resolver.Query(ctx, aQuestion, ecsOpt)
		}

		if aqr.Err == nil && len(aqr.Answer) > 0 {
			qr.Answer, qr.Authority, qr.Additional = m.synthesizer.Synthesize(
				qr.Answer, qr.Authority, qr.Additional,
				aqr.Answer, aqr.Authority, aqr.Additional, qr.Validated)
			qctx.DNS64Applied = true
			log.Debugf("DNS64: synthesized %d AAAA records for %s", len(qr.Answer), qname)
		}

		return err
	})
}
