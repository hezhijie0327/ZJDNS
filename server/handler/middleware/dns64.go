package middleware

import (
	"context"
	"zjdns/internal/dns64"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// DNS64 synthesises AAAA records from A-record answers when the
// original AAAA query returned no answer records and DNS64 is configured.
// It wraps the Resolution middleware — after resolution completes, it
// checks if DNS64 synthesis is needed and performs a secondary A lookup.
type DNS64 struct {
	synthesizer *dns64.Synthesizer
	secondary   *handler.Secondary
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

		// Perform the secondary A lookup through the shared cache-first /
		// singleflight helper.  A cached NODATA answer (empty Answer)
		// short-circuits the lookup — no upstream re-query per AAAA miss.
		aqr := m.secondary.Lookup(ctx, qname, dns.TypeA, qclass, ecsOpt, dnssecOK)

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
