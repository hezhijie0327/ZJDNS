package middleware

import (
	"context"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/pool"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Validation rejects malformed DNS queries (domain too long,
// invalid labels, ANY/AXFR/IXFR query types) before any other processing.
// Invalid queries receive a REFUSED response with an EDE error code.
type Validation struct{}

// Wrap implements Middleware.
func (m *Validation) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		if qctx.Req == nil || len(qctx.Req.Question) == 0 {
			msg := pool.DefaultMessage.Get()
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}

		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)

		if len(qname) <= config.MaxDomainLength &&
			qtype != dns.TypeANY &&
			qtype != dns.TypeAXFR &&
			qtype != dns.TypeIXFR &&
			zdnsutil.IsValidDomainLabels(qname) {
			return next.ServeDNS(ctx, qctx)
		}

		// Build REFUSED response with EDE.
		msg := pool.DefaultMessage.Get()
		dnsutil.SetReply(msg, qctx.Req)
		msg.Rcode = dns.RcodeRefused

		if len(qname) > config.MaxDomainLength || !zdnsutil.IsValidDomainLabels(qname) {
			qctx.EDE = edns.NewEDEOption(edns.EDECodeInvalidData, "")
		} else {
			qctx.EDE = edns.NewEDEOption(edns.EDECodeNotSupported, "")
		}
		qctx.Res = msg
		return nil
	})
}
