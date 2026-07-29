package middleware

import (
	"context"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Validation rejects malformed DNS queries (domain too long,
// invalid labels, ANY/AXFR/IXFR query types) before any other processing.
// Invalid queries receive a REFUSED or FORMERR (for nil/empty questions)
// response with an EDE error code.
type Validation struct{}

// Wrap implements Wrapper.
func (m *Validation) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		if qctx.Req == nil || len(qctx.Req.Question) == 0 {
			log.Debugf("QUERY: rejecting nil/empty question with FORMERR")
			msg := pool.DefaultMessage.Get()
			if qctx.Req != nil {
				dnsutil.SetReply(msg, qctx.Req)
			} else {
				msg.Response = true
			}
			msg.Rcode = dns.RcodeFormatError
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorInvalidData, ExtraText: ""}
			qctx.Res = msg
			return nil
		}

		// Reject non-standard opcodes (RFC 6895 §3.1).
		if req := qctx.Req; req.Opcode != dns.OpcodeQuery {
			log.Debugf("QUERY: rejecting non-query opcode %d with NOTIMP", req.Opcode)
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, req)
			msg.Rcode = dns.RcodeNotImplemented
			qctx.Res = msg
			return nil
		}

		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)

		// Allow CHAOS class for ZJDNS introspection queries (stats, db.clear, etc.).
		// Other non-IN classes are rejected per RFC 6895 §3.1.
		if qd.Header().Class != dns.ClassINET && qd.Header().Class != dns.ClassCHAOS {
			log.Debugf("QUERY: rejecting non-IN/CHAOS class %d for %s with REFUSED", qd.Header().Class, qname)
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, qctx.Req)
			msg.Rcode = dns.RcodeRefused
			qctx.Res = msg
			return nil
		}

		if len(qname) <= config.MaxDomainLength &&
			qtype != dns.TypeANY &&
			qtype != dns.TypeAXFR &&
			qtype != dns.TypeIXFR &&
			dnsutil.IsName(qname) {
			return next.ServeDNS(ctx, qctx)
		}

		// Build REFUSED response with EDE.
		if len(qname) > config.MaxDomainLength || !dnsutil.IsName(qname) {
			log.Debugf("QUERY: rejecting invalid domain %q (len=%d) with REFUSED", qname, len(qname))
		} else {
			log.Debugf("QUERY: rejecting unsupported query type %s for %s with REFUSED", dns.TypeToString[qtype], qname)
		}
		msg := pool.DefaultMessage.Get()
		dnsutil.SetReply(msg, qctx.Req)
		msg.Rcode = dns.RcodeRefused

		if len(qname) > config.MaxDomainLength || !dnsutil.IsName(qname) {
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorInvalidData, ExtraText: ""}
		} else {
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorNotSupported, ExtraText: ""}
		}
		qctx.Res = msg
		return nil
	})
}
