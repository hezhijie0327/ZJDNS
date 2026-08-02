package middleware

import (
	"context"
	"strings"
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

// wireNameLength returns the RFC 1035 §2.3.4 wire-form length (per-label
// length octets + label octets + root octet) of a presentation-form FQDN,
// or -1 when the name cannot be a valid wire name. Escaped octets (\DDD or
// \X) count as one octet.
func wireNameLength(name string) int {
	if !strings.HasSuffix(name, ".") {
		return -1
	}
	total := 1 // root octet
	labelLen := 0
	// Iterate the FULL name: the trailing dot terminates the final label.
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c == '\\' && i+1 < len(name):
			i++ // escaped octet counts as one wire octet
			labelLen++
		case c == '.':
			if labelLen == 0 || labelLen > 63 {
				return -1
			}
			total += 1 + labelLen // length octet + label
			labelLen = 0
		default:
			labelLen++
		}
		if labelLen > 63 {
			return -1
		}
	}
	return total
}

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
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: ""}
			qctx.Res = msg
			qctx.Responded = true
			return nil
		}

		// Reject non-standard opcodes (RFC 6895 §3.1).
		if req := qctx.Req; req.Opcode != dns.OpcodeQuery {
			log.Debugf("QUERY: rejecting non-query opcode %d with NOTIMP", req.Opcode)
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, req)
			msg.Rcode = dns.RcodeNotImplemented
			qctx.Res = msg
			qctx.Responded = true
			return nil
		}

		// Only a single question is handled anywhere downstream (Question[0]
		// indexing, SetReply echoing one question) — a multi-question query
		// could smuggle an invalid name or ANY/AXFR/IXFR type past this gate.
		if len(qctx.Req.Question) != 1 {
			log.Debugf("QUERY: rejecting multi-question query (%d questions) with FORMERR", len(qctx.Req.Question))
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			qctx.Responded = true
			return nil
		}

		qname := qctx.Qname
		qtype := qctx.Qtype
		qclass := qctx.Qclass
		// Fallback for callers that don't go through handler.ServeDNS (e.g. tests).
		// Also trigger when Qclass is zero: a caller that sets Qname/Qtype but
		// not Qclass would otherwise be rejected (0 is neither IN nor CHAOS).
		if qname == "" || qclass == 0 {
			qd := qctx.Req.Question[0]
			qname = qd.Header().Name
			qtype = dns.RRToType(qd)
			qclass = qd.Header().Class
		}

		// Allow CHAOS class for ZJDNS introspection queries (stats, etc.).
		// Other non-IN classes are rejected per RFC 6895 §3.1.
		if qclass != dns.ClassINET && qclass != dns.ClassCHAOS {
			log.Debugf("QUERY: rejecting non-IN/CHAOS class %d for %s with REFUSED", qclass, qname)
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, qctx.Req)
			msg.Rcode = dns.RcodeRefused
			qctx.Res = msg
			qctx.Responded = true
			return nil
		}

		// Compare against the RFC 1035 wire-form limit (255 octets incl. the
		// root): the presentation length overcounts \DDD escapes and the
		// trailing dot, falsely rejecting valid max-length names, and
		// undercounts nothing — an invalid name with many labels passes a
		// presentation check while exceeding 255 wire octets.
		wireLen := wireNameLength(qname)
		// wireNameLength >= 0 already validates name structure (labels, length,
		// trailing dot) — dnsutil.IsName is redundant here.
		if wireLen >= 0 && wireLen <= 255 &&
			qtype != dns.TypeANY &&
			qtype != dns.TypeAXFR &&
			qtype != dns.TypeIXFR {
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
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: ""}
		} else {
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorNotSupported, ExtraText: ""}
		}
		qctx.Res = msg
		qctx.Responded = true
		return nil
	})
}
