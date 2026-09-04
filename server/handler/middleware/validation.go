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

// maxWireNameLen is the RFC 1035 §2.3.4 wire-form name limit (255 octets
// including the root octet).
const maxWireNameLen = 255

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
			if log.IsDebug() {
				log.Debugf("QUERY: rejecting nil/empty question with FORMERR")
			}
			msg := pool.DefaultMessage.Get()
			if qctx.Req != nil {
				dnsutil.SetReply(msg, qctx.Req)
			} else {
				msg.Response = true
			}
			msg.Rcode = dns.RcodeFormatError
			// RFC 8914 §4.1: code 0 (Other) SHOULD carry ExtraText.
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: "malformed query"}
			qctx.Res = msg
			return nil
		}

		// Reject non-standard opcodes (RFC 1035 §4.1.1 — opcode field).
		if req := qctx.Req; req.Opcode != dns.OpcodeQuery {
			if log.IsDebug() {
				log.Debugf("QUERY: rejecting non-query opcode %d with NOTIMP", req.Opcode)
			}
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, req)
			msg.Rcode = dns.RcodeNotImplemented
			qctx.Res = msg
			return nil
		}

		// Only a single question is handled anywhere downstream (Question[0]
		// indexing, SetReply echoing one question) — a multi-question query
		// could smuggle an invalid name or ANY/AXFR/IXFR type past this gate.
		if len(qctx.Req.Question) != 1 {
			if log.IsDebug() {
				log.Debugf("QUERY: rejecting multi-question query (%d questions) with FORMERR", len(qctx.Req.Question))
			}
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, qctx.Req)
			msg.Rcode = dns.RcodeFormatError
			qctx.Res = msg
			return nil
		}

		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)

		// Allow CHAOS class for ZJDNS introspection queries (stats, etc.).
		// Other non-IN classes are rejected per RFC 6895 §3.2.
		if qd.Header().Class != dns.ClassINET && qd.Header().Class != dns.ClassCHAOS {
			if log.IsDebug() {
				log.Debugf("QUERY: rejecting non-IN/CHAOS class %d for %s with REFUSED", qd.Header().Class, qname)
			}
			msg := pool.DefaultMessage.Get()
			dnsutil.SetReply(msg, qctx.Req)
			msg.Rcode = dns.RcodeRefused
			qctx.Res = msg
			return nil
		}

		// Compare against the RFC 1035 wire-form limit (255 octets incl. the
		// root): the presentation length overcounts \DDD escapes and the
		// trailing dot, falsely rejecting valid max-length names, and
		// undercounts nothing — an invalid name with many labels passes a
		// presentation check while exceeding 255 wire octets.
		// NXNAME (128) is a Meta-TYPE signalling compact denial (RFC 9824
		// §3.5): a resolver MUST NOT forward or iterate it — rejected here.
		// ANY is deliberately NOT rejected: RFC 8482 minimal responses are
		// synthesized by the Any middleware (after zone rules run).
		wireLen := wireNameLength(qname)
		if wireLen >= 0 && wireLen <= maxWireNameLen &&
			qtype != dns.TypeNXNAME &&
			qtype != dns.TypeAXFR &&
			qtype != dns.TypeIXFR &&
			dnsutil.IsName(qname) {
			return next.ServeDNS(ctx, qctx)
		}

		// Build REFUSED response with EDE.  A name whose wire length is
		// invalid (a >63-byte label fails wireNameLength while passing the
		// presentation-form checks) is an invalid-domain rejection, not an
		// unsupported-qtype one (H-L10).
		if len(qname) > config.MaxDomainLength || !dnsutil.IsName(qname) || wireNameLength(qname) < 0 {
			if log.IsDebug() {
				log.Debugf("QUERY: rejecting invalid domain %q (len=%d) with REFUSED", qname, len(qname))
			}
		} else {
			if log.IsDebug() {
				log.Debugf("QUERY: rejecting unsupported query type %s for %s with REFUSED", dns.TypeToString[qtype], qname)
			}
		}
		msg := pool.DefaultMessage.Get()
		dnsutil.SetReply(msg, qctx.Req)
		// RFC 9824 §3.5: NXNAME (Meta-TYPE 128) queries MUST be answered with
		// FORMERR; AXFR/IXFR remain REFUSED (transfer rejection).
		if qtype == dns.TypeNXNAME {
			msg.Rcode = dns.RcodeFormatError
		} else {
			msg.Rcode = dns.RcodeRefused
		}

		if len(qname) > config.MaxDomainLength || !dnsutil.IsName(qname) {
			// RFC 8914 §4.1: code 0 (Other) SHOULD carry ExtraText.
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorOther, ExtraText: "invalid domain name"}
		} else {
			// EDE 30 (Invalid Query Type, IANA registry) — the modern code for
			// unsupported qtypes; Cloudflare 1.1.1.1 uses it for the same case.
			qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorInvalidQueryType, ExtraText: ""}
		}
		qctx.Res = msg
		return nil
	})
}
