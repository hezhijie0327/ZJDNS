package resolver

import (
	"strings"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// attachMQType attaches MQTYPE-Query for the configured types minus the
// primary QTYPE (§3.3: data types only, non-empty remainder).
func attachMQType(msg *dns.Msg, mqtype []uint16, primary uint16) {
	if len(mqtype) == 0 {
		return
	}
	if _, meta := config.MQTypeMetaTypes[primary]; meta {
		return
	}
	var buf [config.DefaultMQTypeMaxQTx]uint16
	attach := buf[:0]
	for _, t := range mqtype {
		if t != primary {
			attach = append(attach, t)
		}
	}
	if len(attach) == 0 {
		return
	}
	msg.Pseudo = append(msg.Pseudo, &dns.MQQUERY{Types: attach})
}

// parseMQResponse validates a response's MQTYPE options per §3.5:
// MQTYPE-Query in a response → unsupported (nil, false); duplicated
// MQTYPE-Response or a QTx duplicating another QTx/primary → invalid (true).
func parseMQResponse(resp *dns.Msg) (mqr *dns.MQRESPONSE, invalid bool) {
	for _, rr := range resp.Pseudo {
		switch opt := rr.(type) {
		case *dns.MQRESPONSE:
			if mqr != nil {
				return nil, true // more than one MQTYPE-Response
			}
			mqr = opt
		case *dns.MQQUERY:
			return nil, false // MQTYPE-Query in a response — unsupported
		}
	}
	if mqr == nil {
		return nil, false
	}
	seen := make(map[uint16]struct{}, len(mqr.Types)+1)
	if len(resp.Question) > 0 {
		seen[dns.RRToType(resp.Question[0])] = struct{}{}
	}
	for _, t := range mqr.Types {
		if _, dup := seen[t]; dup {
			return nil, true // QTx duplicates the primary or another QTx
		}
		seen[t] = struct{}{}
	}
	return mqr, false
}

// warmFromMQResponse caches the merged records of the completed QTx types
// (§3.5: a listed QTx was completely answered — positive records with their
// RRSIGs, or a denial with SOA proofs).
func (r *Resolver) warmFromMQResponse(resp *dns.Msg, qname string, qclass uint16, mqr *dns.MQRESPONSE, ecs *edns.ECSOption, validated bool) {
	if r.cache == nil || resp == nil || mqr == nil || resp.Truncated || resp.Rcode == dns.RcodeServerFailure {
		return
	}
	qname = dnsutil.Canonical(qname)
	hasSOA := false
	for _, rr := range resp.Ns {
		if dns.RRToType(rr) == dns.TypeSOA {
			hasSOA = true
			break
		}
	}
	for _, qt := range mqr.Types {
		answer, found := filterMQTypeRecords(resp.Answer, qname, qt)
		switch {
		case found:
			r.cache.Set(qname, qt, qclass, ecs, answer, nil, nil, validated, resp.Rcode)
		case hasSOA:
			r.cache.Set(qname, qt, qclass, ecs, nil, resp.Ns, nil, validated, resp.Rcode)
		default:
			log.Debugf("MQTYPE: %s %s in MQTYPE-Response but not cacheable (no records, no SOA denial)", qname, dns.TypeToString[qt])
		}
	}
}

// filterMQTypeRecords returns the owner==qname records of one bundled type
// (records of qt, or RRSIGs covering qt).
func filterMQTypeRecords(rrs []dns.RR, qname string, qt uint16) ([]dns.RR, bool) {
	var out []dns.RR
	for _, rr := range rrs {
		h := rr.Header()
		if !strings.EqualFold(h.Name, qname) {
			continue
		}
		switch t := dns.RRToType(rr); t {
		case qt:
			out = append(out, rr)
		case dns.TypeRRSIG:
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == qt {
				out = append(out, rr)
			}
		}
	}
	return out, len(out) > 0
}

// stripMQBundled removes the merged bundled-type records (and their RRSIGs)
// from the answer; CNAME-chain records (owner != qname) are untouched.
func stripMQBundled(answer []dns.RR, qname string, mqtype []uint16) []dns.RR {
	if len(answer) == 0 || len(mqtype) == 0 {
		return answer
	}
	strip := make(map[uint16]struct{}, len(mqtype))
	for _, t := range mqtype {
		strip[t] = struct{}{}
	}
	out := answer[:0]
	for _, rr := range answer {
		h := rr.Header()
		if !strings.EqualFold(h.Name, qname) {
			out = append(out, rr)
			continue
		}
		t := dns.RRToType(rr)
		if _, ok := strip[t]; ok {
			continue
		}
		if t == dns.TypeRRSIG {
			if sig, ok := rr.(*dns.RRSIG); ok {
				if _, covered := strip[sig.TypeCovered]; covered {
					continue
				}
			}
		}
		out = append(out, rr)
	}
	return out
}

// hasMQQUERY reports whether the pseudo-section carries an MQTYPE-Query.
func hasMQQUERY(pseudo []dns.RR) bool {
	for _, rr := range pseudo {
		if _, ok := rr.(*dns.MQQUERY); ok {
			return true
		}
	}
	return false
}

// removeMQQUERY returns pseudo without the MQTYPE-Query option (RFC 10029
// fallback: retry without the option when the query was dropped).
func removeMQQUERY(pseudo []dns.RR) []dns.RR {
	out := pseudo[:0]
	for _, rr := range pseudo {
		if _, ok := rr.(*dns.MQQUERY); ok {
			continue
		}
		out = append(out, rr)
	}
	return out
}
