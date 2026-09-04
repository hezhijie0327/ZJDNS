package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// Any answers QTYPE=ANY queries with the RFC 8482 minimal response: a single
// HINFO record signalling that the server implements RFC 8482 (§2).  Serving
// the full zone content for ANY is a classic amplification vector; a minimal
// response keeps the semantic ("anything is fine, ask for specifics") without
// the abuse.
//
// It runs after the Zone middleware so operator-defined zone rules for ANY
// queries take precedence; only unmatched ANY queries reach this short-circuit.
type Any struct {
	store cache.Store
}

// Wrap implements Wrapper.
func (m *Any) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		if qctx.Qtype != dns.TypeANY {
			return next.ServeDNS(ctx, qctx)
		}
		qname := qctx.Qname

		// RFC 8482 §4.2: "RFC8482" as the CPU field, empty OS — the same
		// minimal response Cloudflare and BIND serve.
		msg := handler.BuildResponseMsg(qctx.Req)
		msg.Answer = []dns.RR{&dns.HINFO{
			Hdr: dns.Header{
				Name:  qname,
				TTL:   config.DefaultHINFOTTL,
				Class: dns.ClassINET,
			},
			Cpu: "RFC8482", Os: "",
		}}
		qctx.Res = msg
		// Record the short-circuit like Zone/PTR do — ANY answers must
		// appear in query_stats/query_log (R3-M21).
		if m.store != nil {
			rec := cache.AcquireRequestRecord()
			rec.Qname = qname
			rec.Qtype = dns.TypeANY
			rec.Qclass = qctx.Qclass
			rec.Protocol = qctx.Protocol
			rec.Result = "any"
			rec.Rcode = dns.RcodeSuccess
			m.store.RecordRequest(rec)
			cache.ReleaseRequestRecord(rec)
		}
		if log.IsDebug() {
			log.Debugf("ANY: serving RFC 8482 minimal response for %s", qname)
		}
		return nil
	})
}
