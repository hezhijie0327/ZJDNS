package middleware

import (
	"context"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
)

// Resolution is the terminal handler.  It performs upstream or
// recursive DNS resolution via the Resolver interface, with singleflight
// deduplication of concurrent identical queries (handler.PendingRequests).
//
// Resolution is the innermost middleware — it ignores the next
// handler and always produces a resolution result.
type Resolution struct {
	resolver handler.Resolver
	pending  *handler.PendingRequests
}

// Wrap implements Middleware.  The next handler is ignored — this middleware
// is terminal.
func (m *Resolution) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Guard against nil resolver.
		if m.resolver == nil {
			log.Warnf("RESOLVER: resolver not set — returning SERVFAIL")
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeServerFailure
			qctx.Res = msg
			return nil
		}

		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)
		qclass := qd.Header().Class
		ecsOpt := qctx.ECSOpt
		dnssecOK := qctx.ClientRequestedDNSSEC

		question := handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}

		// Singleflight dedup: if another goroutine is already resolving the
		// same query, wait for its result.
		if m.pending != nil {
			if qr, follower := m.pending.Join(qname, qtype, qclass, ecsOpt, dnssecOK); follower {
				qctx.ResolutionResult = qr
				qctx.Resolved = true
				if qr.Err != nil {
					qctx.ResolutionError = true
				}
				return nil
			}
			// Ensure Done is always called — even on panic — so the pending
			// map entry is cleaned up and followers are unblocked.
			// Clone records before sharing with followers to prevent
			// concurrent modification of shared RR headers (e.g. zone rule
			// domain rewrite via restoreDomain).
			defer func() {
				m.pending.Done(qname, qtype, qclass, ecsOpt, dnssecOK,
					cloneQueryResult(qctx.ResolutionResult))
			}()
		}

		log.Debugf("RESOLVER: resolving %s %s", qname, dns.TypeToString[qtype])
		qr := m.resolver.Query(ctx, question, ecsOpt)

		qctx.ResolutionResult = qr
		qctx.Resolved = true
		if qr.Err != nil {
			qctx.ResolutionError = true
		}
		return nil
	})
}

// cloneQueryResult returns a deep copy of qr where the Answer, Authority,
// and Additional slices and their RRs are cloned so the result can be safely
// shared with singleflight followers without racing on RR header fields
// (e.g. zone rule domain rewrite via restoreDomain).
func cloneQueryResult(qr *resolver.QueryResult) *resolver.QueryResult {
	if qr == nil {
		return nil
	}
	cloned := *qr
	cloned.Answer = cloneRRs(qr.Answer)
	cloned.Authority = cloneRRs(qr.Authority)
	cloned.Additional = cloneRRs(qr.Additional)
	return &cloned
}

// cloneRRs returns a deep copy of a slice of RRs. Each RR is cloned via
// its Clone method, which copies the header and record data.
func cloneRRs(rrs []dns.RR) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = rr.Clone()
	}
	return out
}
