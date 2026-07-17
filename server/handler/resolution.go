package handler

import (
	"context"
	"zjdns/internal/log"

	"codeberg.org/miekg/dns"
)

// ResolutionMiddleware is the terminal handler.  It performs upstream or
// recursive DNS resolution via the Resolver interface, with singleflight
// deduplication of concurrent identical queries (PendingRequests).
//
// ResolutionMiddleware is the innermost middleware — it ignores the next
// handler and always produces a resolution result.
type ResolutionMiddleware struct {
	resolver Resolver
	pending  *PendingRequests
}

// Wrap implements Middleware.  The next handler is ignored — this middleware
// is terminal.
func (m *ResolutionMiddleware) Wrap(next QueryHandler) QueryHandler {
	return QueryHandlerFunc(func(ctx context.Context, qctx *QueryContext) error {
		// Guard against nil resolver.
		if m.resolver == nil {
			log.Warnf("RESOLVER: resolver not set — returning SERVFAIL")
			msg := buildResponseMsg(qctx.Req)
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

		question := Question{Name: qname, Qtype: qtype, Qclass: qclass}

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
		}

		log.Debugf("RESOLVER: resolving %s %s", qname, dns.TypeToString[qtype])
		qr := m.resolver.Query(ctx, question, ecsOpt)

		// Notify followers.
		if m.pending != nil {
			m.pending.Done(qname, qtype, qclass, ecsOpt, dnssecOK, qr)
		}

		qctx.ResolutionResult = qr
		qctx.Resolved = true
		if qr.Err != nil {
			qctx.ResolutionError = true
		}
		return nil
	})
}
