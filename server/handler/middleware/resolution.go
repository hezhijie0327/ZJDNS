package middleware

import (
	"context"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// ResolutionMiddleware is the terminal handler.  It performs upstream or
// recursive DNS resolution via the Resolver interface, with singleflight
// deduplication of concurrent identical queries (handler.PendingRequests).
//
// ResolutionMiddleware is the innermost middleware — it ignores the next
// handler and always produces a resolution result.
type ResolutionMiddleware struct {
	resolver handler.Resolver
	pending  *handler.PendingRequests
}

// Wrap implements Middleware.  The next handler is ignored — this middleware
// is terminal.
func (m *ResolutionMiddleware) Wrap(next handler.QueryHandler) handler.QueryHandler {
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
		}

		// Ensure Done is always called — even on panic — so the pending
		// map entry is cleaned up and followers are unblocked.
		if m.pending != nil {
			defer func() {
				m.pending.Done(qname, qtype, qclass, ecsOpt, dnssecOK, qctx.ResolutionResult)
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
