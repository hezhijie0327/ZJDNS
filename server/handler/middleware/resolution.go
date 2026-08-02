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
	// ctx is the server-scope lifecycle context: the singleflight work fn
	// runs under it so the leader's client disconnecting cannot cancel the
	// shared query all followers are waiting on.
	ctx context.Context
}

// Wrap implements Wrapper.  The next handler is ignored — this middleware
// is terminal.
func (m *Resolution) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Guard against nil resolver.
		if m.resolver == nil {
			log.Debugf("RECURSION: resolver not set — returning SERVFAIL")
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeServerFailure
			qctx.Res = msg
			qctx.Responded = true
			return nil
		}

		qname := qctx.Qname
		qtype := qctx.Qtype
		qclass := qctx.Qclass
		// Fallback for callers that don't go through handler.ServeDNS (e.g. tests).
		if qname == "" {
			qd := qctx.Req.Question[0]
			qname = qd.Header().Name
			qtype = dns.RRToType(qd)
			qclass = qd.Header().Class
		}
		ecsOpt := qctx.ECSOpt
		dnssecOK := qctx.ClientRequestedDNSSEC

		question := handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}

		// Singleflight dedup: if another goroutine is already resolving the
		// same query, wait for its result. The shared work runs under the
		// SERVER-scope ctx — the leader client's disconnect must not cancel
		// the resolution all followers are waiting on.
		if m.pending != nil {
			log.Debugf("RECURSION: resolving %s %s", qname, dns.TypeToString[qtype])
			qr := m.pending.DoJoin(ctx, qname, qtype, qclass, ecsOpt, dnssecOK, func() *resolver.QueryResult {
				return m.resolver.Query(m.ctx, question, ecsOpt)
			})
			if qr == nil {
				// A nil result (e.g. an evicted singleflight follower) must
				// not leave the client with no response at all.
				msg := handler.BuildResponseMsg(qctx.Req)
				msg.Rcode = dns.RcodeServerFailure
				qctx.Res = msg
				qctx.Responded = true
				return nil
			}
			qctx.ResolutionResult = qr
			if qr.Err != nil {
				qctx.ResolutionError = true
			}
			return nil
		}

		log.Debugf("RECURSION: resolving %s %s", qname, dns.TypeToString[qtype])
		qr := m.resolver.Query(ctx, question, ecsOpt)
		if qr == nil {
			msg := handler.BuildResponseMsg(qctx.Req)
			msg.Rcode = dns.RcodeServerFailure
			qctx.Res = msg
			qctx.Responded = true
			return nil
		}

		qctx.ResolutionResult = qr
		if qr.Err != nil {
			qctx.ResolutionError = true
		}
		return nil
	})
}
