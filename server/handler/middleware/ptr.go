package middleware

import (
	"context"
	"zjdns/cache"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// PTRMiddleware intercepts PTR-type reverse-lookup queries on cache miss
// and attempts to answer them from the ptr_map table.  If a match is found
// it short-circuits with a forged PTR response; otherwise it delegates to
// the next handler.
type PTRMiddleware struct {
	store cache.Store
}

// Wrap implements Middleware.
func (m *PTRMiddleware) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Only run on cache miss.
		if qctx.CacheHit {
			return next.ServeDNS(ctx, qctx)
		}

		qd := qctx.Req.Question[0]
		qtype := dns.RRToType(qd)
		if qtype != dns.TypePTR {
			return next.ServeDNS(ctx, qctx)
		}

		qname := qd.Header().Name
		qclass := qd.Header().Class

		ip := zdnsutil.ParseReverseDNSName(qname)
		if ip == nil {
			return next.ServeDNS(ctx, qctx)
		}

		results := m.store.ReverseLookup(ip.String())
		if len(results) == 0 {
			return next.ServeDNS(ctx, qctx)
		}

		records := make([]dns.RR, 0, len(results))
		for _, result := range results {
			records = append(records, zdnsutil.NewPTRRecord(qname, result.Name, result.TTL, qclass))
		}

		response := handler.BuildResponseMsg(qctx.Req)
		response.Answer = records
		response.Rcode = dns.RcodeSuccess
		qctx.Res = response
		qctx.CacheServed = true

		log.Debugf("PTR: reverse lookup %s -> %d records (from cache)", qname, len(records))
		return nil
	})
}
