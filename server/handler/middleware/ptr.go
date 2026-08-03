package middleware

import (
	"context"
	"zjdns/cache"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/server/handler"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
)

// PTR intercepts PTR-type reverse-lookup queries on cache miss
// and attempts to answer them from the ptr_map table.  If a match is found
// it short-circuits with a forged PTR response; otherwise it delegates to
// the next handler.
type PTR struct {
	store cache.Store
	stats *stats.Collector
}

// Wrap implements Wrapper.
func (m *PTR) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		// Only run on cache miss.
		if qctx.CacheEntry != nil {
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
		qctx.Responded = true
		qctx.CacheServed = true

		// CacheServed makes CacheStore skip stats — record the hit here so
		// PTR-served queries stay visible in the request distribution.
		if m.stats != nil {
			m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "ptr", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
		}

		log.Debugf("PTR: reverse lookup %s -> %d records (from cache)", qname, len(records))
		return nil
	})
}
