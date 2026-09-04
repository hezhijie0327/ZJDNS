package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/server/handler"

	"codeberg.org/miekg/dns"
)

// CacheLookup checks the response cache before the resolver runs.
// Three outcomes:
//   - Fresh hit: builds the response and short-circuits.
//   - Expired but can serve stale: serves stale, refresh strategy delegated
//     to the refreshCoordinator.
//   - Miss or expired-and-cannot-serve: delegates to next.
type CacheLookup struct {
	store       cache.Store
	refresh     *refreshCoordinator
	preferStale bool
}

// Wrap implements Wrapper.
func (m *CacheLookup) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
		qname := qctx.Qname
		qtype := qctx.Qtype
		qclass := qctx.Qclass
		ecsOpt := qctx.ECSOpt

		entry, found, isExpired := m.store.Get(qname, qtype, qclass, ecsOpt)
		if !found {
			return next.ServeDNS(ctx, qctx)
		}

		// Fresh hit — serve immediately.
		if !isExpired {
			qctx.Res = buildCacheResponse(qctx, entry, false)
			qctx.Result = "hit" // journal rcode comes from the served response (negative-cache NXDOMAIN → 3)

			// Prefetch if TTL is below threshold.  Gate order matters: the
			// in-flight check (tryStart) runs BEFORE ShouldStart — the
			// cooldown's timestamp is a side effect, and burning it on a
			// refresh that never starts throttles the key for nothing (H-L9).
			if m.refresh.canStart() && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) &&
				m.refresh.tryStart(qname, qtype, qclass, ecsOpt) &&
				m.refresh.cooldown != nil && m.refresh.cooldown.ShouldStart(qname, qtype, log.NowUnixNano(), config.DefaultPrefetchThrottleInterval.Nanoseconds()) {
				m.refresh.spawnPrefetch("prefetch fresh-hit", qname, qtype, qclass, ecsOpt)
			}
			return nil
		}

		// Expired.

		// Can serve stale.
		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			qctx.Res = buildCacheResponse(qctx, entry, true)

			// PreferStale: return stale immediately, refresh in background.
			if m.preferStale && m.refresh.canStart() {
				if m.refresh.tryStart(qname, qtype, qclass, ecsOpt) {
					m.refresh.spawnPrefetch("stale prefetch", qname, qtype, qclass, ecsOpt)
				}
				qctx.Result = "stale"
				return nil
			}

			// Default: try a quick foreground refresh, fall back to stale.
			if !m.refresh.canStart() || !m.refresh.tryStart(qname, qtype, qclass, ecsOpt) {
				qctx.Result = "stale"
				return nil
			}

			return m.refresh.serveExpiredWithRefresh(qctx, qname, qtype, qclass, ecsOpt, entry)
		}

		// Expired and cannot serve stale — let the resolver handle it.
		// The entry is dropped without being served: return the pool-owned
		// TTL-offset slice (buildCacheResponse would have released it).
		cache.ReleaseTTLOffsets(entry.TTLOffsets)
		return next.ServeDNS(ctx, qctx)
	})
}

// buildCacheResponse builds a response from a cached entry, marking the
// stale-answer EDE (RFC 8914 code 3, Stale Answer) when serving expired data. Shared by
// CacheLookup and CacheStore.
func buildCacheResponse(qctx *handler.QueryContext, entry *cache.Entry, isExpired bool) *dns.Msg {
	qctx.ResHasDNSSEC = entry.HasDNSSEC
	msg := handler.BuildCacheEntryResponse(qctx.Req, entry, qctx.ClientRequestedDNSSEC, isExpired)
	if isExpired {
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorStaleAnswer, ExtraText: ""}
	}
	return msg
}
