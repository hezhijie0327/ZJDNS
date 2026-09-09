package middleware

import (
	"context"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
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
	// aggressiveNSEC enables RFC 8198 synthesis of NXDOMAIN/NODATA from the
	// cached, signature-verified NSEC/NSEC3 index on a cache miss.
	aggressiveNSEC bool
	// dns64 disables that synthesis for AAAA queries when DNS64 is wired:
	// a synthesized AAAA-NODATA would bypass the DNS64 middleware's A-based
	// synthesis (RFC 6147 §5.1.2).
	dns64 bool
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
			return m.synthesizeNegative(ctx, qctx, next)
		}

		// Fresh hit — serve immediately.
		if !isExpired {
			qctx.Res = buildCacheResponse(qctx, entry, false)
			qctx.Result = "hit" // journal rcode comes from the served response (negative-cache NXDOMAIN → 3)

			// Prefetch if TTL is below threshold.  startThrottled keeps the
			// in-flight check before the cooldown's timestamp side effect —
			// burning the cooldown on a refresh that never starts (already in
			// flight) would throttle the key for nothing.
			if m.refresh.canStart() && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) &&
				m.refresh.startThrottled(qname, qtype, qclass, ecsOpt) {
				m.refresh.spawnPrefetch("prefetch fresh-hit", qname, qtype, qclass, ecsOpt)
			}
			return nil
		}

		// Expired.

		// Can serve stale.
		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			qctx.Res = buildCacheResponse(qctx, entry, true)

			// PreferStale: return stale immediately, refresh in background.
			// The cooldown applies here too: a key whose refreshes fail must
			// not re-refresh at full query rate (refresh storm on an
			// upstream outage).
			if m.preferStale && m.refresh.canStart() {
				if m.refresh.startThrottled(qname, qtype, qclass, ecsOpt) {
					m.refresh.spawnPrefetch("stale prefetch", qname, qtype, qclass, ecsOpt)
				}
				qctx.Result = "stale"
				return nil
			}

			// Default: try a quick foreground refresh, fall back to stale.
			if !m.refresh.canStart() || !m.refresh.startThrottled(qname, qtype, qclass, ecsOpt) {
				qctx.Result = "stale"
				return nil
			}

			return m.refresh.serveExpiredWithRefresh(qctx, qname, qtype, qclass, ecsOpt, entry)
		}

		// Expired and cannot serve stale — let the resolver handle it.
		// The entry is dropped without being served: release the pooled
		// TTL-offset slice and the pooled response wire
		// (buildCacheResponse would have released both).
		entry.ReleaseOffsets()
		pool.ReleaseWire(entry.ResponseWire)
		return next.ServeDNS(ctx, qctx)
	})
}

// synthesizeNegative answers a cache miss from the RFC 8198 aggressive index:
// a cached, signature-verified NSEC/NSEC3 range may deny the name outright, or
// the cache-deduced wildcard (§5.3) may carry the answer.  Synthesized
// responses are written through the normal cache path so repeat queries take
// the plain hit path; any gap (feature off, CD bit, DNS64 AAAA, index miss,
// store race) falls back to normal resolution — RFC 8198 App. A: "If errors
// happen in an aggressive negative caching algorithm, resolvers MUST fall back
// to resolve the query as usual."
func (m *CacheLookup) synthesizeNegative(ctx context.Context, qctx *handler.QueryContext, next handler.QueryHandler) error {
	// RFC 8020 NXDOMAIN cut — independent of aggressive_nsec: a cached
	// NXDOMAIN denies its whole subtree (rcode semantics, no DNSSEC angle;
	// DNS64 never synthesizes for NXDOMAIN per RFC 6147 §5.1.2).  Only the
	// DNSSEC-based RFC 8198 syntheses honor the CD-bit rule (App. A).
	if qctx.Qclass == dns.ClassINET {
		if !qctx.Req.CheckingDisabled && (!m.dns64 || qctx.Qtype != dns.TypeAAAA) && m.aggressiveNSEC {
			if rcode, authority, ok := m.store.SynthesizeNegative(qctx.Qname, qctx.Qtype, qctx.Qclass); ok {
				return m.serveSynthesized(ctx, qctx, nil, authority, rcode, next)
			}
			if answer, authority, ok := m.store.SynthesizeWildcard(qctx.Qname, qctx.Qtype, qctx.Qclass); ok {
				// A synthesized wildcard answer is a validated positive — no
				// rcode override; AD follows the serve-path gates (RFC 6840 §5.8).
				return m.serveSynthesized(ctx, qctx, answer, authority, dns.RcodeSuccess, next)
			}
		}
		if soa, ttl, ok := m.store.NegativeAncestor(qctx.Qname); ok {
			soa.Header().TTL = uint32(ttl) //nolint:gosec // G115: DNS TTL — protocol-bounded uint32
			if log.IsDebug() {
				log.Debugf("CACHE: RFC 8020 NXDOMAIN cut for %s (denied ancestor cached)", qctx.Qname)
			}
			return m.serveSynthesized(ctx, qctx, nil, []dns.RR{soa}, dns.RcodeNameError, next)
		}
	}
	return next.ServeDNS(ctx, qctx)
}

// serveSynthesized persists a synthesized response as a regular validated
// cache entry (the SOA carries the RFC 2308 §5 negative TTL where present) and
// serves it via the plain cache-hit path; a store race (eviction, ECS key)
// falls through to normal resolution.
func (m *CacheLookup) serveSynthesized(ctx context.Context, qctx *handler.QueryContext, answer, authority []dns.RR, rcode uint16, next handler.QueryHandler) error {
	m.store.Set(qctx.Qname, qctx.Qtype, qctx.Qclass, qctx.ECSOpt,
		answer, authority, nil, true, rcode)
	if entry, found, expired := m.store.Get(qctx.Qname, qctx.Qtype, qctx.Qclass, qctx.ECSOpt); found && !expired {
		qctx.Res = buildCacheResponse(qctx, entry, false)
		qctx.Result = "hit"
		return nil
	}
	return next.ServeDNS(ctx, qctx)
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
