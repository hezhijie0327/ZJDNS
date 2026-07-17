package handler

import (
	"context"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/internal/ttl"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// CacheLookupMiddleware checks the response cache before the resolver runs.
// Three outcomes:
//   - Fresh hit: builds the response and short-circuits.
//   - Expired but can serve stale: serves stale, triggers background refresh.
//   - Miss or expired-and-cannot-serve: sets CacheEntry and delegates to next.
type CacheLookupMiddleware struct {
	store            cache.Store
	closed           func() bool
	prefetchCooldown *PrefetchCooldown
	pendingRefreshes *pending.Group[pendingKey]
	refreshGroup     *errgroup.Group
	refreshCtx       context.Context
	preferStale      bool
	resolver         Resolver
}

// Wrap implements Middleware.
func (m *CacheLookupMiddleware) Wrap(next QueryHandler) QueryHandler {
	return QueryHandlerFunc(func(ctx context.Context, qctx *QueryContext) error {
		qd := qctx.Req.Question[0]
		qname := qd.Header().Name
		qtype := dns.RRToType(qd)
		qclass := qd.Header().Class
		ecsOpt := qctx.ECSOpt
		dnssecOK := qctx.ClientRequestedDNSSEC

		entry, found, isExpired := m.store.Get(qname, qtype, qclass, ecsOpt, dnssecOK)
		if !found {
			return next.ServeDNS(ctx, qctx)
		}

		qctx.CacheEntry = entry
		qctx.CacheHit = true

		// Fresh hit — serve immediately.
		if !isExpired {
			qctx.Res = m.buildResponse(qctx, entry, false)
			qctx.CacheServed = true

			// Prefetch if TTL is below threshold.
			if !m.closed() && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) &&
				m.prefetchCooldown != nil && m.prefetchCooldown.ShouldStart(qname, log.NowUnixNano(), config.DefaultPrefetchThrottleInterval.Nanoseconds()) &&
				m.tryStartRefresh(qname, qtype, qclass, ecsOpt) {
				m.refreshGroup.Go(func() error {
					defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
					return m.refreshCacheEntry(qctx, qname, qtype, qclass, ecsOpt)
				})
			}
			return nil
		}

		// Expired.
		qctx.CacheIsStale = true

		// Can serve stale.
		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			qctx.Res = m.buildResponse(qctx, entry, true)
			qctx.CacheServed = true

			// Handle stale serving strategies.
			if m.preferStale && !m.closed() {
				// PreferStale: return stale immediately, refresh in background.
				if m.tryStartRefresh(qname, qtype, qclass, ecsOpt) {
					m.refreshGroup.Go(func() error {
						defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
						return m.refreshCacheEntry(qctx, qname, qtype, qclass, ecsOpt)
					})
				}
				return nil
			}

			// Default: try a quick foreground refresh, fall back to stale.
			refreshed := !m.closed() && m.tryStartRefresh(qname, qtype, qclass, ecsOpt)
			if !refreshed {
				return nil
			}

			return m.serveExpiredWithRefresh(ctx, qctx, qname, qtype, qclass, ecsOpt, entry)
		}

		// Expired and cannot serve stale — let the resolver handle it.
		return next.ServeDNS(ctx, qctx)
	})
}

func (m *CacheLookupMiddleware) serveExpiredWithRefresh(ctx context.Context, qctx *QueryContext, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, entry *cache.Entry) error {
	done := make(chan struct{})
	var qr *resolver.QueryResult

	go func() {
		defer close(done)
		defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
		question := Question{Name: qname, Qtype: qtype, Qclass: qclass}
		qr = m.resolver.Query(m.refreshCtx, question, ecsOpt)
	}()

	timer := time.NewTimer(config.DefaultServeExpiredClientTimeout)
	defer timer.Stop()

	select {
	case <-done:
		if qr != nil && qr.Err == nil {
			// Refresh completed — rebuild response with fresh data.
			// qctx.Res already has stale response; replace with fresh.
			msg := buildResponseMsg(qctx.Req)
			dnssecOK := qctx.ClientRequestedDNSSEC
			msg.Answer = cache.ProcessRecords(qr.Answer, 0, false, dnssecOK)
			msg.Ns = cache.ProcessRecords(qr.Authority, 0, false, dnssecOK)
			msg.Extra = cache.ProcessRecords(qr.Additional, 0, false, dnssecOK)
			if qr.Validated {
				msg.AuthenticatedData = true
			}
			qctx.Res = msg
			qctx.CacheServed = false
		}
	case <-timer.C:
		// Stale response stays in qctx.Res.  Background refresh continues.
		m.refreshGroup.Go(func() error {
			defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
			select {
			case <-done:
				if qr != nil && qr.Err == nil && qr.Cacheable {
					qd := qctx.Req.Question[0]
					m.store.Set(qname, qtype, qclass, ecsOpt, dns.RRToType(qd) != 0, // dnssecOK approximation
						qr.Answer, qr.Authority, qr.Additional, qr.Validated)
				}
			case <-m.refreshCtx.Done():
			}
			return nil
		})
	}

	return nil
}

func (m *CacheLookupMiddleware) buildResponse(qctx *QueryContext, entry *cache.Entry, isExpired bool) *dns.Msg {
	msg := buildResponseMsg(qctx.Req)
	dnssecOK := qctx.ClientRequestedDNSSEC

	if isExpired {
		responseTTL := entry.RemainingTTL()
		msg.Answer = cache.ProcessRecords(entry.Answer, int64(responseTTL), false, dnssecOK)
		msg.Ns = cache.ProcessRecords(entry.Authority, int64(responseTTL), false, dnssecOK)
		msg.Extra = cache.ProcessRecords(entry.Additional, int64(responseTTL), false, dnssecOK)
		qctx.EDE = edns.NewEDEOption(edns.EDECodeStaleAnswer, "")
	} else {
		elapsed := ttl.Elapsed(entry.Timestamp)
		msg.Answer = cache.ProcessRecords(entry.Answer, elapsed, true, dnssecOK)
		msg.Ns = cache.ProcessRecords(entry.Authority, elapsed, true, dnssecOK)
		msg.Extra = cache.ProcessRecords(entry.Additional, elapsed, true, dnssecOK)
	}

	if entry.Validated {
		msg.AuthenticatedData = true
	}

	return msg
}

// refreshCacheEntry performs a full resolution cycle and updates the cache.
// Used for background prefetch and stale-entry refresh.
func (m *CacheLookupMiddleware) refreshCacheEntry(qctx *QueryContext, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption) error {
	question := Question{Name: qname, Qtype: qtype, Qclass: qclass}
	qr := m.resolver.Query(m.refreshCtx, question, ecsOpt)
	if qr.Err != nil {
		return qr.Err
	}
	if qr.Cacheable {
		m.store.Set(qname, qtype, qclass, ecsOpt, false, qr.Answer, qr.Authority, qr.Additional, qr.Validated)
	}
	return nil
}

func (m *CacheLookupMiddleware) tryStartRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if m.pendingRefreshes == nil {
		return true
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	if !m.pendingRefreshes.Start(key) {
		log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		return false
	}
	return true
}

func (m *CacheLookupMiddleware) finishRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if m.pendingRefreshes == nil {
		return
	}
	key := buildPendingKey(qname, qtype, qclass, ecs, false)
	m.pendingRefreshes.Done(key)
}
