package middleware

import (
	"context"
	"sync/atomic"
	"time"
	"zjdns/cache"
	"zjdns/config"
	"zjdns/edns"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pending"
	"zjdns/server/handler"
	"zjdns/server/resolver"
	"zjdns/stats"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// CacheLookup checks the response cache before the resolver runs.
// Three outcomes:
//   - Fresh hit: builds the response and short-circuits.
//   - Expired but can serve stale: serves stale, triggers background refresh.
//   - Miss or expired-and-cannot-serve: sets CacheEntry and delegates to next.
type CacheLookup struct {
	store            cache.Store
	stats            *stats.Collector
	closed           func() bool
	prefetchCooldown *handler.PrefetchCooldown
	pendingRefreshes *pending.Group[handler.PendingKey]
	refreshGroup     *errgroup.Group
	refreshCtx       context.Context
	preferStale      bool
	resolver         handler.Resolver
}

// Wrap implements Wrapper.
func (m *CacheLookup) Wrap(next handler.QueryHandler) handler.QueryHandler {
	return handler.QueryHandlerFunc(func(ctx context.Context, qctx *handler.QueryContext) error {
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

			m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "hit", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})

			// Prefetch if TTL is below threshold.
			if m.closed != nil && !m.closed() && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) &&
				m.prefetchCooldown != nil && m.prefetchCooldown.ShouldStart(qname, log.NowUnixNano(), config.DefaultPrefetchThrottleInterval.Nanoseconds()) &&
				m.tryStartRefresh(qname, qtype, qclass, ecsOpt) {
				if m.refreshGroup != nil {
					_ = m.refreshGroup.TryGo(func() error {
						defer zdnsutil.HandlePanic("Cache refresh: prefetch fresh-hit")
						defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
						_ = m.refreshCacheEntry(qname, qtype, qclass, ecsOpt) // error logged inside
						return nil                                            // prevent errgroup context cancellation cascade
					})
				}
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
			if m.preferStale && m.closed != nil && !m.closed() {
				// PreferStale: return stale immediately, refresh in background.
				if m.tryStartRefresh(qname, qtype, qclass, ecsOpt) {
					if m.refreshGroup != nil {
						if !m.refreshGroup.TryGo(func() error {
							defer zdnsutil.HandlePanic("Cache refresh: stale prefetch")
							defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
							_ = m.refreshCacheEntry(qname, qtype, qclass, ecsOpt)
							return nil
						}) {
							m.finishRefresh(qname, qtype, qclass, ecsOpt)
						}
					}
				}
				m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "stale", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
				return nil
			}

			// Default: try a quick foreground refresh, fall back to stale.
			refreshed := m.closed != nil && !m.closed() && m.tryStartRefresh(qname, qtype, qclass, ecsOpt)
			if !refreshed {
				m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "stale", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
				return nil
			}

			return m.serveExpiredWithRefresh(ctx, qctx, qname, qtype, qclass, ecsOpt, entry)
		}

		// Expired and cannot serve stale — let the resolver handle it.
		return next.ServeDNS(ctx, qctx)
	})
}

func (m *CacheLookup) serveExpiredWithRefresh(ctx context.Context, qctx *handler.QueryContext, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, entry *cache.Entry) error {
	done := make(chan struct{})
	var qr *resolver.QueryResult
	var refreshFinished atomic.Bool

	if m.refreshGroup != nil {
		if !m.refreshGroup.TryGo(func() error {
			defer zdnsutil.HandlePanic("Cache refresh: foreground refresh")
			defer close(done)
			defer func() {
				if refreshFinished.CompareAndSwap(false, true) {
					m.finishRefresh(qname, qtype, qclass, ecsOpt)
				}
			}()
			// Bound the background refresh to prevent goroutine accumulation under
			// pathological upstream latency.  refreshCtx already covers shutdown.
			// Note: refreshCtx is from errgroup.WithContext() and is never nil.
			refreshCtx, cancel := context.WithTimeout(m.refreshCtx, config.DefaultBackgroundTimeout)
			defer cancel()
			question := handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}
			qr = m.resolver.Query(refreshCtx, question, ecsOpt)
			return nil
		}) {
			close(done)
			m.finishRefresh(qname, qtype, qclass, ecsOpt)
		}
	}

	timer := time.NewTimer(config.DefaultServeExpiredClientTimeout)
	defer timer.Stop()

	select {
	case <-done:
		if qr != nil && qr.Err == nil {
			// Refresh completed — rebuild response with fresh data.
			// qctx.Res already has stale response; replace with fresh.
			msg := handler.BuildResponseMsg(qctx.Req)
			dnssecOK := qctx.ClientRequestedDNSSEC
			msg.Answer = cache.ProcessRecords(qr.Answer, 0, false, dnssecOK)
			msg.Ns = cache.ProcessRecords(qr.Authority, 0, false, dnssecOK)
			msg.Extra = cache.ProcessRecords(qr.Additional, 0, false, dnssecOK)
			if qr.Validated {
				msg.AuthenticatedData = true
			}
			dnssecStatus := config.DNSSECStatusInsecure
			switch {
			case qr.Validated:
				dnssecStatus = config.DNSSECStatusSecure
			case qr.DNSSECEDE != 0:
				dnssecStatus = config.DNSSECStatusBogus
			}
			qctx.Res = msg
			qctx.CacheServed = false
			m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "miss", ResponseTime: handler.ElapsedMS(qctx.StartTime), Rcode: dns.RcodeSuccess, Poisoned: qr.Poisoned, DNSSECStatus: dnssecStatus})
		} else {
			// Refresh failed — serve stale response.
			m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "stale", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
		}
	case <-timer.C:
		// Stale response stays in qctx.Res.  Background refresh continues.
		m.stats.Record(&stats.Request{Protocol: qctx.Protocol, Result: "stale", Rcode: dns.RcodeSuccess, ResponseTime: handler.ElapsedMS(qctx.StartTime)})
		if m.refreshGroup != nil {
			_ = m.refreshGroup.TryGo(func() error {
				defer zdnsutil.HandlePanic("Cache refresh: background update")
				defer func() {
					if refreshFinished.CompareAndSwap(false, true) {
						m.finishRefresh(qname, qtype, qclass, ecsOpt)
					}
				}()
				select {
				case <-done:
					if qr != nil && qr.Err == nil && qr.Cacheable {
						m.store.Set(qname, qtype, qclass, ecsOpt, false, // dnssecOK — background refresh does not need DNSSEC
							qr.Answer, qr.Authority, qr.Additional, qr.Validated)
					}
				case <-m.refreshCtx.Done():
				}
				return nil
			})
		}
	}

	return nil
}

func (m *CacheLookup) buildResponse(qctx *handler.QueryContext, entry *cache.Entry, isExpired bool) *dns.Msg {
	msg := handler.BuildCacheEntryResponse(qctx.Req, entry, qctx.ClientRequestedDNSSEC, isExpired)
	if isExpired {
		qctx.EDE = &dns.EDE{InfoCode: dns.ExtendedErrorStaleAnswer, ExtraText: ""}
	}
	return msg
}

// refreshCacheEntry performs a full resolution cycle and updates the cache.
// Used for background prefetch and stale-entry refresh.
func (m *CacheLookup) refreshCacheEntry(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption) error {
	question := handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}
	qr := m.resolver.Query(m.refreshCtx, question, ecsOpt)
	if qr.Err != nil {
		log.Debugf("CACHE: refresh failed for %s (type=%d): %v", qname, qtype, qr.Err)
		return qr.Err
	}
	if !qr.Cacheable {
		log.Debugf("CACHE: refresh skipped for %s (type=%d) — response not cacheable", qname, qtype)
		return nil
	}
	m.store.Set(qname, qtype, qclass, ecsOpt, false, qr.Answer, qr.Authority, qr.Additional, qr.Validated)
	log.Debugf("CACHE: refresh updated %s (type=%d, answer=%d)", qname, qtype, len(qr.Answer))
	m.stats.Record(&stats.Request{Result: "prefetch"})
	return nil
}

func (m *CacheLookup) tryStartRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if m.pendingRefreshes == nil {
		return true
	}
	key := handler.BuildPendingKey(qname, qtype, qclass, ecs, false)
	if !m.pendingRefreshes.Start(key) {
		log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		return false
	}
	return true
}

func (m *CacheLookup) finishRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if m.pendingRefreshes == nil {
		return
	}
	key := handler.BuildPendingKey(qname, qtype, qclass, ecs, false)
	m.pendingRefreshes.Done(key)
}
