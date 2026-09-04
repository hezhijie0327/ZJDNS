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
	"zjdns/internal/pool"
	"zjdns/server/handler"
	"zjdns/server/resolver"

	"codeberg.org/miekg/dns"
	"golang.org/x/sync/errgroup"
)

// CacheLookup checks the response cache before the resolver runs.
// Three outcomes:
//   - Fresh hit: builds the response and short-circuits.
//   - Expired but can serve stale: serves stale, triggers background refresh.
//   - Miss or expired-and-cannot-serve: delegates to next.
type CacheLookup struct {
	store            cache.Store
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
		qname := qctx.Qname
		qtype := dns.RRToType(qd)
		qclass := qd.Header().Class
		ecsOpt := qctx.ECSOpt

		entry, found, isExpired := m.store.Get(qname, qtype, qclass, ecsOpt)
		if !found {
			return next.ServeDNS(ctx, qctx)
		}

		qctx.CacheHit = true

		// Fresh hit — serve immediately.
		if !isExpired {
			qctx.Res = buildCacheResponse(qctx, entry, false)
			qctx.CacheServed = true

			rec := cache.AcquireRequestRecord()
			rec.Qname = qname
			rec.Qtype = qtype
			rec.Qclass = qclass
			rec.Protocol = qctx.Protocol
			rec.Result = "hit"
			rec.Rcode = int(qctx.Res.Rcode) // cached entry's real rcode (negative-cache NXDOMAIN → rcode 3)
			m.store.RecordRequest(rec)
			cache.ReleaseRequestRecord(rec)

			// Prefetch if TTL is below threshold. TryGo, not Go: the call
			// sits on the per-query path, and Go blocks when the refresh
			// concurrency limit is saturated — prefetch is best-effort and
			// must not delay the response.
			// refreshGroup nil (test-only wiring): tryStartRefresh would mark
			// the pending gate with no goroutine to ever release it, blocking
			// all future refreshes for the key — skip prefetch entirely.
			// Gate order matters: the in-flight check (tryStartRefresh) runs
			// BEFORE ShouldStart — the cooldown's timestamp is a side effect,
			// and burning it on a refresh that never starts throttles the key
			// for nothing (H-L9).
			if m.refreshGroup != nil && m.closed != nil && !m.closed() && entry.ShouldPrefetch(config.DefaultPrefetchThresholdPercent) &&
				m.tryStartRefresh(qname, qtype, qclass, ecsOpt) &&
				m.prefetchCooldown != nil && m.prefetchCooldown.ShouldStart(qname, qtype, log.NowUnixNano(), config.DefaultPrefetchThrottleInterval.Nanoseconds()) {
				if !m.refreshGroup.TryGo(func() error {
					defer zdnsutil.HandlePanic("Cache refresh: prefetch fresh-hit")
					defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
					_ = m.refreshCacheEntry(qname, qtype, qclass, ecsOpt) // error logged inside
					return nil                                            // prevent errgroup context cancellation cascade
				}) {
					// Refresh concurrency saturated — undo the in-flight
					// gate so a later refresh can start.
					m.finishRefresh(qname, qtype, qclass, ecsOpt)
				}
			}
			return nil
		}

		// Expired.

		// Can serve stale.
		if entry.CanServeExpired(config.DefaultStaleMaxAge) {
			qctx.Res = buildCacheResponse(qctx, entry, true)
			qctx.CacheServed = true

			// Handle stale serving strategies.
			if m.preferStale && m.closed != nil && !m.closed() {
				// PreferStale: return stale immediately, refresh in background.
				// refreshGroup nil (test-only wiring) must skip entirely — the
				// gate acquired here would never be released (L6, mirroring
				// the fresh-hit guard above).
				if m.refreshGroup != nil && m.tryStartRefresh(qname, qtype, qclass, ecsOpt) {
					if !m.refreshGroup.TryGo(func() error {
						defer zdnsutil.HandlePanic("Cache refresh: stale prefetch")
						defer m.finishRefresh(qname, qtype, qclass, ecsOpt)
						_ = m.refreshCacheEntry(qname, qtype, qclass, ecsOpt) // error logged inside
						return nil                                            // prevent errgroup context cancellation cascade
					}) {
						m.finishRefresh(qname, qtype, qclass, ecsOpt) // slot saturated
					}
				}
				rec := cache.AcquireRequestRecord()
				rec.Qname = qname
				rec.Qtype = qtype
				rec.Qclass = qclass
				rec.Protocol = qctx.Protocol
				rec.Result = "stale"
				rec.Rcode = int(qctx.Res.Rcode) // stale entry's real rcode
				m.store.RecordRequest(rec)
				cache.ReleaseRequestRecord(rec)
				return nil
			}

			// Default: try a quick foreground refresh, fall back to stale.
			// refreshGroup guard mirrors the prefetch and preferStale paths:
			// with no goroutine to run finishRefresh, an acquired gate would
			// block all future refreshes for the key (2026-09 H-M1).
			refreshed := m.refreshGroup != nil && m.closed != nil && !m.closed() && m.tryStartRefresh(qname, qtype, qclass, ecsOpt)
			if !refreshed {
				rec := cache.AcquireRequestRecord()
				rec.Qname = qname
				rec.Qtype = qtype
				rec.Qclass = qclass
				rec.Protocol = qctx.Protocol
				rec.Result = "stale"
				rec.Rcode = int(qctx.Res.Rcode) // stale entry's real rcode
				m.store.RecordRequest(rec)
				cache.ReleaseRequestRecord(rec)
				return nil
			}

			return m.serveExpiredWithRefresh(qctx, qname, qtype, qclass, ecsOpt, entry)
		}

		// Expired and cannot serve stale — let the resolver handle it.
		// The entry is dropped without being served: return the pool-owned
		// TTL-offset slice (buildCacheResponse would have released it).
		cache.ReleaseTTLOffsets(entry.TTLOffsets)
		return next.ServeDNS(ctx, qctx)
	})
}

func (m *CacheLookup) serveExpiredWithRefresh(qctx *handler.QueryContext, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, entry *cache.Entry) error {
	done := make(chan struct{})
	var qr *resolver.QueryResult
	var refreshFinished atomic.Bool

	// TryGo, not Go: this call sits on the per-query path, and Go blocks
	// when the refresh concurrency limit is saturated — the client would
	// wait for a refresh slot instead of getting the stale response. On
	// saturation the done channel is closed below so the timer path serves
	// stale immediately and the background closure (if it later acquires a
	// slot) does not block on <-done forever.
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
			rc := m.refreshCtx
			if rc == nil {
				rc = context.Background()
			}
			refreshCtx, cancel := context.WithTimeout(rc, config.DefaultBackgroundTimeout)
			defer cancel()
			question := handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}
			qr = m.resolver.Query(refreshCtx, question, ecsOpt)
			return nil
		}) {
			m.finishRefresh(qname, qtype, qclass, ecsOpt) // slot saturated
			close(done)                                   // never closed otherwise — the timer-path closure would block until process exit (M5)
		}
	}

	timer := time.NewTimer(config.DefaultServeExpiredClientTimeout)
	defer timer.Stop()

	select {
	case <-done:
		if qr != nil && qr.Err == nil {
			// Refresh completed — rebuild response with fresh data.
			// qctx.Res already has the stale pooled response; return it to
			// the pool before replacing it, and clear the stale-answer EDE
			// (RFC 8914 code 3, Stale Answer) — the served response is fresh now, and
			// carrying the stale EDE would mislead the client.
			if stale := qctx.Res; stale != nil {
				pool.DefaultMessage.Put(stale)
			}
			qctx.EDE = nil
			msg := handler.BuildResponseMsg(qctx.Req)
			// Align with buildSuccess: propagate the resolution rcode
			// (NXDOMAIN from the authoritative server was served as
			// NOERROR/NODATA) and the DNSSEC validation EDE.
			if qr.Rcode != 0 && qr.Rcode != dns.RcodeSuccess {
				msg.Rcode = qr.Rcode
			}
			if qr.DNSSECEDE != 0 {
				qctx.EDE = &dns.EDE{InfoCode: qr.DNSSECEDE, ExtraText: ""}
			}
			dnssecOK := qctx.ClientRequestedDNSSEC
			msg.Answer = cache.ProcessRecords(qr.Answer, 0, false, dnssecOK)
			msg.Ns = cache.ProcessRecords(qr.Authority, 0, false, dnssecOK)
			msg.Extra = cache.ProcessRecords(qr.Additional, 0, false, dnssecOK)
			if qr.Validated {
				msg.AuthenticatedData = true
			}
			qctx.Res = msg
			qctx.CacheServed = false
			// Heal the cache: resolver.Query never writes entries, and the
			// timer-path goroutine below only runs when the refresh outlasts
			// the serve-expired window — a fast refresh would otherwise leave
			// the entry permanently stale (H11).
			if qr.Cacheable && resolver.DNSSECCacheable(qr.Validated, qr.DNSSECEDE) {
				m.store.Set(qname, qtype, qclass, ecsOpt,
					qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)
			}
			rec := cache.AcquireRequestRecord()
			rec.Qname = qctx.Qname
			rec.Qtype = qctx.Qtype
			rec.Qclass = qctx.Req.Question[0].Header().Class
			rec.Protocol = qctx.Protocol
			rec.Result = "miss"
			rec.Rcode = int(qr.Rcode) // fresh resolution rcode (msg.Rcode was aligned to it above)
			m.store.RecordRequest(rec)
			cache.ReleaseRequestRecord(rec)
		} else {
			// Refresh failed — serve stale response.
			rec := cache.AcquireRequestRecord()
			rec.Qname = qname
			rec.Qtype = qtype
			rec.Qclass = qclass
			rec.Protocol = qctx.Protocol
			rec.Result = "stale"
			rec.Rcode = int(qctx.Res.Rcode) // stale entry's real rcode
			m.store.RecordRequest(rec)
			cache.ReleaseRequestRecord(rec)
		}
	case <-timer.C:
		// Stale response stays in qctx.Res.  Background refresh continues.
		rec := cache.AcquireRequestRecord()
		rec.Qname = qname
		rec.Qtype = qtype
		rec.Qclass = qclass
		rec.Protocol = qctx.Protocol
		rec.Result = "stale"
		rec.Rcode = int(qctx.Res.Rcode) // stale entry's real rcode
		m.store.RecordRequest(rec)
		cache.ReleaseRequestRecord(rec)
		// TryGo, not Go: this call sits on the per-query path and Go blocks
		// while the refresh limit is saturated. The foreground refresh
		// (started above) already released its gate via refreshFinished, so
		// a failed TryGo only drops the opportunistic cache write — the next
		// query re-refreshes.
		if m.refreshGroup != nil {
			if !m.refreshGroup.TryGo(func() error {
				defer zdnsutil.HandlePanic("Cache refresh: background update")
				defer func() {
					if refreshFinished.CompareAndSwap(false, true) {
						m.finishRefresh(qname, qtype, qclass, ecsOpt)
					}
				}()
				// Defensive nil guard mirroring the foreground path below
				// (refreshCtx is wired by the server, nil only in tests).
				rc := m.refreshCtx
				if rc == nil {
					rc = context.Background()
				}
				select {
				case <-done:
					if qr != nil && qr.Err == nil && qr.Cacheable && resolver.DNSSECCacheable(qr.Validated, qr.DNSSECEDE) {
						m.store.Set(qname, qtype, qclass, ecsOpt,
							qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)
					}
				case <-rc.Done():
				}
				return nil
			}) {
				if log.IsDebug() {
					log.Debugf("CACHE: refresh slot saturated — cache update skipped for %s (type=%d)", qname, qtype)
				}
			}
		}
	}

	return nil
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

// refreshCacheEntry performs a full resolution cycle and updates the cache.
// Used for background prefetch and stale-entry refresh.
func (m *CacheLookup) refreshCacheEntry(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption) error {
	refreshCtx := m.refreshCtx
	if refreshCtx == nil { // nil only in tests — mirrors serveExpiredWithRefresh
		refreshCtx = context.Background()
	}
	question := handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}
	qr := m.resolver.Query(refreshCtx, question, ecsOpt)
	if qr.Err != nil {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh failed for %s (type=%d): %v", qname, qtype, qr.Err)
		}
		return qr.Err
	}
	if !qr.Cacheable {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh skipped for %s (type=%d) — response not cacheable", qname, qtype)
		}
		return nil
	}
	if !resolver.DNSSECCacheable(qr.Validated, qr.DNSSECEDE) {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh skipped for %s (type=%d) — bogus validation result", qname, qtype)
		}
		return nil
	}
	m.store.Set(qname, qtype, qclass, ecsOpt, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)
	if log.IsDebug() {
		log.Debugf("CACHE: refresh updated %s (type=%d, answer=%d)", qname, qtype, len(qr.Answer))
	}
	return nil
}

func (m *CacheLookup) tryStartRefresh(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if m.pendingRefreshes == nil {
		return true
	}
	key := handler.BuildPendingKey(qname, qtype, qclass, ecs, false)
	if !m.pendingRefreshes.Start(key) {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		}
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
