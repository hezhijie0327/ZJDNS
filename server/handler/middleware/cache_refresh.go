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

// refreshCoordinator owns the cache-refresh machinery: in-flight dedup
// (pending.Group), the bounded errgroup, the refresh context, and the
// prefetch cooldown.  CacheLookup delegates every refresh decision here and
// keeps only the lookup/serve policy.  All goroutine choreography — TryGo
// saturation handling, gate release, panic containment — lives in this file.
//
// A nil group (test-only wiring) disables every refresh path: an acquired
// in-flight gate with no goroutine to release it would block all future
// refreshes for the key (2026-09 H-M1).
type refreshCoordinator struct {
	store    cache.Store
	resolver handler.Resolver
	inFlight *pending.Group[handler.PendingKey]
	group    *errgroup.Group
	ctx      context.Context
	closed   func() bool
	cooldown *handler.PrefetchCooldown
}

// canStart reports whether refreshes may run at all: a coordinator is
// wired, the server is up, and a goroutine slot provider exists.  A nil
// coordinator (CacheLookup built without one) disables every refresh path.
func (c *refreshCoordinator) canStart() bool {
	return c != nil && c.group != nil && c.closed != nil && !c.closed()
}

// tryStart acquires the in-flight gate for a key; false when a refresh for
// the same key is already running.
func (c *refreshCoordinator) tryStart(qname string, qtype, qclass uint16, ecs *edns.ECSOption) bool {
	if c == nil || c.inFlight == nil {
		return true
	}
	key := handler.BuildPendingKey(qname, qtype, qclass, ecs, false)
	if !c.inFlight.Start(key) {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh skipped for %s — already in flight", qname)
		}
		return false
	}
	return true
}

// finish releases the in-flight gate acquired by tryStart.
func (c *refreshCoordinator) finish(qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if c == nil || c.inFlight == nil {
		return
	}
	key := handler.BuildPendingKey(qname, qtype, qclass, ecs, false)
	c.inFlight.Done(key)
}

// spawnPrefetch runs refresh as a best-effort background job, releasing the
// in-flight gate on slot saturation so a later refresh can start.  TryGo,
// not Go: the call sits on the per-query path, and Go blocks when the
// refresh concurrency limit is saturated — prefetch must not delay the
// response.
func (c *refreshCoordinator) spawnPrefetch(reason, qname string, qtype, qclass uint16, ecs *edns.ECSOption) {
	if !c.group.TryGo(func() error {
		defer zdnsutil.HandlePanic("Cache refresh: " + reason)
		defer c.finish(qname, qtype, qclass, ecs)
		_ = c.refresh(qname, qtype, qclass, ecs) // error logged inside
		return nil                               // prevent errgroup context cancellation cascade
	}) {
		c.finish(qname, qtype, qclass, ecs) // slot saturated
	}
}

// refresh performs a full resolution cycle and updates the cache.  Used for
// background prefetch and stale-entry refresh.
func (c *refreshCoordinator) refresh(qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption) error {
	qr := c.resolver.Query(c.refreshCtx(), handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}, ecsOpt)
	if qr.Err != nil {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh failed for %s (type=%d): %v", qname, qtype, qr.Err)
		}
		return qr.Err
	}
	if !handler.StoreIfCacheable(c.store, qname, qtype, qclass, ecsOpt, qr) {
		if log.IsDebug() {
			log.Debugf("CACHE: refresh skipped for %s (type=%d) — not cacheable", qname, qtype)
		}
		return nil
	}
	if log.IsDebug() {
		log.Debugf("CACHE: refresh updated %s (type=%d, answer=%d)", qname, qtype, len(qr.Answer))
	}
	return nil
}

// refreshCtx returns the refresh context (nil only in tests — the server
// always wires one).
func (c *refreshCoordinator) refreshCtx() context.Context {
	if c.ctx == nil {
		return context.Background()
	}
	return c.ctx
}

// serveExpiredWithRefresh serves the stale response immediately while a
// foreground refresh races a client timeout: on a fast fresh result the
// fresh response replaces the stale one, on timeout (or refresh failure) the
// stale response stands and the refresh continues in the background.
func (c *refreshCoordinator) serveExpiredWithRefresh(qctx *handler.QueryContext, qname string, qtype, qclass uint16, ecsOpt *edns.ECSOption, _ *cache.Entry) error {
	done := make(chan struct{})
	var qr *resolver.QueryResult
	var refreshFinished atomic.Bool

	// TryGo, not Go: this call sits on the per-query path, and Go blocks
	// when the refresh concurrency limit is saturated — the client would
	// wait for a refresh slot instead of getting the stale response. On
	// saturation the done channel is closed below so the timer path serves
	// stale immediately and the background closure (if it later acquires a
	// slot) does not block on <-done forever.
	if c.group != nil {
		if !c.group.TryGo(func() error {
			defer zdnsutil.HandlePanic("Cache refresh: foreground refresh")
			defer close(done)
			defer func() {
				if refreshFinished.CompareAndSwap(false, true) {
					c.finish(qname, qtype, qclass, ecsOpt)
				}
			}()
			// Bound the background refresh to prevent goroutine accumulation
			// under pathological upstream latency.  The refresh ctx already
			// covers shutdown.
			refreshCtx, cancel := context.WithTimeout(c.refreshCtx(), config.DefaultBackgroundTimeout)
			defer cancel()
			qr = c.resolver.Query(refreshCtx, handler.Question{Name: qname, Qtype: qtype, Qclass: qclass}, ecsOpt)
			return nil
		}) {
			c.finish(qname, qtype, qclass, ecsOpt) // slot saturated
			close(done)                            // never closed otherwise — the timer-path closure would block until process exit (M5)
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
			// (RFC 8914 code 3, Stale Answer) — the served response is fresh
			// now, and carrying the stale EDE would mislead the client.
			if stale := qctx.Res; stale != nil {
				pool.DefaultMessage.Put(stale)
			}
			qctx.EDE = nil
			msg := handler.BuildResponseMsg(qctx.Req)
			// Align with the miss path: propagate the resolution rcode
			// (NXDOMAIN from the authoritative server was served as
			// NOERROR/NODATA) and the DNSSEC validation EDE.
			if qr.Rcode != 0 && qr.Rcode != dns.RcodeSuccess {
				msg.Rcode = qr.Rcode
			}
			if qr.DNSSECEDE != 0 {
				qctx.EDE = &dns.EDE{InfoCode: qr.DNSSECEDE, ExtraText: ""}
			}
			dnssecOK := qctx.ClientRequestedDNSSEC
			msg.Answer = zdnsutil.ProcessRecords(qr.Answer, 0, false, dnssecOK)
			msg.Ns = zdnsutil.ProcessRecords(qr.Authority, 0, false, dnssecOK)
			msg.Extra = zdnsutil.ProcessRecords(qr.Additional, 0, false, dnssecOK)
			if qr.Validated {
				msg.AuthenticatedData = true
			}
			qctx.Res = msg
			// Heal the cache: resolver.Query never writes entries, and the
			// timer-path goroutine below only runs when the refresh outlasts
			// the serve-expired window — a fast refresh would otherwise
			// leave the entry permanently stale (H11).
			handler.StoreIfCacheable(c.store, qname, qtype, qclass, ecsOpt, qr)
			qctx.Result = "miss" // journal rcode: msg.Rcode was aligned to qr.Rcode above
		} else {
			// Refresh failed — serve stale response.
			qctx.Result = "stale"
		}
	case <-timer.C:
		// Stale response stays in qctx.Res.  Background refresh continues.
		qctx.Result = "stale"
		// TryGo, not Go: this call sits on the per-query path and Go blocks
		// while the refresh limit is saturated. The foreground refresh
		// (started above) already released its gate via refreshFinished, so
		// a failed TryGo only drops the opportunistic cache write — the next
		// query re-refreshes.
		if c.group != nil {
			if !c.group.TryGo(func() error {
				defer zdnsutil.HandlePanic("Cache refresh: background update")
				defer func() {
					if refreshFinished.CompareAndSwap(false, true) {
						c.finish(qname, qtype, qclass, ecsOpt)
					}
				}()
				select {
				case <-done:
					if qr != nil && qr.Err == nil {
						handler.StoreIfCacheable(c.store, qname, qtype, qclass, ecsOpt, qr)
					}
				case <-c.refreshCtx().Done():
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

// newRefreshCoordinator wires the coordinator from the chain dependencies.
func newRefreshCoordinator(deps *Dependencies) *refreshCoordinator {
	return &refreshCoordinator{
		store:    deps.Cache,
		resolver: deps.Resolver,
		inFlight: deps.PendingRefrs,
		group:    deps.RefreshGroup,
		ctx:      deps.RefreshCtx,
		closed:   deps.Closed,
		cooldown: deps.PrefetchCooldown,
	}
}
