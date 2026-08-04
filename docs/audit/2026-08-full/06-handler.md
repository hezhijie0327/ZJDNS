# handler — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: server/handler (+ server/handler/middleware)
> 发现数量: 10 ({"MEDIUM":4,"LOW":6})

### F1 [MEDIUM] rfc — BADCOOKIE responses receive EDNS options twice — duplicate SUBNET/COOKIE options in one OPT
- **文件**: server/handler/middleware/response.go:67
- **问题**: On invalid/expired server cookie, middleware/edns.go buildBadCookieResponse (line 127) already calls ApplyToMessage (appends SUBNET+COOKIE to msg.Pseudo), then the outermost Response middleware's finalizeResponse runs unconditionally on any non-nil qctx.Res (no RcodeBadCookie guard) and calls ApplyToMessage again (line 67): shouldAddEDNS is true (qctx.ECSOpt non-nil, cookieStr non-empty, len(qctx.Req.Pseudo)>0). msg.Pseudo ends up [SUBNET, COOKIE, SUBNET, COOKIE]. edns.Handler.ApplyToMessage (edns/edns.go:118-136) only appends — it is not idempotent and there is no dedup at pack time.
- **风险**: The BADCOOKIE response violates RFC 7871 (multiple SUBNET options in one message are invalid) and RFC 7873 (cookie must be echoed once); clients may reject the OPT, fail to learn the new server cookie and loop on BADCOOKIE.
- **修复建议**: Guard finalizeResponse (or the shouldAddEDNS branch) for qctx.Res.Rcode == dns.RcodeBadCookie — the BADCOOKIE response already carries its EDNS options; or remove the pre-application in buildBadCookieResponse and let Response middleware apply EDNS exactly once.

### F2 [MEDIUM] logic — Stale-answer EDE (16) survives onto a freshly-refreshed response
- **文件**: server/handler/middleware/cache_lookup.go:176
- **问题**: buildResponse(qctx, entry, true) sets qctx.EDE = ExtendedErrorStaleAnswer (line 227) when serving the stale response. When the foreground refresh in serveExpiredWithRefresh completes within DefaultServeExpiredClientTimeout (600ms), the fresh response replaces qctx.Res (line 176) but qctx.EDE is never cleared; the outer Response middleware then attaches EDE 16 (stale answer) to a response built from fresh resolution data.
- **风险**: Clients that rely on EDE 16 for staleness detection (RFC 8767/RFC 8914) misclassify fresh answers as stale data, potentially preferring alternate sources or refusing to cache.
- **修复建议**: Clear qctx.EDE (e.g. qctx.EDE = nil) in the '<-done' success branch before assigning the fresh response, or rebuild the EDE state from the refresh result.

### F3 [MEDIUM] concurrency — errgroup.Go called on the per-query path blocks when refresh concurrency limit is saturated
- **文件**: server/handler/middleware/cache_lookup.go:138
- **问题**: cacheRefreshGroup is created with errgroup.WithContext + SetLimit(config.DefaultCacheRefreshConcurrency=64) (server/server.go:75-76). errgroup.Group.Go blocks until a slot frees. It is invoked synchronously inside the query path at lines 71 (prefetch on fresh hit, before the response is returned), 95 (stale prefetch) and 138 (serveExpiredWithRefresh — BEFORE the client-facing timer even starts). Each refresh goroutine is bounded by DefaultBackgroundTimeout (10s), so when 64 refreshes are in flight a cache-hit query can stall up to ~10s.
- **风险**: Latency cliff / head-of-line blocking: a burst of distinct expiring keys (e.g. after cache flush) stalls fresh-hit and stale-served query handling behind the refresh semaphore.
- **修复建议**: Run the refresh spawn in its own goroutine (bounded by HandlePanic + the pendingRefreshes dedup) so the query path never blocks on Go, or use a non-blocking semaphore (try-acquire) and fall back to skipping the refresh.

### F4 [MEDIUM] pool-leak — Stale pooled response message replaced without Put — pooled message lost on every fast stale-refresh
- **文件**: server/handler/middleware/cache_lookup.go:168
- **问题**: The stale response is built at line 87 (qctx.Res = m.buildResponse(...) → pool.DefaultMessage.Get() via BuildResponseMsg). When the foreground refresh completes within the 600ms window, a second pooled message is built (line 168) and assigned to qctx.Res; the first message is never returned to pool.DefaultMessage (its buffers are dropped to GC). Same pattern in cache_store.go buildSuccess ECS-mismatch branch (line 93: second BuildResponseMsg discards the one from line 67).
- **风险**: Steady per-query allocation churn on the serve-expired path: pooled message and RR buffers are lost instead of reused, increasing GC pressure and pool miss rate (QPS drop on busy stale-serving deployments).
- **修复建议**: Put the replaced response before overwriting qctx.Res, matching the pool discipline in the protocol listeners (e.g. cache_lookup.go line 176: if qctx.Res != nil { qctx.Res.Data = nil; pool.DefaultMessage.Put(qctx.Res) } before assignment).

### F5 [LOW] pool-leak — ECS-mismatch SERVFAIL path discards the already-built pooled response message
- **文件**: server/handler/middleware/cache_store.go:93
- **问题**: In buildSuccess, msg := handler.BuildResponseMsg(qctx.Req) at line 67; on ECS response mismatch the branch builds a second message (line 93) and returns it, dropping the first pooled message without Put.
- **风险**: One pooled message lost per ECS-mismatched query (rare: spoofed/misrouted upstream responses), plus the wasted BuildResponseMsg work.
- **修复建议**: Reuse the existing msg: set msg.Answer/Ns/Extra = nil (or rebuild in place), set msg.Rcode = SERVFAIL and return it instead of allocating a second message.

### F6 [LOW] dead-code — ErrDrop sentinel and QueryContext.Dropped have no producers — dead drop mechanism
- **文件**: server/handler/middleware.go:66
- **问题**: grep across the whole repo: ErrDrop is only referenced at its definition (middleware.go:66) and in handler.go:142 (errors.Is(err, ErrDrop) || qctx.Dropped); QueryContext.Dropped (context.go:58) is never assigned true anywhere. No middleware or defense component returns ErrDrop anymore, so the drop path (and the carefully documented no-double-Put guard at handler.go:143-145) is unreachable.
- **风险**: Dead code misleading future maintenance: the drop contract is documented in the QueryHandler interface doc but nothing can trigger it; the do-not-Put guard protects a path that never runs.
- **修复建议**: Either restore a producer (defense/hopguard drop on poison verdict) or remove ErrDrop, the Dropped field and the handler.go:142 branch; keep the guard only if a producer is planned.

### F7 [LOW] panic — AssembleChain calls deps.ZoneEvaluator.HasRules() without nil check, contradicting the 'nil-checked' doc comment
- **文件**: server/handler/middleware/chain.go:119
- **问题**: The Dependencies doc comment (lines 24-26) lists ZoneEvaluator under 'Optional fields (nil-checked before use)', but line 119 calls deps.ZoneEvaluator.HasRules() unconditionally — a nil interface would panic at chain assembly. Production is safe only because server.go:96 always passes zone.New(db) (never nil).
- **风险**: Any future caller that follows the documented contract and passes a nil ZoneEvaluator crashes at startup with a nil-interface panic.
- **修复建议**: Either nil-check before HasRules (if deps.ZoneEvaluator != nil && deps.ZoneEvaluator.HasRules()) or correct the comment to state ZoneEvaluator is required.

### F8 [LOW] panic — buildBadCookieResponse nil-cookieOpt branch dereferences cookieOpt.ClientCookie — latent nil panic
- **文件**: server/handler/middleware/edns.go:119
- **问题**: Line 117: if cookieOpt == nil || len(cookieOpt.ClientCookie) != edns.DefaultCookieClientLen { ... } — when cookieOpt is nil the branch is entered and line 119 evaluates len(cookieOpt.ClientCookie) in the Debugf call → nil pointer dereference. Both current callers (lines 87, 96) pass a non-nil cookieOpt (both are guarded by cookieOpt != nil before), so the panic is unreachable today, but the defensive nil-check itself is the trigger if it ever fires.
- **风险**: Panic (caught only by the protocol layer's HandlePanic, dropping the query) exactly in the case the guard claims to handle.
- **修复建议**: Hoist the length computation behind a nil check: if cookieOpt == nil { log...; return FORMERR } then use len(cookieOpt.ClientCookie) unconditionally.

### F9 [LOW] panic — Response.finalizeResponse dereferences qctx.Req without nil guard — inconsistent with Validation's nil-Req handling
- **文件**: server/handler/middleware/response.go:46
- **问题**: Validation middleware explicitly handles qctx.Req == nil (validation.go:56-69), but finalizeResponse dereferences it: line 46 len(req.Question) and line 64 len(qctx.Req.Pseudo). With a nil Req, line 46 panics (ParseFromDNS is nil-safe but the Question access is not). Unreachable in production because Handler.ServeDNS (handler.go:108) rejects nil/empty-question requests before creating a QueryContext — but the chain-level contract is inconsistent: one middleware survives nil Req, the outermost one panics.
- **风险**: Panic (query dropped via HandlePanic) if the chain is ever invoked with a nil-Req QueryContext, e.g. by tests or a future refactored entry point.
- **修复建议**: Guard finalizeResponse: if req == nil { return } after msg := qctx.Res, or normalize req = &dns.Msg{} for nil before the Pseudo/Question accesses.

### F10 [LOW] panic — serveExpiredWithRefresh timer-branch goroutine calls m.refreshCtx.Done() without the nil guard used elsewhere in the same function
- **文件**: server/handler/middleware/cache_lookup.go:214
- **问题**: The foreground refresh goroutine defensively handles nil refreshCtx (lines 148-151: rc := m.refreshCtx; if rc == nil { rc = context.Background() }), but the background-update goroutine spawned in the timer branch selects on m.refreshCtx.Done() (line 214) directly — with a nil context.Context interface this panics when the select is evaluated (also the select would never fire on the Done case). Production always supplies RefreshCtx (server.go:281), so this only bites non-standard wiring.
- **风险**: Panic in the background-update goroutine if a caller constructs CacheLookup with a nil refreshCtx (inconsistent defensive contract within one function).
- **修复建议**: Use the same local fallback: rc := m.refreshCtx; if rc == nil { rc = context.Background() } and select on rc.Done().
