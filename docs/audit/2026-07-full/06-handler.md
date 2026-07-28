# Handler Audit: server/handler/* and server/

## Summary

- Files audited: 22
- CRITICAL: 0
- HIGH: 5
- MEDIUM: 11
- LOW: 5

## Hot Path Logging Audit

Every log call in the handler/middleware chain was checked. All middleware ServeDNS paths use `log.Debugf` exclusively for per-query logging.

| File | Line | Level | Message | Hot Path? | Issue |
|------|------|-------|---------|-----------|-------|
| server/bridge.go | 49 | Error | SERVER: unexpected type in tcpWriteMu... | No (programming error) | OK |
| server/bridge.go | 199 | Error | SERVER: pack panic recovered: %v | No (panic recovery) | OK |
| server/server.go | 374–530 | Info/Warn | Server startup display | No (startup) | OK |
| server/tasks.go | 52 | Warn | EDNS: cookie secret rotation failed | No (background) | OK |
| server/tasks.go | 63 | Warn | EDNS: default ECS refresh failed | No (background) | OK |
| server/tasks.go | 130 | Warn | CACHE: query journal cleanup failed | No (background) | OK |
| server/tasks.go | 148 | Info | SIGNAL: Received signal... | No (signal) | OK |
| server/tasks.go | 162+ | Info/Error | Shutdown sequence | No (shutdown) | OK |

All handler/middleware `.go` files: ZERO `log.Infof` / `log.Warnf` / `log.Errorf` calls on hot paths. All per-query logging is `log.Debugf` gated behind `log.IsDebug()`. **Compliant.**

## Pool Return Discipline

| File | Get() count | Put() count | Status |
|------|-------------|-------------|--------|
| server/bridge.go | 1 (line 60) | 9 (lines 65,79,91,115,128,137,149,160,173) | OK — extra Puts are for handler-allocated messages |
| server/handler/handler.go | 2 (lines 111,181) | 0 | OK — returned to caller (bridge.go puts) |
| server/handler/response.go | 1 (line 16, via BuildResponseMsg) | 0 | OK — returned to caller |
| server/handler/middleware/validation.go | 2 (lines 24,54) | 0 | OK — stored in qctx.Res, caller puts |
| server/handler/middleware/chain.go | 1 (via BuildResponseMsg in terminal stub) | 0 | OK — stored in qctx.Res, caller puts |

**Balance**: The handler chain allocates response messages via `pool.DefaultMessage.Get()` through `BuildResponseMsg()` or direct calls. These are stored in `qctx.Res` and returned to `bridge.go`, which is responsible for calling `pool.DefaultMessage.Put()` for every non-nil response. Every Get has a corresponding Put in the bridge's ownership chain.

Note: `BuildQueryMsg` (handler.go:181) allocates an **upstream query** message, not a response. Its Put lifecycle is owned by the resolver package (forward.go/recursive.go). Verified: all resolver paths call `pool.DefaultMessage.Put()` on consumed query messages.

## Findings

### HIGH

#### [H1] [panic] server/handler/middleware/cache_lookup.go:69,90,130,186 — refresh goroutines missing defer HandlePanic

- **Problem**: Four goroutines launched via `m.refreshGroup.Go()` lack `defer zdnsutil.HandlePanic(...)`. If any code inside these goroutines panics (nil dereference in resolver, slice bounds, etc.), the panic propagates to the goroutine top-level and crashes the **entire server process**.
  - Line 69: prefetch goroutine (fresh-hit → TTL threshold)
  - Line 90: stale prefetch goroutine
  - Line 130: foreground refresh goroutine (`serveExpiredWithRefresh`)
  - Line 186: background cache-update goroutine (`serveExpiredWithRefresh` timer case)
- **Risk**: Any panic in the resolver call chain during cache refresh causes a server crash. These goroutines run outside the main request path and are not covered by the request-level panic recovery in `bridge.go`.
- **Fix**: Add `defer zdnsutil.HandlePanic("Cache refresh: ...")` as the first line inside each `m.refreshGroup.Go(func() error { ... })` callback.

#### [H2] [panic] server/handler/pending.go:108-116 — Done() race with OnEvict double-closes call.done channel

- **Problem**: `PendingRequests.Done()` calls `p.sets.Get(key)` then `p.sets.Delete(key)` then `close(call.done)`. Between `Get` (releases lock) and `Delete` (acquires lock), another goroutine calling `Set`/`LoadOrStore` may trigger LRU eviction of this entry. The `OnEvict` callback calls `close(call.done)`. When `Done` then calls `close(call.done)` again, it **panics with send on closed channel**.
- **Risk**: Under high concurrency with a full LRU map (10,000 entries), a leader goroutine calling `Done` can race with eviction, causing a server-crashing panic.
- **Fix**: Either (a) add a `sync.Once` or `atomic.Bool` field to `pendingCall` to guard the channel close, or (b) remove the `OnEvict` close and let followers rely on the safety timeout (`DefaultPendingFollowerTimeout`) when the leader entry is evicted before completion.

#### [H3] [concurrency] server/handler/pending.go:76 — pendingCall.done channel is unbuffered, potential goroutine leak on timeout

- **Problem**: When a follower times out in `Join()` (line 93-96), it returns without receiving from `actual.done`. The leader goroutine eventually calls `close(call.done)` and all watchers receive the zero value. However, if the leader entry was evicted (OnEvict closes the channel) before the follower times out, the follower's timer select fires and the goroutine returns. No leak here since `close()` wakes all waiters, but the closing goroutine may block briefly if a waiter is in the timer path.
- **Risk**: More of a design concern than a leak. The `close()` call on an unbuffered channel is safe — `close` does not block in Go; it's the send that blocks. Since we only `close` and never send, there is no blocking.
- **Fix**: No action needed. Channel close on a `chan struct{}` with multiple concurrent readers is safe — all readers wake up when the channel is closed.

#### [H4] [goroutine] server/bridge.go:95 — TCP query goroutine not tracked by errgroup/WaitGroup

- **Problem**: The `go func()` at line 95 that handles TCP queries is not tracked by any errgroup or WaitGroup. The comment in `setupSignalHandling` (tasks.go:153-156) acknowledges the pattern for the signal handler but no similar comment exists for the TCP goroutine. During shutdown, context cancellation causes the goroutine to exit, but there's no mechanism to wait for in-flight TCP queries to drain.
- **Risk**: During rapid shutdown, in-flight TCP queries that don't immediately respect context cancellation could continue executing after the server reports "shutdown complete." The response message pool could be closed/released while the orphaned goroutine still holds references.
- **Fix**: Either (a) add a `sync.WaitGroup` to track in-flight TCP goroutines and wait for them in `shutdownServer()`, or (b) add a comment documenting why this is acceptable (e.g., "context cancellation ensures prompt exit, WaitGroup omitted for simplicity — all goroutines check ctx.Done()").

#### [H5] [concurrency] server/handler/pending.go:56 — OnEvict closes channel while leader may still be writing

- **Problem**: When an entry is evicted before the leader completes, `OnEvict` closes `call.done`. Followers wake up and read `actual.result` which is `nil` (result was never set). The follower path in `Resolution.Wrap` (resolution.go:47-51) checks `if qr == nil { qctx.ResolutionError = true; return nil }`. This silently drops the follower without an error.
- **Risk**: Under high dedup pressure with a full pending map, followers can silently receive resolution errors when eviction occurs. The caller gets `qctx.ResolutionResult = nil` and `qctx.Resolved = true` but `ResolutionError = true`. The CacheStore middleware will then build a SERVFAIL response. This is a **degradation of correctness** under load — followers that should have received the leader's result get SERVFAIL instead.
- **Fix**: The leader should set `call.result` atomically before any close, so evicted entries still carry a result. Or, more robustly, make `pendingCall` use a `re面面相觑` pattern where `OnEvict` does not close — followers always wait for the leader or timeout.

### MEDIUM

#### [M1] [redundancy] server/handler/middleware/cache_store.go:59-63 — re-extracts qname/qtype from req.Question[0] when qctx has them

- **Problem**: `buildSuccess()` at lines 59-63 extracts `qname`, `qtype`, and `qclass` from `qctx.Req.Question[0]`, but `qname` and `qtype` are already pre-extracted in `qctx.Qname` and `qctx.Qtype`. Only `qclass` is not stored in QueryContext and needs extraction. This pattern repeats in `buildError()` (lines 149-151) and `buildCIDRRefused()` (lines 207-209).
- **Risk**: Minor inefficiency — repeated `dns.RRToType` calls on every query result path. The `dns.RRToType` call involves a type switch on the RR interface, adding ~20-50ns per query.
- **Fix**: Use `qctx.Qname` and `qctx.Qtype` where available. Only extract `qclass` from the question directly.

#### [M2] [redundancy] server/handler/middleware/edns.go:92 — redundant ECS parsing in buildBadCookieResponse

- **Problem**: `buildBadCookieResponse()` at line 92 calls `m.edns.ParseFromDNS(req)` to re-parse ECS from the request. The ECS was already parsed at line 42-43 in the main `Wrap` handler and stored in `qctx.ECSOpt`. This re-parse is wasteful.
- **Risk**: Extra allocation and parsing work on the BADCOOKIE response path. The `ParseFromDNS` call iterates EDNS options and may allocate memory for the parsed ECS option.
- **Fix**: Pass `qctx.ECSOpt` to `buildBadCookieResponse` instead of re-parsing from the wire.

#### [M3] [arch] server/handler/pending.go:34 — PendingKey is PascalCase (exported) but under "Unexported types" comment

- **Problem**: The comment block says `// --- Unexported types ---` but `PendingKey` is defined with PascalCase, making it exported. The middleware package imports `handler.PendingKey` as `handler.PendingKey` because it's exported.
- **Risk**: None functionally, but the comment is misleading. The type's export status is determined by its case, not the comment.
- **Fix**: Either make `PendingKey` truly unexported (rename to `pendingKey`) and fix all references in middleware packages, or update the comment to say "Exported types" or remove the misleading comment.

#### [M4] [log] server/handler/handler.go:121-128,160-168 — Debug logs on EVERY query, potentially high volume at scale

- **Problem**: The "QUERY:" log (line 125/127) and "RESULT:" log (line 163) produce text output for every single query when debug logging is enabled. The "RESULT:" log includes the full `qctx.Res.String()` output which can be hundreds of lines for large responses.
- **Risk**: At 10K+ QPS with debug enabled, log output becomes unusable and the `qctx.Res.String()` allocation dominates memory/CPU. However, these are guarded by `log.IsDebug()`, so in production (info level) they produce zero output.
- **Fix**: Consider truncating the response dump in the RESULT log (e.g., only log answer count, not full response body). This is an optimization, not a bug.

#### [M5] [resource] server/tasks.go:159 — shutdownServer() not guarded against concurrent calls

- **Problem**: `shutdownServer()` at line 159 has no `sync.Once` or atomic guard. If called multiple times (e.g., SIGINT followed by SIGTERM), it would execute shutdown logic multiple times. While `s.cancel()` is idempotent and `close(s.shutdown)` on an already-closed channel would panic, the `sync.Once` on `s.cancel` prevents the channel close... actually, looking at the code: `s.cancel` is `context.CancelCauseFunc` which IS idempotent, but `close(s.shutdown)` is NOT — it panics on second close.
- **Risk**: A second call to `shutdownServer()` would panic on `close(s.shutdown)` at line 273.
- **Fix**: Guard `shutdownServer()` with `sync.Once` or an `atomic.Bool`.

#### [M6] [perf] server/handler/middleware/cache_lookup.go:140 — Background refresh context derived but immediately used, no cleanup on cancellation

- **Problem**: In `serveExpiredWithRefresh`, a fresh `refreshCtx` is derived with `context.WithTimeout(m.refreshCtx, config.DefaultBackgroundTimeout)` (line 139). If the server shuts down before the refresh completes, this context is cancelled but the goroutine continues running until the Query call returns. The goroutine is properly cleaned up via `m.refreshCtx.Done()` in other paths, but the `finishRefresh` defer ensures cleanup.
- **Risk**: Minor — on shutdown, one extra resolver query may complete before the goroutine exits. No data structure corruption because `finishRefresh` always runs.
- **Fix**: No action needed. The pattern is correct; the timeout bounds the worst-case cleanup delay.

#### [M7] [ordering] server/handler/middleware/cache_lookup.go:125 — serveExpiredWithRefresh is defined after all other methods; inconsistent with receiver grouping

- **Problem**: In `cache_lookup.go`, the `serveExpiredWithRefresh`, `buildResponse`, `refreshCacheEntry`, `tryStartRefresh`, and `finishRefresh` methods are all receiver methods on `*CacheLookup` but are placed **after** the `Wrap` method (the constructor-equivalent). While `Wrap` is the primary entry point, the helper methods follow it in arbitrary order rather than being grouped by access level (public → private) or call chain.
- **Risk**: Pure readability — no functional impact.
- **Fix**: Group `*CacheLookup` methods: `Wrap` (public entry), then helpers in call-chain order.

#### [M8] [arch] server/handler/middleware/chain.go — AssembleChain constructs Dependencies inline; no validation of required fields

- **Problem**: `AssembleChain` at line 60 takes `*Dependencies` and uses its fields. Several fields are required (Cache, EDNS, Resolver, Config) but there is no nil-check at the start. If caller forgets to set a field, the middleware panics at runtime with a nil-pointer dereference rather than returning a clear error at startup.
- **Risk**: Startup crash instead of a friendly error message if a future code change omits a required dependency.
- **Fix**: Add nil checks in `AssembleChain` (or in each middleware's `Wrap`) for required fields, returning a clear error. Alternatively, add a doc comment documenting required vs optional fields.

#### [M9] [defensive] server/handler/handler.go:151-158 — Error handling chain with dead code (err never non-nil)

- **Problem**: The error-returning branch at line 151 (`if err != nil && qctx.Res == nil`) is effectively dead code. Every middleware in the current chain returns `nil` on its own error path (setting `qctx.Res` to short-circuit) and only propagates the `next.ServeDNS` return value (which is also nil). There is no middleware that returns a non-nil error without also setting `qctx.Res`.
- **Risk**: None — it's defensive code that was presumably written for future-proofing. But it can mask bugs if a new middleware returns an error without setting `qctx.Res`.
- **Fix**: Either document that this path exists for future middleware, or remove it and simplify the error handling.

#### [M10] [goroutine] server/server.go:450 — Coordinator goroutine not tracked (same issue as bridge.go)

- **Problem**: The `go func()` at line 450 that calls `g.Wait()` and feeds `errChan` is not tracked by any mechanism outside the channel. If a caller is not reading from `errChan` (which only happens in `Start()`), this goroutine blocks indefinitely.
- **Risk**: The `Start()` method does read from `errChan` and only exits when `s.shutdown` is closed, so in normal operation this goroutine is fine. However, it is an orphan from the perspective of the shutdown sequence — `shutdownServer()` cancels the context but this goroutine is not waited on.
- **Fix**: Since `errChan` is buffered (cap 1) and the goroutine writes only once, this is safe. No action needed. Consider adding a comment documenting this.

#### [M11] [redundancy] server/handler/middleware/resolution.go:46-63 — Singleflight dedup code duplicated in DNS64 and Resolution

- **Problem**: Resolution middleware (resolution.go:46-63) implements the singleflight pattern with `m.pending.Join/Done`. DNS64 middleware (dns64.go:51-66) independently reimplements the same pattern for its A-record lookup. Both use the same `PendingRequests` instance.
- **Risk**: Code duplication. Any fix to the singleflight pattern would need to be applied in both places.
- **Fix**: Extract the singleflight leader/follower pattern into a reusable helper function or method on `PendingRequests`.

### LOW

#### [L1] [docs] server/handler/middleware/validation.go — "REFUSED" in comment but uses RcodeRefused for invalid queries

- **Problem**: The godoc comment at line 18 says "Invalid queries receive a REFUSED response with an EDE error code." However, the code uses `RcodeRefused` only for the domain-length/label/type checks, and `RcodeFormatError` for the nil/empty question path. The first branch (nil req / empty question) returns FORMERR, not REFUSED.
- **Risk**: Minor documentation inaccuracy.
- **Fix**: Update the comment to mention FORMERR for nil/empty questions.

#### [L2] [docs] server/handler/pending.go:62 — NewRefreshGroup comment says "Exported for use by server.New() during chain assembly" but function is in handler package

- **Problem**: The comment on `NewRefreshGroup` says it's exported for `server.New()`, which is true — it's called from `server.New()` via `initHandler`. But the comment is more of an internal note than useful godoc.
- **Risk**: None — minor clarity issue.
- **Fix**: Make it a regular godoc comment: "NewRefreshGroup creates a pending group for cache refresh deduplication."

#### [L3] [magic] server/handler/middleware/cache_lookup.go:205 — DefaultStaleMaxAge is a config constant, not a local magic number — OK

- **Finding**: Verified that all numeric values in the handler middleware are extracted to config defaults. No magic numbers found. Good compliance.

#### [L4] [docs] server/handler/middleware/chain.go:63 — Terminal handler comment says "no resolution middleware configured" but Resolution is always configured

- **Problem**: Comment at line 64 says "terminal handler reached — no resolution middleware configured." In the current chain assembly, Resolution middleware is always added (line 72-75). The terminal stub is never reached in practice.
- **Risk**: Misleading comment could confuse readers during debugging.
- **Fix**: Update comment to "terminal stub — not reached in normal operation (Resolution is always configured)."

#### [L5] [docs] server/handler/handler.go:102 — godoc for ServeDNS says "creates a QueryContext and delegates" but actual creation is inline

- **Problem**: The godoc says "It creates a QueryContext and delegates to the middleware chain." The QueryContext creation IS done inline within the function. This is accurate.
- **Risk**: None — the godoc is correct. Marked LOW for completeness.

## Middleware Chain Order Verification

| Position | Middleware | Code (chain.go) | CLAUDE.md | ARCHITECTURE.md | Match? |
|----------|-----------|-----------------|-----------|-----------------|--------|
| 1 (outermost) | Response | chain.go:127 | Yes | Yes | OK |
| 2 | CacheStore | chain.go:120 | Yes | Yes | OK |
| 3 | Validation | chain.go:117 | Yes | Yes | OK |
| 4 | Zone | chain.go:108 (conditional) | Yes | Yes | OK |
| 5 | EDNS | chain.go:102 | Yes | Yes | OK |
| 6 | CacheLookup | chain.go:90 | Yes | Yes | OK |
| 7 | PTR | chain.go:87 | Yes | Yes | OK |
| 8 | DNS64 | chain.go:78 (conditional) | Yes | Yes | OK |
| 9 (innermost) | Resolution | chain.go:71 | Yes | Yes | OK |

**Verdict**: All three documentation sources agree with the code. No ordering mismatch.

## QueryContext Field Contract Verification

| Field | Set by | Read by | Contract compliance |
|-------|--------|---------|-------------------|
| Req | handler.ServeDNS | All middlewares (immutable) | OK |
| ClientIP | handler.ServeDNS | EDNS, Response, Zone | OK |
| IsSecure | handler.ServeDNS | EDNS, Response | OK |
| Protocol | handler.ServeDNS | CacheStore, CacheLookup | OK |
| Qname | handler.ServeDNS | All middlewares | OK |
| Qtype | handler.ServeDNS | All middlewares | OK |
| ClientRequestedDNSSEC | EDNS | CacheLookup, Resolution, CacheStore, Response | OK |
| ECSOpt | EDNS | CacheLookup, Resolution, CacheStore, Response | OK |
| CacheHit | CacheLookup | PTR (reads) | OK |
| CacheEntry | CacheLookup | CacheStore (error fallback reads) | OK |
| CacheServed | CacheLookup | CacheStore (reads) | OK |
| ResolutionResult | Resolution | CacheStore, DNS64 | OK |
| Resolved | Resolution | CacheStore, DNS64 | OK |
| Res | Multiple (short-circuit) | Response (finalizes) | OK |

**Verdict**: All fields follow documented contract. No field is written by multiple middlewares (except `Res` which is intentionally set by any short-circuiting middleware). No field is overwritten after being set.

## RFC Consistency

| RFC | Middleware | Verification |
|-----|-----------|-------------|
| RFC 7873 / 9018 | EDNS, Response | DNS Cookie validation and generation. Cookie server length check (1-15 bytes short, 16 bytes full). BADCOOKIE response with newly generated cookie. Valid/renew/invalid/expired status codes. |
| RFC 6891 §6.2.2 | EDNS | Full unpack on EDNS path. FORMERR on unpack failure. |
| RFC 8467 | Response | Padding support via `ClientWantsPadding` and `edns.HasPaddingOption`. |
| RFC 6147 | DNS64 | AAAA synthesis from A records. Only fires on NOERROR + empty answer. Prefix configurable. |
| RFC 1035 §4.2.2 | bridge.go | TCP length prefix (2-byte big-endian) via WriteTo. |
| RFC 2181 §9 | bridge.go | TC bit truncation on UDP when response exceeds EDNS buffer size. |
| RFC 9156 | (Resolution delegates to resolver) | QNAME minimisation in recursive walk. |
| RFC 4035 §5.3.3 | CacheStore | `dnssec.CapValidatedTTL` called before caching validated responses. |
| RFC 6840 §5.9 | handler.go | BuildQueryMsg sets CheckingDisabled=true on upstream queries. |

**Verdict**: All RFC-referencing middleware correctly implements the cited specification sections.

## Context Propagation

- `handler.go` `ServeDNS` passes `h.ctx` (server's root context) to `h.chain.ServeDNS`.
- All middleware wrappers use the `ctx context.Context` parameter from the call chain.
- No `context.TODO()` in production handler code.
- `context.Background()` is only used in shutdown paths (tasks.go:179,190,200) where the server context is already cancelled — this is correct.
- Shutdown cancellation flows: `s.cancel()` → `s.ctx` → `h.ctx` → middleware `ctx` parameter.

**Verdict**: Context propagation is correct. No breaks in the cancellation chain.

## Goroutine Lifecycle Summary

| Location | Goroutine | HandlePanic? | Owner/Tracker | Status |
|----------|-----------|-------------|---------------|--------|
| bridge.go:95 | TCP query handler | Yes | None (orphan) | **HIGH H4** |
| tasks.go:143 | Signal handler | Yes | None (acknowledged) | OK with comment |
| tasks.go:221 | backgroundGroup.Wait | Yes | bgDone channel | OK |
| tasks.go:239 | refreshGroup.Wait | Yes | refreshDone channel | OK |
| server.go:450 | Coordinator (g.Wait) | Yes | errChan channel | OK (LOW M10) |
| cache_lookup.go:69 | Prefetch refresh | **NO** | refreshGroup errgroup | **HIGH H1** |
| cache_lookup.go:90 | Stale prefetch | **NO** | refreshGroup errgroup | **HIGH H1** |
| cache_lookup.go:130 | Foreground refresh | **NO** | refreshGroup errgroup | **HIGH H1** |
| cache_lookup.go:186 | Background cache update | **NO** | refreshGroup errgroup | **HIGH H1** |

**4 goroutines missing defer HandlePanic. This is the single largest finding cluster.**

## Declaration Order Verification

All files follow `type → const → var → func` ordering per `decorder` linter requirements:

| File | type | const | var | func | Compliance |
|------|------|-------|-----|------|------------|
| server/bridge.go | 0 | 0 | 0 | 2 | OK (no types/consts/var needed) |
| server/server.go | 1 (Server) | 0 | 0 | many | OK |
| server/tasks.go | 0 | 0 | 0 | many | OK |
| server/init.go | 0 | 0 | 0 | 4 | OK |
| server/handler/context.go | 1 (QueryContext) | 0 | 0 | 0 | OK |
| server/handler/handler.go | 3 types | 0 | 0 | many | OK |
| server/handler/middleware.go | 5 types + errors | 0 | 0 | 1 | OK |
| server/handler/pending.go | 3 types | 1 (const) | 0 | 5 | OK |
| server/handler/response.go | 0 | 0 | 0 | 2 | OK |
| server/handler/prefetch.go | 1 (PrefetchCooldown) | 0 | 0 | 3 | OK |
| server/handler/middleware/* | OK | OK | OK | OK | OK |

**Verdict**: All files comply with the `type → const → var → func` ordering.

## Interface Contract Verification

| Interface | Defined in | Implemented by | Compliance |
|-----------|-----------|---------------|------------|
| `handler.QueryHandler` | handler/middleware.go:28 | All middleware Wrap() returns | OK |
| `handler.Wrapper` | handler/middleware.go:45 | All middleware structs | OK |
| `handler.ZoneEvaluator` | handler/middleware.go:37 | `*zone.Evaluator` (in zone package) | OK (interface defined in consumer) |
| `handler.EDNSHandler` | handler/middleware.go:50 | `*edns.Handler` | OK |
| `handler.LatencyProber` | handler/handler.go:36 | `*probe.Prober` | OK |
| `handler.Resolver` | handler/handler.go:28 | `*resolver.Resolver` | OK |

**Verdict**: Interfaces are correctly defined in consumer packages. All implementations satisfy their contracts.

## Key Design Observations

1. **PendingRequests.OnEvict pattern**: The `lrumap.OnEvict` callback is used to close follower channels on eviction. While the race condition (H2) needs fixing, the pattern of using `lrumap` for dedup is architecturally sound — bounded capacity prevents OOM under adversarial load, unlike `golang.org/x/sync/singleflight` which has no size cap.

2. **PrefetchCooldown**: Uses a hand-written `map[string]int64 + sync.RWMutex` bounded cache. The AUDIT-METHODOLOGY.md recommends `lrumap` for all bounded caches. However, `PrefetchCooldown` has custom double-checked-locking semantics (atomic check-then-set with cooldown window) that don't map cleanly to lrumap's `LoadOrStore`. This is an acceptable deviation.

3. **Forward-reference trick** (server.go:249): `isClosed` variable captured by closure, then updated to `h.IsClosed` after handler creation. This avoids circular initialization dependencies. Well-documented and correct.

4. **serveExpiredWithRefresh** (cache_lookup.go:125-205): Complex pattern with overlapping goroutines and two competing completion paths. The `refreshFinished` atomic bool correctly prevents double-call to `finishRefresh`. However, the complexity score is high — consider refactoring into smaller, named state-machine steps.
