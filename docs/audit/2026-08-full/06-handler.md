# 06-handler.md — server/handler/*

Phase 1 package audit — handler package (query pipeline core). Every file read in full;
test files (`pending_test.go`, `middleware/*_test.go`, `benchmark_test.go`) used as reference only.

## Inventory

| File | Lines | Role |
|------|-------|------|
| `server/handler/context.go` | 61 | QueryContext (mutable per-query state) |
| `server/handler/handler.go` | 214 | Handler, ServeDNS entry, qctxPool, BuildQueryMsg |
| `server/handler/middleware.go` | 66 | QueryHandler / Wrapper / interfaces |
| `server/handler/pending.go` | 145 | Singleflight dedup (PendingRequests) |
| `server/handler/prefetch.go` | 92 | PrefetchCooldown map |
| `server/handler/response.go` | 80 | BuildResponseMsg / pre-packed entry→msg builder |
| `middleware/chain.go` | 166 | AssembleChain (11 layers) |
| `middleware/response.go` | 244 | Outermost: EDNS/EDE/cookie finalisation + direct-wire fast path |
| `middleware/edns.go` | 178 | ECS/cookie/version parsing + BADCOOKIE/BADVERS/FORMERR |
| `middleware/mqtype.go` | 398 | RFC 10029 multi-QTYPE merge |
| `middleware/cache_store.go` | 279 | Post-resolution: build response, cache write, logging, probe |
| `middleware/validation.go` | 147 | RFC 9824 §3.5 / RFC 1035 name+label rejection |
| `middleware/zone.go` | 162 | Zone rule evaluation, synthetic responses, wildcard rewrite |
| `middleware/any.go` | 58 | RFC 8482 minimal ANY |
| `middleware/cache_lookup.go` | 334 | fresh→serve / stale→serve+refresh / miss→delegate |
| `middleware/ptr.go` | 69 | Reverse PTR from ptr_map |
| `middleware/dns64.go` | 101 | RFC 6147 AAAA synthesis |
| `middleware/resolution.go` | 78 | Terminal: upstream/recursive + singleflight |

Chain verification (outermost → innermost, `chain.go`): Response → EDNS → MQTYPE → CacheStore →
Validation → Zone → Any → CacheLookup → PTR → DNS64 → Resolution. Matches `chain.go`'s own
comment; **CLAUDE.md and FLOWCHARTS.md list a stale order** (see L6).

## Findings

### CRITICAL

- [CRITICAL/logic] `middleware/cache_store.go:49` + `middleware/zone.go:101,156-160` — the zone wildcard-rewrite path (records-less `*.domain` rule, default Rcode=0) sets `qctx.ZoneMatched=true` and delegates, but never sets `Res`; CacheStore's gate `if qctx.CacheServed || qctx.ZoneMatched || qctx.Res != nil { return err }` then skips response construction for exactly this path, so `handler.ServeDNS` returns nil and the listener silently drops the query (client timeout, no log, no SERVFAIL). Regression from the middleware refactor (b8682dc): the old code rewrote `qd.Header().Name = zoneResult.Domain` so resolution ran on the rewritten name and a response was built; today the question is never rewritten (the rewrite itself is dead — `RewrittenName` is only consumed by the no-op `restoreDomain`), and the response is dropped. | risk: every query matching a records-less wildcard rule receives no answer; supported feature silently broken | fix: gate on `qctx.Res != nil` only (ZoneMatched alone must not suppress buildSuccess), and restore the question rewrite (mutate a copy of the question, or apply the rewrite before Resolution) or delete the dead branch.

### HIGH

- [HIGH/race+memory] `middleware/response.go:58-67`, `server/handler/response.go:45-77` × `cache/store.go:272-275,464-470` — serve-time in-place mutation of the pre-packed wire (TTL deduction `PutUint32`, ID/RD byte patch `PutUint16`) races and aliases with the pending read-through buffer: `cache.Get` for a pending entry returns `entry.ResponseWire` aliasing `pendingEntry.msgWire` (uncompressed path, `owned = wire`), which is the SAME buffer the batch writer commits to SQLite (`flushCacheEntries` → `StmtEntryInsert(item.msgWire)`) and which concurrent queries of the same key share. Result: (a) data race between serve goroutines and the flush goroutine on the same bytes; (b) two concurrent clients patching different IDs into one buffer → one client receives the other's message ID → dropped response; (c) committed SQLite rows carry serve-time-deducted TTLs and a garbage ID. The cache comment "callers only read ResponseWire … aliasing is safe" is invalidated by the handler's in-place mutation. | risk: corrupted committed cache rows, wrong message IDs under load | fix: copy the wire in `buildEntry` for the pending path (or store a copy in the write item); keep the middleware 0-alloc contract.

- [HIGH/perf+correctness] `middleware/cache_lookup.go:192-234` — the foreground stale-refresh success path (`case <-done`, `qr.Err == nil`) rebuilds the client response but never calls `store.Set`; the only cache write is the "opportunistic" timer-path goroutine (lines 251-277) that starts only when the refresh outlasts `DefaultServeExpiredClientTimeout` (600 ms). Since `resolver.Query` never writes answer entries itself, a fast foreground refresh leaves the cache permanently stale: every subsequent client repeats a full upstream resolution (the default `preferStale=false` path), and the stale entry is never healed. | risk: perpetual upstream load for expired entries; "serve+refresh" only refreshes the served response | fix: `store.Set(...)` in the done-path success branch (mirror `refreshCacheEntry`).

### MEDIUM

- [MEDIUM/pool-leak] `middleware/mqtype.go:273-276`, `middleware/dns64.go:62-70` — `cache.ReleaseTTLOffsets(entry.TTLOffsets)` is called only when `found && entry.Unpack() == nil` (MQTYPE) / additionally `len(entry.Answer) > 0` (DNS64); an unpack failure or empty-answer hit falls through to the resolver without releasing the pool-owned offset slice. | risk: pooled-slice leak on every corrupt/empty entry hit | fix: `defer`-style release at acquisition, or release on all exit paths.

- [MEDIUM/correctness] `middleware/cache_lookup.go:204-222` — the foreground-refresh fresh-rebuild path drops `qr.Rcode` (an NXDOMAIN refresh is served as NOERROR/NODATA), `qr.DNSSECEDE`/`UpstreamEDE` (bogus results misclassified), and skips DNS64 synthesis, diverging from `CacheStore.buildSuccess` semantics. | risk: wrong negative-answer semantics and DNSSEC status on refreshed stale entries | fix: mirror `buildSuccess`'s rcode/EDE handling.

- [MEDIUM/correctness] `middleware/mqtype.go:273` + `middleware/dns64.go:62` — secondary cache lookups ignore `isExpired`: a stale entry is served with its FULL stored TTL (no deduction, no stale-EDE) in merged/synthesized responses, so clients over-cache expired data. | risk: stale data cached client-side at full TTL | fix: check `isExpired` (serve stale only within window, deduct TTL).

- [MEDIUM/inefficiency] `middleware/zone.go:96`, `middleware/any.go:50`, `middleware/ptr.go:61` — heap-allocate `&cache.RequestRecord{...}` instead of the established `cache.AcquireRequestRecord()`/`ReleaseRequestRecord()` pool used by CacheLookup/CacheStore; one heap allocation per matched query. | risk: unnecessary hot-path allocations + pattern inconsistency | fix: use the pool.

- [MEDIUM/logging] `middleware/cache_store.go:114-121` — the ECS-mismatch SERVFAIL early-returns before `RecordRequest`, so spoofed/misrouted ECS responses are invisible in query_stats/query_log. | risk: security-relevant event unobservable | fix: record the request before returning.

### LOW

- [LOW/logic-defensive] `middleware/resolution.go:60-61,70-71` → `handler/handler.go:189` — a nil `QueryResult` leaves `Res` nil with nil error, so `ServeDNS` returns nil; bridge guards with `response != nil` (silent drop). Unreachable today (`resolver.Query` always returns `&qr`), but the guard should produce SERVFAIL for contract safety. | fix: build SERVFAIL when qr == nil.

- [LOW/pool-leak] `middleware/cache_lookup.go:73-88,100-113,127-141` — when `refreshGroup == nil` (test-only wiring), `tryStartRefresh` marks the pending gate but `finishRefresh` never runs, permanently blocking future refreshes for that key. `refreshCacheEntry` (line 298) also lacks the `refreshCtx` nil guard that `serveExpiredWithRefresh` has (lines 174-177) — a nil ctx would panic inside the refresh goroutine (recovered by HandlePanic). | fix: nil-guard refreshCtx in refreshCacheEntry; finish gate when group nil.

- [LOW/magic-number] `middleware/validation.go:118` — literal `255` (RFC 1035 §2.3.4 wire-name limit) and `middleware/mqtype.go:191` — literal `64` (EDNS overhead) are un-named. | fix: named consts (config/defaults.go or package top).

- [LOW/comment-accuracy] `middleware/any.go:46`, `middleware/ptr.go:57` — set `qctx.CacheServed = true` as a "skip CacheStore" marker though the response was not served from cache; the field name misleads and the `CacheServed`/`ZoneMatched` terms of the CacheStore gate (cache_store.go:49) are redundant with `Res != nil` — the redundancy is what masked finding C1. | fix: rename or drop the flag terms from the gate.

- [LOW/docs] `CLAUDE.md` "Query Pipeline" and `docs/FLOWCHARTS.md:9` list a stale middleware order (EDNS after Any; FLOWCHARTS omits MQTYPE/Any); the actual chain is Response → EDNS → MQTYPE → CacheStore → Validation → Zone → Any → CacheLookup → PTR → DNS64 → Resolution. | fix: sync both docs to `chain.go`.

- [LOW/inefficiency] `middleware/resolution.go:49` — `findMQQUERY` scans `req.Pseudo` a third time per query (MQTYPE.pre, MQTYPE.post path, Resolution); the option could be captured in qctx once. Also `MQTYPE.merge` re-validates nothing but rescans pseudo. | fix: hoist into QueryContext.

- [LOW/inefficiency] `middleware/cache_lookup.go:74` — `PrefetchCooldown.ShouldStart` is keyed on qname only, so an A prefetch suppresses a concurrent AAAA prefetch for the same name within the 3 s window. | fix: include qtype in the key.

## Package observations

**Chain order & responsibilities** — verified correct against `chain.go`; no cross-layer leaks found. Each middleware's pre/post phases sit where their comments claim (MQTYPE outside CacheStore so its post runs after `Res` exists; EDNS outside MQTYPE so `Pseudo` is populated first; Zone inside Any so rules win; Validation outermost of the rejecters). CacheLookup's stale+foreground-refresh path blocks synchronously inside its pre-phase before delegating — the one structural oddity, but deliberate.

**QueryContext lifecycle** — `*qctx = QueryContext{...}` in `handler.go:142` zeroes every pooled field; refresh goroutines capture only values (verified: the four goroutine sites in cache_lookup.go never touch qctx). `resp.Data` is niled by `pool.Put` (`*msg = dns.Msg{}`), so the `serveExpiredWithRefresh` `Put(stale)` is safe. EDE stickiness: qctx.EDE is per-request zeroed, cleared on stale→fresh transitions (cache_lookup.go:203) — no stale-EDE leakage in this package.

**0 B/op direct-wire contract** — the handler-side fast path stays allocation-free (ID/RD byte patch, `ednsStateFor` only scans Pseudo; ParseFromDNS allocates only when a SUBNET is present, which implies the EDNS middleware already ran). Note: `cache.Get`'s pending-key build (`buildCacheKey`, strings.Builder) allocates per lookup — that cost lives in the cache package's audit scope but must be counted against the contract; flagging for cross-phase synthesis.

**Goroutine hygiene** — all 5 refresh goroutines have `defer HandlePanic`, are errgroup-tracked (`TryGo` — correct non-blocking choice on the per-query path), and their pending gates are released via CAS-guarded `finishRefresh`. `PrefetchCooldown.Cleanup` has an owner (`server/tasks.go`). No owner-less goroutines.

**Errors** — `%w` chains intact; `errors.As(queryErr, &dnsErr)` correct; `_ = m.refreshCacheEntry(...)` documented ("error logged inside"); `findMQQUERY` `_` in Resolution is documented (invalid already FORMERR'd).

**Constants/RFC** — cookie length checks match RFC 7873 §5.2.2 (8 and 16-40); BADCOOKIE for server-cookie≠16 is a legitimate §5.2.3 option; EDNS buffer sizing per RFC 6891; MQTYPE cap per RFC 10029 §4; budget mirror of bridge.go's RFC 2181 §9 clamp verified consistent. Two magic literals (L4).

**Hot-path logging** — clean: every per-query log is Debug-gated; the only Warn is the security deny for destructive CHAOS endpoints (zone.go:87). Badcookie responses get a stats record in ServeDNS (RFC 7873 §5.2 result class) — verified present.

**Notable cross-package debt for synthesis** — (1) C1's root cause is the redundancy between `ZoneMatched`/`CacheServed` and `Res != nil` in the CacheStore gate; (2) H1's root cause sits in the cache package's pending aliasing contract vs. the handler's in-place wire mutation — needs a coordinated fix; (3) `cache.ProcessRecords`/`Set` clone semantics verified safe (Set deep-clones; ProcessRecords shares but nothing mutates after Pack).
