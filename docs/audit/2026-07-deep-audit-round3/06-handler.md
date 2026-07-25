# Handler Layer Audit (Round 3)

**Date:** 2026-07-25
**Scope:** `server/handler/` and `server/handler/middleware/`
**Audit dimensions:** Code quality, Memory safety, Lock correctness, Coupling, Architecture, Performance, Panic detection

---

## Summary

- **CRITICAL:** 1
- **HIGH:** 0
- **MEDIUM:** 6
- **LOW:** 6
- **INFO:** 3

---

## CRITICAL

### C1 — Nil-dereference cascade when leader panics before setting ResolutionResult

**File:** `server/handler/middleware/resolution.go`, lines 47-53
**Tags:** `panic`, `memory-safety`, `concurrency`

```go
if qr, follower := m.pending.Join(qname, qtype, qclass, ecsOpt, dnssecOK); follower {
    qctx.ResolutionResult = qr
    qctx.Resolved = true
    if qr.Err != nil {             // <-- nil dereference if qr is nil
        qctx.ResolutionError = true
    }
    return nil
}
defer func() {
    m.pending.Done(qname, qtype, qclass, ecsOpt, dnssecOK,
        qctx.ResolutionResult)     // <-- passes nil if panic before assignment
}()
```

**Problem:** If the leader's `m.resolver.Query()` panics (or the leader fails before `qctx.ResolutionResult` is assigned), the deferred `Done()` executes with `qctx.ResolutionResult == nil`. `PendingRequests.Done()` calls `cloneQueryResult(nil)` which returns nil, then stores nil as the shared result and closes `call.done`. Followers waiting on `Join()` receive `(nil, true)` and immediately dereference `qr.Err` on a nil pointer, causing a cascading panic across ALL follower goroutines that were deduplicated onto that key.

**Risk if unfixed:** A single panic in one resolution goroutine can crash every follower waiting on the same pending key. Under concurrent query load this can cascade into a multi-goroutine crash.

**Fix:** Guard the follower path against nil `qr`:

```go
if qr, follower := m.pending.Join(qname, qtype, qclass, ecsOpt, dnssecOK); follower {
    if qr == nil {
        qctx.ResolutionError = true
        return nil // or return ErrDrop / SERVFAIL
    }
    qctx.ResolutionResult = qr
    qctx.Resolved = true
    if qr.Err != nil {
        qctx.ResolutionError = true
    }
    return nil
}
```

---

## HIGH

*(None found.)*

---

## MEDIUM

### M1 — Missing RequestRecord when foreground refresh succeeds after error

**File:** `server/handler/middleware/cache_lookup.go`, lines 147-166
**Tags:** `observability`, `data-loss`

In `serveExpiredWithRefresh`, the select on `done` vs `timer.C` has three outcomes:
1. `<-done` fires AND `qr.Err == nil` → records `"miss"` RequestRecord (line 161-165).
2. `<-timer.C` fires → records `"stale"` RequestRecord (line 169-174).
3. `<-done` fires AND `qr.Err != nil` → **no RequestRecord is recorded at all.**

When outcome 3 occurs, the stale response (already set in `qctx.Res` at line 82) is sent to the client but no statistics are written to the database. The caller at lines 103-115 also does not record because it returned `m.serveExpiredWithRefresh(...)` directly.

**Risk if unfixed:** Query statistics undercount for this class of query (stale served, foreground refresh completed but returned an error). Minor observability gap.

**Fix:** Add a `RequestRecord` write in the `<-done` branch when `qr.Err != nil`:

```go
case <-done:
    if qr != nil && qr.Err == nil {
        // ... existing fresh-response logic ...
    } else {
        // Record as stale — the stale response is what the client gets
        m.store.RecordRequest(&cache.RequestRecord{
            Qname: qname, Qtype: qtype, Qclass: qclass,
            ECS: ecsOpt, DNSSECOK: qctx.ClientRequestedDNSSEC,
            Protocol: qctx.Protocol, Result: "stale", Rcode: dns.RcodeSuccess,
            EntryID: entry.ID,
        })
    }
```

### M2 — No OPT record in response when no ECS/cookie/EDE/TCP-KA is present

**File:** `server/handler/middleware/response.go`, lines 61-62
**Tags:** `rfc-compliance`, `interoperability`

```go
shouldAddEDNS := ecsOpt != nil || qctx.ClientRequestedDNSSEC || cookieStr != "" ||
    qctx.EDE != nil || qctx.IsSecure || qctx.TCPKeepalive > 0
```

RFC 6891 Section 6.2.2 requires that a server **MUST** include an OPT record in the response if the request contained one, to advertise the UDP response size. If a DNS request contains an OPT record but has no ECS, no DNSSEC OK bit, no cookie, no EDE, no transport security, and no TCP keepalive, the condition above evaluates to `false`, and no OPT record is added to the response.

**Risk if unfixed:** Interoperability issues with clients that require the OPT record in responses (some stub resolvers use it to determine the supported UDP buffer size). The request's OPT record is silently dropped.

**Fix:** Also check if the request had an OPT record:

```go
shouldAddEDNS := ecsOpt != nil || qctx.ClientRequestedDNSSEC || cookieStr != "" ||
    qctx.EDE != nil || qctx.IsSecure || qctx.TCPKeepalive > 0 ||
    qctx.Req.IsEdns() // always echo OPT when the request had one
```

### M3 — PrefetchCooldown.Cleanup schedule not guaranteed under load

**File:** `server/handler/prefetch.go`, lines 57-83
**Tags:** `memory`, `reliability`

The `Cleanup` method is called from `server/tasks.go` line 98 on a ticker with period `DefaultPrefetchThrottleInterval * 10` = `3s * 10` = **30 seconds**. Under sustained diverse-query load, the `data` map can accumulate up to `DefaultPrefetchCooldownMaxEntries` (10,000) entries before the next cleanup cycle. The cleanup then evicts half, but during the 30-second window the map holds 10,000 entries.

**Risk if unfixed:** Bounded memory usage (10,000 entries is ~200KB assuming 20-byte keys + 8-byte values). Acceptable at default settings, but if the server handles millions of unique domains, entries may be evicted before their cooldown expires, causing redundant prefetches. Not a memory leak, but suboptimal dedup.

**Fix:** Reduce cleanup interval or make it configurable. Consider switching to an LRU map instead of a raw `map[string]int64` with periodic cleanup.

### M4 — Zone domain rewrite mutates shared request message for all inner middlewares

**File:** `server/handler/middleware/zone.go`, lines 95-98
**Tags:** `correctness`, `data-race`

```go
if zoneResult.Domain != qname {
    qctx.OriginalName = qname
    qd.Header().Name = zoneResult.Domain  // mutates shared req.Question[0]
}
```

This mutates `req.Question[0].Header().Name` in place, which is visible to all downstream middlewares (EDNS, CacheLookup, PTR, DNS64, Resolution) that read `req.Question[0].Header().Name` for the qname. The code has a documented fallback via `qctx.OriginalName` in the Response middleware, but:

1. Not all downstream consumers use the rewritten name consistently — some use `req.Question[0].Header().Name`, others use `qctx.Qname` (which retains the original). This creates an inconsistency where the two sources disagree.
2. The mutation is on a pooled object (`qctx.Req`). After ServeDNS returns, the protocol listener puts the message back in the pool. If the protocol listener reads any field of the message after the handler returns (e.g., for logging), it will see the rewritten name, not the original.

**Risk if unfixed:** Subtle inconsistencies in logging, cache keys, and PTR reverse lookups when zone rewriting is active. Pool reuse could expose rewritten names to unrelated queries.

**Fix:** Instead of mutating `qd.Header().Name`, pass the rewritten name through a dedicated `QueryContext` field and let each middleware that needs it explicitly opt in. This avoids mutating shared state.

### M5 — `buildError` stale fallback misses fresh cache entries added concurrently

**File:** `server/handler/middleware/cache_store.go`, line 151
**Tags:** `correctness`, `reliability`

```go
if entry, found, _ := m.store.Get(qname, qtype, qclass, ecsOpt, dnssecOK); found && entry.IsExpired() && entry.CanServeExpired(config.DefaultStaleMaxAge) {
```

When resolution fails, `buildError` only falls back to staled entries. It ignores fresh entries that may have been cached by another goroutine between CacheLookup (which missed) and Resolution (which failed). If a concurrent query succeeded and cached a fresh response, this query would still return SERVFAIL.

Additionally, the `isExpired` return value from `Get` is discarded (`_`), and `entry.IsExpired()` is called again — a redundant method call.

**Risk if unfixed:** Transient SERVFAIL responses under concurrent load when Resolution fails but another goroutine already cached the answer. Low impact, but a missed optimization.

**Fix:** Fall back to any entry (fresh or stale), not just expired ones:

```go
if entry, found, isExpired := m.store.Get(qname, qtype, qclass, ecsOpt, dnssecOK); found {
    if !isExpired {
        // Serve fresh entry
        return m.buildFromCacheEntry(qctx, entry, false)
    }
    if entry.CanServeExpired(config.DefaultStaleMaxAge) {
        return m.buildFromCacheEntry(qctx, entry, true)
    }
}
```

### M6 — DNS64 post-processing on followers causes redundant A-record synthesis

**File:** `server/handler/middleware/dns64.go`, lines 50-73
**Tags:** `performance`, `redundancy`

When singleflight dedup (`PendingRequests`) is active and a follower receives the leader's cloned `QueryResult`, the follower's `ResolutionResult.Answer` is a pre-clone snapshot taken before DNS64 synthesis occurred. The follower's DNS64 post-processing sees no AAAA records, performs its own A-record lookup (deduplicated via a second `PendingRequests`), and re-synthesizes AAAA records. This means:

1. The A-record lookup is deduplicated — good.
2. But the follower calls `m.synthesizer.Synthesize()` again with the same inputs, producing identical AAAA records.
3. The `Synthesize()` result overwrites the follower's `qr.Answer` (clone), which is local and discarded after response construction.

**Risk if unfixed:** Redundant CPU in the Synthesize call per follower when DNS64 is active. Low performance impact since DNS64 synthesis is cheap and rare, but detectable under high follower counts.

**Fix:** Clone the `ResolutionResult` after DNS64 synthesis in `PendingRequests.Done()`, so followers don't need to re-synthesize. This requires moving the `Done()` call from Resolution middleware to after DNS64 post-processing, which is a larger refactor.

---

## LOW

### L1 — Nil/empty-question FORMATERR responses lack question section

**File:** `server/handler/middleware/validation.go`, lines 22-27
**Tags:** `rfc-compliance`, `inconsistency`

When `req == nil` or `len(req.Question) == 0`, the response is constructed with just `pool.DefaultMessage.Get()` + `Rcode = FormatError`. No `SetReply` is called, so the response has no question section. For the REFUSED case later in the same function (line 42-43), `SetReply` IS called, correctly echoing the question.

RFC 6891 does not strictly require echoing an empty question, but consistent behavior across error responses is good practice.

**Fix:** For the `len(Question) == 0` case, still call `dnsutil.SetReply(msg, req)` to echo any partial question data that may exist. For `req == nil`, the current behavior is acceptable.

### L2 — `entry.IsExpired()` called redundantly in buildError

**File:** `server/handler/middleware/cache_store.go`, line 151
**Tags:** `inefficiency`

`store.Get()` returns `(entry, found, isExpired)`, but `isExpired` is discarded with `_` and `entry.IsExpired()` is called again on the next line. These are logically equivalent — `Get` internally uses `entry.IsExpired()` to compute the third return value.

**Risk if unfixed:** One extra method call per error-path stale-fallback check (virtually zero cost).

**Fix:** Use the returned `isExpired` value instead of re-calling `entry.IsExpired()`.

### L3 — Stale "Phase 3" comment in middleware.go

**File:** `server/handler/middleware.go`, lines 25-27
**Tags:** `dead-code`, `documentation`

```go
// NOTE: Renamed from Handler to avoid collision with the existing Handler
// struct.  Will be renamed back to Handler in Phase 3 when the old struct
// is removed.
```

The `QueryHandler` interface was renamed to avoid a collision. The comment says Phase 3 will rename it back. There is no evidence Phase 3 is planned or that the old `Handler` struct is being removed. The comment is stale and will mislead future maintainers.

**Fix:** Update or remove the comment.

### L4 — `Wrapper` interface name inconsistent with project conventions

**File:** `server/handler/middleware.go`, line 46
**Tags:** `naming`, `inconsistency`

The interface is named `Wrapper` with a `Wrap` method, but every implementation and comment calls it "Middleware". The project conventions (`golang-naming skill`) suggest the interface should be named `Middleware` with method `Wrap`.

**Fix:** Rename `Wrapper` to `Middleware` if no external code references it by name. Since Go interfaces are satisfied implicitly, the rename is safe.

### L5 — `CIDRFiltered` field is never set

**File:** `server/handler/context.go`, line 55
**Tags:** `dead-code`

The `CIDRFiltered bool` field in `QueryContext` is declared but never set to `true` by any middleware. The Ruleset middleware (which would set it) does not exist as a separate file. CIDR filtering is handled inside the resolver, which returns `ErrCIDRFilterRefused` when all records are filtered, and CacheStore handles it via `buildCIDRRefused`. The `CIDRFiltered` field is dead.

**Risk if unfixed:** Dead field in a hot-path struct adds unnecessary memory per query context.

**Fix:** Remove the field if no future middleware will set it.

### L6 — `DNS64Applied` field is set but never read

**File:** `server/handler/context.go`, line 54; `server/handler/middleware/dns64.go`, line 70
**Tags:** `dead-code`

`qctx.DNS64Applied = true` is set in dns64.go but never read by any code path. It could be useful for metrics/logging but is currently unused.

**Risk if unfixed:** Dead field in a hot-path struct adds unnecessary memory per query context.

**Fix:** Either remove the field, or wire it into a request log / metrics callback.

---

## INFO

### I1 — PendingRequests cleanup goroutine lifetime tied to server

**File:** `server/handler/pending.go`, lines 57-79
**Tags:** `goroutine-leak`, `lifetime`

The `NewPendingRequests()` constructor spawns a background goroutine that runs for the entire server lifetime (60-second ticker, map cleanup). If the `PendingRequests` instance is abandoned or recreated (not current practice — it's created once in `server.New()`), the goroutine leaks. This is by design for a long-running server but should be noted for future refactoring.

### I2 — PendingKey map eviction can orphan follower goroutines

**File:** `server/handler/pending.go`, lines 65-75
**Tags:** `correctness`, `robustness`

The cleanup goroutine evicts half the entries when `len(sets) > 10000`. If an active leader entry is evicted before `Done()` is called, the `pendingCall` struct is leaked and follower goroutines wait until the 60-second timeout. The code acknowledges this in comments. Acceptable under normal load but could cause brief latency spikes under flood.

### I3 — ACK-only EDNS options conditionally dropped

**File:** `server/handler/middleware/response.go`, lines 61-62
**Tags:** `design-choice`

The `shouldAddEDNS` guard drops the OPT record unconditionally when none of the tracked conditions fire. This means EDNS extension options that the code doesn't explicitly track (future EDNS options, vendor-specific options) are stripped from the response even if the client sent them. Documented design choice, but worth noting for future EDNS option support.

---

## Architectural Observations

### Middleware chain ordering

Execution order (outermost → innermost):
1. Response — finalizes EDNS, restores domain names
2. CacheStore — post-resolution cache write + stats
3. Validation — domain/label/type rejection
4. Zone — zone rule evaluation (may short-circuit)
5. EDNS — ECS/cookie parsing, BADCOOKIE handling
6. CacheLookup — cache hit/miss/stale with prefetch
7. PTR — reverse PTR from cache map
8. DNS64 — AAAA synthesis
9. Resolution — terminal upstream/recursive resolution

The ordering is verified correct. Notably:
- Validation runs INSIDE Zone, so zone rules can override validation responses (intentional — zone rules are policy).
- CacheLookup runs INSIDE EDNS, so ECS is parsed before cache key computation (correct).
- PTR runs INSIDE CacheLookup, so it only fires on cache miss (correct).
- CacheStore runs AFTER Resolution returns, so it writes cache after resolution completes (correct).

### Pool discipline

All middleware paths that call `pool.DefaultMessage.Get()`:
- Assign the message to `qctx.Res`, which the protocol listener Puts after ServeDNS returns.
- No path creates a message without eventually returning it to the caller.

No pool leaks detected.

### Lock correctness

- `PendingRequests.mu`: Used correctly in Join/Done/Cleanup. No lock-ordering issues (single mutex).
- `PrefetchCooldown.mu`: Double-checked locking with correct RLock/Lock split. No deadlocks.
- All map accesses are synchronized.

### Memory safety

- Shared cache entry RRs are protected by `ProcessRecords` cloning (except fast path where records are not shared with cache).
- `cloneQueryResult` deep-copies RRs before sharing with followers.
- No unbounded growth in pending maps (capped at 10K with periodic eviction and follower timeouts).
