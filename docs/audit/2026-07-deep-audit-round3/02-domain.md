# Domain Layer Audit — Round 3

**Date**: 2026-07-25
**Scope**: config, database, cache, edns, zone, ruleset packages
**Auditor**: Claude Code

---

## Finding Summary

| ID | Severity | Category | File | Line |
|----|----------|----------|------|------|
| D-01 | CRITICAL | panic | edns/padding.go | 17 |
| D-02 | HIGH | panic | zone/zone.go | 384-388 |
| D-03 | LOW | sql | database/schema.go | 39 |
| D-04 | LOW | panic | cache/store.go | 155, 290 |
| D-05 | LOW | inefficiency | cache/store.go | 193-196 |
| D-06 | LOW | code-quality | edns/cookie.go | 66 |
| D-07 | LOW | memory | cache/ptr.go | 43 |
| D-08 | LOW | code-quality | config/validate.go | 369 |

### Cleared Items (verified no issue)

| Pattern | Result |
|---------|--------|
| Pool discipline (all `Get()` matched by `Put()`) | 4 sites, all correct |
| Import layer violations | 0 violations |
| Lock correctness (explicit mutexes) | No mutexes used; SQLite WAL suffices |
| Dead code | None found |
| SQL string concatenation without separators | All multi-statement execs use `;` |
| Prepared statement parameter count mismatch | All match their call sites |
| Unbounded growth | All caches bounded via LRU maps |
| Goroutine leaks | `AsyncStatsWriter` goroutine lifecycle properly managed |

---

## D-01: HasPaddingOption nil dereference panic

**File**: `edns/padding.go`, line 17
**Severity**: CRITICAL
**Category**: panic

**Problem**: `HasPaddingOption(req *dns.Msg) bool` immediately accesses `req.Pseudo` on line 17 without checking whether `req` is nil. If any code path calls this function with a nil `*dns.Msg`, the result is a nil-pointer dereference panic that terminates the goroutine.

Currently all callers (in `server/handler/middleware/`) pass the incoming DNS request which is always non-nil in normal operation. However, the function is exported and has no documented precondition. A nil value could reach this function via:
- An error-recovery path that clears `qctx.Req` and then calls `ResponseMiddleware`.
- Future code that reuses `HasPaddingOption` in a context where the message may be nil.

**Risk**: Any invocation with nil `req` crashes the query goroutine.

**Fix**: Add a nil guard at the top of the function:
```go
func HasPaddingOption(req *dns.Msg) bool {
    if req == nil {
        return false
    }
    if len(req.Pseudo) > 0 {
        ...
    }
    ...
}
```

---

## D-02: wildcardArgsPool defense-in-depth path causes panic

**File**: `zone/zone.go`, lines 384-388
**Severity**: HIGH
**Category**: panic

**Problem**: The `wildcardArgsPool.Get()` result is asserted with comma-ok, and the fallback branch allocates an empty slice — but then immediately slices it to `maxWildcardLabels+2` (18 elements):

```go
argsPtr, ok := wildcardArgsPool.Get().(*[]any)   // line 384
if !ok {
    argsPtr = &[]any{}                            // empty slice, len=0, cap=0
}
args := (*argsPtr)[:maxWildcardLabels+2]          // [:18] on empty slice → PANIC
```

The `sync.Pool.New` function correctly returns `*[]any` with length `maxWildcardLabels+2`, so the type assertion will always succeed in practice. The `if !ok` branch is defense-in-depth that is itself broken — if it ever triggered, it would panic with an index-out-of-bounds instead of recovering gracefully.

**Risk**: While extremely unlikely (requires pool corruption), this is a latent panic bomb in defense-in-depth code. If a future refactor changes the pool item type without updating this site, the resulting panic will be confusing because the error message would be "slice bounds out of range" rather than a type mismatch.

**Fix**: Allocate a properly-sized slice in the fallback:
```go
if !ok {
    a := make([]any, maxWildcardLabels+2)
    argsPtr = &a
}
```

---

## D-03: Version string concatenated into SQL DDL

**File**: `database/schema.go`, line 39
**Severity**: LOW
**Category**: sql

**Problem**: `database.Version` is concatenated directly into a SQL string literal using `+`:

```go
INSERT OR IGNORE INTO version (rowid, version) VALUES (1, '` + Version + `');
```

If `Version` (a package-level variable settable by any caller before `Open()`) contained a single quote character, this would either produce a SQL syntax error or — in a worst case with crafted input — allow SQL injection. Currently `Version` is set at build time as a semver string, so the risk is minimal, but the DDL string also contains other static values that could be parameterized.

The `//nolint:gosec` comment on line 30 acknowledges the lint but the `Version` concatenation is within the same multi-statement `Exec` block, not the line that the nolint suppresses.

**Risk**: Very low — semver strings do not contain single quotes. However, `Version` is not `const` and could theoretically be set to an arbitrary value by test code or a future caller.

**Fix options**:
1. After the DDL batch executes, run a separate parameterized `INSERT OR REPLACE INTO version (rowid, version) VALUES (1, ?)` with the version bound as a parameter.
2. Validate `Version` contains only `[0-9a-zA-Z._-]` before using it in SQL.

---

## D-04: Bare type assertions on sync.Pool.Get()

**File**: `cache/store.go`, lines 155 and 290
**Severity**: LOW
**Category**: panic

**Problem**: Two `sync.Pool.Get()` calls use bare (non-comma-ok) type assertions:

```go
// line 155
dbuf := decompressBufPool.Get().(*[]byte)

// line 290
argsPtr := latencyArgsPool.Get().(*[maxLatencyLookupIPs]any)
```

If any code path places a value of a different type into these pools, these assertions panic. The `New` functions are consistent with the `Put` calls in the current codebase, so this is safe today. However, bare type assertions on pool values are a fragility pattern — they will panic rather than degrade if the pool ever contains an unexpected type.

This is the same class of issue as D-02, but the D-02 case additionally has a broken fallback, which is why this is LOW while D-02 is HIGH.

**Risk**: Very low in the current codebase. Increases with code churn if the pool item type is changed and a `Put` site is missed.

**Fix**: Use comma-ok form and handle the mismatch:
```go
dbuf, ok := decompressBufPool.Get().(*[]byte)
if !ok {
    dbuf = new([]byte)
    *dbuf = make([]byte, 0, decompressBufCap)
}
```

---

## D-05: L1 cache stores expired entries, causing repeat SQLite fallthrough

**File**: `cache/store.go`, lines 193-196
**Severity**: LOW
**Category**: inefficiency

**Problem**: In `Get()`, after a SQLite cache hit where the entry IS expired, the L1 memory cache is still populated with the expired entry:

```go
// Populate L1 memory cache for future queries.
if s.dnsL1 != nil {
    s.dnsL1.Set(dnsL1Key{qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecOK}, entry)
}
isExpired := ttl.IsExpired(ts, entryTTL)
return entry, true, isExpired
```

On the next query for the same key:
1. L1 lookup returns the entry (it's still in the cache).
2. `ttl.IsExpired(entry.Timestamp, entry.TTL)` returns true.
3. Fall through to SQLite for the same data.
4. Repeat.

The L1 cache entry becomes toxic: it's found but always expired, so every query bypasses L1 and hits SQLite. The entry occupies an LRU slot without providing any benefit until evicted.

**Risk**: Minor — adds unnecessary SQLite queries for stale entries under repeated query load. Self-corrects via LRU eviction when the cache is under pressure from fresh entries.

**Fix**: Only populate L1 when the entry is not expired:
```go
if s.dnsL1 != nil && !isExpired {
    s.dnsL1.Set(dnsL1Key{qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecOK}, entry)
}
```

---

## D-06: timeNow uint32 overflow for timestamps after 2038

**File**: `edns/cookie.go`, line 66
**Severity**: LOW
**Category**: code-quality

**Problem**: The cookie timestamp function converts `int64` Unix time to `uint32`:

```go
var timeNow = func() uint32 { return uint32(log.NowUnix()) }
```

Unix timestamps will exceed `math.MaxUint32` (4,294,967,295) on 2106-02-07. Before that, they will exceed the DNS cookie lifetime boundaries. At the conversion, any `int64` value > `math.MaxUint32` silently wraps.

**Context**: RFC 9018 DNS server cookies use uint32 timestamps by design, so this is not a deviation from the specification. All DNS cookie implementations share this limitation.

**Risk**: Not actionable today — uint32 timestamps are standard for DNS cookies (RFC 9018, RFC 7873). Flagged for awareness.

**Fix**: None required per RFC convention. Could add a comment documenting the 2106 horizon.

---

## D-07: insertPtrMap per-row heap allocation for dedup key

**File**: `cache/ptr.go`, line 43
**Severity**: LOW
**Category**: memory (performance)

**Problem**: The deduplication map key is constructed via string concatenation per unique IP+name pair:

```go
key := r.rdataIP + "\x00" + r.name
```

This allocates a new string on every `insertPtrMap` call with A/AAAA records. For a response with 20 A/AAAA records across all sections, this creates up to 20 short-lived string allocations during every `Set()` call.

**Context**: `insertPtrMap` is called from `Set()` which is on the query response path. These allocations are small and short-lived, so GC pressure is minimal. The approach is standard Go.

**Risk**: Negligible in isolation. If the full query path is being optimized for zero-alloc, this is one of many sites.

**Fix**: Use a struct key to avoid concatenation:
```go
type ptrKey struct{ ip, name string }
seen := make(map[ptrKey]bool, len(recs))
```

---

## D-08: validateProbePort mutates caller struct as side effect

**File**: `config/validate.go`, line 369
**Severity**: LOW
**Category**: code-quality

**Problem**: `validateProbePort` modifies the caller's `port` field as a side effect:

```go
func validateProbePort(index int, protocol string, port *int, defaultPort int) error {
    if *port <= 0 {
        *port = defaultPort
    }
```

The function is named `validate*` which conventionally implies read-only checking. The mutation is documented in the comment on line 367-368, making it intentional and visible. However, mixing validation with default-filling violates the principle of least surprise and couples validation to mutation.

**Risk**: Very low — the function is only called from `validateLatencyProbeStep` in the same package, and the pattern is well-documented. Future readers might incorrectly assume `validate*` functions are side-effect-free.

**Fix**: Either rename to `validateAndDefaultProbePort` or split into a separate `defaultProbePort` function called before validation.

---

## Verified: Pool Discipline

All 4 `sync.Pool` / `pool.DefaultMessage` / `pool.DefaultBuffer` acquisition sites have matching `Put` calls:

| File | Line(s) | Pool | Pattern |
|------|---------|------|---------|
| `cache/store.go` | 155-163 | `decompressBufPool` | Get → defer clear + Put |
| `cache/store.go` | 165-176 | `pool.DefaultMessage` | Get → explicit Put on error, defer Put on success |
| `cache/store.go` | 290-296 | `latencyArgsPool` | Get → defer nil-clear + Put |
| `cache/store.go` | 355-363 | `pool.DefaultMessage` | Get → explicit Put after Pack |
| `zone/zone.go` | 384-389 | `wildcardArgsPool` | Get → defer Put (with D-02 fallback bug) |

All paths verified correct. No leaks.

---

## Verified: Import Layer

Checked every `import` statement in all 6 domain packages against the allowed-exception list:

| Package | Domain Imports | Allowed Exception | Verdict |
|---------|---------------|-------------------|---------|
| `config` | `internal/log`, `internal/stamp`, `internal/dnsutil` | N/A (foundation) | OK |
| `database` | `config` | Yes (config) | OK |
| `cache` | `config`, `database` | Yes (both) | OK |
| `edns` | `config` | Yes (config) | OK |
| `zone` | `config`, `database` | Yes (both) | OK |
| `ruleset` | `config` | Yes (config) | OK |

No violations. No domain package imports another domain package outside the allowed exceptions.

---

## Verified: Lock Correctness

No explicit mutexes are used in domain packages. Concurrency is managed via:
- **SQLite WAL mode** serializes writers; concurrent readers proceed in parallel.
- **`atomic.Int64` / `atomic.Pointer`** for lock-free counters and pointer swaps (cookie secrets, ECS defaults, entry counts).
- **`sync.Pool`** for thread-local reusable buffers.
- **`sync.Once`** for idempotent close in `AsyncStatsWriter`.

No lock ordering concerns, no IO inside critical sections, no missing unlocks.

---

## Verified: SQL Correctness

All multi-statement SQL `Exec` calls use proper `;` separators. No missing separators that could silently concatenate SQL clauses.

Parameter counts verified for all 8 prepared statements against their call sites — all match.

The only SQL construction with user-influenced data is D-03 (`database.Version` concatenation in DDL).

---

## Verified: Memory Safety

- **All caches bounded**: `dnsL1` (LRU), `latencyL1` (LRU), `exactCache` (LRU), `matchCache` (LRU).
- **Async writer channel**: bounded at `config.DefaultAsyncStatsBufferSize` (64), drops records when full.
- **No goroutine leaks**: The only background goroutine (`AsyncStatsWriter.run`) has a clean shutdown path via `Close()` -> `close(ch)` -> drain -> exit.
- **No unbounded map growth**: `dynamics` map in zone is bounded by config rule count; `tags` map in ruleset is bounded by config rule set count.
- **No use-after-Put of sync.Pool items**: All pooled values are fully consumed before being returned to the pool, or are zeroed/nil-cleared before return.

---

## Verified: Dead Code

Searched all exported and unexported symbols in the domain packages. No unused functions, types, or variables found.

---

## Files Audited

All 21 files read and analyzed:

- `config/config.go`, `config/defaults.go`, `config/ecs.go`, `config/load.go`, `config/validate.go`
- `database/db.go`, `database/migration.go`, `database/schema.go`, `database/sqlutil.go`, `database/stmts.go`
- `cache/cache.go`, `cache/store.go`, `cache/async_writer.go`, `cache/stats.go`, `cache/ptr.go`
- `edns/edns.go`, `edns/ecs.go`, `edns/cookie.go`, `edns/padding.go`
- `zone/zone.go`, `zone/parse.go`, `zone/wire.go`
- `ruleset/ruleset.go`, `ruleset/iptrie.go`
