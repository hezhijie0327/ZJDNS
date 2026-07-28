# Handler + Middleware Audit — Agent Findings

## Scope

16 files: `server/handler/*` and `server/handler/middleware/*`

## Assessment Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 5 |
| HIGH | 2 |

---

## CRITICAL Findings

### C8: nil pointer dereference on `qr.Err` in Resolution direct path

**File**: `server/handler/middleware/resolution.go:69`
**Category**: `panic`, `nil-dereference`

When `m.pending == nil` (no singleflight dedup), `m.resolver.Query()` can return nil,
but `qr.Err` is accessed without nil check. The `m.pending != nil` path correctly
guards with `if qr == nil { return }`, but the direct path omits it.

**Risk**: Server crash if resolver returns nil.

**Fix**: Add `if qr == nil` guard matching line 52 pattern.

### C9: nil pointer dereference on `aqr.Err` in DNS64

**File**: `server/handler/middleware/dns64.go:61`
**Category**: `panic`, `nil-dereference`

`aqr` from `DoJoin()` or `m.resolver.Query()` is not nil-checked before accessing
`aqr.Err`. Both call sites can return nil.

**Risk**: Server crash on DNS64 synthesis path.

**Fix**: Add `if aqr != nil && aqr.Err == nil && len(aqr.Answer) > 0` guard.

### C10: nil `m.refreshGroup.Go()` dereference in CacheLookup

**File**: `server/handler/middleware/cache_lookup.go:70,92,133,190`
**Category**: `panic`, `nil-dereference`, `parameter-validation`

`m.refreshGroup` is documented as optional but `CacheLookup` calls `.Go()` without
nil check. `tryStartRefresh` returns true when `pendingRefreshes == nil`, leading
to unconditional `.Go()` call on nil group.

**Risk**: Server crash on first cache miss or stale entry refresh.

**Fix**: Nil-check `m.refreshGroup` before each call, or guard `tryStartRefresh`.

### C11: nil `m.closed()` function call in CacheLookup

**File**: `server/handler/middleware/cache_lookup.go:67,89,109`
**Category**: `panic`, `nil-dereference`

`m.closed` (type `func() bool`) is optional but called without nil check at 3 locations.

**Risk**: Server crash on any cache-hit path if `Closed` not configured.

**Fix**: Add `if m.closed != nil && m.closed()` guard.

### C12: nil `m.refreshCtx` in `context.WithTimeout`

**File**: `server/handler/middleware/cache_lookup.go:143`
**Category**: `panic`, `context-propagation`

`m.refreshCtx` is optional but passed to `context.WithTimeout()` without nil check.

**Risk**: Server crash on expired-entry refresh path.

**Fix**: Nil-check before `context.WithTimeout`, fall back to `context.Background()`.

---

## HIGH Findings

### H7: missing nil check on `deps` in `AssembleChain`

**File**: `server/handler/middleware/chain.go:67`
**Category**: `parameter-validation`

Public function `AssembleChain` accesses `deps.Resolver` etc. without checking
`deps == nil`. Produces confusing startup panic instead of clear error.

**Risk**: Hard-to-debug startup crash.

### H8: `BuildResponseMsg` with nil `req` leaves QR bit unset

**File**: `server/handler/response.go:15-28`
**Category**: `memory-safety`, `RFC-consistency`

When `req == nil`, `msg.Response` is not set, leaving whatever the pooled message
contained (QR=0 for query reuse). Invalid DNS response per RFC 1035 §4.1.1.

**Risk**: Clients reject SERVFAIL responses — invisible error.

**Fix**: Add `msg.Response = true` in the nil-req fallthrough.

---

## Quality Notes

- **Pool discipline**: Clean — every `Get()` correctly stores result in `qctx.Res`
- **Goroutine hygiene**: Strong — all goroutines have `defer HandlePanic` + errgroup tracking
- **Lock correctness**: Sound — double-checked locking in prefetch, lrumap for pending
- **Error wrapping**: Consistent
- **Context propagation**: Intentional design — refreshes use server lifecycle ctx, not query ctx
