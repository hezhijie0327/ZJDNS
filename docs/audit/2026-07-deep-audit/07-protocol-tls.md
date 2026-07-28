# Protocol TLS/TLCP Audit — Agent Findings

## Scope

11 files: `server/protocol/tls/*` and `server/protocol/tlcp/*`

## Assessment Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 4 |

---

## HIGH Findings

### H9: TLCP DoT — no read deadline / context check blocks Shutdown

**File**: `server/protocol/tlcp/tlcp.go:85-112`
**Category**: `goroutine-leak`, `resource-lifecycle`

`handleDOTConn` never calls `conn.SetReadDeadline()` and never checks `s.ctx.Done()`.
`ReadTCPMsg`'s doc explicitly warns: "The caller MUST set a read deadline." The TLS DoT
handler (`tls.go:166`) sets a read deadline; the TLCP DTLS handler (`dtlcp.go:284`) also
sets one. The TLCP DoT handler alone violates the contract.

During Shutdown, idle TLCP DoT connections block on `io.ReadFull` until TCP keep-alive
timeout (~2 hours), preventing graceful shutdown.

**Fix**: Add `conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))` before
each `ReadTCPMsg` call, matching TLS DoT reference.

### H10: 5 of 7 handlers use non-deferred pool.Put — message leak on panic

**Files**: `tls/https.go:128-130`, `tls/dtls.go:154-181`, `tls/quic.go:223-229`,
`tlcp/tlcp.go:107-110`, `tlcp/dtlcp.go:316-343`
**Category**: `pool-leak`, `memory-safety`

The reference pattern (`tls/tls.go:234`) uses `defer pool.DefaultMessage.Put(resp)`.
Only 2 of 7 handlers follow this: TLS DoT (`tls.go`) and TLCP DoH (`http_tlcp.go`).
The remaining 5 use explicit (non-deferred) Put. If a panic occurs between Get and Put,
`HandlePanic` recovers but the deferred Put never fires — the message leaks.

**Risk**: Pool exhaustion under panic-triggering error conditions.

**Fix**: Replace `pool.DefaultMessage.Put(resp)` with `defer pool.DefaultMessage.Put(resp)`.

### H11: TLCP DoT — resp==nil terminates connection (inconsistent with TLS DoT)

**File**: `server/protocol/tlcp/tlcp.go:100-103`
**Category**: `cross-protocol-inconsistency`, `resource-lifecycle`

TLCP DoT processes queries synchronously per connection. A nil response terminates
the entire connection. TLS DoT uses worker goroutines — nil response only terminates
that query. An attacker who can trigger nil responses forces TLCP DoT clients to
reconnect.

**Fix**: Change `return` to `continue` when resp is nil.

### H12: QUIC handleDOQStream — blocks without context check

**File**: `server/protocol/tls/quic.go:171-231`
**Category**: `goroutine-leak`, `context-propagation`

`handleDOQStream` blocks on `io.ReadFull(stream, ...)` without checking context
or setting read deadline. During shutdown, stream goroutines may linger until
QUIC transport cleanup.

**Fix**: Derive per-stream context from `conn.Context()`, add `select` on ctx.Done
before blocking reads.

---

## Items Verified Clean

- Panic/nil dereference: All type assertions use comma-ok
- Lock correctness: `dtlcpListener.Close()` avoids self-deadlock
- Error wrapping: Consistent `%w` usage
- Context: All I/O accept ctx first argument; no `context.TODO()` in production
- Close idempotency: `dtlcpListener.Close()` guarded by atomic + lock
- Parameter validation: Constructors check nil config/handler
- Constants: All numeric values from config package
- Dead code: None found
- Goroutine: Every `go func()` has `defer HandlePanic` + errgroup ownership
