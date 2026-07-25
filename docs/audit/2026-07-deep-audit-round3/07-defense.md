# Defense + Server Core + CLI Layer — Round 3

**Date**: 2026-07-25
**Scope**: server/defense/poisonguard.go, server/server.go, server/init.go, server/bridge.go, server/tasks.go, cmd/zjdns/*.go, cmd/zjdns/cli/*.go
**Auditor**: Claude Code

---

## Finding Summary

| ID | Severity | Category | File | Line |
|----|----------|----------|------|------|
| DC-01 | HIGH | memory | cmd/zjdns/cli/probe.go | 80 |
| DC-02 | MEDIUM | shutdown | server/tasks.go | 168-170 |
| DC-03 | MEDIUM | pool-leak | server/bridge.go | 47 |
| DC-04 | MEDIUM | pool-leak | server/server.go | 265-295 |
| DC-05 | MEDIUM | coupling | cmd/zjdns/cli/generate.go | 15 |
| DC-06 | LOW | memory | server/bridge.go | 72 |
| DC-07 | LOW | memory | server/tasks.go | 140-154 |
| DC-08 | LOW | memory | cmd/zjdns/main.go | 31, 42, 47 |
| DC-09 | LOW | dead-code | cmd/zjdns/cli/parse.go | 105-110 |
| DC-10 | LOW | inefficiency | cmd/zjdns/cli/probe.go | 203-222 |
| DC-11 | LOW | defense | server/defense/poisonguard.go | 46-47 |

### Cleared Items (verified no issue)

| Pattern | Result |
|---------|--------|
| Pool discipline (all `Get()` matched by `Put()`) in bridge.go | 3 paths, all correct |
| Lock correctness (detector/defense state) | Detector is stateless — no locks needed |
| Import layer violations (server/) | 0 violations — all imports follow the DAG |
| Server shutdown ordering | Correct: listeners → connections → background tasks → cache |
| Signal handling correctness | SIGINT/SIGTERM captured, graceful shutdown triggered |
| Defense algorithms (poisonguard) | State machine correct for root/TLD/authoritative cases |
| QUIC pool goroutine leak | Not in scope, but warmup properly uses `warmWg.Wait()` |
| PoisonDetector nil-safety | All response params checked for nil before access |
| TLCP goroutine lifecycle | `Start()` returns quickly, `Shutdown()` handled inside errgroup goroutine |

---

## DC-01: Premature TCP connection close breaks all TLS probing

**File**: `cmd/zjdns/cli/probe.go`, line 80
**Severity**: HIGH
**Category**: memory (resource leak / broken path)

**Problem**: In `dialProbeTarget()`, the TLS branch uses a deferred `tcpConn.Close()` that closes the raw TCP socket **before the function returns**, rendering the returned `tlsConn` unusable:

```go
tcpConn, err := net.Dial("tcp", host)
if err != nil {
    return nil, err
}
defer func() { _ = tcpConn.Close() }()   // line 80 — deferred close fires on return
tlsConn := eTLS.Client(tcpConn, tlsCfg)
// ... handshake succeeds ...
return tlsConn, nil                       // defer closes tcpConn here
```

When `dialProbeTarget` returns `tlsConn` to the caller, the deferred function has already closed the underlying `tcpConn`. The returned `eTLS.Conn` wraps the now-closed connection. Any subsequent `Read`/`Write` on the connection will fail with "use of closed network connection" or similar.

This affects all three TLS probe operations:
- `probePipeline(addr)` — line 166 (TLS target sends 5 queries, all fail silently or with errors)
- `probeConnReuse(addr)` — line 237 (TLS target sends 3 queries, all fail)
- `probeIdleTimeout(addr)` — line 267 (TLS target sends 1 query, fails immediately)

**Risk**: Any `--probe` invocation against a `tls://` target produces incorrect results (silent failures or confusing errors). TCP targets (`tcp://`) are unaffected. This makes the TLS probing feature completely non-functional without any user-visible indication of the problem.

**Fix**: Remove the unconditional `defer`. Close `tcpConn` explicitly only on error paths, so the returned `tlsConn` retains a live underlying connection:

```go
case "tls":
    host = tryAddPort(host, defaultTLSPort)
    serverName, _, _ := net.SplitHostPort(host)
    tlsCfg := &eTLS.Config{
        MinVersion:         eTLS.VersionTLS12,
        ServerName:         serverName,
        InsecureSkipVerify: true,
        CurvePreferences:   []eTLS.CurveID{},
    }
    tcpConn, err := net.Dial("tcp", host)
    if err != nil {
        return nil, err
    }
    tlsConn := eTLS.Client(tcpConn, tlsCfg)
    if err := tlsConn.SetDeadline(time.Now().Add(probeTLSHandshakeTimeout)); err != nil {
        tcpConn.Close()
        return nil, fmt.Errorf("set deadline: %w", err)
    }
    if err := tlsConn.Handshake(); err != nil {
        tcpConn.Close()
        return nil, fmt.Errorf("TLS handshake: %w", err)
    }
    if err := tlsConn.SetDeadline(time.Time{}); err != nil {
        tcpConn.Close()
        return nil, fmt.Errorf("clear deadline: %w", err)
    }
    return tlsConn, nil
```

---

## DC-02: TLCP server not explicitly shut down in shutdownServer

**File**: `server/tasks.go`, lines 168-170 (and `server/server.go`, lines 412-425)
**Severity**: MEDIUM
**Category**: shutdown

**Problem**: `shutdownServer()` explicitly calls `Shutdown()` on the TLS server (line 181), the plain server (line 178), the DNSCrypt server (line 187), and the pprof server (line 196). The TLCP server is **not** included in this list.

TLCP shutdown is handled entirely inside the `Start()` errgroup goroutine (server.go lines 412-425):
```go
g.Go(func() error {
    defer zdnsutil.HandlePanic("TLCP server")
    if err := s.tlcpServer.Start(s); err != nil {
        return fmt.Errorf("TLCP startup: %w", err)
    }
    <-ctx.Done()
    if err := s.tlcpServer.Shutdown(); err != nil {     // Shutdown inside goroutine
        log.Errorf("TLCP: shutdown failed: %v", err)
    }
    return nil
})
```

This works because:
1. `tlcp.Server.Start()` returns quickly (it spawns listeners internally in sub-goroutines).
2. The goroutine blocks on `<-ctx.Done()`.
3. Context cancellation (from `shutdownServer`) unblocks it, and `Shutdown()` is called.

However, this is inconsistent with all other protocol servers and introduces a subtle dependency: TLCP shutdown depends solely on correct context propagation through the chain `s.ctx → serverCtx → ctx`. If any future refactoring changes the context hierarchy (e.g., using a separate context for TLCP), the TLCP server would never shut down cleanly. The context-propagation chain is fragile because it spans two functions (`New` creates `s.ctx`, `Start` derives `serverCtx` from `s.ctx`, then `ctx` from `serverCtx`).

Compare with TLS, which has the same `<-ctx.Done()` pattern in the goroutine but ALSO has an explicit `s.tls.Shutdown()` call in `shutdownServer()`.

**Risk**: Low-to-medium. A future refactoring that decouples the TLCP context from `s.ctx` would cause TLCP to hang on shutdown. Currently functional, but the inconsistency is a maintenance trap.

**Fix**: Add explicit `tlcpServer.Shutdown()` to `shutdownServer()`, matching the pattern used for all other protocol servers:

```go
// In shutdownServer(), after DNSCrypt shutdown:
if s.tlcpServer != nil {
    if err := s.tlcpServer.Shutdown(); err != nil {
        log.Errorf("TLCP: shutdown failed: %v", err)
    }
}
```

And in the `Start()` goroutine, remove the `Shutdown()` call — the goroutine's only role is lifecycle monitoring via `<-ctx.Done()`:

```go
g.Go(func() error {
    defer zdnsutil.HandlePanic("TLCP server")
    if err := s.tlcpServer.Start(s); err != nil {
        return fmt.Errorf("TLCP startup: %w", err)
    }
    <-ctx.Done()
    return nil
})
```

---

## DC-03: Bare type assertion on sync.Map.LoadOrStore result

**File**: `server/bridge.go`, line 47
**Severity**: MEDIUM
**Category**: pool-leak / panic

**Problem**: `LoadOrStore` returns `any`, which is then asserted without the comma-ok pattern:

```go
entryI, _ := s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
entry := entryI.(*tcpWriteEntry)       // bare assertion
```

If any code path ever stores a non-`*tcpWriteEntry` value in `s.tcpWriteMu` (e.g., a future code change that stores a different type for the same key), this assertion panics the current request goroutine.

The `sync.Map` is also accessed in the sweep goroutine (`startTCPWriteMuSweep`, tasks.go line 106-113) using `Range`, which uses a bare assertion too (line 107-108), but that one is inside a `Range` callback and would only affect the sweep goroutine, not crash the server.

**Risk**: Low in current code — the map is only ever written to from this single line, and only stores `*tcpWriteEntry`. Increases with code churn. A panic here kills the query goroutine but is caught by the deferred `HandlePanic` on line 29, so the server survives.

**Fix**: Use comma-ok and return SERVFAIL on type mismatch:

```go
entryI, _ := s.tcpWriteMu.LoadOrStore(addr, &tcpWriteEntry{})
entry, ok := entryI.(*tcpWriteEntry)
if !ok {
    log.Errorf("SERVER: unexpected type in tcpWriteMu: %T", entryI)
    return
}
```

---

## DC-04: deps.Closed replaced after middlewares capture it

**File**: `server/server.go`, lines 265 and 295
**Severity**: MEDIUM
**Category**: pool-leak / shutdown

**Problem**:

```go
// line 265 — stub during assembly
Closed: func() bool { return false },

// ... AssembleChain(deps) creates middlewares that capture deps.Closed ...

h := handler.NewHandler(chain, ...)

// line 295 — replace with real function AFTER middlewares assembled
deps.Closed = h.IsClosed
```

The middleware chain is assembled on line 289 via `middleware.AssembleChain(deps)`. At that point, `deps.Closed` returns `false` (the stub). The middlewares that reference `deps.Closed` capture the function pointer value at assembly time. If they store it as a field value (not as a pointer to the `Dependencies` struct), the replacement on line 295 has no effect — those middlewares would always see `false` for `Closed()`.

Whether this is actually a problem depends on how the individual middlewares reference `deps.Closed`:
- **If they store `deps.Closed` as `func() bool` field** (by value): They capture the stub permanently. The `MarkClosed()` call would never prevent these middlewares from processing requests during shutdown.
- **If they store `*Dependencies`** (by pointer): The replacement works, and `h.IsClosed` is used thereafter.

**Risk**: Medium. If any middleware in the chain stores `Closed` as a function value rather than retaining a pointer to `Dependencies`, that middleware would never observe the closed state. During shutdown, it would continue processing requests until the server is fully torn down. This could lead to requests being processed on partially-shut-down components.

**Fix options**:
1. Move the `deps.Closed` field to a `*atomic.Pointer[func() bool]` so all captures see updates.
2. Move `h.IsClosed` into `Dependencies` itself (make Handler own a reference to `Dependencies`) so the stub is never needed.
3. Verify that all middlewares reference `deps` via pointer, not by value (per-middleware audit required).

---

## DC-05: CLI imports server/protocol/dnscrypt

**File**: `cmd/zjdns/cli/generate.go`, line 15
**Severity**: MEDIUM
**Category**: coupling

**Problem**: The CLI tool (`cmd/zjdns/cli/generate.go`) imports `server/protocol/dnscrypt` to call `GenerateDNSCryptConfig`:

```go
import (
    serverdnscrypt "zjdns/server/protocol/dnscrypt"
)
```

This breaks the import layering rule: CLI is a top-level consumer and should not import server sub-packages. It pulls the entire DNSCrypt server implementation into the CLI binary, increasing binary size and creating a dependency where CLI changes can be blocked by server package changes. The comment on lines 12-14 acknowledges this coupling but justifies it by the effort required to split out key generation.

**Risk**: Low in practice — the import is stable and limited to one function. Medium for binary size (the entire DNSCrypt implementation is linked). If the DNSCrypt package is ever refactored or has build-tag constraints, the CLI would break.

**Fix**: Extract `GenerateDNSCryptConfig` (and the key generation logic it calls) into a separate package under `internal/` (e.g., `internal/dnscrypttool`). The server package would still import it for its own use, and the CLI would import it too — the layering rule is preserved because `internal/` is foundation-level.

---

## DC-06: TCP query goroutines not tracked in errgroup or WaitGroup

**File**: `server/bridge.go`, line 72
**Severity**: LOW
**Category**: memory (goroutine leak)

**Problem**: Every TCP DNS request spawns a goroutine (`go func() { ... }()` on line 72) that is not tracked in any errgroup or WaitGroup. On server shutdown:
1. The goroutine may be blocked on `s.tcpSem <- struct{}{}` or actively processing.
2. The `select` with `s.ctx.Done()` (line 80) handles cancellation, so the goroutine exits when the context is done.
3. However, if the goroutine has already acquired `s.tcpSem` and is inside `handler.ServeDNS()`, it will continue processing even after shutdown begins.

These goroutines are bounded by `entry.capacity` (per-client, `DefaultMaxPipe`) and `s.tcpSem` (global, `DefaultServerGoroutineLimit`). They are not leaked in the traditional sense — they all eventually exit — but they are untracked and may outlive the server's `Start()` function return.

**Risk**: Low. In-flight TCP queries during shutdown complete normally or fail quickly due to context cancellation. The goroutines terminate via `<-s.ctx.Done()` or by completing their work. No resource leak because each goroutine cleans up after itself (releases capacity/semaphore slots in deferred functions).

**Fix** (optional): Add a `sync.WaitGroup` to track active TCP query goroutines and wait for them in `shutdownServer()` after cancelling the context, before closing the query client. This is defense-in-depth — not required for correctness today.

---

## DC-07: Signal handler goroutine untracked

**File**: `server/tasks.go`, lines 140-154
**Severity**: LOW
**Category**: memory (documented)

**Problem**: The signal handler goroutine is not tracked in any errgroup or WaitGroup:

```go
func (s *Server) setupSignalHandling() {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

    go func() {
        defer zdnsutil.HandlePanic("Signal handler")
        defer signal.Stop(sigChan)
        select {
        case sig := <-sigChan:
            log.Infof("SIGNAL: Received signal %v, starting graceful shutdown", sig)
            s.shutdownServer()
        case <-s.ctx.Done():
        }
    }()
}
```

The comment on lines 150-153 fully documents this and notes that if `Wait()` dependencies are added, this must be tracked. The goroutine exits cleanly when either a signal arrives or the context is cancelled. On signal, it calls `shutdownServer()` synchronously from within the goroutine, which cancels the context and thus unblocks the `case <-s.ctx.Done()` in the signal handler itself — but since `shutdownServer()` runs before the `select` returns, this is fine.

**Risk**: Low. The goroutine always exits via one of the two select cases. No resource leak.

---

## DC-08: os.Exit(1) skips deferred functions in main()

**File**: `cmd/zjdns/main.go`, lines 31, 42, 47
**Severity**: LOW
**Category**: memory / cleanup

**Problem**: Three call sites use `os.Exit(1)` which terminates the process immediately without running deferred functions:

```go
os.Exit(1) // line 31 — config load failure
os.Exit(1) // line 42 — server creation failure
os.Exit(1) // line 47 — server startup failure
```

The comment on line 31 states "This package has no defers; safe." This is correct today — `main()` has no `defer` statements, and the `server.New()` and `server.Start()` functions have their own cleanup paths (context cancellation, deferred `serverCancel`, etc.). However, `os.Exit` skips defers in ALL goroutines, including any deferred cleanup in the errgroup goroutines or background tasks that are still running.

Currently the failure paths are clean because:
- Config load failure: No server resources allocated yet.
- Server creation failure: `cancel(err)` is called in `New()` error paths, but `os.Exit` means deferred cleanup in spawned goroutines may not run. In practice, the process exits immediately, so the OS reclaims everything.
- Server startup failure: Same as above.

**Risk**: Low currently. If `main()` ever adds a defer (e.g., log flush, metric export), it would be silently skipped on error. The pattern is fragile but safe for the current code.

**Fix**: Replace `os.Exit(1)` with `log.Fatal` (which also calls `os.Exit` but documents intent) or restructure to return errors to a wrapper that exits cleanly. Alternatively, just add a clarifying nolint comment on each call.

---

## DC-09: Redundant --help handling before flag parsing

**File**: `cmd/zjdns/cli/parse.go`, lines 105-110
**Severity**: LOW
**Category**: dead-code (minor)

**Problem**: `ParseFlags` manually checks for `-h`/`--help` in `os.Args` before calling `fs.Parse()`:

```go
for _, arg := range osArgs[1:] {
    if arg == "-h" || arg == "--help" {
        fs.Usage()
        return "", true
    }
}
```

The `flag.FlagSet` already handles `-h`/`--help` with the default `flag.ContinueOnError` error handling. If `-h` is passed, `fs.Parse()` prints usage and returns `ErrHelp`. The code ignores this error (line 113: `if err := fs.Parse(osArgs[1:]); err != nil { return "", true }`). So the manual check is redundant — the flow is:

1. Manual check catches `-h` before parsing → prints usage → exits.
2. If manual check is removed, `fs.Parse()` would print usage (via `fs.Usage()`) and return `ErrHelp` → caught by line 113 → exits.

The two code paths produce slightly different output ordering (manual check prints usage before any error messages from Parse, while the default path would print flag parse errors before usage). The difference is cosmetic.

**Risk**: Negligible. The code works correctly. The manual check is simply unnecessary.

**Fix**: Remove the manual check — `flag.FlagSet` handles `-h` natively:

```go
if err := fs.Parse(osArgs[1:]); err != nil {
    if errors.Is(err, flag.ErrHelp) {
        return "", true
    }
    fs.Usage()
    return "", true
}
```

---

## DC-10: Probe latency measurement is cumulative, not per-query

**File**: `cmd/zjdns/cli/probe.go`, lines 203 and 219
**Severity**: LOW
**Category**: inefficiency (cosmetic)

**Problem**: In `probePipeline()`, the latency measurement for each response uses `start` which was set before the query-sending loop:

```go
start := time.Now()
for i := range domains {
    _ = conn.SetReadDeadline(time.Now().Add(probePipelineReadTimeout))
    resp, err := readDNSMsg(conn)
    // ...
    latency := time.Since(start).Milliseconds()
    fmt.Printf("  ← response #%d (%dms) rcode=%s\n", resp.ID, latency, dns.RcodeToString[resp.Rcode])
}
```

The `latency` value is cumulative from the start of the probe, not per-query. For a server that processes queries sequentially (serializing responses), the Nth response shows the cumulative time, not the individual query's round-trip time. This is misleading.

For example, with 5 queries sent:
- Response #0: ~10ms (correct — first query RTT)
- Response #1: ~12ms (should be ~10ms but cumulative shows 2ms more)
- Response #3: ~15ms, etc.

The displayed latency values drift upward as more responses arrive, because they're measured from a single `start` point rather than per-query timestamps.

**Risk**: Cosmetic — the displayed latency numbers are slightly inflated for later queries. Does not affect the pipelining correctness detection (the OOO detection and count comparison are correct).

**Fix**: Record per-query send timestamps and measure latency per response:

```go
sendTimes := make([]time.Time, probePipelineNumQueries)
for i, d := range domains {
    sendTimes[i] = time.Now()
    // ... send query ...
}
for i := range domains {
    resp, err := readDNSMsg(conn)
    // ...
    latency := time.Since(sendTimes[resp.ID]).Milliseconds()
    // ...
}
```

---

## DC-11: VerdictUncertain documented as unused by callers

**File**: `server/defense/poisonguard.go`, lines 46-47
**Severity**: LOW
**Category**: defense (code-quality)

**Problem**: The `VerdictUncertain` value is returned by `classify()` for authoritative-level responses but is documented as never checked by callers:

```go
// No caller checks VerdictUncertain (VerdictPoisoned is the only
// actionable signal). Retained as a placeholder for future
// multi-vantage-point analysis that could resolve this ambiguity.
```

This means all authoritative-level responses are classified as `Uncertain`, which is functionally equivalent to `Clean` from the caller's perspective. The authoritative-level hijacking detection is a stub waiting for multi-vantage-point analysis that hasn't been implemented.

The `Validate()` method returns `VerdictUncertain` (line 129), and its callers only check for `VerdictPoisoned`. So authoritative-level poisoning is never detected.

**Risk**: Low — the limitation is documented and well-understood. The Detector's current capability (root + TLD level detection) covers the most common hijacking scenarios (GFW injection at root/forwarding servers). Authoritative-level detection would require a fundamentally different approach (multi-vantage comparison).

---

## Verified: Pool Discipline in bridge.go

All pool-managed objects in bridge.go have correct Get/Put discipline:

| Path | Pool.Get() line(s) | Pool.Put() line(s) | Pattern |
|------|-------------------|--------------------|---------|
| TCP SERVFAIL path | 56 (`pool.DefaultMessage.Get`) | 61 (pack error), 68 (after write) | Explicit Put on both paths |
| TCP query path (goroutine) | handler.ServeDNS returns pooled msg | 92 (pack error), 105 (write lock timeout), 111 (after write) | Explicit Put on all 3 paths |
| UDP query path | handler.ServeDNS returns pooled msg | 123 (pack error), 135 (truncate pack error), 142 (after write) | Explicit Put on all 3 paths |

All paths verified. No leaks. The `handler.ServeDNS()` contract (returns pooled `*dns.Msg` or nil) is correctly followed.

---

## Verified: PoisonDetector State Machine

The Detectgorilla's three-level classification is correct:

| Zone | Condition | Verdict | Rationale |
|------|-----------|---------|-----------|
| Root (`.`) | A/AAA for `*.root-servers.net` | Clean | Glue records for root server hostnames |
| Root (`.`) | NS/DS for TLDs | Clean | Legitimate root delegations |
| Root (`.`) | Name is `.` | Clean | Root query for itself |
| Root (`.`) | Anything else | Poisoned | Middlebox injection |
| TLD | Name equals zone | Clean | SOA/NS records for the TLD itself |
| TLD | Name differs from zone | Poisoned | Middlebox injection |
| Authoritative | Any | Uncertain | Cannot distinguish by content alone |

Edge cases verified:
- `response == nil` → returns `Clean` (no panic)
- Empty Answer section → returns `Clean`
- Query name doesn't match any Answer RR → returns `Clean`
- `IsPoisonedByTLD` only checks A/AAAA records → other types are not flagged
- `isTLD` returns false for empty or multi-label strings → root check uses `zone == "."` not `isTLD`

---

## Verified: Import Layer (server/ packages)

| Package | Imports from server/ sub-packages | Domain package imports | Verdict |
|---------|-----------------------------------|----------------------|---------|
| `server/server.go` | `defense`, `handler`, `handler/middleware`, `protocol/tls`, `resolver`, `resolver/dnssec`, `resolver/probe`, `upstream` | `config`, `cache`, `database`, `edns`, `ruleset`, `zone` | OK |
| `server/tasks.go` | None | `config` | OK |
| `server/bridge.go` | None | `config` | OK |
| `server/init.go` | `defense`, `resolver`, `resolver/dnssec`, `upstream` | `config`, `cache`, `edns` | OK |
| `cmd/zjdns/main.go` | `server` | `config`, `database` | OK |
| `cmd/zjdns/cli/generate.go` | `server/protocol/dnscrypt` | `config` | **DC-05** |
| `cmd/zjdns/cli/*.go` | None | `config`, `database` | OK |

No violations except DC-05 (documented and accepted).

---

## Verified: Shutdown Ordering

The shutdown sequence in `shutdownServer()` (tasks.go) follows the correct order:

1. **`handler.MarkClosed()`** — prevents new requests from entering the chain
2. **`s.cancel(errors.New("server shutdown"))`** — cancels all derived contexts
3. **`s.plain.Shutdown(shutdownCtx)`** — stops plain UDP/TCP listeners
4. **`s.tls.Shutdown()`** — stops TLS/DoT/DoQ/DoH/DoH3/DTLS listeners
5. **`s.dnscryptServer.Shutdown(ctx)`** — stops DNSCrypt listener
6. **`s.pprofServer.Shutdown(ctx)`** — stops pprof HTTP listener
7. **Wait for `s.backgroundGroup.Wait()`** — background tasks finish
8. **Wait for `s.handler.CacheRefreshGroup().Wait()`** — cache refresh tasks finish
9. **`s.handler.Prober().Close()`** — latency prober (owns QUIC connections)
10. **`s.queryClient.Close()`** — outbound transport pools (waits for warmup via `warmWg`)
11. **`cacheStore.Close()`** — cache store (AsyncStatsWriter flush + close)
12. **`log.DefaultTimeCache.Stop()`** — log time cache
13. **`close(s.shutdown)`** — signals `Start()` to return

All steps present and correctly ordered. Background tasks are waited on before the query client is closed (needed for in-flight refresh/resolve operations). The prober is closed before the query client (prober owns QUIC connections).

The errgroup `g` from `Start()` is managed by the coordinator goroutine and not explicitly waited on in `shutdownServer()`. This is correct — the coordinator's `g.Wait()` returns when all protocol server goroutines exit (triggered by context cancellation + explicit `Shutdown()` calls), and its `close(errChan)` unblocks `Start()`'s `for err := range errChan` loop, which then blocks on `<-s.shutdown` until `shutdownServer()` closes it.

---

## Verified: Signal Handling

Signal handling in `setupSignalHandling()` (tasks.go):

- **SIGINT/SIGTERM** are registered via `signal.Notify` with a buffered channel (size 1).
- On signal: calls `shutdownServer()` on the signal handler goroutine (not deferred to main goroutine).
- On context cancellation: the `select` also catches `s.ctx.Done()`, so explicit cancellation also cleans up the signal handler.
- `defer signal.Stop(sigChan)` cleans up the signal registration when the goroutine exits.
- The goroutine is not tracked (DC-07), but this is acceptable — it always exits via one of the two select cases.

No issues. The single-buffered channel ensures at least one signal is captured. If a second signal arrives before `signal.Stop` runs, it's dropped — acceptable for graceful shutdown.

---

## Verified: Dead Code

No dead code found. All exported functions and methods in the audited files are referenced:

| Symbol | Referenced by |
|--------|--------------|
| `Server.ServeDNS()` | TLS server interface + external benchmarks |
| `Server.Start()` | `main.go` |
| `SetRootFilesDir()` | `main.go` |
| `isRecursiveMode()` | `server.go` initDNSResolver |
| All CLI dispatch functions | `parse.go` ParseFlags |
| All probe functions | `probe.go` runProbe dispatcher |

---

## Files Audited

All 13 files read and analyzed:

- `server/defense/poisonguard.go`
- `server/server.go`
- `server/init.go`
- `server/bridge.go`
- `server/tasks.go`
- `cmd/zjdns/main.go`
- `cmd/zjdns/banner.go`
- `cmd/zjdns/version.go`
- `cmd/zjdns/cli/dnsstamp.go`
- `cmd/zjdns/cli/generate.go`
- `cmd/zjdns/cli/parse.go`
- `cmd/zjdns/cli/probe.go`
- `cmd/zjdns/cli/sql.go`

Supporting reads for verification:
- `server/upstream/client.go` (warmup lifecycle, Close)
- `server/upstream/warmup.go` (warmWg tracking)
- `server/protocol/tlcp/server.go` (Start/Shutdown lifecycle)
- `server/protocol/plain/server.go` (Start/Shutdown signature)
