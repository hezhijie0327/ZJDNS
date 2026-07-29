# 25 · 交叉分析：Goroutine 生命周期

> 审计 Agent：Phase 2a · Goroutine
> 范围：全项目 HandlePanic、owner、取消路径、errgroup SetLimit


Now I have a complete picture. Let me compile the full audit report.

---

## Goroutine Lifecycle Audit Report

### Summary

- **22 bare `go func()` spawns** across non-test files
- **6 `errgroup.Go` groups** with ~15+ goroutine spawns
- **3 DNSCrypt accept-loop goroutines** (`go s.serveUDP`, `go s.serveTCP`, `go s.rotationLoop`)
- **2 untracked coordinator goroutines** (server errgroup wait, TLS errgroup wait)
- **4 fire-and-forget probe goroutines** with no lifecycle tracking

---

### FINDING 1 (MEDIUM) -- Server coordinator goroutine untracked

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/server.go:459-468`

```go
go func() {
    defer zdnsutil.HandlePanic("Server coordinator")
    if err := g.Wait(); err != nil { ... }
    close(errChan)
}()
```

**Problem:** This goroutine calls `g.Wait()` on the protocol server errgroup and forwards the first error to `errChan`. It has no owner — no WaitGroup, no errgroup, no done channel to wait on. The code at line 151-156 explicitly acknowledges this:

> "The coordinator goroutine that calls g.Wait() is also orphaned — the shutdown path uses cancel-only signalling instead of a coordinated group wait."

**Risk:** If the coordinator goroutine panics (despite `HandlePanic`), there is no mechanism to propagate the failure. During shutdown, `shutdownServer()` cancels the errgroup context (causing `g.Wait()` to return), but nobody waits for the coordinator goroutine to finish. In tests, this can cause goroutine leak detection failures.

**Fix:** Track the coordinator goroutine in a separate `errgroup.Group` or `sync.WaitGroup` that is waited on during shutdown. Alternatively, use `errgroup.Group` for the errgroup lifecycle: wrap it so `g.Wait()` is called synchronously in the main `Start()` goroutine, eliminating the need for a separate coordinator goroutine.

---

### FINDING 2 (MEDIUM) -- TLS server coordinator goroutine untracked

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/server.go:256-265`

```go
go func() {
    defer zdnsutil.HandlePanic("TLS server coordinator")
    if err := g.Wait(); err != nil { ... }
    close(errChan)
}()
```

**Problem:** Same pattern as Finding 1. The TLS protocol server uses a bare goroutine to wait on its internal errgroup. The `Start()` method reads from `errChan` to capture startup errors, but after startup, the coordinator goroutine runs untracked.

**Risk:** During TLS server shutdown (`s.cancel()`), the errgroup goroutines exit and `g.Wait()` returns, but nothing ensures the coordinator goroutine has completed before `Shutdown()` returns. Same panic propagation gap as Finding 1.

**Fix:** Same as Finding 1 — track the coordinator or eliminate the need for it by synchronously blocking on `g.Wait()`.

---

### FINDING 3 (LOW) -- Fire-and-forget NS address probe goroutines

**Files:**
- `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive_ns.go:114`
- `/Users/hezhijie/Downloads/ZJDNS/server/resolver/ns_addresses.go:94`
- `/Users/hezhijie/Downloads/ZJDNS/server/resolver/ns_addresses.go:135`
- `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go:336`

All are identical in pattern:

```go
go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
```

**Problem:** Each goroutine is fire-and-forget — no WaitGroup, no errgroup, no owner tracking. They use `r.ctx` so context cancellation will propagate, but the resolver has no mechanism to wait for these goroutines to complete during shutdown.

**Risk:** If `ProbeNSAddrs` is blocked on an unresponsive upstream (e.g., HTTP/3 QUIC dial to a nameserver) and the cache or database is closed during shutdown, the probe writes to the closed cache (`r.cache.Set()`), potentially causing a panic on a closed BadgerDB transaction.

**Fix:** Collect these goroutines in a `sync.WaitGroup` field on the `Recursive` resolver. Call `wg.Wait()` during resolver shutdown or defer it in `Server.shutdownServer()`. Since these are latency probes with short timeouts, the impact on shutdown latency is minimal.

---

### FINDING 4 (LOW) -- Signal handler goroutine not tracked

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/tasks.go:130-143`

```go
go func() {
    defer zdnsutil.HandlePanic("Signal handler")
    defer signal.Stop(sigChan)
    select {
    case sig := <-sigChan:
        ...
    case <-s.ctx.Done():
    }
}()
```

**Problem:** The signal handler goroutine is not tracked in any errgroup or WaitGroup. A code comment at line 140-143 acknowledges this.

**Risk:** Low — the goroutine exits cleanly on signal receipt or context cancellation. No resource leak. The only concern is if `shutdownServer()` blocks (e.g., background group timeout), the signal handler has already exited and cannot process a second signal (e.g., SIGTERM from systemd after timeout).

**Fix:** Track in `backgroundGroup` with `s.backgroundGroup.Go(...)` for consistency. The errgroup's context cancellation will unblock the select naturally.

---

### FINDING 5 (LOW) -- DNSCrypt accept-loop goroutines are bare goroutines, not in errgroup

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go:168, 201, 207`

```go
go s.serveUDP(s.ctx, conn)      // line 168
go s.serveTCP(s.ctx, listener)  // line 201
go s.rotationLoop()             // line 207
```

**Problem:** Unlike TLS/TLCP/plain protocol servers (which register their accept loops via `errgroup.Go()`), the DNSCrypt server launches its accept loops as bare goroutines. They are tracked via a `sync.WaitGroup` (`s.wg`) through `Add(1)`/`Done()` calls inside `serveUDP`/`serveTCP`, and the WaitGroup is swapped atomically during shutdown. `rotationLoop` is not tracked and relies solely on context cancellation.

**Risk:** The WaitGroup swap pattern (Finding 6) creates a window where goroutines could register with the wrong WaitGroup. `rotationLoop` has no lifecycle tracking at all — it relies exclusively on `s.ctx.Done()` for cancellation.

**Fix:** (A) Track `rotationLoop` in `s.wg` like the other two. (B) Consider migrating all three to the project's consistent errgroup pattern, or (C) ensure the WaitGroup swap covers all three.

---

### FINDING 6 (LOW-MEDIUM) -- DNSCrypt WaitGroup swap is fragile

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go:259-260`

```go
prevWg := s.wg
s.wg = &sync.WaitGroup{}
```

**Problem:** During `Shutdown()`, the server atomically replaces `s.wg` with a fresh WaitGroup, then waits on `prevWg`. This creates a safety window: any handler goroutine started via `s.wg.Go()` after the swap increments the new WaitGroup, which nobody waits for. The shutdown sequence relies on context cancellation to prevent new goroutines from being started after the swap, but this is implicit rather than enforced.

**Risk:** If a network packet arrives between the swap and the context cancellation (which happens before the swap at line 258: `s.cancel(...)`), a handler goroutine registers with the wrong WaitGroup and may panic on closed resources during processing, or may never complete.

**Fix:** The context cancellation happens *before* the swap, so in practice this is safe. However, the pattern is fragile and should be documented more clearly, or refactored to avoid the swap entirely (e.g., use an `errgroup.Group` and `ctx.Done()` checks instead).

---

### FINDING 7 (INFO) -- SOCKS5 UDP relay double-goroutine nesting

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/socks5/udp.go:180-201`

```go
go func() {
    defer zdnsutil.HandlePanic("SOCKS5 UDP relay")
    done := make(chan struct{})
    go func() {
        defer zdnsutil.HandlePanic("SOCKS5 UDP relay")
        var buf [1]byte
        _, _ = ctrlConn.Read(buf[:])
        defer close(done)
    }()
    select {
    case <-done:
    case <-ctrlClosed:
        _ = ctrlConn.Close()
    }
    ...
}()
```

**Problem:** The inner goroutine blocks on `ctrlConn.Read()` (a blocking I/O call). The outer goroutine uses `ctrlClosed` to unblock it. This is a documented pattern (line 171-178). It works correctly, but it spawns one extra goroutine per UDP relay that is blocked in `Read()` for the lifetime of the relay.

**Risk:** Nil — the pattern is correct and the documentation explains why it can't be simplified (combining into one goroutine would require additional synchronization). However, using `ctrlConn.SetReadDeadline()` with a polling loop would eliminate the inner goroutine entirely.

**Fix:** Consider using `SetReadDeadline(time.Now().Add(pollInterval))` in a single goroutine with a select on `<-ctrlClosed`, eliminating the nested goroutine.

---

### FINDING 8 (INFO) -- `resultChan` in nameserver.go is never closed

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go:34`

```go
resultChan := make(chan *dns.Msg, 1)
```

**Problem:** Unlike forward.go (which closes `resultChan` after `g.Wait()`), this channel is never closed. The code uses a separate `errgroupDone` channel to signal completion.

**Risk:** Nil — the buffered channel (size 1) is GC'd when the function returns. This is an intentional design choice to avoid the "send on closed channel" hazard that closing `resultChan` would introduce.

**Fix:** None required. Pattern is correct.

---

### Comprehensive Goroutine Inventory (all non-test goroutine spawns)

| # | File | Line | HandlePanic | Owner | Cancel Path | Bounded | Finding |
|---|------|------|-------------|-------|-------------|---------|---------|
| 1 | `internal/latency/prober.go` | 80 | Yes | `sync.WaitGroup` | `ctx.Done()` + `p.ctx.Done()` | Semaphore chan | OK |
| 2 | `internal/log/log.go` | 324 | Custom recover | None | `t.done` chan close | — | OK (lifetime of program) |
| 3 | `server/tasks.go` | 130 | Yes | None | `s.ctx.Done()` + sigChan | — | Finding 4 |
| 4 | `server/tasks.go` | 208 | Yes | `bgDone` chan + timer | — (g.Wait returns) | Shutdown timeout | OK |
| 5 | `server/tasks.go` | 226 | Yes | `refreshDone` chan + timer | — (g.Wait returns) | Shutdown timeout | OK |
| 6 | `server/bridge.go` | 98 | Yes | Semaphore chan + ctx | `s.ctx.Done()` | `tcpSem` chan | OK |
| 7 | `server/server.go` | 459 | Yes | None | — (g.Wait returns) | — | **Finding 1** |
| 8 | `server/protocol/tls/server.go` | 256 | Yes | None | — (g.Wait returns) | — | **Finding 2** |
| 9 | `server/protocol/tls/tls.go` | 111 | Yes | `writerDone` chan | `writeCh` close | — (1 writer) | OK |
| 10 | `server/protocol/tls/tls.go` | 230 | Yes | `sync.WaitGroup` | `connCtx.Done()` | `workerCap` chan | OK |
| 11 | `server/protocol/dnscrypt/server.go` | 264 | Yes | `done` chan + timer | — (prevWg.Wait) | Shutdown timeout | OK |
| 12 | `server/resolver/recursive_ns.go` | 114 | Yes | **None** | `r.ctx.Done()` (implicit) | — | **Finding 3** |
| 13 | `server/resolver/forward.go` | 97 | Yes | `g.Wait()` + close | — (g.Wait returns) | — | OK |
| 14 | `server/resolver/ns_addresses.go` | 94 | Yes | **None** | `r.ctx.Done()` (implicit) | — | **Finding 3** |
| 15 | `server/resolver/ns_addresses.go` | 135 | Yes | **None** | `r.ctx.Done()` (implicit) | — | **Finding 3** |
| 16 | `server/resolver/nameserver.go` | 173 | Yes | `errgroupDone` chan | — (g.Wait returns) | — | OK |
| 17 | `server/resolver/nameserver.go` | 270 | Yes | `sync.WaitGroup` | `queryCtx.Done()` | wg.Wait | OK |
| 18 | `server/resolver/nameserver.go` | 276 | Yes | `sync.WaitGroup` | `queryCtx.Done()` | wg.Wait | OK |
| 19 | `server/resolver/nameserver.go` | 336 | Yes | **None** | `r.ctx.Done()` (implicit) | — | **Finding 3** |
| 20 | `server/upstream/socks5/udp.go` | 180 | Yes | `ctrlClosed` chan | `ctrlConn.Read()` unblock | — | Finding 7 (INFO) |
| 21 | `server/upstream/socks5/udp.go` | 183 | Yes | `done` chan | — (Read returns) | — | Finding 7 (INFO) |
| 22 | `server/protocol/dnscrypt/server.go` | 168,201,207 | Yes (inside fn) | `s.wg` (Add/Done) | `s.ctx.Done()` | `workerCap` chan | Finding 5 |

### errgroup.SetLimit coverage

| errgroup | File | Line | SetLimit | Value |
|----------|------|------|----------|-------|
| Server protocol errgroup | `server/server.go` | 401 | No | Unlimited |
| TLS protocol errgroup | `server/protocol/tls/server.go` | 199 | No | Unlimited |
| TLCP serverGroup | `server/protocol/tlcp/server.go` | 117-118 | Yes | `DefaultServerGoroutineLimit` |
| Forward resolver | `server/resolver/forward.go` | 48-49 | Yes | `concurrencyLimit(len(servers))` |
| Nameserver query | `server/resolver/nameserver.go` | 35-37 | Yes | `min(len(ns), DefaultMaxConcurrentNS)` |
| NS address resolve | `server/resolver/nameserver.go` | 224-225 | Yes | `concurrencyLimit(len(nsRecords))` |
| DoQ streams | `server/protocol/tls/quic.go` | 138-139 | Yes | `DefaultMaxConcurrentStreams` |
| backgroundGroup | `server/server.go` | 72-74 | Yes | `DefaultCacheRefreshConcurrency` |
| cacheRefreshGroup | `server/server.go` | 72-74 | Yes | `DefaultCacheRefreshConcurrency` |

**Finding (INFO):** The two main protocol server errgroups (server.go line 401 and tls/server.go line 199) do NOT use `SetLimit`, meaning all protocol listeners (UDP, TCP, DoT, DoQ, DoH, DoH3, DTLS) could theoretically be spawned without a concurrency cap. In practice, the number of listeners is bounded by configuration (at most a few dozen ports), so this is not a risk.

### Channel single-owner close audit

All channels have unambiguous single-owner close patterns:

- `t.done` (log.go) -- closed once via `sync.Once` in `Stop()` ✓
- `sigChan` (tasks.go) -- created, passed to `signal.Notify`, never explicitly closed (signal.Stop) ✓
- `bgDone`, `refreshDone` (tasks.go) -- created, sent to once, never closed (timer-based select, not range) ✓
- `errChan` (server.go:395, tls/server.go:197) -- closed once by coordinator goroutine ✓
- `s.shutdown` (server.go:80) -- closed once in `shutdownCleanup()` ✓
- `writeCh` (tls.go:108) -- closed in defer after `wg.Wait()`, single closer ✓
- `writerDone` (tls.go:110) -- closed once by writer goroutine defer ✓
- `resultChan` (forward.go:43) -- closed once by coordinator goroutine after `g.Wait()` ✓
- `resultChan` (nameserver.go:34) -- never closed (intentional design) ✓
- `errgroupDone` (nameserver.go:172) -- closed once by goroutine defer ✓
- `done` (cache_lookup.go:136) -- closed once by refresh goroutine defer ✓
- `done` (tls/quic.go:126) -- closed once by `context.AfterFunc` ✓
- `done` (dnscrypt/server.go:263) -- closed once by goroutine defer ✓
- `done` (socks5/udp.go:182) -- closed once by inner goroutine defer ✓
- `d.ctrlClosed` (socks5/udp.go:166) -- closed in `cleanupLocked()` which creates a replacement after close ✓
- `call.done` (pending.go) -- closed via `sync.Once` ✓
- `w.done` (cache/async_writer.go) -- closed via defer in `run()` ✓
- `rotateCh` (dnscrypt/server.go:121) -- closed once in `Shutdown()` ✓
- `entry.capacity`, `entry.writeMu` (bridge.go) -- created in `Acquire` and not closed (bounded chan, no close needed) ✓
- `p.sem` (prober.go) -- not closed (bounded chan, no close needed) ✓
- `workerCap` (dnscrypt/server.go, tls/tls.go) -- not closed (bounded chan, no close needed) ✓

No double-close hazards found.

---

### Recommendations (priority order)

1. **(MEDIUM)** Track the two coordinator goroutines (Findings 1, 2) in a WaitGroup or eliminate them by making `g.Wait()` synchronous in the startup path. This closes the panic-propagation gap and prevents test-level goroutine leak warnings.

2. **(LOW)** Collect the four fire-and-forget NS probe goroutines (Finding 3) into a WaitGroup on the `Recursive` resolver. Add a `WaitProbes()` method and call it in the shutdown sequence before cache/database closure. The change is ~10 lines total.

3. **(LOW)** Track `rotationLoop` in `s.wg` in the DNSCrypt server (Finding 5), or migrate to errgroup for consistency with the rest of the codebase.

4. **(LOW)** Move the signal handler (Finding 4) from a bare goroutine into `backgroundGroup.Go(...)` for lifecycle consistency.

5. **(INFO)** Document the `server.go` and `tls/server.go` errgroup's lack of `SetLimit` as intentional (since listener count is configuration-bounded), or remove the discrepancy with the TLCP pattern.