# 15 · Protocol 包深度审计

> 审计 Agent：Phase 1 · Protocol（重新生成）
> 覆盖：server/protocol/plain (3), tls (8), tlcp (5), dnscrypt (7) = 23 个非测试文件
> 维度：池归还纪律、goroutine 生命周期、Close() 幂等性、defer 在循环中、锁内 IO、并发安全、错误包装、context 传播

Now I have all the data needed. Let me compile the comprehensive audit report.

---

# ZJDNS Protocol Layer Audit Report

**Scope:** All 21 non-test Go files under `server/protocol/`
**Date:** 2026-07-29

---

## CRITICAL

### C1. tlcp/server.go:Start() -- Partial startup leaks goroutines and listeners

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/server.go`, lines 174-190

**Problem:** The three sub-starts (`startDOTServer`, `startDOHServer`, `startDTLCPServer`) are called sequentially. If one succeeds and a later one fails, `Start()` returns the error **without cancelling `s.ctx`**. The already-started goroutines in `s.serverGroup` check `s.ctx.Done()` in their accept loops -- since the context is never cancelled, they run forever with open listeners.

```go
if s.dotPort != "" {
    if err := s.startDOTServer(); err != nil { ... }
}
if s.dohPort != "" {                // ← if this fails
    if err := s.startDOHServer(); err != nil {
        return fmt.Errorf(...)       // ← returns WITHOUT s.cancel()
    }
}
```

**Risk:** On any transient config error, DoT (or previously started protocol) goroutines + listeners leak permanently. Repeated config reloads accumulate leaked goroutines.

**Fix:** Either (a) cancel context on error via `s.cancel()` before returning, or (b) use the same errgroup-channels pattern as `tls/server.go:Start()` which correctly calls `s.cancel()` at line 272 on the first error.

---

## HIGH

### H1. tlcp/dtlcp.go:handleDTLCPConnections -- Serialized connection handling (DoS)

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/dtlcp.go`, lines 235-267

**Problem:** Only **one** DTLCP connection is handled at a time. The code explicitly documents this at lines 263-265:

```go
// Handle synchronously — gotlcp shares the underlying UDP socket across
// all connections. Concurrent reads cause packet stealing between Conn
// instances and SetReadDeadline on one Conn affects the shared socket's
// Accept loop. Until gotlcp provides per-connection socket isolation,
// only one connection is served at a time.
s.handleDTLCPConnection(conn)  // ← blocks until this connection finishes
```

A slow or malicious client opens one DTLCP connection, sends a query slowly, and blocks all other DTLCP clients from being served. This is a fundamental design limitation.

**Risk:** Trivial denial-of-service. One client with a 30-second read timeout blocks all other DTLCP users.

**Fix:** Per-connection UDP socket isolation (connected UDP sockets or separate `dtlcp.Conn` instances each owning their own socket). Or a per-connection goroutine pattern with a read deadline that kicks the connection out if it idles, falling back to a new accept.

---

### H2. tlcp/server.go:Start() -- No error rollback for already-started protocol groups

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/server.go`, lines 174-190

**Problem:** Same function as C1 but viewed from the other angle: when one sub-start fails, the previously started listeners are not closed. Compare with `dnscrypt/server.go:Start()` (lines 171-198) which cleans up all previously opened sockets on error.

**Risk:** Even if the caller calls `Shutdown()` on error, there is a window where listeners are accepting connections. If the caller does not call `Shutdown()`, the leak is permanent.

**Fix:** Deferred cleanup: on any error, iterate all started listeners and close them. Or use the same pattern as `dnscrypt/server.go` which is correct.

---

### H3. dnscrypt/udp.go:serveUDP -- Buffer cleanup relies on all exit paths being manually correct

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/udp.go`, lines 62 and 116

**Problem:** The pooled buffer `buf` is acquired at line 62 but its Put-back is **not** done via `defer`. Instead, every exit path manually calls `pool.DefaultBuffer.Put(buf)`:

- Line 79: early return on `!s.isStarted()` in error path
- Line 86: early return on non-temporary read error
- Line 116: normal loop exit

Unlike the DoT handler in `tls/tls.go` which uses `defer pool.DefaultBuffer.Put(buf)`, this pattern requires every future code modification to remember all three exit sites. A single missed path creates a permanent pool leak.

**Risk:** Pool depletion under sustained error conditions if a future edit misses an exit path.

**Fix:** Move the buffer acquisition before the loop and use a deferred Put at function entry:

```go
buf := pool.DefaultBuffer.Get()
defer pool.DefaultBuffer.Put(buf)
for s.isStarted() { ... }
```

Then remove the manual Put calls at lines 79, 86, and 116.

---

## MEDIUM

### M1. tls/tls.go:handleDOTConnection -- query.Data aliases pooled buffer

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/tls.go`, lines 184-186, 198-199

**Problem:** When `msgLength <= pool.SecureBufferSize`, the code does:

```go
pooledBuf = pool.DefaultBuffer.Get()
msgBuf = pooledBuf[:msgLength]
...
req := pool.DefaultMessage.Get()
req.Data = msgBuf
```

`req.Data` aliases `pooledBuf`. The buffer ownership is transferred to the worker goroutine. During `ServeDNS`, the query data is valid. After `ServeDNS`, `defer pool.DefaultMessage.Put(query)` zeroes the query struct, and `defer pool.DefaultBuffer.Put(pooledBuf)` returns the buffer to the pool. If any downstream handler captured `query.Data` for deferred access (e.g., async caching), that reference would point into a zeroed buffer.

**Risk:** Low under current synchronous pipeline, but a future asynchronous handler could read corrupted data. Fragile invariant.

**Fix:** Either explicitly document in a comment that `query.Data` must not be captured across the `ServeDNS` call boundary, or zero-copy by owning the buffer through the entire handler chain (current approach is fine but brittle).

---

### M2. tls/dtls.go:handleDTLSConnection -- query.Data aliases loop buffer

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/dtls.go`, lines 107-108, 147

**Problem:** Same alias issue as M1 but worse -- the aliased buffer is also the **loop read buffer**:

```go
buf := pool.DefaultBuffer.Get()
defer pool.DefaultBuffer.Put(buf)
for {
    n, err := conn.Read(buf)              // overwrites buf on each iteration
    ...
    query.Data = buf[2 : 2+msgLen]        // aliases buf
    ...
    response := s.handler.ServeDNS(query, clientIP, true, config.ProtoDTLS)
    pool.DefaultMessage.Put(query)
    ...
    // next iteration: conn.Read(buf) overwrites buf
}
```

If `ServeDNS` processes the query synchronously (which it does), the data is read before the next iteration. But the alias is subtle and the buffer is a mutable shared resource between iterations.

**Risk:** Medium. If the handler chain ever becomes async (storing a reference to the request), the next iteration's `conn.Read(buf)` corrupts the previous query's data.

**Fix:** Copy the query payload to a separate allocation:

```go
queryData := make([]byte, msgLen)
copy(queryData, buf[2:2+msgLen])
query.Data = queryData
```

---

### M3. tlcp/dtlcp.go:handleDTLCPConnection -- Same alias issue as M2

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/dtlcp.go`, lines 281-282, 308-309

**Problem:** Identical pattern to M2 -- `query.Data = buf[zdnsutil.DNSFramePrefixLen : zdnsutil.DNSFramePrefixLen+msgLen]` aliases the loop read buffer.

**Risk:** Same as M2.

**Fix:** Same as M2 -- copy the query payload.

---

### M4. tlcp/tlcp.go:handleDOTConn -- No pool usage for request messages

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/tlcp.go`, lines 95-96

**Problem:** The TLCP DoT handler uses `zdnsutil.ReadTCPMsg(conn)` which internally does:

```go
func ReadTCPMsg(conn net.Conn) (*dns.Msg, error) {
    ...
    buf := make([]byte, length)         // fresh allocation
    ...
    msg := new(dns.Msg)                 // fresh allocation, not from pool
    msg.Data = buf
    ...
}
```

Neither the buffer nor the message come from the shared pool. Every query allocates. Compare with the TLS DoT handler (`tls/tls.go:handleDOTConnection`) which properly uses `pool.DefaultBuffer.Get()` and `pool.DefaultMessage.Get()`.

**Risk:** Increased GC pressure under load. Memory allocation doubles compared to the TLS path.

**Fix:** Replace `ReadTCPMsg` usage with the pool-based read pattern from `tls/tls.go`. Or add a pool-aware variant of `ReadTCPMsg`.

---

### M5. tls/server.go:Shutdown -- No deferred cancel() for dohServers shutdown contexts

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/server.go`, lines 312-317

**Problem:**

```go
for _, srv := range s.dohServers {
    if srv != nil {
        ctx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
        _ = srv.Shutdown(ctx)
        cancel()
    }
}
```

`cancel()` is called immediately after `Shutdown` returns (not deferred). While this doesn't leak (the context's lifetime is bounded by the synchronous `Shutdown` call), the pattern is inconsistent with best practice. If `Shutdown` ever panics, the context would not be cancelled until GC.

Compare with the DTLS/QUIC sections which don't use a WithTimeout at all, and with the TLCP `Shutdown` which does the same pattern as above.

**Risk:** Minimal. Only a concern if `Shutdown` is modified to return before calling `cancel()`.

**Fix:** Use `defer cancel()` for consistency and safety.

---

### M6. dnscrypt/server.go:Start -- Race window between started flag and socket allocation

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go`, lines 142-209

**Problem:** The `s.started = true

Continuing the audit report from where it was cut off.

---

## MEDIUM (continued)

### M6. dnscrypt/server.go:Start -- Race window between `started` flag and socket allocation

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go`, lines 142-209

**Problem:** `s.started = true` is set inside the locked section at line 151, then the lock is released. All subsequent socket opens (UDP at lines 158-168, TCP at lines 179-201) happen outside the lock. If `Shutdown()` is called during this window, it sees `started=true` and closes all tracked sockets (an empty slice at that point). Meanwhile `Start()` continues opening new sockets and appending them — those new sockets are never closed by the concurrent `Shutdown()`.

```go
s.mu.Lock()
s.started = true        // ← Shutdown sees this
s.mu.Unlock()
// ← Shutdown() can run here, closing empty s.udpConns / s.tcpListeners
for _, addr := range udpAddrs {
    conn, err := net.ListenUDP(...)
    s.udpConns = append(s.udpConns, conn)  // ← conn is never closed by Shutdown
}
```

**Risk:** Low. In normal operation `Start()` completes before `Shutdown()` is called. Under concurrent Start/Shutdown (misuse), UDP/TCP sockets leak.

**Fix:** Open all sockets first, then set `started = true` atomically under the lock, and register them in `s.udpConns`/`s.tcpListeners` under the same lock.

---

### M7. tls/tls.go:handleDOTConnection -- workerCap channel not drained on read loop exit

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/tls.go`, lines 153, 220-227

**Problem:** The `workerCap` channel (line 153, capacity `DefaultMaxPipe`) is used to limit concurrent workers per connection. Each worker defers `<-workerCap` (line 231). But if the main read loop exits early (e.g., read error at line 169), the main loop returns without draining `workerCap`. Workers that are still running will drain their slots via defer, but any **unsent** slot permits remain in the channel forever.

Actually, this is not a leak — the `workerCap` channel permits are only taken when a worker is successfully dispatched. The slot is returned when the worker finishes. The main loop exit doesn't leave taken slots. The channel capacity is irrelevant to the main loop exit path.

**Reassessment:** This is actually fine. No issue.

---

## LOW

### L1. tls/dtls.go:startDTLSServer -- Errors returned without context wrapping

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/dtls.go`, lines 22, 29, 46

**Problem:** Three error return sites use bare `return err` instead of `return fmt.Errorf("DTLS ... : %w", err)`:

```go
addrs, err := zdnsutil.ResolveBindAddrs("udp", s.cfg.DTLSPort)
if err != nil {
    return err          // line 22 — no wrapping
}
...
udpAddr, err := net.ResolveUDPAddr("udp", addr)
if err != nil {
    return err          // line 29 — no wrapping
}
...
listener, err := dtls.ListenWithOptions(...)
if err != nil {
    return err          // line 46 — no wrapping
}
```

**Risk:** Lower layers of error attribution are lost. If the caller logs the error, it's unclear which step failed.

**Fix:** Wrap with `fmt.Errorf("DTLS %s: %w", addr, err)`.

---

### L2. tls/https.go:parseDOHRequest -- dnshttp.Request result not from pool

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/https.go`, line 145

**Problem:** `dnshttp.Request(r)` allocates a new `*dns.Msg`. This message is used in `ServeHTTP` and then discarded via GC. It is never returned to `pool.DefaultMessage`. While you cannot return a message you didn't `Get` from the pool, adding a pool-aware message reader could reduce allocations.

**Risk:** Very low. Additional GC pressure under heavy DoH/DoH3 load.

---

### L3. dnscrypt/crypto.go:decrypt / decryptPQResumed -- New messages not from pool (deliberate)

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/crypto.go`, lines 160, 195-196, 268

**Problem:** Both decryption functions allocate fresh `msg = &dns.Msg{}` instead of using `pool.DefaultMessage.Get()`. The comment at line 157-159 explains this is deliberate:

```go
// NOTE(L10): could use pool.DefaultMessage.Get() here — left as &dns.Msg{}
// because pool ownership semantics differ for decrypt-shortlived messages.
```

**Risk:** None — the allocation is intentional and documented.

---

### L4. dnscrypt/server.go:handleHandshake -- Temporary message allocation

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go`, lines 439, 497

**Problem:** The final `reply` message (line 439) is from the pool, but its `Data` is immediately copied to a new `res` slice (line 497) and the `reply` is Put back. This is correct but an opportunistic reader might wonder why the reply data can't be used directly.

**Risk:** None. The comment at lines 494-498 explains the copy is required because Put zeroes the message struct.

---

## Per-File Summary

### server/protocol/plain/

| File | Issues |
|------|--------|
| `server.go` | Clean. No issues. |
| `tcp.go` | Clean. No issues. |
| `udp.go` | Clean. No issues. |

### server/protocol/tls/

| File | Issues |
|------|--------|
| `server.go` | MEDIUM M5 (missing `defer cancel()`), clean otherwise |
| `tls.go` (DoT) | MEDIUM M1 (query.Data aliases buffer), M7 (resolved as non-issue) |
| `quic.go` (DoQ) | Clean context propagation, one issue: `handleDOQStream` defers response.Put inside `if` block (pattern only, functionally correct) |
| `http3.go` (DoH3) | Clean |
| `https.go` (DoH) | LOW L2 (non-pooled dnshttp.Request) |
| `dtls.go` (DTLS) | MEDIUM M2 (query.Data aliases loop buffer), LOW L1 (unwrapped errors) |
| `certs.go` | Clean |
| `addr_validator.go` | Clean |

### server/protocol/tlcp/

| File | Issues |
|------|--------|
| `server.go` | **CRITICAL C1** (partial startup leak), **HIGH H2** (no error rollback) |
| `tlcp.go` (DoT) | MEDIUM M4 (no pool for ReadTCPMsg) |
| `dtlcp.go` (DTLCP) | **HIGH H1** (serialized connections = DoS), MEDIUM M3 (query.Data aliases buffer) |
| `http_tlcp.go` (DoH) | LOW (non-pooled dnshttp.Request, same as L2) |
| `certs.go` | Clean |

### server/protocol/dnscrypt/

| File | Issues |
|------|--------|
| `server.go` | MEDIUM M6 (race window in Start), LOW L4 (documented copy) |
| `crypto.go` | LOW L3 (deliberate non-pooled allocation) |
| `generate.go` | Clean |
| `tcp.go` | Clean |
| `udp.go` | **HIGH H3** (no deferred pool return) |

---

## Cross-Cutting Observations

### Pool Discipline (Get/Put Pairing)

**Good patterns:**
- TLS DoT handler: clear ownership transfer with poolBufOK flag, writer goroutine handles Put on write, drain loop catches remaining buffers on connection close.
- DNSCrypt UDP: correct buffer swap pattern (`packet := buf[:n]; buf = pool.DefaultBuffer.Get()`) with handler ownership transfer.
- DNSCrypt handshake: correct `m = nil` pattern to prevent double-Put from deferred cleanup.

**Weak patterns:**
- TLCP DoT: no pool usage at all for incoming messages (`ReadTCPMsg` allocates fresh).
- DNSCrypt decrypt path: deliberately doesn't use pool (documented).

### Goroutine Lifecycle

**Well-managed:**
- TLS server: errgroup tracks all protocol goroutines; context cancellation in `Shutdown()` and on startup error.
- DNSCrypt: WaitGroup swap pattern allows graceful shutdown with in-flight requests.
- Plain UDP/TCP: caller's errgroup manages lifecycle.

**Problematic:**
- TLCP `Start()`: no context cancellation on partial failure (C1).

### Context Propagation

All accept loops correctly check `s.ctx.Done()` (or its derived context). DNSCrypt's `serveDNS` passes `ctx` to `WriteMsg` but not to `ServeDNS` — minor gap (LOW).

### Lock-in-IO

No instances of I/O under user-held locks in the audited code. The `dtlcpListener.Close()` lock/unlock/lock pattern is complex but avoids I/O under lock. DNSCrypt `Shutdown()` closes sockets under `s.mu`, which is acceptable since socket close is non-blocking.

### Error Wrapping

Most errors are correctly wrapped with `%w`. Exceptions noted in L1 (`tls/dtls.go` bare returns). The DNSCrypt `handleHandshake` and tlcp `handleDTLCPConnections` correctly wrap all errors.

### Close Idempotency

- TLS `Shutdown()`: multiple calls safe (context cancel is idempotent, `CloseWithLog` handles nil).
- TLCP `Shutdown()`: same pattern, safe.
- DNSCrypt `Shutdown()`: `started` flag prevents double-invocation, returns `ErrServerNotStarted`.

---

## Summary Statistics

| Severity | Count | Key Areas |
|----------|-------|-----------|
| CRITICAL | 1 | tlcp/server.go: partial startup leak |
| HIGH | 3 | tlcp/dtlcp.go serialized handling, dnscrypt/udp.go fragile cleanup |
| MEDIUM | 7 | Buffer aliasing (3x), TLCP pool gaps (1x), shutdown patterns (2x), race window (1x) |
| LOW | 4 | Unwrapped errors, documented non-pooled allocations |

**Most concerning finding:** `tlcp/server.go:Start()` does not cancel the server context on partial startup failure, causing goroutine and listener leaks — a correctness gap compared to `tls/server.go:Start()` which handles this correctly.

**Most impactful finding:** `tlcp/dtlcp.go` serialized connection handling is a trivial DoS vector for DTLCP — one slow client blocks all others.