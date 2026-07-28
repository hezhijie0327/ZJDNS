# Upstream Audit: server/upstream/*

## Summary
- Files audited: 22
- CRITICAL: 0, HIGH: 2, MEDIUM: 9, LOW: 8

## lrumap Usage Audit

| File | lrumap instance | Value type | OnEvict set? | Status |
|------|----------------|------------|-------------|--------|
| `server/upstream/client.go:53` | proxyDialers | `*socks5.Dialer` | YES — `d.Close()` at line 114 | OK |
| `server/upstream/tls/client.go:41` | quicConfigs | `*quic.Config` | N/A (config, no resources) | OK |
| `server/upstream/tls/client.go:43` | dohTransports | `*http.Client` | NO | **MEDIUM** — evicted clients leak idle HTTP connections |
| `server/upstream/tls/client.go:44` | doh3Transports | `*http.Client` | NO | **MEDIUM** — same as above |
| `server/upstream/tlcp/client.go:24` | httpClient | `*http.Client` | NO | **MEDIUM** — same as above |
| `server/upstream/dnscrypt/client.go:23` | cache | `*State` | N/A (keys only, no external resources) | OK |
| `server/upstream/tls/client.go:39` | dtlsSessions | `*lrumap.DTLSSessionStore` | N/A (wraps `lrumap.Map[string, dtls.Session]` — `dtls.Session` is a value interface, no resources) | OK |

## Findings

### [HIGH] [Data Race] server/upstream/dnscrypt/client.go:215 + state.go:99,200 — Unprotected c.cache write vs read

- **Problem**: `Client.Close()` sets `c.cache = nil` (client.go line 215) without any synchronization. Meanwhile, `state()` reads `c.cache` (state.go line 99: `c.cache.Get(cacheKey)`) and `buildState()` writes to `c.cache` (line 200: `c.cache.Set(cacheKey, state)`) without holding any lock. If `Close()` races with an in-flight query, this is a data race on the `c.cache` pointer.
- **Risk**: Concurrent nil-write vs read/write on `c.cache`. Go's race detector would flag this. The `c.cache == nil` check in `buildState` (line 197) is a band-aid, not a fix — the race window exists before the check.
- **Fix**: Add a `sync.Mutex` to `Client` to protect `c.cache` access, or use `atomic.Pointer` for the cache field and nil-check atomically in `state()`. Since `Close()` is called during server shutdown with `warmWg.Wait()` already done, the race window is bounded to in-flight queries — but it is still a data race.

### [HIGH] [Performance / Locking] server/upstream/pool/quic.go:146-156 — QUIC.Shutdown holds p.mu during blocking close

- **Problem**: `QUIC.Shutdown()` calls `pc.close()` while holding `p.mu`. `close()` calls `quic.Conn.CloseWithError()` which sends a CONN_CLOSE frame and may block briefly for I/O. While `quic-go`'s `CloseWithError` is non-blocking in practice, the design pattern is inconsistent with `ConnPool.Shutdown` (pool/tcp.go lines 466-481) which correctly collects all connections under the lock and closes them outside it.
- **Risk**: If a future `quic-go` version makes `CloseWithError` blocking, or if the network write buffers are full, `p.mu` is held for the duration, blocking all pool operations (Acquire, Put, Remove, WarmUp).
- **Fix**: Follow the same pattern as `ConnPool.Shutdown`:
  ```go
  func (p *QUIC) Shutdown() {
      p.mu.Lock()
      p.closed = true
      var all []*QUICConn
      for _, conns := range p.conns {
          all = append(all, conns...)
      }
      p.conns = make(map[string][]*QUICConn)
      p.mu.Unlock()
      for _, pc := range all {
          pc.close()
      }
  }
  ```

### [MEDIUM] [Resource Leak] server/upstream/tls/client.go:43-44 — dohTransports/doh3Transports LRU eviction leaks HTTP connections

- **Problem**: `dohTransports` and `doh3Transports` are `*lrumap.Map[string, *http.Client]` without an `OnEvict` callback. Each cached `*http.Client` wraps an `*http.Transport` (or `*http3Transport`) with open connections. When an entry is LRU-evicted, the underlying `*http.Client` is dropped without closing idle connections. The `Close()` method handles explicit shutdown via `Range`, but eviction bypasses this.
- **Risk**: Bounded leak (max `DefaultTransportMax*2 + DefaultTransportMax = 192` clients) per upstream client lifetime. Each leaked client holds its TCP/TLS/QUIC connections until the OS GCs them via keepalive timeout.
- **Fix**: Set `OnEvict` on both maps in `New()`:
  ```go
  c.dohTransports.OnEvict = func(_ string, client *http.Client) {
      if ct, ok := client.Transport.(*eHTTP.CompatableTransport); ok {
          ct.CloseIdleConnections()
      }
  }
  c.doh3Transports.OnEvict = func(_ string, client *http.Client) {
      if t, ok := client.Transport.(*http3Transport); ok {
          _ = t.Close()
      }
  }
  ```

### [MEDIUM] [Resource Leak] server/upstream/tlcp/client.go:24 — httpClient LRU eviction leaks TLCP connections

- **Problem**: Same pattern as DoH/DoH3 — `httpClient` is an `*lrumap.Map[string, *http.Client]` without `OnEvict`. LRU-evicted HTTP clients leak their underlying TLCP transport connections.
- **Fix**: Add `OnEvict` in `New()`:
  ```go
  c.httpClient.OnEvict = func(_ string, client *http.Client) {
      if t, ok := client.Transport.(*http.Transport); ok {
          t.CloseIdleConnections()
      }
  }
  ```

### [MEDIUM] [Goroutine Leak Risk] server/upstream/socks5/udp.go:179-198 — Monitor goroutines lack HandlePanic

- **Problem**: The double-goroutine pattern in `establishUDPRelay` (lines 179-198) does not use `defer zdnsutil.HandlePanic(...)` in either the outer or inner goroutine. If `ctrlConn.Read` panics (extremely unlikely for `net.Conn`, but possible with alternative `Conn` implementations), the `done` channel is never closed, causing the outer goroutine to leak indefinitely.
- **Risk**: Goroutine leak under edge-case panic scenarios.
- **Fix**: Add `defer zdnsutil.HandlePanic("SOCKS5 UDP relay")` to both goroutines. Additionally, change `close(done)` to `defer close(done)` in the inner goroutine for robustness.

### [MEDIUM] [Code Duplication] server/upstream/tls/https.go:116-171 — createDOHClient has duplicated nil-guard block

- **Problem**: The nil-guard at lines 117-123 (`if c.dohTransports == nil`) contains the exact same transport-construction logic as the main path at lines 130-171. The two blocks differ only in caching behavior (lines 163-170).
- **Risk**: Code drift risk — any future change to transport construction must be applied in two places.
- **Fix**: Consolidate. Move the nil guard to return early:
  ```go
  if c.dohTransports == nil {
      tr, ok := c.dohClient.Transport.(*eHTTP.Transport)
      if !ok { return &http.Client{Timeout: c.dohClient.Timeout, Transport: &eHTTP.CompatableTransport{}} }
      return &http.Client{Timeout: c.dohClient.Timeout, Transport: &eHTTP.CompatableTransport{Transport: tr}}
  }
  ```
  Then the rest of the function runs unconditionally with the cache.

### [MEDIUM] [Code Duplication] server/upstream/tls/http3.go:127-131 — createDOH3Client same nil-guard pattern

- **Problem**: Same duplication as `createDOHClient` — the nil-guard returns `c.doh3Client` directly while the main path constructs a full `*http.Client` with custom transport.
- **Risk**: Same code drift risk.
- **Fix**: Same approach — move nil-guard to early return.

### [MEDIUM] [Code Quality] server/upstream/pool/quic.go — Redundant dialing map cleanup in Acquire

- **Problem**: After `p.dialing[key]--` (line 103 in the dial-completion path), the same `if p.dialing[key] == 0 { delete(p.dialing, key) }` pattern is repeated at lines 107-109, 114-116, and 124-126. Since `dialing[key]` was just decremented, at most one of these can match (when it reaches 0). The repetition is unnecessary.
- **Fix**: Consolidate to a single check: `if p.dialing[key] == 0 { delete(p.dialing, key) }` placed just before `p.mu.Unlock()` at line 127, or use a defer.

### [MEDIUM] [Error Handling] server/upstream/socks5/udp.go:325-345 — socks5UDPConn.Read inconsistent error wrapping

- **Problem**: `socks5PacketConn.ReadFrom` wraps errors with `fmt.Errorf("socks5: read: %w", err)` and `fmt.Errorf("socks5: parse UDP datagram: %w", err)`. But `socks5UDPConn.Read` (lines 333, 339) returns bare errors from `c.conn.Read()` and `parseDatagram()` without wrapping, making it harder to trace the error origin.
- **Risk**: Debugging difficulty — errors from `socks5UDPConn.Read` lack the "socks5:" prefix that other SOCKS5 errors have.
- **Fix**: Wrap errors:
  ```go
  nr, err := c.conn.Read((*buf))
  if err != nil {
      return 0, fmt.Errorf("socks5: read: %w", err)
  }
  dg, _, err := parseDatagram((*buf)[:nr])
  if err != nil {
      return 0, fmt.Errorf("socks5: parse UDP datagram: %w", err)
  }
  ```

### [MEDIUM] [Comment Accuracy] server/upstream/tls/https.go:83 — Typo in comment

- **Problem**: Line 83: `"retry., while cached clients"` — `".,"` should be `";"`.
- **Fix**: Change `"retry.,"` to `"retry;"`.

### [LOW] [Resource Cleanup] server/upstream/socks5/udp.go:179-198 — Documented double-close of ctrlConn (M19)

- **Problem**: When `Close()` is called, `cleanupLocked()` closes `d.ctrlConn`. Then `close(d.ctrlClosed)` signals the monitor goroutine, which also calls `_ = ctrlConn.Close()` (line 191). Go's `net.Conn.Close()` is idempotent, but alternative `Conn` implementations may not be. Acknowledged in code comment (M19).
- **Risk**: Low with Go stdlib; potential issue with custom `net.Conn` implementations.
- **Fix**: Already documented. Could be fixed by having the monitor goroutine check `d.ctrlConn == ctrlConn` before calling Close (similar to the cleanupLocked guard).

### [LOW] [Performance / Context] server/upstream/pool/quic.go:70-134 — Acquire does not check ctx cancellation before dial

- **Problem**: `QUIC.Acquire` checks the context only implicitly through `dialFunc`. If the context is already cancelled, Acquire still acquires the lock, does the live-connection scan, and only discovers cancellation inside `dialFunc` (or not at all if `dialFunc` ignores the context).
- **Fix**: Add `select { case <-ctx.Done(): return nil, ctx.Err(); default: }` before the lock (or just after acquiring live connections).

### [LOW] [Performance] server/upstream/pool/tcp.go:153 — WriteBuf trackingID update bounds check is unreachable

- **Problem**: The bounds check at line 153 (`if len(writeBuf) < zdnsutil.DNSFramePrefixLen+2`) can never trigger. When `writeBuf` is the pooled buffer (size `SecureBufferSize` = 8192), it's always large enough. When `writeBuf` is freshly allocated (oversized query), it has exactly `zdnsutil.DNSFramePrefixLen + len(msgData)` bytes, and since the minimum DNS message is 12 bytes, `len(msgData) >= 12 > 2`.
- **Risk**: None — dead code. Cleanup for clarity.
- **Fix**: Remove the check, or replace with an assertion.

### [LOW] [Context Propagation] server/upstream/tls/dtls.go:60 — DTLS dial lacks context

- **Problem**: `dtls.DialWithOptions` does not accept a `context.Context` (pion/dtls library limitation). The context is used only for `SetDeadline` afterwards. This means a cancelled context during DTLS dial won't abort the dial until the connection is established.
- **Risk**: Delayed cancellation during DTLS handshake. Known library limitation.
- **Fix**: Track upstream pion/dtls for context support. Consider adding `dialCtx, cancel := context.WithTimeout(ctx, c.timeout)` before calling `SetDeadline`.

### [LOW] [Context Propagation] server/upstream/tlcp/dtlcp.go:24-41 — dialDTLCP uses context only for HandshakeContext

- **Problem**: `net.ListenPacket("udp", ":0")` (line 30) and the initial packet listen are not context-aware. Only the subsequent `conn.HandshakeContext(ctx)` is cancellable.
- **Risk**: Minor — listen is near-instant.
- **Fix**: Not actionable without an existing context-aware listen API in Go stdlib.

### [LOW] [Spec Compliance] server/upstream/tls/quic.go:72-76 — 0-RTT rejection retry uses same QUIC connection

- **Problem**: Acknowledged spec non-compliance: RFC 9000 requires a fresh QUIC connection when 0-RTT is rejected, but the current code retries on the same `pc.Conn`. This works because `quic-go` falls back to a full handshake internally, but a spec-compliant implementation would dial a new connection.
- **Risk**: Low — works with current quic-go. May break with future quic-go versions that enforce the spec strictly.
- **Fix**: As documented — dial a new connection on 0-RTT rejection.

### [LOW] [Code Quality] server/upstream/warmup.go:27-33 — proxyDialer stores nil on error, wasting LRU slot

- **Problem**: When `socks5.New` fails, `c.proxyDialers.Set(server.Proxy, nil)` stores a nil entry in the LRU cache. This consumes a slot permanently (nil is a valid `*socks5.Dialer`) and shortens the effective cache size.
- **Risk**: Negligible — cache is 128 entries, and a single nil entry is harmless.
- **Fix**: Either skip the `Set` on error, or use a dedicated error sentinel value.

### [LOW] [Constant Usage] server/upstream/plain/tcp.go:86-88 + tls/dtls.go:71-72 + tlcp/dtlcp.go:71-72 — Literal 2 instead of zdnsutil.DNSFramePrefixLen

- **Problem**: Three files use the literal `2` for the DNS 2-byte length prefix instead of the named constant `zdnsutil.DNSFramePrefixLen` (which is defined as `const DNSFramePrefixLen = 2`). While functionally identical, it's inconsistent with other code that uses the constant.
- **Affected lines**:
  - `plain/tcp.go:86`: `writeBuf := make([]byte, 2+len(msg.Data))`
  - `tls/dtls.go:71`: `req := make([]byte, 2+queryLen)`
  - `tlcp/dtlcp.go:71`: `req := make([]byte, 2+queryLen)`
- **Fix**: Replace `2` with `zdnsutil.DNSFramePrefixLen`.

### [LOW] [Magic Number] server/upstream/dnscrypt/client.go:172 — Inline constant maxQueryLen = 4096

- **Problem**: The `maxQueryLen` constant is defined inline in `Execute()` rather than as a package-level or config constant. This is used for DNSCrypt min-query-len escalation bounds.
- **Fix**: Extract to a named config constant or package-level constant with a descriptive name.

### [LOW] [Error Handling] server/upstream/socks5/socks5.go:395-407 — splitHostPort silently defaults on SplitHostPort error

- **Problem**: When `net.SplitHostPort` fails (no port in address), `splitHostPort` silently uses `config.DefaultUDPPort` instead of returning the error. While this is intentional (DNS default port 53), a comment would clarify the design choice and warn proxy users to configure ports explicitly.
- **Fix**: Add a comment explaining the default-port fallback.

### [LOW] [Documentation] server/upstream/pool/tcp.go:91 — SetSegmentation docstring is mixed into Exchange doc

- **Problem**: The `Exchange` method's docstring (line 90) contains a stray `SetSegmentation` description: `"// SetSegmentation configures TCP DNS message segmentation for this connection."` that appears between `Exchange` and the method body.
- **Fix**: Move the `SetSegmentation` description to the `SetSegmentation` method itself (lines 92-96).

## File-by-File Audit Notes

### server/upstream/client.go
- Parameter validation present (lines 126-131)
- Context: `WithTimeout` for each query, fresh context for TCP fallback (correct)
- DNSCrypt UDP→TCP fallback uses fresh context — correct
- `Close()`: nil-safe, waits for warmWg, ranges proxyDialers, closes dnscrypt client. **Missing**: does not close plainClient or tlcpClient. The plainClient has no Close method (no pooled resources to clean up beyond what the pool manages). tlcpClient's Close method is nil — verify.
- Logs: all Debug level on hot path — appropriate

### server/upstream/warmup.go
- `proxyDialer`: nil LRU cache entry on error (LOW)
- `WarmUpConnections`: uses `sync.WaitGroup.Go` — needs Go 1.21+. Correct.
- `HandlePanic`: present on warmup goroutine. Good.

### server/upstream/plain/client.go
- HopGuard reference: initialized via `defense.NewHopGuard()` — no import-layer violation (both server sub-packages)
- Struct is minimal — clean design

### server/upstream/plain/tcp.go
- Nil validation on msg and server
- Pooled path: correct Acquire/Remove pattern, segmentation, fallback to non-pooled
- Non-pooled fallback: `exchangeViaProxy` correctly gets pooled message, returns it on error
- Pool return discipline: `pool.DefaultMessage.Get()` at line 93, `Put` on all error paths and after successful parse. IDs restored on response. **Correct**.
- `defer func() { _ = conn.Close() }()` at line 77 — no resource leak

### server/upstream/plain/udp.go
- Spoofguard multi-read: correct pool return across all paths
- `spoofguardState.processPacket/pickBest`: all pool.Get messages are Put on error, or returned. **Correct**.
- `transfer` from `s.last`/`s.prev` to caller — ownership transfer, caller's responsibility. **Correct**.
- `copyBuf` reuse in `spoofguardState` — avoids per-candidate heap allocation. Good.
- `buf` cleared before Put (lines 116, 133) — prevents data leakage. Good.
- Raw socket TTL capture: guarded by `server.HopGuard` and `conn != nil` check. Correct.
- Hopguard warns once per address via `hopguardWarned.LoadOrStore`. Good.

### server/upstream/tls/client.go
- 6 LRU maps: only `proxyDialers` has `OnEvict` (see lrumap audit above)
- `Close()`: ranges transports, calls CloseIdleConnections, pools Shutdown. **Missing**: OnEvict not set for dohTransports/doh3Transports
- TLS configs: eTLS vs stdTLS correctly separated for eTLS/KTLS vs std TLS/QUIC
- `resetQUICConfig`: clones config, replaces TokenStore. Correct concurrency (config accessed only via getQUICConfig which does Set, or via reset).

### server/upstream/tls/tls.go
- Pooled DoT: Acquire → Exchange → handle error → Remove on dead. Correct
- Non-pooled fallback: `exchangeOverTLS` gets pooled message, puts on error. **Correct**.
- `dialTLSConn`: TCP keepalive set. TLS handshake with context. **Correct**.

### server/upstream/tls/dtls.go
- No context for `dtls.DialWithOptions` — library limitation (LOW)
- DTLS session store via lrumap.DTLSSessionStore — correct
- Response buffer: `pool.DefaultBuffer.Get()` → `respBuf[2:2+respLen]` → `pool.DefaultMessage.Data = msgBuf` → `resp.Data = nil` before `defer pool.DefaultBuffer.Put(respBuf)`. **Correct lifecycle**.

### server/upstream/tls/quic.go
- Pooled DoQ: Acquire → doQUICQuery → handle 0-RTT retry → Remove on failure. Correct
- Non-pooled path: dial → doQUICQuery → handle 0-RTT → Put/close. Correct
- `doQUICQuery`: msg.ID set to 0 per RFC 9250. Correct
- Buffer sizing: fallback to `make` when pool buffer insufficient. Correct
- Response buffer lifecycle: `respBuf` from pool → `body` sub-slice → `resp.Data = body` → `resp.Data = nil` (before Pool.Put via defer). **Correct**.
- Pool Put: pools connection after successful query; closes on no-pool path. Correct

### server/upstream/tls/https.go
- Cached client retry: on cached failure, closes idle connections, deletes entry, creates new client, retries up to `DefaultSecureTransportRetries` times. Correct pattern.
- First request: no retry (documented). Consider adding retry for consistency.
- `createDOHClient`: code duplication with nil-guard (MEDIUM). `LoadOrStore` for racy cache update. Correct.
- Comment typo: "retry.," (MEDIUM).

### server/upstream/tls/http3.go
- `http3Transport`: custom RoundTripper with `OnlyCachedConn: true` first, fallback to `RoundTrip`. Connection reuse optimization. Correct.
- `Close`: RWMutex-guarded. Idempotent via `closed` bool. Correct.
- Retry loop: `for range` (Go 1.22+), checks `isQUICRetryable`. Correct patterns.
- `isQUICRetryable`: comprehensive QUIC error checking. Good.

### server/upstream/tlcp/client.go
- LRU httpClient without OnEvict (MEDIUM). Holds TLCP transport connections.
- `tlcpClientConfig`/`dtlcpClientConfig`: SM2 curve forced, empty RootCAs (SM2-incompatible system pool), session caching. Correct.
- `tlcpSessions`/`dtlcpSession`: standard LRU caches. Correct.

### server/upstream/tlcp/tlcp.go
- `ExecuteTLCP`: validates, clones config, calls `exchangeOverTLCP`. Correct.
- `dialTLCPConn`: same pattern as `dialTLSConn` with TLCP instead of TLS. Correct.
- Pool: no TCP connection pooling for TLCP — uses single-exchange pattern only. This is intentional (TLCP connections are not pooled).

### server/upstream/tlcp/dtlcp.go
- `dialDTLCP`: `net.ListenPacket("udp", ":0")` — context-unaware listen (LOW). `HandshakeContext` is cancellable. Correct.
- Response buffer lifecycle: `pool.DefaultBuffer.Get()` → `respBuf[2:2+respLen]` → `response.Data = msgBuf` → `resp.Data = nil` before `defer`. **Correct**.
- Close with log: `zdnsutil.CloseWithLog`. Good.

### server/upstream/tlcp/http_tlcp.go
- `ExecuteHTTPTLCP`: validates, parses URL, builds transport, caches in LRU map. Correct.
- `DialTLSContext` callback for TLCP dial. Correct.
- Transport constructed per upstream. Cached. No OnEvict (MEDIUM).

### server/upstream/dnscrypt/client.go
- `Execute`: full DNSCrypt v2 + PQ (X-Wing) flow. Correct.
- `minQueryLen` escalation on TC (lines 171-186): retries with larger padding. Correct.
- State lock: `prepareQuery` called under `state.mu`. Good.
- PQ control block: stored under `state.mu`. Correct.
- `prepareQuery` (crypto.go): classical → PQ resumed → PQ cached → PQ fresh encapsulation fallback. Correct.
- `newNonce`: crypto/rand read, returns zero on error (documented as impossible). OK.
- No `SharedKeySize` confusion — returned from `prepareQuery`, used for decrypt. Correct.
- Data race on `c.cache` between `Close()` and query paths (HIGH).

### server/upstream/dnscrypt/cert.go
- `FetchCert`: UDP → TCP fallback on error/truncation. Correct error wrapping with both UDP and TCP errors.
- `fetchCertOverUDP`: heap-allocated buffer (`make([]byte, config.DefaultDNSCryptResponseBuffer)`). Not pooled — single-use fetch, not hot path. Acceptable.
- `fetchCertOverTCP`: manual 2-byte length framing. Correct. MaxMsgSize check. Correct.

### server/upstream/dnscrypt/crypto.go
- `prepareQuery`: key management under lock. Classical, PQ-resumed, PQ-cached, PQ-fresh. Correct.
- PQ fresh encapsulation: generates new ciphertext, caches it. Correct.
- Function returns `sharedKey` explicitly — avoids reading `state.sharedKey` outside lock. Good design.

### server/upstream/dnscrypt/state.go
- `resolveStamp`: stamp parsing, fallback to Address/ServerName/PublicKey. Correct.
- `state`: FQDN normalization, cache lookup, cert fetch via `FetchCert`. Correct.
- `buildState`: classical key pair generation, shared key derivation, PQ fields. Correct.
- `parseCert`: iterates TXT answers, validates signature and date, picks highest serial. Correct.
- `deleteState`: removes from cache for next query to re-fetch. Correct.

### server/upstream/pool/tcp.go
- Pipelining: map[uint16]pending for in-flight queries. Correct.
- `Exchange`: capacity semaphore, trackingID collision detection, write under writeMu, response via resultCh. Correct.
- `readLoop`: goroutine with HandlePanic. Reads length prefix + body, unpacks, dispatches to resultCh. Correct.
- `close`: sync.Once, closes conn, drains inflight with nil signals. Correct.
- `Acquire`: finds non-full conn, falls back to dialing. TOCTOU documented (benign). Correct.
- `dialAndAdd`: dials outside p.mu, handles pool-full by replacing dead conn. Correct.
- `Shutdown`: collects conns outside p.mu, then closes each. Correct pattern.
- `Remove`: removes from slice outside p.mu. Correct.
- Buffer lifecycle: bodyBuf from pool, shared with resp.Data, resp.Data = nil before Put. **Correct**.

### server/upstream/pool/quic.go
- `QUICConn.close`: sync.Once. `isDead`: checks both closed atomic and quic-go context. Correct.
- `Acquire`: round-robin selection, dial completion with pool-full/closed checks. Correct.
- `Put`: dedup by *quic.Conn pointer. Handles closed pool. Correct.
- `Shutdown`: **holds p.mu during close** (HIGH).
- `Remove`: removes from slice under p.mu. Correct.
- No idle-timeout reaping — relies on quic-go's KeepAlivePeriod and MaxIdleTimeout. Acceptable.

### server/upstream/socks5/socks5.go
- SOCKS5 protocol constants fully defined. Good.
- `Dialer`: shared TCP (via DialContext) and independent UDP relays. Correct.
- Handshake: No-Auth + User/Pass. Correct.
- `parseDatagram`: RSV, FRAG, ATYP parsing. IPv4/IPv6/Domain support. Correct.
- `writeDatagramHeader`: IPv4/IPv6 header. Correct.
- `readAddress`: reads BND.ADDR+PORT, resolves domain to IP. Correct.
- Pool variables: ReadPool exported for upstream consumers (plain/udp.go). WritePool unexported. Good.
- `cleanupLocked`: nil-guard idempotent. Recreates ctrlClosed channel. Double-close documented (LOW).

### server/upstream/socks5/tcp.go
- `DialContext`: CONNECT command. Deadline from ctx. Handshake then connect. Clears deadline after connect. Correct.
- `connect`: validates version, REP, RSV. Skips BND address. Correct error messages.

### server/upstream/socks5/udp.go
- `socks5PacketConn`/`socks5UDPConn`: two wrapper types for SOCKS5 UDP relay. Correct.
- `ListenPacket`: creates fresh Dialer per call — avoids shared-socket problem. Documented cost. Correct.
- `establishUDPRelay`: handshake, UDP ASSOCIATE, connected UDP socket, monitor goroutine. Correct.
- Monitor goroutine: **no HandlePanic** (MEDIUM). Double-close documented (LOW).
- `socks5UDPConn.Read`: **inconsistent error wrapping** (MEDIUM).
- Buffer pools: ReadBufPool 64KB, WritePool 1500B. Correct sizing.
- Write: pools small writes, heap-allocates large. Correct.
- Close: calls done() which invokes fresh.Close(). Idempotent via nil checks.

## Audit Methodology Cross-Reference

| Dimension | Scope | Key Findings |
|-----------|-------|-------------|
| 1. Code Quality | All files | Duplicate nil-guard in https.go/http3.go; redundant dialing cleanup in quic.go |
| 2. Memory Safety | Pool return discipline | All pool.Get → defer pool.Put or explicit Put on every exit path. **No leaks found.** |
| 3. Lock Correctness | All mutex/atomic | Data race on dnscrypt c.cache (HIGH). All other lock patterns correct (consistent ordering, no deadlocks). |
| 4. Coupling | Import graph | No import-layer violations. Server sub-packages import each other (allowed). |
| 5. Architecture | God packages, naming | Well-separated protocol packages. Consistent naming. |
| 6. Performance | QPS, hot path | Buffer pooling correct. Connection pooling correct. No hot-path allocations beyond pool gets. |
| 7. Panic Detection | Nil deref, bounds, assertions | All bare type assertions check `ok`. All map writes check nil. All bounds checked. |
| 8. Error Handling | %w, sentinel | Consistent %w wrapping. SOCKS5 UDP Read inconsistent (MEDIUM). |
| 9. Context Propagation | All I/O | DTLS dial lacks context (library limitation). All other paths pass ctx correctly. |
| 10. Goroutine Lifecycle | Leaks, HandlePanic | SOCKS5 monitor goroutines lack HandlePanic (MEDIUM). readLoop has HandlePanic (good). |
| 11. Resource Lifecycle | Close idempotent | Conn.close (sync.Once), QUICConn.close (sync.Once), cleanupLocked (nil-guard). All correct. |
| 12. Log Quality | Hot path spam | All hot-path logs at Debug level. Appropriate Warn usage for config issues. |
| 13. Documentation | ARCHITECTURE.md match | Good inline comments. TOCTOU, M19, L15 notes are excellent. |
| 14. Parameter Validation | Nil/empty checks | All Exchange methods validate msg and server. Consistent error messages. |
| 15. Constants | Magic numbers | SOCKS5 constants well extracted. A few literal `2` for DNS length prefix. |
| 16. RFC Consistency | Protocol specs | All protocols follow RFCs. QUIC 0-RTT retry on same connection is known non-compliance. |
| 17. Comment Accuracy | Stale references | https.go comment typo (MEDIUM). spoofguardBufPool comment matches code. |
| 18. Function Ordering | type→const→var→func | Followed in all files. |
