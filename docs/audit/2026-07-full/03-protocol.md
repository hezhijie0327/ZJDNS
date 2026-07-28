# Protocol Audit: server/protocol/*

## Summary
- Files audited: 18 (plus 2 test files skimmed)
- Packages audited: `plain`, `tls`, `tlcp`, `dnscrypt`
- CRITICAL: 1, HIGH: 2, MEDIUM: 7, LOW: 5

## Pool Return Discipline Check

For each protocol handler, verify the pattern against the standard template (TLS DoT in `tls/tls.go`):

| Protocol | File | Pattern | Status |
|----------|------|---------|--------|
| Plain UDP | `udp.go` | No direct pool usage (delegates to `dns.Server`) | N/A |
| Plain TCP | `tcp.go` | No direct pool usage (delegates to `dns.Server`) | N/A |
| TLS DoT (template) | `tls.go` | `DefaultMessage.Get()` -> `defer Put` in worker; `DefaultBuffer.Get()` -> ownership transfer to worker or `defer Put`; write buffer with pooled flag | **STANDARD** |
| TLS DTLS | `dtls.go` | `DefaultMessage.Get()` -> manual `Put` on every path; stack-allocated `buf` (not pooled) | OK |
| TLS QUIC | `quic.go` | `DefaultMessage.Get()` + `defer Put` + manual `Put` on same `req` | **DOUBLE-RETURN** |
| TLS DoH | `https.go` | No pool `Get` on request (uses `dnshttp.Request`); only `Put(response)` on response path | OK |
| TLS DoH3 | `http3.go` | No pool usage; delegates to `http3.Server` | N/A |
| TLCP DoT | `tlcp.go` | No direct pool usage (uses `zdnsutil.ReadTCPMsg`/`WriteTCPMsg`); `Put(resp)` after write | OK |
| TLCP DTLCP | `dtlcp.go` | `DefaultMessage.Get()` -> manual `Put` on every path; stack-allocated `buf` (not pooled) | OK |
| TLCP DoH | `http_tlcp.go` | No pool `Get` (uses `dnshttp.Request`); `defer Put(resp)` after write | OK |
| DNSCrypt UDP | `udp.go` | Buffer ownership transfer: `Get` -> read -> swap -> handler goroutine `defer Put` | OK (well-designed) |
| DNSCrypt TCP | `tcp.go` | No pool usage; reads via `dnscryptcrypto.ReadPrefixed` | OK |
| DNSCrypt Handshake | `server.go` | `Get` + nil-guarded `defer Put` via `if m != nil` flag pattern | OK |
| DNSCrypt Crypto | `crypto.go` | No pool usage (uses `&dns.Msg{}`) | OK |

---

## Findings

### CRITICAL

#### [CRITICAL] [内存安全] tls/quic.go:198,202,209,215 — Pool double-return in handleDOQStream

- **Problem**: `handleDOQStream` has `defer pool.DefaultMessage.Put(req)` at line 198, BUT also calls `pool.DefaultMessage.Put(req)` manually at lines 202 (Unpack error), 209 (non-zero ID), and 215 (normal path). In every execution path, `req` is returned to the pool at least twice. `sync.Pool.Put` is not idempotent — double-returning means two goroutines can `Get` the same `*dns.Msg` pointer, leading to concurrent mutation of shared memory.

- **Risk**: Data corruption, query cross-talk (one client gets another's DNS request/response data), crashes from corrupted internal state. In a concurrent DNS server, this is a ticking time bomb.

- **Fix**: Remove the `defer pool.DefaultMessage.Put(req)` on line 198 and put `pool.DefaultMessage.Put(req)` only in the two early-return error paths (lines 202, 209). The normal path at line 215 (`pool.DefaultMessage.Put(req)`) is correct — it returns `req` after `ServeDNS` consumes it. Alternatively, remove all manual `Put` calls and rely solely on the `defer`, but then `req` lives until `handleDOQStream` returns (through `respondQUIC`), which is also after it is no longer needed. The cleanest fix: delete line 198's defer, keep lines 202 and 209, keep line 215.

---

### HIGH

#### [HIGH] [资源生命周期] tls/server.go:286-337 — DoQ transport leak in Shutdown

- **Problem**: `Shutdown()` iterates over and closes `dotListeners`, `doqListeners`, `doqConns`, `h3Server`, `dohServers`, `httpsListeners`, `h3Listeners`, `h3Transports`, `h3Conns`, and `dtlsListeners`. But `doqTransports` (`s.doqTransports`) is NOT included in the cleanup. The DoQ transports (created in `startDOQServer`, line 56-60) are `*quic.Transport` instances that hold goroutines for connection tracking, idle timeout, and retransmission. They are never explicitly closed.

- **Risk**: Resource leak on server shutdown. The `quic.Transport` goroutines may keep running after `Shutdown` returns, holding memory and goroutine stack space until the process exits.

- **Fix**: Add a cleanup loop for `s.doqTransports` in `Shutdown()`, analogous to the `h3Transports` cleanup (lines 323-327). Because `quic.Transport.Close()` also closes the underlying `Conn`, the `doqConns` close should happen after transport close (or be removed). The correct order is: close transports (which closes their connections), then close any remaining directly-managed connections.

```go
for _, t := range s.doqTransports {
    if t != nil {
        _ = t.Close()
    }
}
```

Note: After transport Close, the individual `doqConns` close is redundant but harmless (idempotent close on `*net.UDPConn`).

#### [HIGH] [Goroutine生命周期] dnscrypt/udp.go:100 + dnscrypt/tcp.go:75 — Unbounded goroutine creation per packet/connection

- **Problem**: `serveUDP` (line 100) calls `s.wg.Go(func() { ... })` for every UDP datagram received, and `serveTCP` (line 75) calls the same for every accepted TCP connection. Neither has a concurrency semaphore or rate limiter. A flood of UDP packets or TCP connections creates an unbounded number of goroutines.

- **Risk**: Under DoS or high load, goroutine count grows without bound, leading to memory exhaustion, scheduler thrashing, and OOM.

- **Fix**: Add a semaphore (buffered channel) to limit concurrent handlers. A `workerCap` pattern (as in `tls/tls.go` line 209) limits concurrent handlers. Alternatively, use `errgroup.SetLimit()` (as in `tls/quic.go` line 137). For `serveUDP`, since UDP is connectionless and each handler is short-lived, even a modest limit of 512 concurrent handlers provides adequate flood protection without blocking legitimate traffic.

---

### MEDIUM

#### [MEDIUM] [常量提取] tlcp/dtlcp.go:334 — Hardcoded 2 instead of DNSFramePrefixLen

- **Problem**: `copy(resp[2:], response.Data)` hardcodes the value `2` instead of using the named constant `zdnsutil.DNSFramePrefixLen`. The same file correctly uses `zdnsutil.DNSFramePrefixLen` in other places (lines 297, 300, 301, 333, 334).

- **Risk**: If `DNSFramePrefixLen` ever changes (extremely unlikely but the principle holds), this one hardcoded offset would be missed. It also makes the code less grep-friendly.

- **Fix**: Replace `copy(resp[2:], ...)` with `copy(resp[zdnsutil.DNSFramePrefixLen:], response.Data)`.

#### [MEDIUM] [错误处理] tlcp/http_tlcp.go:87 — Leaks internal error detail to HTTP client

- **Problem**: When `dnshttp.Request(r)` fails, the handler writes `http.Error(w, err.Error(), http.StatusBadRequest)` — exposing the full internal error string (which may include library internals, parsing details, or file paths) to the HTTP client. The TLS DoH handler (`tls/https.go:146-148`) correctly uses `http.StatusText(http.StatusBadRequest)` instead.

- **Risk**: Information disclosure — internal error messages can leak implementation details, library versions, or parsing internals to clients.

- **Fix**: Replace `http.Error(w, err.Error(), ...)` with `http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)`.

#### [MEDIUM] [代码质量] tls/http3.go:69-91 — DoH3 accept loop repeats DoQ setup pattern

- **Problem**: The DoH3 accept loop (lines 69-91) manually accepts QUIC connections from an `EarlyListener` and passes them to `h3Server.ServeQUICConn`. This is a partial re-implementation of `http3.Server.ServeListener`, which handles listener setup and accept-loop semantics. The `h3Server` field on `Server` is set at line 38 but `ServeListener` is never called.

- **Risk**: Duplicated accept-loop logic. The manual accept loop may miss edge cases that `http3.Server.ServeListener` handles (e.g., graceful shutdown coordination, connection state tracking). Also, setting `h3Server` at line 38 but never calling `ServeListener` is misleading.

- **Fix**: Either use `h3Server.ServeListener(capturedH3)` (replacing the manual loop), or document clearly why the manual accept loop is necessary (e.g., if custom error handling or per-connection logging is required). If custom logging is the reason, move the logging inside the `ServeQUICConn` goroutine and simplify the loop.

#### [MEDIUM] [代码质量] tls/server.go:256-265 — Coordinator goroutine with buffered channel

- **Problem**: The `Start()` method spawns a coordinator goroutine that calls `g.Wait()` and sends the result to `errChan`. The `for err := range errChan` loop on lines 267-274 iterates exactly once (since `errChan` is closed after the send). The semantics are correct but the pattern is fragile — if more than one protocol goroutine fails, only the first error is captured, and the loop exits. This is acceptable behavior but should be documented.

- **Risk**: If DoT fails and then DoH also fails, the DoH error is silently lost. The first error triggers `s.cancel(...)` which cancels everything else, so the second error never reaches `errChan` anyway. This is correct behavior but subtle.

- **Fix**: Add a comment explaining that the first protocol startup error triggers cancellation of all other listeners, so only the first error matters. Or, accept all errors via a multi-error collector.

#### [MEDIUM] [RFC一致性] tls/quic.go:180 — Zero-length check but RFC 9250 requires different error code

- **Problem**: `if msgLen == 0` returns a generic close with `pool.QUICCodeProtocolError`. RFC 9250 Section 4.3.1 specifies that a 0-length 2-byte prefix is a protocol error (QUIC code 0x1, which is `QUICCodeProtocolError`). This is technically compliant, but the error message "invalid length" is vague.

- **Risk**: Very minor — a more descriptive error would aid debugging.

- **Fix**: Change the error message to "zero-length DNS message" for the `msgLen == 0` case, and "message too large" for the size-limit case.

#### [MEDIUM] [耦合度] tls/server.go:51 + tlcp/server.go:29 — Both protocol servers import edns.DNSHandler

- **Problem**: Both `tls.Server` and `tlcp.Server` store `edns.DNSHandler` (an interface defined in the `edns` domain package). The `edns` package is Layer 3 (domain), while `server/protocol/*` is Layer 4 (server sub). This is architecturally correct per the DAG (Layer 4 imports Layer 3), but it means the protocol packages have a compile-time dependency on the EDNS handler interface definition. If `edns.DNSHandler` changes signature, all three protocol packages need recompilation.

- **Risk**: None architecturally — the dependency flows downward as designed. But it's worth noting that this ties the protocol packages to the domain layer.

- **Fix**: No change needed. This is by design per the architecture.

#### [MEDIUM] [性能] tls/dtls.go:106 + tlcp/dtlcp.go:280 — Stack-allocated 64KB buffer per DTLS/DTLCP connection

- **Problem**: Both `handleDTLSConnection` and `handleDTLCPConnection` allocate a `make([]byte, pool.UDPBufferSize)` buffer on the heap per-connection. `pool.UDPBufferSize` is 1232 (EDNS0 recommended size), but `pool.DefaultBuffer` (SecureBufferSize=8192 from pool) is available via `pool.DefaultBuffer.Get()`. The DTLS/DTLCP handlers could use pooled buffers instead of per-connection allocation.

- **Risk**: Each DTLS connection allocates 8KB of heap that lives for the connection duration. Under heavy load (thousands of DTLS connections), this adds memory pressure. Using the pool would amortize allocation costs.

- **Fix**: Replace `make([]byte, pool.UDPBufferSize)` with `pool.DefaultBuffer.Get()` and `defer pool.DefaultBuffer.Put(buf)`. This is safe because both DTLS and DTLCP handlers are synchronous (one query at a time) so the buffer is not aliased across goroutines.

---

### LOW

#### [LOW] [注释准确性] tls/tls.go:99 — Comment says "read deadline handles idle connection cleanup" but keep-alive handles it

- **Problem**: The comment at line 99-101 states "The read deadline handles idle connection cleanup" alongside TCP keep-alive configuration. The actual idle timeout is set via `SetReadDeadline` at line 164, which is 15 seconds (`DefaultTCPPoolIdleTimeout`). The keep-alive period (line 96) is separate. The comment could be clearer about which mechanism handles idle timeouts (read deadline) vs. NAT/firewall state (keep-alive).

- **Risk**: Low — maintainers might misunderstand the interplay between the two timeout mechanisms.

- **Fix**: Clarify: "TCP keep-alive prevents NAT/firewall state timeout; `SetReadDeadline` handles idle client connection cleanup."

#### [LOW] [常量提取] dnscrypt/server.go:531 — Magic number 255 for TXT chunk size

- **Problem**: `const maxChunk = 255` is used as the maximum DNS TXT chunk size. This is consistent with the TXT RR wire format (max 255 bytes per string), but the value 255 is a DNS protocol constant that should be a named constant from a shared location.

- **Risk**: Low — if another package hard-codes the same boundary, they could diverge. But 255 is deeply embedded in the DNS protocol.

- **Fix**: Consider defining `MaxTXTChunkSize` in `internal/dnsutil` or referencing `dns.MaxTxtStringLen` if available in the miekg/dns library.

#### [LOW] [函数排序] dnscrypt/tcp.go:24 — Constant `defaultReadTimeout` placed after type definition

- **Problem**: The declaration order in `tcp.go` is: type (line 18-23), const (line 25-27), then function (line 31+). CLAUDE.md requires `type -> const -> var -> func` per file. This is correct. But the constant `defaultReadTimeout` is defined at file scope (line 25) while the comment at line 29 ("tcpResponseWriter writes...") is misplaced between const and func blocks, making the separation ambiguous.

- **Risk**: Cosmetic formatting issue.

- **Fix**: Reorder or move the comment before the function block.

#### [LOW] [注释准确性] tls/quic.go:123 — Comment says `CloseWithError` but the constant is `QUICCodeNoError`

- **Problem**: The comment on line 123 says "CloseWithError" (describing the call at line 122) but the actual call uses `pool.QUICCodeNoError` and an empty string. The connection is closed with no error, which is correct for graceful shutdown. The comment is accurate ("defer close on connection teardown") but the nearby comment on lines 119-134 could note that a zero error code is used for graceful close.

- **Risk**: Very low — the code is correct, just the comment could be slightly clearer about graceful close semantics.

- **Fix**: Add "graceful close with NoError code" to the comment.

#### [LOW] [代码质量] plain/udp.go:29 — UDPSize uses pool.UDPBufferSize (1232) instead of a named protocol constant

- **Problem**: The UDP server configures `UDPSize: pool.UDPBufferSize` (line 29). `pool.UDPBufferSize` is defined as 1232 in `internal/pool/pool.go`, which is the EDNS0-recommended UDP payload size. However, using `pool.UDPBufferSize` here couples the plain protocol listener to the pool package for a value that is actually a protocol default (RFC 6891 recommended buffer size).

- **Risk**: Very low — 1232 is unlikely to change, but semantic coupling exists.

- **Fix**: Define `DefaultUDPSize = 1232` in `config/defaults.go` and reference it from there.

---

## Additional Observations

### Test Files (skimmed, not fully audited)

**dnscrypt/server_test.go**: Good test coverage for key rotation, cert TXT building, and handshake TTL. Tests use `time.Now()` for TTL comparisons with tolerance windows, which is appropriate for timer-based testing.

**dnscrypt/dns_test.go**: Good coverage for `DNSSize` and `Normalize` across UDP/TCP. Tests for truncation behavior, question preservation, and round-trip correctness.

Both test files follow Go testing conventions. No obvious issues found in the quick review.

### Architecture Layer Compliance

All protocol packages (`plain`, `tls`, `tlcp`, `dnscrypt`) correctly import only from allowed layers:
- `config` (Layer 1-2) for settings and constants
- `edns` (Layer 3) for DNSHandler interface (allowed: Layer 4 imports Layer 3)
- `internal/*` (Foundation) for log, pool, dnsutil, lrumap, dnscryptcrypto
- External dependencies (miekg/dns, quic-go, eTLS, eHTTP, pion/dtls, gotlcp, circl)

No violation of the import DAG. The `edns.DNSHandler` interface dependency is the correct pattern for avoiding circular imports between protocol and handler packages.

### Key Strengths Observed

1. **DNSCrypt buffer ownership**: `serveUDP` (udp.go:62-108) has a well-designed buffer ownership transfer pattern — read into `buf`, slice `packet`, swap `buf` with a fresh `Get()`, pass `packet` to the goroutine which `Put`s it on return. This is the correct template for zero-copy pooled I/O.

2. **TLS DoT worker pattern**: `handleDOTConnection` (tls/tls.go:84-267) is the reference implementation for other protocol handlers. It demonstrates correct pooled buffer lifecycle with ownership transfer, worker goroutine semaphore (`workerCap`), writer goroutine pattern with draining on shutdown, and connection-scoped `connCtx` for cancellation.

3. **DNSCrypt nil-guarded pool Put**: `handleHandshake` (server.go:355-478) uses `m = nil` after `m` is no longer the active message, preventing the defer from double-returning. This is the correct pattern when multiple `dns.Msg` objects are in flight.

4. **TLS certificate info display**: `displayCertificateInfo` (tls/server.go:376-401) provides comprehensive certificate metadata at Info level, with WARN for near-expiry or expired certificates.

5. **DTLCP custom listener**: `dtlcpListener` is well-documented, including the workaround for `gotlcp` not supporting UDP listen. The `Close()` method correctly handles the straggler pattern (close active connections, re-check for connections accepted between snapshot and actual close).
