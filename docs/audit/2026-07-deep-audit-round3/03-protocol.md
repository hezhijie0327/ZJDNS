# Protocol Layer Audit (Round 3)

**Files audited:** 20 files across `server/protocol/plain/`, `server/protocol/tls/`, `server/protocol/tlcp/`, `server/protocol/dnscrypt/`

**Audit dimensions:** Code quality, Memory safety, Lock correctness, Coupling, Architecture, Performance, Panic detection

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 0 |
| MEDIUM   | 4 |
| LOW      | 5 |
| INFO     | 3 |

Pool discipline is correct throughout all protocol handlers. Every `pool.DefaultMessage.Get()` has a matching `Put` on all code paths. Every `pool.DefaultBuffer.Get()` has a matching `Put`. No leaks were found in the standard pool usage patterns.

The `Message.Put` implementation (`*msg = dns.Msg{}`) zeroes the struct but NOT the backing byte array of `Data`, so the documented "M14 danger" (handleHandshake returning `reply.Data` after `Put`) is safe -- the backing array survives the Put.

---

## MEDIUM Findings

### M1. quicAddrValidator.seen map -- unbounded growth (DoS via spoofed source IPs)

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/addr_validator.go`
**Lines:** 16 (type), 46 (write), 52-70 (sweep)
**Category:** memory, dos
**Risk:** An attacker can exhaust server memory by sending UDP packets from many unique spoofed source IPs.

**Problem:**
The `seen` map (line 16) grows by one entry per unique client source IP address. The periodic sweep (line 52-70) removes entries only after `DefaultQUICAddrCacheTTL` of inactivity. Between sweeps, the map grows unboundedly. An attacker with a sufficiently fast uplink can inject millions of unique IPs (IPv4 has ~4B addresses), each creating a `string→time.Time` entry (~80 bytes). At 1 Gbps with minimum-size UDP packets, this is roughly 1.2M entries/second, or ~100 MB/s of heap growth.

**Fix suggestion:**
Add a hard cap on the map size (e.g., 100K entries) with LRU eviction, or use a fixed-size ring buffer. When the cap is reached, the oldest entry is evicted regardless of TTL.

```go
const maxSeenEntries = 100000

func (v *quicAddrValidator) requiresValidation(addr net.Addr) bool {
    // ...
    v.mu.Lock()
    if len(v.seen) >= maxSeenEntries {
        // Evict oldest or simply skip adding
    }
    v.seen[key] = time.Now()
    v.mu.Unlock()
    return true
}
```

---

### M2. DoQ connection goroutine may leak

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/quic.go`
**Lines:** 117-125
**Category:** goroutine-leak, memory
**Risk:** Each DoQ connection spawns a goroutine that may never exit.

**Problem:**
The `defer` block in `handleDOQConnection` (lines 113-130) spawns a goroutine to wait on `conn.Context().Done()`. The comment at lines 119-121 documents this:

```go
// NOTE: The goroutine waiting on conn.Context().Done() may leak if
// CloseWithError does not transition the context in time and the outer
// select exits via ctx.Done(). This is a known limitation; a production
// fix would track the goroutine via the connection's lifecycle.
```

Under high connection churn or rapid server shutdown, these goroutines accumulate. Each leaked goroutine holds a reference to the `done` channel and the connection context.

**Fix suggestion:**
Replace the goroutine + select pattern with a `context.AfterFunc` callback from `conn.Context()`:

```go
done := make(chan struct{})
afterFunc := context.AfterFunc(conn.Context(), func() { close(done) })
defer func() {
    if afterFunc != nil {
        afterFunc()
    }
}()
```

This avoids the goroutine entirely -- the callback fires inline when the context completes.

---

### M3. TLCP DoH -- no request body size enforcement

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/http_tlcp.go`
**Lines:** 59-96
**Category:** dos, security
**Risk:** An attacker can exhaust server memory by sending a large POST body to the TLCP DoH endpoint.

**Problem:**
The TLS DoH handler (`server/protocol/tls/https.go` lines 146-148) enforces a request body limit:
```go
r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
```

The TLCP DoH handler has no equivalent. `dnshttp.Request(r)` calls `io.ReadAll(r.Body)` internally, which reads the entire body into memory. Without `MaxBytesReader`, a client can send an arbitrarily large POST body, causing OOM. This is the same DoS vector that the TLS DoH handler protects against.

**Fix suggestion:**
Add identical `MaxBytesReader` wrapping before calling `dnshttp.Request`:

```go
r.Body = http.MaxBytesReader(w, r.Body, config.DefaultDOHMaxRequestSize)
```

Also add the GET URL param length check that the TLS handler has.

---

### M4. Pool contamination -- non-pool messages returned to pool

**Files:**
- `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/https.go` (line 128)
- `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/tlcp.go` (line 100)
- `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/http_tlcp.go` (line 80)

**Category:** pool, inefficiency
**Risk:** Pool grows with objects of varying internal buffer sizes, reducing reuse efficiency.

**Problem:**
`dnshttp.Request()` (miekg/dns) and `ReadTCPMsg()` (internal/dnsutil) allocate `*dns.Msg` with `new(dns.Msg)` and bytes with `make()`. These non-pooled messages are returned into `pool.DefaultMessage` via `Put()`. While functionally safe (`Message.Put` zeroes the struct with `*msg = dns.Msg{}`), this replaces clean pooled messages with freshly allocated ones, inflating the pool's working set and reducing its cache-friendliness.

The TLCP DoT handler (tlcp.go line 100) calls `ReadTCPMsg` which allocates a `new(dns.Msg)` and a `make([]byte, length)` buffer per query. Both are now injected into the pool.

**Fix suggestion:**
Replace `dnshttp.Request` and `ReadTCPMsg` usage with pool-aware wrappers:

For TLCP DoT, replace `ReadTCPMsg` with a pool-aware version:
```go
func readTCPMsgPooled(conn net.Conn) (*dns.Msg, error) {
    var prefix [2]byte
    if _, err := io.ReadFull(conn, prefix[:]); err != nil {
        return nil, err
    }
    length := int(prefix[0])<<8 | int(prefix[1])
    buf := pool.DefaultBuffer.Get()
    msgBuf := buf[:length]
    if _, err := io.ReadFull(conn, msgBuf); err != nil {
        pool.DefaultBuffer.Put(buf)
        return nil, err
    }
    msg := pool.DefaultMessage.Get()
    msg.Data = msgBuf
    if err := msg.Unpack(); err != nil {
        pool.DefaultMessage.Put(msg)
        pool.DefaultBuffer.Put(buf)
        return nil, err
    }
    return msg, nil
}
```

For DoH handlers, the `dnshttp.Request` dependency is harder to replace but can be done with a minimal wrapper that parses from a pre-read buffer.

---

## LOW Findings

### L1. Bare type assertion in GenerateResolverConfig

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/generate.go`
**Line:** 61
**Category:** panic, code-style

**Problem:**
```go
cfg.PublicKey = dnscryptcrypto.HexEncodeKey(privateKey.Public().(ed25519.PublicKey))
```

This is a bare `.(ed25519.PublicKey)` type assertion. While safe here (the parameter type is `ed25519.PrivateKey`, guaranteeing the return type), it is non-idiomatic and will panic if the function is ever refactored to accept a broader interface.

**Fix:**
Replace with comma-ok pattern:
```go
pk, ok := privateKey.Public().(ed25519.PublicKey)
if !ok {
    return cfg, errors.New("unexpected public key type")
}
cfg.PublicKey = dnscryptcrypto.HexEncodeKey(pk)
```

---

### L2. DTLS/DTLCP use make() instead of pool for connection buffer

**Files:**
- `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/dtls.go` (line 102)
- `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/dtlcp.go` (line 274)

**Category:** inefficiency, cross-protocol

**Problem:**
Both DTLS and DTLCP connection handlers allocate a fresh byte buffer per connection with `make([]byte, pool.UDPBufferSize)` instead of using `pool.DefaultBuffer.Get()`. Every other protocol handler (DoT, DoQ, DNSCrypt) uses the pool consistently. While `make` per connection (not per query) is acceptable, this is an inconsistency that could cause excess allocations under high connection churn.

**Fix:**
Replace `make([]byte, pool.UDPBufferSize)` with `pool.DefaultBuffer.Get()` and return via `pool.DefaultBuffer.Put(buf)` in the defer.

---

### L3. DTLS/DTLCP -- missing HandlePanic on server accept goroutines

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/dtls.go`
**Lines:** 46-49 (startDTLSServer), 81 (handleDTLSConnections)

**Category:** panic

**Problem:**
The DTLS server accept loop `handleDTLSConnections` has `defer zdnsutil.HandlePanic("DTLS accept loop")` at line 57. However, the goroutine spawned in `startDTLSServer` (lines 46-49) does NOT have its own `HandlePanic` -- it relies on the inner function's defer. If `handleDTLSConnections` panics before the defer is registered (e.g., during `listener.Accept()`), the panic would not be caught.

Compare with TLS DoT server (server.go lines 197-204 and tls.go lines 46-48) which wraps the entire goroutine body in `HandlePanic`.

**Fix:**
Add `defer zdnsutil.HandlePanic("DTLS server")` to the goroutine in `startDTLSServer` (line 46), before the `handleDTLSConnections` call:

```go
s.serverGroup.Go(func() error {
    defer zdnsutil.HandlePanic("DTLS server")
    s.handleDTLSConnections(listener)
    return nil
})
```

Same fix for `startDTLCPServer` (`server/protocol/tlcp/dtlcp.go` line 218).

---

### L4. DoH/ServeHTTP -- pool.Put(req) on non-pooled message could double-put

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/https.go`
**Lines:** 112, 128

**Category:** pool, correctness

**Problem:**
`parseDOHRequest` calls `dnshttp.Request(r)` which returns `*dns.Msg` allocated via `new(dns.Msg)`. The return value is assigned to `req` (line 112). On line 128, `pool.DefaultMessage.Put(req)` is called unconditionally.

If `s.handler.ServeDNS` (line 127) somehow returns the same `*dns.Msg` pointer as its response (it shouldn't, but there is no contract preventing it), then both the response Put (line 134) and the request Put (line 128) would Put the same pointer into the pool, leading to a double-put and potential corruption.

This is a theoretical concern -- the middleware chain always allocates a new `*dns.Msg` for the response. However, a hardening comment or defensive `req = nil` after Put would prevent future issues.

**Fix:**
Set `req = nil` after `pool.DefaultMessage.Put(req)` to catch any accidental reuse:
```go
pool.DefaultMessage.Put(req)
req = nil
```

---

### L5. DTLCP `readFirstDatagram` -- shared buffer race window

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/dtlcp.go`
**Lines:** 116-143

**Category:** memory, data-race

**Problem:**
`readFirstDatagram` reads into `l.buf` (the listener's shared buffer) at line 122. Between `ReadFromUDP` returning (line 122) and `copy(packet, l.buf[:n])` (line 140), the buffer content could be overwritten by a concurrent read. However, this is currently safe because `readFirstDatagram` is always called from a single goroutine (the accept loop). Nevertheless, the shared mutable `l.buf` is a latent bug -- any future refactoring that introduces concurrent Accept calls would create a data race.

**Fix suggestion:**
Allocate the read buffer inside `readFirstDatagram` instead of using the shared `l.buf`:

```go
func (l *dtlcpListener) readFirstDatagram() ([]byte, *net.UDPAddr, error) {
    for {
        if l.closed.Load() {
            return nil, nil, net.ErrClosed
        }
        buf := make([]byte, pool.UDPBufferSize)  // per-call allocation
        n, remoteAddr, err := l.udpConn.ReadFromUDP(buf)
        if err != nil {
            return nil, nil, err
        }
        // ...
        packet := make([]byte, n)
        copy(packet, buf[:n])
        return packet, remoteAddr, nil
    }
}
```

---

## INFO / Observations

### I1. DTLCP single-connection bottleneck

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/dtlcp.go`
**Lines:** 256-259

The comment at line 253-256 documents that `gotlcp` shares the underlying UDP socket across all connections, requiring synchronous handling. This means DTLCP can only serve one client at a time. Not a bug, but architecturally limiting.

### I2. TLCP DoT best-effort binding vs other protocols' fail-fast

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/tlcp.go`
**Lines:** 43-46

When a TCP listen fails, TLCP DoT logs a warning and continues to the next address (`continue`). All other protocol handlers (plain TCP, TLS DoT, etc.) return an error immediately, stopping all listeners. Intentional design choice for TLCP (best-effort multi-bind).

### I3. M14 pattern (handleHandshake) is safe

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go`
**Lines:** 487-488

The documented "danger" pattern -- returning `reply.Data` after `pool.DefaultMessage.Put(reply)` -- is safe because:
1. `Message.Put` does `*msg = dns.Msg{}` which zeros only the struct fields (setting `Data = nil`), NOT the backing byte array.
2. `res` is a separate slice variable that still references the backing array.
3. The backing array was allocated by `reply.Pack()` and is NOT from `DefaultBuffer`.

The comment can be updated to reflect this.

---

## Cross-Protocol Consistency Check

| Pattern | TLS DoT | TLS DoH | TLS DoQ | TLS DTLS | TLCP DoT | TLCP DoH | TLCP DTLCP | DNSCrypt |
|---------|---------|---------|---------|----------|----------|----------|------------|----------|
| Pool get/put discipline | OK | OK | OK | OK | OK | OK | OK | OK |
| response nil guard before Put | OK | OK | OK | OK | OK | OK | OK | OK |
| HandlePanic on accept loop | -- | -- | -- | OK | OK | -- | OK | -- |
| HandlePanic on per-conn handler | OK | -- | OK | OK | OK | -- | -- | OK |
| Request body size limit | OK | OK | N/A | N/A | N/A | **MISSING** | N/A | N/A |
| Pool for read buffer | OK | N/A | OK | **make()** | **make()** | N/A | **make()** | OK |
| conn.RemoteAddr nil-safe | OK | N/A | N/A | OK | OK | N/A | OK | OK |

Key: OK = correct, MISSING = finding, make() = uses stack allocation instead of pool, -- = no separate accept loop, N/A = not applicable

---

## Files Not Modified

This is a read-only audit. No files were changed.

---

## Conclusion

The protocol layer is well-structured with correct pool discipline throughout -- every `Get` has a matching `Put` on all code paths, and there are no CRITICAL/HIGH findings.

The most impactful findings are the **unbounded `quicAddrValidator` map** (M1) and the **TLCP DoH missing body size limit** (M3), both of which are DoS vectors. The **DoQ goroutine leak** (M2) is documented but fixable with `context.AfterFunc`. The remaining LOW findings are code hygiene improvements.

The TLCP DoT handler's use of `ReadTCPMsg` (which allocates outside the pool) is the most notable cross-protocol inconsistency -- the TLS DoT handler correctly uses the pool, and TLCP DoT should follow the same pattern.
