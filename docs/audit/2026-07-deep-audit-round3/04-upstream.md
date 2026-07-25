# Audit: Upstream Layer

**Date:** 2026-07-25 | **Scope:** `server/upstream/*` (client, warmup, plain, tls, tlcp, dnscrypt, pool, socks5)

---

## CRITICAL

### US-01: DTLCP missing `response.Data = nil` -- use-after-free of pooled buffer

**File:** `server/upstream/tlcp/dtlcp.go:85`  
**Category:** memory / pool-leak  
**Risk:** Corrupted DNS responses; undefined behavior reading zeroed memory after the pooled buffer is recycled.

`respBuf` is acquired from `pool.DefaultBuffer` with a deferred `Put()` that clears the buffer. `msgBuf` is a sub-slice of `respBuf[2 : 2+respLen]` and is assigned directly to `response.Data`. After `Unpack()` succeeds, the function returns while `response.Data` still points into `respBuf`. The deferred `pool.DefaultBuffer.Put(respBuf)` zeroes the buffer, leaving `response.Data` dangling -- any subsequent read of `response.Data` (e.g. `response.Truncated`) reads cleared memory.

The identical pattern in `tls/dtls.go:90` was fixed with `response.Data = nil` before return, but `tlcp/dtlcp.go` was not updated.

**Fix:** Add `response.Data = nil` immediately after the successful `Unpack()` check, before the debug log and return.

---

### US-02: `proxyDialer()` calls `d.SafeURL()` on nil pointer when `socks5.New` fails

**File:** `server/upstream/warmup.go:42`  
**Category:** panic / nil-dereference  
**Risk:** Guaranteed nil-dereference panic on any DNSCrypt or proxied upstream that has an invalid `sdns://` stamp or malformed proxy URL.

```go
d, err := socks5.New(server.Proxy, c.timeout)
if err != nil {
    log.Warnf("UPSTREAM: invalid proxy %s for %s: %v", d.SafeURL(), ...)
```

`socks5.New` returns `(nil, error)` on failure. `SafeURL()` is a pointer-receiver method with no nil guard, so `d.SafeURL()` panics immediately.

**Fix:** Use `server.Proxy` as the string argument instead of `d.SafeURL()` when `err != nil`, or add `if d != nil { ... }` guard before `SafeURL()`.

---

### US-03: `pool/tcp.go` readLoop leaks `DefaultBuffer` on responses > 8192 bytes

**File:** `server/upstream/pool/tcp.go:217-263`  
**Category:** memory / pool-leak  
**Risk:** Progressive depletion of the global `DefaultBuffer` pool under sustained traffic with large TCP DNS responses (>8192 bytes DNSSEC/NSEC3). Each oversized response loses one 8192-byte buffer permanently.

```go
bodyBuf := zpool.DefaultBuffer.Get()       // always acquired
pooled := int(msgLen) <= len(bodyBuf)       // false when msgLen > 8192
if pooled {
    body = bodyBuf[:msgLen]
} else {
    body = make([]byte, msgLen)             // bodyBuf dropped on floor
}
// ...
if _, err := io.ReadFull(c.conn, body); err != nil {
    if pooled { zpool.DefaultBuffer.Put(bodyBuf) }  // NO else branch
    return
}
// ...
if err := resp.Unpack(); err != nil {
    if pooled { zpool.DefaultBuffer.Put(bodyBuf) }  // NO else branch
    zpool.DefaultMessage.Put(resp)
    continue
}
resp.Data = nil
if pooled { zpool.DefaultBuffer.Put(bodyBuf) }      // NO else branch
```

When `pooled == false`, `bodyBuf` is acquired from the pool on line 217 but never returned on ANY of the three exit paths (ReadFull error, Unpack error, success). A single `defer` would not work here because on the `pooled == true` path `bodyBuf` must outlive `resp.Data` until `resp.Data = nil`. The simplest fix is to `Put(bodyBuf)` immediately on the `else` branch of line 222.

**Fix:** On the `pooled = false` branch, immediately return `bodyBuf` to the pool before the `make`:
```go
} else {
    zpool.DefaultBuffer.Put(bodyBuf)
    body = make([]byte, msgLen)
}
```

---

## HIGH

### US-04: DNSCrypt PQ ticket stored without valid resume secret

**File:** `server/upstream/dnscrypt/client.go:125-141`  
**Category:** logic / data-integrity  
**Risk:** Subsequent PQ-resumed queries use a stored ticket with a zero-valued `pqResumeSecret`, producing garbage shared keys and failing queries with confusing errors.

```go
state.mu.Lock()
state.pqTicket = ticket                    // SET unconditionally
state.pqTicketExpiry = time.Now().Add(...) // SET unconditionally
pqResumeSecret, err := dnscryptcrypto.PQResumeSecret(...)
if err != nil {
    state.mu.Unlock()                      // Unlock but FALLS THROUGH
    log.Debugf(...)
    // continue -- state.pqTicket is set, but state.pqResumeSecret is NOT
```

`prepareQuery()` (`crypto.go:18`) checks `len(state.pqTicket) > 0` and tries `PQResumedSharedKey(state.pqResumeSecret, ...)`. When `pqResumeSecret` is the zero value (not set on the error path), the derivation function either errors (falling back) or produces a garbage key causing a query failure.

**Fix:** Move `state.pqTicket = ticket` and `state.pqTicketExpiry` assignment AFTER the `PQResumeSecret` success check, or clear them on the error path.

---

### US-05: Data race on `state.minQueryLen` in DNSCrypt client

**File:** `server/upstream/dnscrypt/client.go:155-158`  
**Category:** lock / data-race  
**Risk:** Concurrent goroutines incrementing `state.minQueryLen` without synchronization cause a data race. While the maximum is bounded (4096), the race violates the Go memory model and could produce corrupted reads in `prepareQuery`.

```go
if response.Truncated && !useTCP {
    const maxQueryLen = 4096
    if state.minQueryLen+64 <= maxQueryLen {
        state.minQueryLen += 64            // NOT protected by state.mu
```

**Fix:** Hold `state.mu` for this write, or use `sync/atomic` for `minQueryLen`.

---

## MEDIUM

### US-06: Bare type assertion on `c.dohClient.Transport` in `createDOHClient`

**File:** `server/upstream/tls/https.go:150`  
**Category:** panic / type-assertion  
**Risk:** Panics if `c.dohClient.Transport` is not `*eHTTP.Transport` (e.g. after `Close()` or with custom `dohClient` injection). Currently only triggered on the code path where `c.dohTransports != nil`, which holds in normal operation, but the assertion is unchecked.

```go
transport := c.dohClient.Transport.(*eHTTP.Transport).Clone()
```

Line 126 uses the safe comma-ok form for the same field; line 150 should match.

**Fix:** Use comma-ok or add an explicit guard:
```go
eTransport, ok := c.dohClient.Transport.(*eHTTP.Transport)
if !ok {
    return c.dohClient
}
transport := eTransport.Clone()
```

---

### US-07: `spoofguardBufPool` uses fixed 4096-byte buffer instead of pool.DefaultBuffer

**File:** `server/upstream/plain/udp.go:37-42`  
**Category:** inefficiency / consistency  
**Risk:** Second-class buffer pool; inconsistent with the rest of the codebase. The 4096-byte limit is the standard maximum DNS UDP payload, so data loss is unlikely -- but exceeding this silently truncates the UDP datagram.

```go
var spoofguardBufPool = sync.Pool{
    New: func() any {
        b := make([]byte, 4096)
        return &b
    },
}
```

This pool is separate from `pool.DefaultBuffer` (8192 bytes). The size choice is reasonable for UDP, but the pool fragmentation reduces reuse. Consider using `pool.DefaultBuffer` or aligning with `config.DefaultDNSCryptUDPSize` (4096).

**Fix:** Either use `pool.DefaultBuffer` (8192) for this pool, or document why 4096 is intentional and add a comment noting the truncation risk.

---

### US-08: `socks5/udp.go` monitor goroutine -- `ctrlClosed` channel never closed, dead code

**File:** `server/upstream/socks5/udp.go:166-198`  
**Category:** dead-code / maintainability  
**Risk:** The `ctrlClosed` channel in the monitor double-goroutine is replaced (not closed) by `cleanupLocked()`, making the `case <-ctrlClosed` branch unreachable. The goroutine still exits correctly because `cleanupLocked()` also calls `ctrlConn.Close()`, which unblocks the inner Read goroutine, which closes `done`. The `ctrlClosed` mechanism is dead code that misleads readers.

```go
// establishUDPRelay sets:
ctrlClosed := make(chan struct{})
d.ctrlClosed = ctrlClosed
// ...
// cleanupLocked replaces (does not close):
d.ctrlClosed = make(chan struct{})  // old ctrlClosed GC'd, never signaled
```

**Fix:** Either close the old channel in `cleanupLocked` before replacement, or remove `ctrlClosed` and simplify the monitor to just wait on `<-done`.

---

### US-09: `pool/tcp.go` Exchange -- collided trackingID update writes past buffer bounds risk

**File:** `server/upstream/pool/tcp.go:150-152`  
**Category:** memory-safety  
**Risk:** After trackingID collision resolution, `binary.BigEndian.PutUint16` writes to `writeBuf[DNSFramePrefixLen:DNSFramePrefixLen+2]`. The `writeBuf` is sliced to `2+msgData` (line 133). The write offset assumes `len(msgData) >= 2`, which is always true for a valid packed DNS message (`msg.Pack()` succeeded). However, if a zero-length or single-byte message somehow bypasses `Pack()`, this writes out of bounds.

**Fix:** Add a length guard or an assertion `len(msgData) >= 2` after the collision loop.

---

## LOW

### US-10: `dnscrypt/client.go` -- `response.Data = nil` not set before return

**File:** `server/upstream/dnscrypt/client.go:146-151`  
**Category:** memory / consistency  
**Risk:** `response.Data` retains the `decrypted` byte slice after `Unpack()`. While `decrypted` is understood to be a fresh allocation (not from a pool), this is inconsistent with the convention established by DTLS/QUIC/socks5 upstream handlers, and would become a use-after-free bug if `DecryptResponse` ever returns a pooled buffer. Defensive fix with negligible cost.

```go
response := pool.DefaultMessage.Get()
response.Data = decrypted
err = response.Unpack()
if err != nil {
    pool.DefaultMessage.Put(response)
    return nil, ...
}
// MISSING: response.Data = nil
```

**Fix:** Add `response.Data = nil` after the successful `Unpack()` check, matching the pattern in all other upstream handlers.

---

### US-11: `pool/tcp.go` Exchange -- orphaned response leak on ctx cancellation race

**File:** `server/upstream/pool/tcp.go:154-171`  
**Category:** memory / race  
**Risk:** In a narrow timing window, after `ctx.Done()` fires and the deferred drain runs, the `readLoop` may have already found the `trackingID` in `inflight` and send a `*dns.Msg` to `resultCh`. The drain has already completed (since trackingID was removed from inflight first, then drain runs). The response becomes trapped in the buffered channel, unreachable, and is garbage collected instead of returned to `DefaultMessage`. Mitigating factors: max 4 leaked messages per connection, only under precise cancellation timing.

**Fix:** Use a double-check drain pattern: remove trackingID from inflight AFTER draining resultCh, not before. This prevents the readLoop from finding the ID after drain. (Trade-off: slight increase in live trackingID window.)

---

### US-12: `socks5/udp.go` WriteTo/Write -- buffer not cleared before Put

**File:** `server/upstream/socks5/udp.go:282,348`  
**Category:** information-disclosure / low  
**Risk:** `socks5WritePool` buffers are returned without clearing. All bytes up to `totalLen` are overwritten by the next caller, but residual data beyond `totalLen` exists in the full 1500-byte buffer. Since buffering is always sliced to `totalLen`, the excess is invisible to the caller. However, the pattern is inconsistent with the Read path which properly clears before Put, and any future code path that omits the full overwrite would have a data leak.

**Fix:** `defer clear(*bp); socks5WritePool.Put(bp)` to match the Read path convention.

---

### US-13: `pool/tcp.go` `SetSegmentation` writeMu held across Pool buf reads

**File:** `server/upstream/pool/tcp.go:93-98`  
**Category:** performance / lock-contention  
**Risk:** `Exchange()` acquires `c.writeMu` for the full `WriteTCPMsgSegmented` call. `SetSegmentation()` also acquires `c.writeMu` to update segmentation config. Since segmentation is set once (or never) per connection, contention is minimal. Not a bug, but the `writeMu` is finer-grained than needed -- `segmentSize`/`segmentDelay` could use `atomic` ops.

**Fix:** (Optional, LOW) Convert `segmentSize`/`segmentDelay` to `atomic.Int32`/`atomic.Int64`.

---

### US-14: `plain/tcp.go` `exchangeViaProxy` -- hardcoded 2-byte framing

**File:** `server/upstream/plain/tcp.go:80-85`  
**Category:** coupling  
**Risk:** The 2-byte length prefix is hardcoded instead of using `zdnsutil.DNSFramePrefixLen`. While `DNSFramePrefixLen` is 2 by definition, the hardcoded constant creates an inconsistency (the pool and dtls code use `DNSFramePrefixLen`).

```go
writeBuf := make([]byte, 2+len(msg.Data))
binary.BigEndian.PutUint16(writeBuf[:2], uint16(len(msg.Data)))
```

**Fix:** Use `zdnsutil.DNSFramePrefixLen` for consistency.

---

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| CRITICAL | 3 | DTLCP use-after-free (US-01), nil dereference in warmup/proxyDialer (US-02), pool/tcp buffer leak on large responses (US-03) |
| HIGH     | 2 | DNSCrypt PQ ticket stored without valid resume secret (US-04), data race on minQueryLen (US-05) |
| MEDIUM   | 4 | Bare type assertion in DoH transport (US-06), hardcoded buffer pool (US-07), dead ctrlClosed channel (US-08), buffer bounds risk (US-09) |
| LOW      | 5 | Missing Data=nil in dnscrypt (US-10), orphaned response race (US-11), uncleared write pool (US-12), lock granularity (US-13), hardcoded framing (US-14) |
| **Total** | **14** | |

### Most impactful fixes (in priority order):

1. **US-02** -- Panics on any server with a bad proxy URL. Immediate crash.
2. **US-01** -- Silent data corruption: `response.Data` points to zeroed memory for every DTLCP query. Same class as the recently-fixed DTLS bug.
3. **US-03** -- Progressive pool exhaustion under large TCP responses. Affects DNSSEC/NSEC3-heavy zones.
4. **US-04** -- PQ ticket without valid resume secret produces garbage shared keys, causing hard-to-debug DNSCrypt failures.
5. **US-05** -- Data race on `minQueryLen`: must hold `state.mu` for the write.
