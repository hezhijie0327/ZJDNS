# Upstream + Server Core + CMD Audit — Agent Findings

## Scope

41 files across `server/upstream/*`, `server/server.go`, `server/bridge.go`, `server/init.go`,
`server/tasks.go`, `cmd/zjdns/*`, `edns/*`, `ruleset/*`, `zone/*`, `config/{ecs,chaos,ddr}.go`.

## CRITICAL Findings

### C2: Use-after-free in TCP pool readLoop (Unpack error path)

**File**: `server/upstream/pool/tcp.go:241-249`
**Category**: `memory-safety`, `pool-leak`

When `resp.Unpack()` fails, the pooled buffer `bodyBuf` is returned to `pool.DefaultBuffer`
before `resp` is returned to `pool.DefaultMessage`. At that point, `resp.Data` still points
into `bodyBuf`'s backing memory. After both returns, a future `Get` from the message pool
sees a `Data` field pointing into freed buffer pool memory.

**Risk**: Data corruption — cross-query data leakage via pooled message reuse.

**Fix**: Set `resp.Data = nil` before `zpool.DefaultMessage.Put(resp)`:
```go
if err := resp.Unpack(); err != nil {
    zpool.DefaultBuffer.Put(bodyBuf)
    resp.Data = nil  // ADD THIS
    zpool.DefaultMessage.Put(resp)
    continue
}
```

### C3: Use-after-free in QUIC doQUICQuery (Unpack error path)

**File**: `server/upstream/tls/quic.go:185-190`
**Category**: `memory-safety`, `pool-leak`

When `response.Unpack()` fails, `response.Data` still points into `respBuf` (pooled buffer).
`response` is Put to message pool at line 189, then deferred `pool.DefaultBuffer.Put(respBuf)`
at line 161 returns the backing buffer. Pooled message now has dangling Data pointer.

**Risk**: Data corruption.

**Fix**: `response.Data = nil` before `pool.DefaultMessage.Put(response)`.

### C4: Use-after-free in DTLS ExecuteDTLS (Unpack error path)

**File**: `server/upstream/tls/dtls.go:93-97`
**Category**: `memory-safety`, `pool-leak`

Identical pattern: `response.Data = msgBuf` where `msgBuf` slices pooled `respBuf`.
On `Unpack()` failure, response Put before buffer defer fires.

**Risk**: Data corruption.

**Fix**: `response.Data = nil` before Put.

### C5: Use-after-free in DTLCP ExecuteDTLCP (Unpack error path)

**File**: `server/upstream/tlcp/dtlcp.go:93-97`
**Category**: `memory-safety`, `pool-leak`

Identical to C4 for DTLCP transport.

**Risk**: Data corruption.

**Fix**: `response.Data = nil` before Put.

### C6: Pool leak on plain UDP-to-TCP fallback

**File**: `server/upstream/client.go:205`
**Category**: `pool-leak`

When UDP fails/truncated, TCP fallback overwrites `result.Response` without returning
the original pooled response to `pool.DefaultMessage`.

**Risk**: Pool exhaustion — each fallback leaks one `*dns.Msg`.
Under sustained truncated-response conditions, the pool is depleted.

**Fix**: Return original response to pool before overwriting:
```go
if result.Response != nil {
    pool.DefaultMessage.Put(result.Response)
}
result.Response = tcpResp
```

### C7: Nil pointer panic on proxy dialer LRU eviction

**File**: `server/upstream/warmup.go:30` + `server/upstream/client.go:114`
**Category**: `panic`, `nil-dereference`

When `socks5.New()` fails, nil `*socks5.Dialer` is stored in LRU map. `OnEvict` callback
calls `d.Close()` without nil check. When LRU evicts nil entry, `d.mu.Lock()` panics.

**Risk**: Server crash on proxy dial failure when LRU fills.

**Fix**: Nil check in OnEvict:
```go
OnEvict: func(_ string, d *socks5.Dialer) {
    if d != nil { _ = d.Close() }
},
```

## HIGH Findings

### H1: Pool leak on DNSCrypt UDP-to-TCP fallback

**File**: `server/upstream/client.go:163`
**Category**: `pool-leak`

Same pattern as C6: DNSCrypt UDP response overwritten by TCP fallback without Put.

**Fix**: Check and Put before overwrite.

### H2: Response.Data not cleared in exchangeOverTLS

**File**: `server/upstream/tls/tls.go:87-97`
**Category**: `memory-safety`

After `response.ReadFrom(tlsConn)` + `response.Unpack()`, `response.Data` retains wire bytes.
Never set to nil before return. Violates reference template (`resp.Data = nil`).

**Risk**: Cross-query data leakage via pooled message.

**Fix**: Add `response.Data = nil` after Unpack.

### H3: Response.Data not cleared in exchangeViaProxy (TCP)

**File**: `server/upstream/plain/tcp.go:93-103`
**Category**: `memory-safety`

Same pattern as H2 for plain TCP via proxy.

**Fix**: Add `response.Data = nil` after Unpack.

### H4: tcpPool never shut down, leaking readLoop goroutines

**File**: `server/upstream/client.go:277-297`
**Category**: `goroutine-leak`, `resource-leak`

`Client.Close()` shuts down TLS/QUIC pools but `plainClient.tcpPool` has no reference
and is never shut down. readLoop goroutines live until TCP idle timeout.

**Risk**: Goroutine leak on server shutdown. Accumulates on repeated config reloads.

### H5: Unmatched-ID response Put back with dangling Data pointer

**File**: `server/upstream/pool/tcp.go:270`
**Category**: `memory-safety`

When response ID doesn't match any in-flight query, `resp` is Put to message pool
without clearing `Data`, which still points into already-returned pool buffer.

**Fix**: `resp.Data = nil` before `zpool.DefaultMessage.Put(resp)`.

### H6: context.Background() used for UDP relay dial

**File**: `server/upstream/socks5/udp.go:151`
**Category**: `context-propagation`

UDP relay dials with `context.Background()` instead of caller's ctx, bypassing
cancellation. During shutdown, the dial proceeds regardless.

**Fix**: Pass caller's ctx to `net.DialContext`.

## Root Cause Analysis

### Systemic Pattern: Pool use-after-free on error paths

6 of the 12 findings (C2-C5, H2-H3, H5) share the same root cause:
`response.Data` aliases a pooled buffer, and on error paths, the response is returned
to `pool.DefaultMessage` before/without clearing `Data`. The success paths in these
same files correctly set `Data = nil` — the error paths were simply missed.

**Prevention**: CI should verify every `pool.DefaultMessage.Put(resp)` is preceded
by `resp.Data = nil` when `resp.Data` was set from a pooled buffer.

### Systemic Pattern: Pool leak on fallback paths

C6 and H1 share the same root cause: when a protocol-level fallback (UDP→TCP) occurs,
the original response is overwritten without returning it to the pool.

**Prevention**: Fallback code should always check if `result.Response` is non-nil
from a pool before overwriting.
