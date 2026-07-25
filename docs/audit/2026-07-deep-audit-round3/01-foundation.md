# Foundation Layer Audit (internal/*)

**Audit scope:** internal/log, internal/pool, internal/lrumap, internal/pending, internal/dnsutil, internal/ipdetect, internal/latency, internal/stamp, internal/siphash, internal/ttl, internal/dns64, internal/dnscryptcrypto

**Date:** 2026-07-25
**Coverage:** 30 source files across 12 packages

---

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 2 |
| LOW | 5 |
| INFO | 3 |

---

## Issue Log

### 1. [HIGH] [panic] stamp/parse.go — Off-by-one slice bounds in `parseSecure` path field

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/stamp/parse.go`, line 160

```go
length = int(bin[pos])
if length > binLen-pos {              // <-- BUG: should be 1+length > binLen-pos
    return fmt.Errorf("stamp: invalid %s stamp", name)
}
pos++
s.Path = string(bin[pos : pos+length])
```

**Problem:** The length check for the path field uses `length > binLen-pos` instead of `1+length > binLen-pos`. The variable `pos` has NOT been incremented yet when the check runs, so `binLen-pos` includes the length-indicator byte itself. The condition fails to reject the case where `length == binLen-pos` — i.e., the available bytes exactly equal the reported data length (with no room for the 1-byte length indicator).

When `length == binLen - pos`, the check passes, then `pos++` advances past the length byte, and `bin[pos : pos+length]` reads one byte past the end of the buffer, producing a slice index out of range panic.

**Trigger scenario:** A crafted sdns:// stamp where, after parsing all preceding fields, the remaining bytes equal `1 + pathLength`. For example, a DoH stamp byte sequence where the path step has binLen=12, pos=10, bin[10]=2 (length=2), and only 2 bytes remain (need 3). This crashes the caller.

**All prior checks in `parseSecure` and sister functions are correct:**
- `parsePlainDNS` line 18: `1+length > binLen-pos` (correct)
- `parseDNSCrypt` line 67: `1+length >= binLen-pos` (conservative)
- `parseSecure` addr line 130: `1+length >= binLen-pos` (conservative)
- `parseSecure` provider-name line 151: `1+length > binLen-pos` (correct)

Line 160 is the only inconsistent check.

**Risk:** Any code path that calls `Parse()` with untrusted input can trigger a panic. The stamp parser is used by the `--dnsstamp --decode` CLI and upstream configuration loading. While not remotely triggerable over the network, it crashes the process on malformed input.

**Fix:** Change line 160 from `if length > binLen-pos` to `if 1+length > binLen-pos`.

---

### 2. [MEDIUM] [panic] ttl/ttl.go — Division by zero in `RemainingTTL` when `staleTTL == 0`

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/ttl/ttl.go`, line 32

```go
cycleRemaining := max(int64(staleTTL)-(timeSinceExpiry%int64(staleTTL)), 1)
```

**Problem:** When `staleTTL == 0` and the entry is expired (i.e., `remaining <= 0`, so `timeSinceExpiry` is used), the expression `timeSinceExpiry % int64(staleTTL)` computes `timeSinceExpiry % 0`, which triggers a division-by-zero panic at runtime.

The early-return at line 27 (`if remaining > 0`) shields fresh entries, but any expired entry combined with `staleTTL = 0` hits the division.

**Risk:** `staleTTL` is a `uint32` sourced from server configuration. If the operator sets `stale_ttl: 0` (or the config package passes a zero value through a fallback path), every cache lookup for an expired entry panics the server goroutine handling that query. Since `staleTTL` is typically 3600 in practice, this requires operator misconfiguration to trigger, but the function lacks any defensive guard.

**Fix:** Add a guard at function entry:
```go
if staleTTL == 0 {
    staleTTL = 1
}
```
Or add a check before the modulus:
```go
if staleTTL == 0 {
    return 0  // or staleTTL = 1
}
```

---

### 3. [MEDIUM] [locking] latency/httppool.go — Mutex acquired on every probe, then I/O inside critical section

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/latency/httppool.go`, lines 32-68

**Problem:** The `get()` method (called for every HTTP probe) acquires `p.mu.Lock()` and holds it during an `http.Client` creation that involves TLS configuration struct initialization. The lock is released at return via `defer`. While the creation path allocates TLS config structs, it does not perform network I/O — the actual HTTP request happens in `probeHTTP` outside the lock. However, the lock does protect the `p.clients` map read/write, which involves a map lookup and potential insert.

On the hot probing path (dozens to hundreds of concurrent probes), the mutex serializes all pool lookups. However, since this function is a read-mostly pattern after initial warmup (each key is created once and then read repeatedly), the overhead is bounded.

**Risk:** The lock serializes `get()` calls. Under heavy concurrent probing (e.g., probing 1000 IPs), all goroutines contend on this single mutex. However, in practice, probes are spaced across goroutines and the critical section is short (map lookup + optional creation). This is a moderate performance concern, not a correctness one.

**Fix (optional):** For a read-mostly, write-rarely pattern, `sync.Map` could reduce contention. However, the current design is acceptable for the expected probing volume (root/NS server startup, client-facing A/AAAA reorder). If probes become a bottleneck, `sync.Map` or a `sync.RWMutex` (RLock for reads, Lock for writes after successful RLock with double-check) would help.

---

### 4. [LOW] [inefficiency] dnscryptcrypto/encryption.go — `Pad` allocates via `make` on every DNSCrypt query

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/encryption.go`, line 24

```go
if n := minSize - len(packet); n > 0 {
    packet = append(packet, make([]byte, n)...)
}
```

**Problem:** The `Pad` function appends `make([]byte, n)` zero-fill to the packet. This allocates a new byte slice on every DNSCrypt query (both client and server). For UDP queries, the padding can be up to several hundred bytes. Combined with the `append`'s potential grow+copy, this can produce multiple allocations per query.

**Risk:** Added GC pressure on DNSCrypt hot paths. Not a correctness issue.

**Fix:** Pre-compute the target capacity and allocate once:
```go
func Pad(packet []byte, minLen int) (padded []byte) {
    minSize := max(minLen, len(packet)+1+(64-(len(packet)+1)%64)%64)
    padded = make([]byte, 0, minSize)
    padded = append(padded, packet...)
    padded = append(padded, 0x80)
    for len(padded) < minSize {
        padded = append(padded, 0)
    }
    return padded
}
```

This allocates exactly once (or zero if `cap(packet) >= minSize`, though typical callers pass the original `packet` which may have a smaller cap).

---

### 5. [LOW] [inefficiency] dnscryptcrypto/certificate.go — `VerifySignature` allocates per call

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/certificate.go`, lines 305-309

```go
func (c *Certificate) VerifySignature(publicKey ed25519.PublicKey) (ok bool) {
    b := make([]byte, c.signedSize())
    c.writeSigned(b)
    return ed25519.Verify(publicKey, b, c.Signature[:])
}
```

**Problem:** `VerifySignature` allocates a new `[]byte` for the signed portion on every call. For classical certificates, this is 52 bytes; for PQ certificates, 1248 bytes. This is called during DNSCrypt server certificate validation — once per query in the worst case (every client connection).

**Risk:** Moderate heap allocation on the DNSCrypt hot path. PQ certificates (1248 bytes per call) are the bigger concern.

**Fix:** Cache the signed portion on the `Certificate` struct after construction:
```go
type Certificate struct {
    // ... existing fields ...
    signedBytes []byte // cached signed portion, set during Sign/UnmarshalBinary
}
```
Then `VerifySignature` uses the cached copy. The tradeoff is one extra 52-1248 byte allocation per certificate instead of per verification.

---

### 6. [LOW] [memory] dnsutil/tcpframe.go — `ReadTCPMsg` allocates unbounded buffer from wire

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/dnsutil/tcpframe.go`, lines 14-29

```go
length := int(prefix[0])<<8 | int(prefix[1])
buf := make([]byte, length)
```

**Problem:** The 2-byte length prefix is parsed and used directly as the allocation size without any upper bound check beyond the implicit `uint16` limit of 65535. Any TLS-speaking peer can request a 65535-byte allocation. While `dns.MaxMsgSize` (65535) is the protocol limit and the allocation is benign at 64KB, repeated large allocations can pressure the GC. Other transport helpers in the codebase (e.g., `dnscryptcrypto/dns.go` `ReadPrefixed`, line 57-58) properly check `packetLen > dns.MaxMsgSize`.

**Risk:** A chatty peer could force repeated 64KB allocations. Minor in practice but inconsistent with the sister function.

**Fix:** Add a bounds check:
```go
length := int(prefix[0])<<8 | int(prefix[1])
if length > dns.MaxMsgSize {
    return nil, ErrMsgTooLarge
}
```

---

### 7. [LOW] [inefficiency] dnscryptcrypto/pq.go — `PQProfileExtension` allocates every call

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/pq.go`, lines 42-46

```go
func PQProfileExtension() []byte {
    ext := make([]byte, len(pqProfileExt))
    copy(ext, pqProfileExt)
    return ext
}
```

**Problem:** Returns a defensive copy of the static profile extension. Every call allocates 12 bytes. Called during certificate unmarshaling (PQ path, once per cert).

**Risk:** Trivial. The function is called once per PQ certificate parsed. The copy exists to prevent callers from mutating the shared `pqProfileExt`. If the contract is that callers must not mutate, this could return `pqProfileExt` directly, eliminating the allocation.

**Fix:** Either document that callers must not mutate the return value and return `pqProfileExt` directly, or pre-allocate a pool of copies. The current approach is acceptable for non-hot-path usage.

---

### 8. [LOW] [inefficiency] stamp/encode.go — `newStampHeader` over-allocates capacity

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/stamp/encode.go`, line 36

```go
bin := make([]byte, 0, 128)
```

**Problem:** The initial capacity of 128 is far more than needed for a stamp header (1 byte proto + 8 bytes props = 9 bytes). Addresses and additional fields are appended after this function returns, so the total stamp is typically 40-100 bytes, making 128 a reasonable upper bound. However, calling `newStampHeader` alone wastes 119 bytes of unreachable capacity on the 9 bytes actually used.

**Risk:** Negligible. Called during stamp encoding only (CLI tool or config export), not on hot paths.

**Fix:** Reduce to `make([]byte, 0, 9)` and let `append` grow as needed.

---

### 9. [INFO] [reliability] dnsutil/dnsutil.go — `extractPrefix` edge case: trailing-colon messages

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/dnsutil/dnsutil.go`, line 194 (via log.go `Log` -> `extractPrefix`)

```go
if idx <= 0 || idx >= len(msg)-1 || msg[idx+1] != ' ' {
    return ""
}
```

**Problem:** The condition `idx >= len(msg)-1` rejects messages where the colon is the last or second-to-last character (e.g., `"PREFIX:"` or `"PREFIX: "`). For `"PREFIX: "` (colon at position 6, message length 8), `6 >= 7` is false, so it passes through. But for a message ending exactly at `:`, the prefix is rejected. Messages in the codebase never end with `:` alone (they always have text after the space), so this is not a practical bug, but it is a defensive gap.

**Risk:** None in practice — all log messages follow `"PREFIX: message"` format with non-empty message.

**Fix:** Change to `idx >= len(msg)-2` to allow `"PREFIX: "` (single trailing space). No impact on existing behavior.

---

### 10. [INFO] [dead-code] stamp/encode.go — `stripDefaultPort` used indirectly

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/stamp/encode.go`, lines 101-103

**Problem:** `stripDefaultPort` is called from `encodeAddrAndHostname` (line 114) and `dnsCryptString` (line 54). The function uses `strings.TrimSuffix` which, when the input lacks the suffix, returns the input unchanged. However, the semantics assume the port, if present, matches the default port for the protocol. If the address contains a non-default port (e.g., `192.0.2.1:5353` with default=443), `stripDefaultPort` is a no-op because the suffix `":443"` is not present. This means the port is preserved in the output — which is the correct behavior. The function's name suggests it "strips" the port, but it only strips the default port, preserving non-default ports. This is correct per the DNS Stamp spec, but the function name is slightly misleading.

**Risk:** None — behavior is correct.

**Fix:** Rename to `stripDefaultPortIfPresent` for clarity (optional).

---

### 11. [INFO] [reliability] pending/pending.go — Key leakage if `Start` leader panics before `Done`

**File:** `/Users/hezhijie/Downloads/ZJDNS/internal/pending/pending.go`, lines 36-46

**Problem:** When `Start(key)` returns true (leader), the caller MUST call `Done(key)`, as documented in the comment. If the leader panics between `Start` and `Done`, the key leaks into the map permanently because the `Done` call is typically deferred but only works if the goroutine exits normally. Any goroutine that calls `HandlePanic` + `recover` (which most do) will execute the deferred `Done`, so this is mitigated by the prevailing pattern. But a goroutine that does NOT have `HandlePanic` + `recover` would leak its key.

**Risk:** Low — all goroutines in the codebase use `defer HandlePanic(...)` and `defer g.Done(key)`. However, this is a fragile invariant that depends on caller discipline.

**Fix:** Consider making `Start` return a cleanup function instead of requiring explicit `Done`:
```go
func (g *Group[K]) Start(key K) (leader bool, cleanup func()) {
    g.mu.Lock()
    if _, loaded := g.sets[key]; loaded {
        g.mu.Unlock()
        return false, nil
    }
    g.sets[key] = struct{}{}
    g.mu.Unlock()
    return true, func() { g.Done(key) }
}
```
This makes it impossible for the caller to forget cleanup — the `cleanup` function is always called via `defer`.

---

## Pool Discipline Check

**Passed:** No Foundation package uses `pool.DefaultMessage.Get()` or `pool.DefaultBuffer.Get()`. The pool package (internal/pool) itself defines these primitives, and all consumers are in server/ layer packages, not Foundation. All `Get`/`Put` pairs in the consumer packages (verified via grep across the codebase for deferred Put following Get) are correctly matched.

---

## Lock Correctness Check

All mutex usage across the Foundation layer is correct:

| File | Lock Type | All Paths Covered |
|------|-----------|-------------------|
| `log/log.go` (SetComponentFilter) | `sync.Mutex` | Yes (Lock + defer Unlock) |
| `log/log.go` (Log) | `sync.RWMutex` (RLock) | Yes (RLock + RUnlock) |
| `lrumap/lrumap.go` (all methods) | `sync.Mutex` | Yes — all early returns have explicit Unlock before return |
| `pending/pending.go` (Start/Done) | `sync.Mutex` | Yes |
| `latency/httppool.go` (get/Close) | `sync.Mutex` | Yes (Lock + defer Unlock) |

No I/O is performed inside any critical section. The `httppool.go get()` method creates `http.Client` and `tls.Config` values under the lock, but these are pure computation (no network), so no blocking I/O occurs inside the lock.

---

## Memory Safety Check

| Risk | Status |
|------|--------|
| Goroutine leaks | Clean — `TimeCache` goroutine terminates via `done` channel; latency probe goroutines bounded by `WaitGroup` and context cancellation |
| Unbounded map growth | Clean — `lrumap.Map` has LRU eviction bound by capacity; `pending.Group` entries removed by `Done`; `httppool` clients map bounded by distinct (port, TLS, HTTP3) keys |
| File descriptor leaks | Clean — all `Close` calls deferred or immediately invoked; `download.go` closes response body; `probes.go` closes TCP/UDP/ICMP sockets |
| Slice/array bounds | One finding: stamp/parse.go line 160 (see Issue #1) |

---

## Architecture / Coupling Check

All Foundation packages properly avoid importing from higher layers (server, handler, resolver, upstream, cache, database, zone, ruleset, edns). The only cross-package imports within Foundation are:

- `internal/dnsutil` imports `internal/log` (permitted — dnsutil is above log)
- `internal/latency` imports `internal/dnsutil` and `internal/log` (permitted)
- `internal/latency` imports `config` (per the known exception for internal/latency)

No cyclic or upward imports exist.

---

## Dead Code / Unused Items

- All exported functions and types in the Foundation layer are referenced by higher-layer packages.
- `dnsutil.DecompressTo()` is used by the cache package on the hot path (decompressing cached entries).
- `stamp.ProtoToConfig()` is used by the config layer when resolving stamps.
- `stamp.BuildDoHURL()` is used by the upstream client for DoH connections.
- No unused imports, types, variables, or functions found.

---

## Overall Assessment

The Foundation layer is generally well-written with clean concurrency patterns, proper resource management, and strong architectural boundaries. The most significant finding is the off-by-one slice bounds check in the stamp parser (Issue #1), which is a genuine crash vulnerability on malformed input. The division-by-zero in `RemainingTTL` (Issue #2) is a defensive gap that requires operator misconfiguration to trigger.

The remaining findings are optimization opportunities or minor reliability improvements. None of the issues represent architectural flaws or systemic problems.
