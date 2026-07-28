# Protocol Audit — server/protocol/dnscrypt/*

## Files Audited

- `server/protocol/dnscrypt/server.go` — Server lifecycle, key rotation, handshake
- `server/protocol/dnscrypt/udp.go` — UDP listener + handler
- `server/protocol/dnscrypt/tcp.go` — TCP listener + handler
- `server/protocol/dnscrypt/crypto.go` — Encrypt/decrypt with shared-key cache
- `server/protocol/dnscrypt/generate.go` — Certificate generation

## Findings

### CRITICAL

#### C1: Shared-key cache uses zero-valued client public key (`crypto.go:176-185`)

**File**: `server/protocol/dnscrypt/crypto.go`, lines 176-185

**Description**: In the `decrypt` method's classical DNSCrypt path, `cpk` (client public key)
is captured at line 176 BEFORE `query.Decrypt()` populates `query.ClientPk` at line 180:

```go
cpk := query.ClientPk                                   // line 176 — ZERO at this point
if cached, ok := s.sharedKeyCache.Get(cpk); ok {        // line 177 — always miss (key is zero)
    query.SharedKey = cached
}
decrypted, decErr := query.Decrypt(b, k.pair.Classical.ResolverSk) // line 180 — sets ClientPk
if decErr == nil && query.SharedKey == [dnscryptcrypto.SharedKeySize]byte{} {
    sk, skErr := dnscryptcrypto.ComputeSharedKey(..., &cpk)  // line 183 — uses ZERO cpk, not query.ClientPk
    if skErr == nil {
        s.sharedKeyCache.Set(cpk, sk)                        // line 185 — stored under ZERO key
    }
}
```

**Impact chain**:
1. First query: `cpk` = zero → cache miss → decrypt succeeds (fresh X25519) → cache stores `{zero: wrong_shared_key}`
2. Second query: `cpk` = zero → cache HIT → `query.SharedKey = wrong_shared_key` → decrypt uses wrong key → **AEAD authentication fails**
3. All subsequent classical DNSCrypt queries fail permanently
4. PQ queries are unaffected (separate code path)

**Fix**: Move `cpk` capture AFTER `Decrypt()` and use `query.ClientPk`:

```go
decrypted, decErr := query.Decrypt(b, k.pair.Classical.ResolverSk)
if decErr == nil {
    cpk := query.ClientPk  // populated by Decrypt
    if cached, ok := s.sharedKeyCache.Get(cpk); ok {
        query.SharedKey = cached
    } else {
        sk, skErr := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &k.pair.Classical.ResolverSk, &cpk)
        if skErr == nil {
            s.sharedKeyCache.Set(cpk, sk)
            query.SharedKey = sk
        }
    }
    // ... unpack and return
}
```

**Risk**: Data corruption — all classical DNSCrypt queries fail with AEAD authentication errors
after the first successful query. Only affected when the server handles more than one
classical DNSCrypt query per key rotation period.

### HIGH — None found

### MEDIUM — None found

### LOW

| ID | File | Line | Category | Description |
|----|------|------|----------|-------------|
| L13 | `server/protocol/dnscrypt/crypto.go` | 176 | perf | Extra X25519 computation at line 183 computes shared key with wrong inputs — wasted CPU |

## Assessment

The DNSCrypt server protocol implementation is otherwise well-structured with correct pool
discipline (defer Put, buffer ownership transfer, DATA copy before Put). The key rotation,
shutdown, and handshake logic are correct.

The one CRITICAL bug (C1) is a subtle ordering error in the shared-key cache initialization.
