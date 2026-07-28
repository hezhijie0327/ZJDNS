# Foundation Audit — internal/* Packages

## Files Audited (22 files)

All files in `internal/log`, `internal/pool`, `internal/dnsutil`, `internal/ipdetect`, `internal/ipttl`,
`internal/siphash`, `internal/ttl`, `internal/lrumap`, `internal/pending`, `internal/dns64`,
`internal/latency`, `internal/stamp`, `internal/dnscryptcrypto`.

## Findings

### CRITICAL — None

### HIGH — None

### MEDIUM

| ID | File | Line | Category | Description |
|----|------|------|----------|-------------|
| M1 | `internal/dnsutil/dnsutil.go` | 54 | correctness | `IsSecureProtocol` does not include "dnscrypt", forcing callers (`warmup.go:45`, `validate.go:189`) to add explicit DNSCrypt checks as workarounds |
| M2 | `internal/dnscryptcrypto/certificate.go` | 197-201 | dead-code | `ErrPQCertTooShort` at line 200 is unreachable — `len(b) < 124` implies `len(b) < 1320` is always true, so the inner if-branch always returns `ErrCertTooShort` |
| M3 | `internal/dnscryptcrypto/dns.go` | 70,95 | panic | `ReadPrefixed` and `WritePrefixed` missing nil conn check — nil conn causes nil pointer dereference in `io.ReadFull` |

### LOW

| ID | File | Line | Category | Description |
|----|------|------|----------|-------------|
| L1 | `internal/dnscryptcrypto/dns.go` | 40 | doc | Godoc comment says `dnsSize returns...` but function is exported `DNSSize` |
| L2 | `internal/dnsutil/bind.go` | 65,72 | comment | `_ = l.Close()` comments say "during shutdown" but TryBind is a startup preflight |
| L3 | `internal/dnsutil/keepalive.go` | 27-28 | comment | Discarded `SetKeepAlive`/`SetKeepAlivePeriod` errors lack inline `// _ = error:` comments |
| L4 | `internal/dnscryptcrypto/xsecretbox.go` | 67,92,114,122 | comment | Multiple `_` discards lack inline comments explaining why errors are safe to ignore |
| L5 | `internal/ipdetect/ipdetect.go` | 64-66 | dead-code | `resp == nil` check after `client.Get()` — per http.Client docs, resp is never nil when err is nil |
| L6 | `internal/ipttl/ipttl.go` | 1 | doc | Package doc says "Package ttlcap" but Go package name is `ipttl` |
| L7 | `internal/dnscryptcrypto/keys.go` | 38-43 | error-wrap | `GenerateEd25519Keypair` returns raw error without `%w` wrapping |
| L8 | `internal/latency/prober.go` | 45-49 | resource | `Close()` not idempotent — no `sync.Once` guard (practically safe since `httpPool.Close()` sets clients=nil) |
| L9 | `internal/latency/httppool.go` | 82 | comment | `_ = t.Close()` lacks inline comment |
| L10 | `internal/dnscryptcrypto/encrypted.go` | 590-602 | redundancy | `EncryptQuery`/`DecryptResponse` are trivial wrappers adding no value over calling methods directly |
| L11 | `config/config.go` | 202-203 | validation | `ProviderName()` returns "2.dnscrypt-cert." for empty domain — no input validation |
| L12 | `database/stmts.go` | 68-73 | coupling | 64-placeholder `StmtIPLatency` must match `cache.maxLatencyLookupIPs` — fragile cross-package constant coupling |

## Assessment

Foundation packages are well-written with good defensive coding. No CRITICAL or HIGH issues found.
The three MEDIUM issues (M1-M3) are correctness concerns that should be fixed. M1 is a protocol
completeness issue, M2 is dead code, M3 is a missing nil guard.
