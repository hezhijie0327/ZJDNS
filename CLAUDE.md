# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Guidelines

1. Think before acting. Read existing files before writing code.
2. Be concise in output but thorough in reasoning.
3. Prefer editing over rewriting whole files.
4. Do not re-read files you have already read.
5. Test your code before declaring done.
6. No sycophantic openers or closing fluff.
7. Keep solutions simple and direct.
8. User instructions always override this file.
9. Commit incrementally — every batch of related changes should be committed
   with a descriptive message. Present changes for review before committing.
10. Run `golangci-lint run && golangci-lint fmt` before committing.

## Build & Test

```bash
# Build
go build -o zjdns

# Build with version info
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns

# All tests
go test ./... -short

# Single package
go test ./server/resolver/... -v

# Single test
go test ./server/resolver/... -run TestIsZoneCut -v

# Benchmarks
go test -bench=. -short ./...
go test -bench=BenchmarkServerProcessQuery -benchtime=3s .

# Lint (pre-commit hook runs this automatically)
golangci-lint run && golangci-lint fmt

# Install pre-commit hook
cp scripts/pre-commit .git/hooks/ && chmod +x .git/hooks/pre-commit
```

Module path: `zjdns` (Go 1.26). Zero `golangci-lint` warnings required.

## Coding Standards

### Naming

**General conventions:**
- **PascalCase** for exported, **camelCase** for unexported. No `snake_case` identifiers.
- **Acronyms all-caps**: `DNS`, `TLS`, `QUIC`, `ECS`, `EDNS`, `EDE`, `CIDR`, `PTR`, `RCODE`, `DNSSEC`, `TCP`, `UDP`, `DOH`, `DOQ`, `DOT`, `SOCKS5`, `HTTP`, `HTTPS`, `IP`, `TTL`, `CNAME`, `DDR`, `KTLS`, `ALPN`.
  - Exported: `DOHRequests`, `SOCKS5Dialer`, `RCODENoError`
  - Unexported first word: `dnssecStatus`, `udpRequests` (acronym lowered as first word)
  - Unexported later word: `lastDNSSECStatus`, `maxTCPConns` (acronym stays all-caps)
- **`Default` prefix reserved for value constants**: `DefaultDNSQueryTimeout`, not `DefaultECSConfig` (that's a type — use `ECSConfig`).

**Fields & receivers:**
- **Field names describe what it IS, not the pattern**: `cache cache.Store`, not `cacheMgr cache.Store`. The type already says it's a Store — the suffix is noise.
- **No `Mgr`/`Manager` suffixes**: prefer descriptive names or drop the suffix entirely. `cacheMgr` → `cache`. `log.Manager` → `log.Logger`.
- **Method receivers**: single letter, first letter of type, lowercased. `(s *Server)` not `(svr *Server)`. Use value receiver only for small immutable types.

**Function/method naming:**
- **No `Get` prefix on getters**: `RemainingTTL()` not `GetRemainingTTL()`. Plain noun for accessors.
- **Constructors use `New` / `NewXxx`**: not `Build`, `Create`, `Init`, `Make`. Exception: `BuildXxx` for building derived values (strings, byte slices), not type instances.
- **Boolean predicates use assertion prefixes**: `IsXxx`, `HasXxx`, `CanXxx`, `ShouldXxx`. `ValidateXxx` returning only `bool` → rename to `IsXxxValid`.
- **Conversion methods**: `ToXxx()` not `AsXxx()` or `IntoXxx()`.
- **Package-level functions over empty structs**: `type Foo struct{}` with methods → convert to functions.
- **Sentinel errors**: `ErrXxx` for exported, `errXxx` for unexported.

**Type naming:**
- **Avoid stutter with package name**: `cache.CacheEntry` → `cache.Entry`. But standard Go types like `server.Server`, `http.Server` are idiomatic — don't force-rename these.

### Performance (Hot Path)
- **`log.NowUnix()` / `log.NowUnixNano()`** instead of `time.Now()` in cache TTL checks, DNSSEC RRSIG validation, last-access timestamps. `TimeCache` updates once per second via `atomic.Value`.
- **Avoid `fmt.Sprintf` on the query path**: use `strings.Builder` for map keys, `strconv.Itoa` over `fmt.Sprint`.
- **Zero-allocation trimming**: prefer sub-slicing (`s[:len(s)-1]`) over `strings.TrimSuffix` for single known bytes.
- **`strings.EqualFold`** over `strings.ToLower` for case-insensitive comparison on the hot path.
- **`slices.SortStableFunc`** over `sort.SliceStable` (generics avoid reflect-based closure dispatch).
- **Hoist fixed-size allocations out of loops**: `var prefix [2]byte` on stack instead of `make([]byte, 2)` per frame.
- **Pre-parse strings to uint16 at load time**: Type/Class strings parsed once in `LoadRules`, stored as `ParsedType`/`ParsedClass`.

### Constants
- All magic numbers must be named constants in `config/defaults.go` with a `Default` prefix.
- No duplicate constants in the same package.
- Leaf packages that can't import `config` may use local `const` blocks with same naming convention.
- Cache key strings follow `prefix:` convention (`dns:`, `dnskey:`, `stats:`).

### Anti-patterns (DO NOT implement)
- **No rate limiting** — accept all queries unconditionally.
- **No per-IP connection limiting** — all listeners accept unlimited connections.
- **No DNSCrypt** — removed; do not reintroduce.

## Architecture

ZJDNS is a high-performance recursive DNS server supporting DoT, DoQ, DoH, DoH3.

### Query Pipeline (`server/handler.go:processDNSQuery`)
1. Request validation (domain/label length, ANY/AXFR/IXFR rejection)
2. `rewrite.Evaluator.Evaluate()` — synthetic response if rule matches
3. `edns.Handler` — extract ECS, DNS Cookie
4. Early DNS Cookie validation (RFC 7873) — invalid cookie → FORMERR
5. `cache.Store.Get()` — hit → serve (with CIDR filtering); miss → resolve
6. `Resolver.Query()` — upstream (first-win) or recursive
7. `Guard` — DNSSEC validation + hijack detection (UDP→TCP fallback)
8. `cidr.Filter.MatchIP()` — filter A/AAAA; all filtered → REFUSED + EDE
9. Cache population, latency probes, response with server cookie

### Query Routing (`server/resolver`)
- Upstream + fallback queried concurrently via `errgroup`; first NOERROR wins
- NXDOMAIN stored as secondary fallback within each query group
- No servers configured → built-in recursive (root→TLD→authoritative)
- CNAME chain exceeded → SERVFAIL (not partial results)

### Recursive Resolution (`server/resolver/recursive.go`)
- Root hints → TLD NS → authoritative NS walk
- NS address latency-sorted cache (ICMP/TCP/UDP probes) via unified engine
- DNSSEC chain-of-trust at each delegation: parent DNSKEY → DS RRSIG → child DNSKEY → answer RRSIG
- Zone cut detection, lame delegation detection, glue record validation
- `dsPresentButUnverified` flag distinguishes bogus delegation from true insecure

### Connection Pools (`server/client/pool/`)
- **TCP/DoT** (RFC 7766): Per-upstream multiplexed connections, out-of-order response matching by DNS message ID, fallback to single-shot on failure
- **DoQ**: QUIC native stream multiplexing, up to 4 connections per upstream
- Server-side DoT: reader→worker→writer three-stage pipeline

### Dependency Graph
```
main ──→ server, config
server ──→ cache, cidr, config, edns, dnsutil, log, pool, rewrite, latency, resolver, security, stats
resolver ──→ config, edns, client, security, dnsutil, latency, log, pool
security ──→ dnsutil, log
pool, log ──→ (zero deps)
```
No circular dependencies.

## Key Types

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig` | `config` | Top-level config (LoadConfig) |
| `edns.Handler` | `edns` | EDNS option parsing/construction |
| `cache.Store` | `cache` | Interface: Get, Set, SetWithDNSSEC, ReverseLookup, Close |
| `stats.Collector` | `stats` | Lock-free atomic metrics |
| `Server` | `server` | Core server lifecycle |
| `Server` | `server/tls` | TLS listeners (DoT, DoQ, DoH, DoH3) |
| `Client` | `server/client` | Outbound queries (UDP/TCP/DoT/DoQ/DoH/DoH3/SOCKS5) |
| `Socks5Dialer` | `server/client` | SOCKS5 proxy (RFC 1928/1929, TCP CONNECT + UDP ASSOCIATE) |
| `Conn` / `Pool` | `server/client/pool` | RFC 7766 pipelined TCP/DoT |
| `QUICPool` / `QUICConn` | `server/client/pool` | QUIC connection pool |
| `Resolver` | `server/resolver` | Upstream + recursive resolution |
| `Recursive` | `server/resolver` | Built-in recursive walk |
| `CryptoValidator` | `server/security` | DNSSEC chain-of-trust (RRSIG, DS, trust anchors) |
| `Guard` | `server/security` | Bundles CryptoValidator + Detector |
| `Prober` | `internal/latency` | Unified probe engine (generic sorter) |
| `MessagePool` / `BufferPool` | `pool` | sync.Pool allocators |

## Logging

All logs use `zjdns/internal/log`. Default level: `info`.

**Component filtering**: `log_level` supports `level:comp1,comp2` syntax (e.g. `"debug:UPSTREAM,RECURSION"`). Messages without a `PREFIX: ` pattern always pass through.

**18 canonical prefixes**: `TLS`, `CACHE`, `UPSTREAM`, `SERVER`, `EDNS`, `RECURSION`, `SECURITY`, `TCPPOOL`, `LATENCY`, `STATS`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PTR`, `PANIC`.

Prefix matches logical component, not Go package. `HIJACK:`/`DNSSEC:` merged → `SECURITY:`. `DOT:`/`DOQ:`/`DOH:` merged → `TLS:`. Hot-path logs are `Debug` only.

## Notable Design Decisions

- **Cache**: RLock reads (zero contention), entry pointer returned directly — `expand()` re-parses from `.Text` non-mutatingly. TTL floor 10s. `CompactRecord.RR` intentionally nil (saves memory; `expand()` uses `.Text`).
- **Pool discipline**: `MessagePool.Put()` zeroes the struct — never read fields after `Put()`. Double-zeroing removed: `Put` zeroes, `Get` trusts.
- **KTLS**: `gitlab.com/go-extension/tls` with `KernelTX`/`KernelRX` (both default `false`, opt-in). Dual configs: eTLS for TCP, crypto/tls for QUIC. Silent fallback on non-Linux.
- **SOCKS5**: Per-upstream optional proxy. TCP CONNECT + UDP ASSOCIATE. `SafeURL()` redacts passwords.
- **DNSSEC**: IANA root KSK trust anchors (key tags 20326 + 38696). `dnssec_enforce: true` → SERVFAIL on bogus; `false` → pass through without AD.
- **EDE propagation**: DNSSEC EDE codes stored atomically on `Recursive.lastDNSSECEDECode`, read by `processQueryError` to avoid error-chain corruption from context cancellation.
- **HandlePanic**: Recovers per-goroutine — a single connection panic terminates only that goroutine, not the server.
- **Config self-sufficiency**: `ProjectName`/`Version` are package-level vars set by `main.go` before `LoadConfig()`.

## Debug Config

`config.debug.json` (not committed):

```json
{
  "server": {
    "port": "15353",
    "log_level": "debug",
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "cache": { "size": 0 }
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

Port 15353 (non-privileged), pure recursive, cache disabled, Debug log level. Start: `./zjdns -config config.debug.json`.

### Test Domains

**Should trigger hijack detection + TCP fallback (blocked by GFW):**
```bash
dig @127.0.0.1 -p 15353 www.google.com A +short
dig @127.0.0.1 -p 15353 www.youtube.com A +short
dig @127.0.0.1 -p 15353 www.facebook.com A +short
dig @127.0.0.1 -p 15353 chatgpt.com A +short
```

**Should resolve normally without TCP fallback:**
```bash
dig @127.0.0.1 -p 15353 www.baidu.com A +short
dig @127.0.0.1 -p 15353 dns.weixin.qq.com.cn A +short
dig @127.0.0.1 -p 15353 updates.cdn-apple.com A +short
```

**DNSSEC validation tests (require `dnssec_enforce: true` in debug config):**
```bash
# Should fail DNSSEC (bogus signature / bad DS)
dig @127.0.0.1 -p 15353 dnssec-failed.org A +short
dig @127.0.0.1 -p 15353 badsign-a.test.dnssec-tools.org A +short
dig @127.0.0.1 -p 15353 sigfail.ippacket.stream A +short

# Should pass DNSSEC (valid chain)
dig @127.0.0.1 -p 15353 sigok.ippacket.stream A +short
```

**EDNS FORMERR retry test:**
```bash
# Microsoft mail.protection.outlook.com rejects EDNS queries with FORMERR.
# ZJDNS should retry without EDNS and still get the answer.
dig @127.0.0.1 -p 15353 zhijie-online.mail.protection.outlook.com A +short
```

Verify hijack detection from logs: `grep -E "hijack detected|rejecting hijacked|tcp=true" /tmp/zjdns.log`
Normal domains should show `tcp=false` throughout; blocked domains should show hijack detection + `tcp=true` restart.

## KTLS Tuning

If `"local error: tls: bad record MAC"` appears, disable kernel RX offload:

```json
{ "server": { "tls": { "ktls": { "kernel_rx": false } } } }
```

Both `kernel_tx` and `kernel_rx` default to `false` (KTLS is opt-in).

## Refactoring Lessons (2026-06-30 Audit)

66 issues fixed across 7 commits covering 18,184 lines. Key takeaways:

1. **Pool discipline**: `sync.Pool.Put()` zeroes state — any code reading fields after `Put()` is a bug no linter catches.
2. **Acronym casing drifts**: `DoH`/`DoT`/`DoQ`/`DNS`/`TLS`/`QUIC` are all-caps everywhere — `DefaultDoHMaxRequestSize` → `DefaultDOHMaxRequestSize`.
3. **Constants diverge between doc and code**: CLAUDE.md documented 5 wrong values. Code is canonical; docs must be verified.
4. **Empty structs are a smell**: `type Validator struct{}` → `func ValidateResponse(...)`.
5. **`Default` prefix on types is misleading**: `DefaultECSConfig` → `ECSConfig`. `Default` means "default value of this constant", not "default configuration".
6. **Commit per batch**: Each batch independently reviewable and revertible. No mega-commit.
7. **Pre-commit hook prevents regression**: `golangci-lint fmt` + `run` catches drift immediately.
