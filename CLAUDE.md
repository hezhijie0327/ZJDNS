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
go build -o zjdns ./cmd/zjdns

# Build with version info
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns

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
sh scripts/install-hook.sh                 # Linux / macOS
pwsh scripts/install-hook.ps1              # Windows PowerShell
```

Module path: `zjdns` (Go 1.26). Zero `golangci-lint` warnings required.

## Coding Standards

### Naming

**General conventions:**
- **PascalCase** for exported, **camelCase** for unexported. No `snake_case` identifiers. Applies to all declarations: `type`, `func`, `const`, `var`, struct fields, method receivers, parameters.
- **Acronyms all-caps**: `DNS`, `TLS`, `QUIC`, `ECS`, `EDNS`, `EDE`, `CIDR`, `PTR`, `RCODE`, `DNSSEC`, `TCP`, `UDP`, `DOH`, `DOQ`, `DOT`, `SOCKS5`, `HTTP`, `HTTPS`, `IP`, `TTL`, `CNAME`, `DDR`, `KTLS`, `ALPN`. Plus DNS-specific: `NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `REFUSED`, `NOTIMP`, `NSEC`, `NSEC3`, `DNSKEY`, `RRSIG`, `KSK`, `ZSK`, `DS`, `TXT`, `PTR`, `ZONE`, `SEP`, `AFINET`, `PADDING`, `COOKIE`, `TLV`, `OPT`. Plus crypto: `SHA`, `HMAC`, `MAC`, `ECDSA`, `ED25519`, `JSON`, `URL`, `ID`.
  - Exported: `DOHRequests`, `SOCKS5Dialer`, `RCODENOERROR`, `EDECodeNoZONEKeyBitSet`, `IsResponseValid`
  - Unexported first word: `dnssecStatus`, `udpRequests` (acronym lowered as first word)
  - Unexported later word: `lastDNSSECStatus`, `maxTCPConns`, `rcodeNOERROR` (acronym stays all-caps)
- **`Default` prefix reserved for value constants**: `DefaultDNSQueryTimeout`, not `DefaultECSConfig` (that's a type — use `ECSConfig`).
- **No `Mgr`/`Manager`/`Handler` suffixes** on field or variable names: the type already carries the semantics. `cache cache.Store`, not `cacheMgr cache.Store`.

**Parameters:**
- **camelCase**, short in narrow scopes, descriptive in exported functions.
- **Single-letter convention**: the smaller the scope, the shorter the name.
  - **Receivers**: always single letter, first letter of type. `(s *Server)`, `(c *Client)`.
  - **Loop variables**: `for i, r := range records` — `i` for index, single letter for element.
  - **Short-function params**: 1–2 letters acceptable when the function body fits on screen.
  - **Longer scopes** (>20 lines): use descriptive names (`cacheKey`, `verifiedDNSKEYs`).
- **No Hungarian notation**: no `iCount`, `strName`, `bEnabled`, `pConn`.
  When renaming receivers with global regex, check for local vars / params / loop vars that share the target name first — rename those, then the receiver. `go build` immediately after; the compiler catches what regex misses.

**Const / Var:**
- **No `UPPER_SNAKE_CASE`**: Go uses PascalCase or camelCase for all identifiers. `DefaultDNSPort`, not `DEFAULT_DNS_PORT`.
- **Sentinel errors**: `ErrXxx` for exported (`ErrCIDRFilterRefused`), `errXxx` for unexported (`errEmptyTag`).

**Function/method naming:**
- **No `Get` prefix on getters**: `RemainingTTL()` not `GetRemainingTTL()`. Plain noun for accessors.
- **Constructors use `New` / `NewXxx`**: not `Build`, `Create`, `Init`, `Make`. Exception: `BuildXxx` for building derived values (strings, byte slices), not type instances.
- **Boolean predicates use assertion prefixes**: `IsXxx`, `HasXxx`, `CanXxx`, `ShouldXxx`. `ValidateXxx` returning only `bool` → rename to `IsXxxValid`.
- **Conversion methods**: `ToXxx()` not `AsXxx()` or `IntoXxx()`.
- **Package-level functions over empty structs**: `type Foo struct{}` with methods → convert to functions.

**Type naming:**
- **Avoid stutter with package name**: `cache.CacheEntry` → `cache.Entry`, `cidr.CIDRMatchInfo` → `cidr.MatchInfo`.  
  **Idiomatic exceptions** (allowed): `server.Server`, `http.Server`, `handler.Handler`, `resolver.Resolver` — when the package is named after the primary type it exports.
- **Unexported types also avoid stutter**: `cidr.cidrRule` → `cidr.rule`.
- **Conversion helpers use `as` prefix**: `asIPv4Net` (converts `*net.IPNet` → `*ipv4Net`). Not `toXxx`.

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
- Stats persistence key: `config.StatsPersistKey = "stats:"`.
- **Code is canonical**: docs and comments must match the actual constant values. Verify, don't assume.
- **RFC 9077/9156 defaults**: `DefaultMaxNegativeTTL = 10800`, `DefaultQnameMinimiseCount = 10`, `DefaultMinimiseOneLabel = 4`.

### Constructors

- **Use `New` / `NewXxx`**: not `Build`, `Create`, `Init`, `Make`. Exception: `BuildXxx` for derived values (strings, byte slices), not type instances.
- **Return concrete types, accept interfaces**: `func New() *MemoryCache` (concrete), but parameters accept interfaces: `func Persist(store PersistStore)`.
- **Group related params into config structs** when a constructor exceeds ~5 parameters. Use a `BackgroundConfig` or `Dependencies` struct rather than functional options unless options are truly optional.
- **Two-phase initialization** is acceptable for circular dependencies: `New()` creates the object, `SetResolver()` / `SetProber()` inject dependencies that could not exist at construction time. Document the required call order.
- **Package-level constructors with `sync.Once`**: infrastructure objects that must be a singleton (like `infraProber`) use `sync.Once` inside the constructor so it is safe to call multiple times.

### Interfaces

- **Define interfaces in the consumer package**, not the producer. Example: `handler.LatencyProber` is defined in `server/handler`, satisfied implicitly by `*server/latency.Prober`.
- **Keep interfaces small**: `PersistStore` has 2 methods, `LatencyProber` has 1. Split large interfaces (`cache.Store` has 6 — acceptable for the cache abstraction, but only because consumers use the subset they need via Go's implicit satisfaction).
- **Use `any` not `interface{}`**: Go 1.18+.

### File Organization

- **One file per logical concern** within a package. Split when a file exceeds ~500 lines.
- **Message vs processing split**: `handler.go` (query pipeline) + `handler_cache.go` (cache hit/miss/refresh) + `message.go` (EDNS/response helpers).
- **Main vs nsec split**: `dnssec_crypto.go` (RRSIG/DNSKEY/DS validation) + `dnssec_nsec.go` (NSEC/NSEC3 denial-of-existence, including `nsec3HashName` + `isDenialOfExistenceValid`).
- **Protocol split**: `socks5.go` (types, handshake, shared helpers) + `socks5_tcp.go` (TCP CONNECT) + `socks5_udp.go` (UDP ASSOCIATE + PacketConn wrapper).
- **Config split**: `config.go` (types, loading, defaults, DDR/Chaos) + `config_validate.go` (all validation functions).
- **Do NOT split** when the split would require exporting internal helpers or when the split crosses 2–3 tightly coupled concerns (a 400-line file is fine).

### Concurrency

- **Pointer receivers** for any struct containing `sync.Mutex`, `sync.RWMutex`, or `atomic.*` fields.
- **`sync.Pool.Put()` zeroes state**: never read fields from an object after `Put()` — the next `Get()` caller owns it. No linter catches this.
- **Package-level mutable state** must use `sync.Once` or `atomic.Pointer` if read concurrently. Example: `var infraProber *ilatency.Prober` + `var infraProberOnce sync.Once`.
- **`context.Context` propagation**: every goroutine must receive a context for cancellation. Use `errgroup` for managing groups of goroutines with shared lifecycle.

### Anti-patterns (DO NOT introduce)
- **No rate limiting** — accept all queries unconditionally.
- **No per-IP connection limiting** — all listeners accept unlimited connections.
- **No DNSCrypt** — removed; do not reintroduce.
- **No domain↔domain imports** (except `edns→config`) — domain packages must be independent.
- **No `internal/`→domain imports** (except `internal/latency→config`) — internal layer stays below domain layer.
- **No `server/` sub-package importing `server/` parent** — sub-packages are leaves below the wiring layer.
- **No `Get` prefix** on accessors — `RemainingTTL()` not `GetRemainingTTL()`.
- **No `Mgr`/`Manager`/`Handler` suffixes** on field or variable names.
- **No Hungarian notation** (`iCount`, `strName`, `bEnabled`, `pConn`).
- **No `snake_case` or `UPPER_SNAKE_CASE`** identifiers — use PascalCase/camelCase.
- **No `Create`/`Build`/`Init`/`Make`** constructors — use `New`/`NewXxx`.
- **No `ValidateXxx` returning only `bool`** — use `IsXxxValid`.
- **No `Default` prefix on types or methods** — reserved for value constants.
- **No `As`/`Into` conversion prefixes** — use `To` or package-level `asXxx` helpers.
- **No `interface{}`** — use `any` (Go 1.18+).
- **No copying of `sync.Mutex`/`atomic.*` values** — always use pointer receivers.
- **No `init()` with side effects** beyond `gob.Register` / driver registration.
- **No importing `edns` from `cache`** — cache uses `config.ECSOption` directly.

## Architecture

ZJDNS is a high-performance recursive DNS server supporting DoT, DoQ, DoH, DoH3.

### Project Structure

```
zjdns/
├── cmd/zjdns/                     ← main.go, banner.go, version.go, bench_test.go (binary)
├── config/                        ← ECSConfig, ECSOption, defaults, validation
├── edns/                          ← Handler, Cookie, EDE, padding (ECSOption alias → config)
├── cache/                         ← Store interface, SQLite relational cache (entries + records + stats tables)
├── cidr/                          ← IP filtering with tag matching
├── rewrite/                       ← Query rewrite rules
├── stats/                         ← Lock-free atomic collector (PersistStore interface)
├── internal/
│   ├── cli/                       ← Flag parsing, example config generation
│   ├── log/                       ← Structured logging + IsDebug guard (zero internal deps)
│   ├── pool/                      ← sync.Pool allocators + QUIC error codes
│   ├── ttl/                       ← Stateless TTL functions (cache + rewrite)
│   ├── dnsutil/                   ← DNS utilities: validation, PTR, panic recovery
│   ├── ipdetect/                  ← Public IP auto-detection
│   └── latency/                   ← Unified probe engine (generic sorter)
└── server/
    ├── server.go                  ← Lifecycle, wiring, listeners
    ├── listen.go                  ← Protocol bridge (UDP/TCP dispatch → io.Copy)
    ├── server_tasks.go            ← Background tasks, shutdown
    ├── handler/                   ← Query pipeline (handler + handler_cache + message)
    ├── client/                    ← Outbound transports (UDP/TCP/DoT/DoQ/DoH/DoH3/SOCKS5)
    ├── client/pool/               ← RFC 7766 pipelined TCP + QUIC connection pools
    ├── resolver/                  ← Upstream + recursive + qname_minimise (RFC 9156)
    │                              ←   recursive.go (core loop) + recursive_helpers.go (7 helpers)
    │                              ←   dnssec_chain.go + nameserver.go + upstream.go + resolver.go
    ├── security/                  ← DNSSEC validation (crypto + nsec) + hijack detection
    ├── tls/                       ← TLS listeners (DoT, DoQ, DoH, DoH3)
    └── probe/                     ← A/AAAA latency probing and record reordering
```

### Import Rules (strict layering, no cycles)

```
Foundation (zero zjdns imports):
  internal/log, internal/pool, internal/ipdetect

Layer 1 (import only foundation):
  internal/dnsutil → log

Layer 2 (import domain foundation):
  config → dnsutil, log              (ECS types live here; edns aliases config.ECSOption)
  internal/latency → config, dnsutil, log

Layer 3 (domain packages — import config + internal/*, never each other):
  edns → config, ipdetect, log, pool        (only domain→domain edge allowed)
  cache → config, dnsutil, log              (no longer imports edns — uses config.ECSOption)
  cidr → config, dnsutil, log
  rewrite → config, dnsutil, log
  stats → config, log                       (PersistStore interface — no cache dependency)

Layer 4 (server sub-packages — import domain + internal, never server/ parent):
  server/security → cache, config, dnsutil, log
  server/client → config, edns, dnsutil, log, pool
  server/client/pool → config, dnsutil, log, pool
  server/probe → config, edns, dnsutil, internal/latency, log
  server/resolver → cache, config, edns, dnsutil, log, pool, server/client, server/security
  server/tls → config, dnsutil, log, pool
  server/handler → cache, config, edns, dnsutil, log, pool, rewrite, server/resolver, stats

Top layer (wiring):
  server → all domain + all server sub-packages
  cmd/zjdns → internal/cli, config, log, server
```

**Key rules:**
- Domain packages never import other domain packages (sole exception: `edns→config`).
- `internal/` packages never import domain packages (except `internal/latency→config`, which is stable because config is foundational).
- `server/` sub-packages never import the `server/` parent.
- No circular dependencies — the graph is a DAG enforced by the compiler.

### Query Pipeline (`server/handler/handler.go:processDNSQuery`)
1. Request validation (domain/label length, ANY/AXFR/IXFR rejection)
2. `rewrite.Evaluator.Evaluate()` — synthetic response if rule matches
3. `edns.Handler` — extract ECS, DNS Cookie
4. Early DNS Cookie validation (RFC 7873) — invalid cookie → BADCOOKIE
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
- FORMERR from authoritative → automatic EDNS-free retry (RFC 6891 §6.2.2)

### Recursive Resolution (`server/resolver/recursive.go`)
- Root hints → TLD NS → authoritative NS walk
- QNAME minimisation (RFC 9156): each delegation level queries only one label past the current zone
- Minimisation QTYPE=A (hides original QTYPE); DS/NSEC/NSEC3 use original QTYPE
- DefaultMaxQnameMinimiseCount=10 steps before full QNAME exposure
- NS address latency-sorted cache (ICMP/TCP/UDP probes) via unified engine
- DNSSEC chain-of-trust at each delegation: parent DNSKEY → DS RRSIG → child DNSKEY → answer RRSIG
- Zone cut detection, lame delegation detection, glue record validation
- `dsPresentButUnverified` flag distinguishes bogus delegation from true insecure

### Connection Pools (`server/client/pool/`)
- **TCP/DoT** (RFC 7766): Per-upstream multiplexed connections, out-of-order response matching by DNS message ID, fallback to single-shot on failure. `Pool.Acquire` delegates dial to `dialAndAdd`/`replaceDead` helpers.
- **DoQ**: QUIC native stream multiplexing, up to 4 connections per upstream
- Server-side DoT: reader→worker→writer three-stage pipeline

## Key Types

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig` | `config` | Top-level config (LoadConfig); owns `ECSConfig` + `ECSOption` |
| `ECSConfig` | `config` | User-facing ECS subnet configuration (moved from edns) |
| `ECSOption` | `config` | Parsed EDNS Client Subnet (edns has type alias: `type ECSOption = config.ECSOption`) |
| `Handler` | `edns` | EDNS option parsing/construction, ECS, Cookie, EDE, Padding |
| `Store` | `cache` | Interface: Get(qname,qtype,qclass,ecs,dnssecOK), Set(params+RRs), UpdateLatency, ReverseLookup, Close |
| `Entry` | `cache` | Cached DNS response: Answer/Authority/Additional ([]dns.RR), Timestamp, TTL, Validated |
| `Collector` | `stats` | Lock-free atomic metrics; uses `PersistStore` interface (no cache dependency) |
| `PersistStore` | `stats` | Interface: SaveStats(key, data, ttl), LoadStats(key) ([]byte, bool) |
| `Server` | `server` | Core lifecycle, wiring, background tasks |
| `Handler` | `server/handler` | DNS query processing pipeline; owns `BackgroundConfig`, `LatencyProber` |
| `BackgroundConfig` | `server/handler` | Groups RefreshGroup/RefreshCtx/Ctx lifecycle params |
| `LatencyProber` | `server/handler` | Interface: Start(qname, qtype, answer, ...) — latency-probes A/AAAA records and updates latency_ms |
| `Server` | `server/tls` | TLS listeners (DoT, DoQ, DoH, DoH3) |
| `Client` | `server/client` | Outbound queries (UDP/TCP/DoT/DoQ/DoH/DoH3/SOCKS5) |
| `SOCKS5Dialer` | `server/client` | SOCKS5 proxy (RFC 1928/1929, TCP CONNECT + UDP ASSOCIATE) |
| `Conn` / `Pool` | `server/client/pool` | RFC 7766 pipelined TCP/DoT |
| `QUICPool` / `QUICConn` | `server/client/pool` | QUIC connection pool |
| `Resolver` | `server/resolver` | Upstream + recursive resolution |
| `Recursive` | `server/resolver` | Built-in recursive walk |
| `CryptoValidator` | `server/security` | DNSSEC chain-of-trust (RRSIG, DS, trust anchors); NSEC/NSEC3 in `dnssec_nsec.go` |
| `Guard` | `server/security` | Bundles CryptoValidator + Detector |
| `Filter` | `cidr` | CIDR-based IP matching; `MatchInfo` + unexported `rule` types |
| `Prober` | `internal/latency` | Unified probe engine (generic sorter) |
| `Prober` | `server/probe` | A/AAAA latency probe + record reordering; `infraProber` (sync.Once) |
| `MessagePool` / `BufferPool` | `internal/pool` | sync.Pool allocators; also holds `QUICCode*` constants |
| `JoinDNSPort` | `internal/dnsutil` | Utility: `ip` → `ip:53` (moved from config) |

## Logging

All logs use `zjdns/internal/log`. Default level: `info`.

**Component filtering**: `log_level` supports `level:comp1,comp2` syntax (e.g. `"debug:UPSTREAM,RECURSION"`). Messages without a `PREFIX: ` pattern always pass through.

**18 canonical prefixes**: `TLS`, `CACHE`, `UPSTREAM`, `SERVER`, `EDNS`, `RECURSION`, `SECURITY`, `TCPPOOL`, `LATENCY`, `STATS`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PTR`, `PANIC`.

Prefix matches logical component, not Go package. `HIJACK:`/`DNSSEC:` merged → `SECURITY:`. `DOT:`/`DOQ:`/`DOH:` merged → `TLS:`. Hot-path logs are `Debug` only.

## Notable Design Decisions

- **Cache (SQLite relational store)**: All DNS responses, NS latency data, DNSKEYs, and PTR mappings share three SQLite tables — no in-memory Go map, no gob encoding. WAL mode + mmap for hot-data-in-memory performance. TTL floor 10s. Negative response TTL capped per RFC 9077. `modernc.org/sqlite` (pure Go, no CGo). See [DB Schema](#db-schema) below.
- **Global TTL manager** (`internal/ttl`): Stateless TTL functions used by both cache (`Entry` methods delegate) and rewrite (`DeductElapsedCyclical`). Stale TTL uses cyclical countdown (`staleTTL - (timeSinceExpiry % staleTTL)`) — resets every staleTTL window giving background refresh repeated chances. Fresh per-RR TTL uses `isElapsed=false, value=responseTTL` for stale (direct assignment) and `isElapsed=true, value=actual_elapsed` for fresh (subtraction).
- **EDNS buffer sizing**: Dual-size strategy — standard upstream queries use 1232 bytes (DNS Flag Day 2020) while recursive (root/TLD) queries use 4096 bytes (`RecursiveUDPBufferSize`) to avoid UDP truncation on DNSSEC-signed root zone referrals (~1400 bytes). Applied in `queryNameserversConcurrent` after `buildMsg` and in `probeTLDForHijack`.
- **Per-interface binding** (`internal/dnsutil/bind.go`): All listeners (UDP, TCP, DoT, DoQ, DoH, DoH3, pprof) bind per-interface IP instead of wildcard. `TryBind` pre-checks each address; unavailable ones are skipped with a WARN log. When another process occupies a port on a specific interface (e.g. warp-svc on 100.96.0.21:53), ZJDNS binds to remaining free IPs without conflict.
- **TCP fallback guard**: `needsTCPFallback` now skips TCP retry when the context is already cancelled (errgroup first-win pattern), eliminating misleading "UDP truncated/failed → TCP fallback → operation was canceled" log chains.
- **QNAME minimisation (RFC 9156)**: Enabled by default for all recursive resolutions at depth 0. Internal infrastructure queries (NS address resolution) use full QNAME. Minimisation steps tracked per-resolution; after DefaultQnameMinimiseCount (10) steps, all remaining labels are exposed. QTYPE=A is used to hide original QTYPE except for DS/NSEC/NSEC3 parent-side types. When a minimised query returns answer records whose owner names don't match the original QNAME (CNAME for the minimised name, not the target), the resolver retries with the full QNAME per RFC 9156 §2.3.
- **Pool discipline**: `MessagePool.Put()` zeroes the struct — never read fields after `Put()`. Double-zeroing removed: `Put` zeroes, `Get` trusts.
- **KTLS**: `gitlab.com/go-extension/tls` with `KernelTX`/`KernelRX` (both default `false`, opt-in). Dual configs: eTLS for TCP, crypto/tls for QUIC. Silent fallback on non-Linux.
- **SOCKS5**: Per-upstream optional proxy. TCP CONNECT (`socks5_tcp.go`) + UDP ASSOCIATE (`socks5_udp.go`). `SafeURL()` redacts passwords. Shared handshake/auth/helpers in `socks5.go`.
- **DNSSEC**: IANA root KSK trust anchors (key tags 20326 + 38696). `dnssec_enforce: true` → SERVFAIL on bogus; `false` → pass through without AD.
- **EDE propagation**: DNSSEC EDE codes stored atomically on `Recursive.lastDNSSECEDECode`, read by `processQueryError` to avoid error-chain corruption from context cancellation.
- **HandlePanic**: Recovers per-goroutine — a single connection panic terminates only that goroutine, not the server.
- **Config self-sufficiency**: `ProjectName`/`Version` are package-level vars set by `main.go` before `LoadConfig()`.
- **Rewite TTL**: Rewrite rules pre-build RRs at `LoadRules()` time. The evaluator tracks `loadedAt`; the handler applies `ttl.DeductElapsedCyclical()` so each RR's TTL cycles independently (`origTTL - (elapsed % origTTL)`) rather than staying static. Rewrite responses bypass cache (client-IP filtering), but TTL now decrements correctly.
- **ECS types in config**: Both `ECSConfig` and `ECSOption` live in `config`. `edns` has a type alias (`type ECSOption = config.ECSOption`) for backward compatibility within the edns package. This breaks the `config→edns` import (config no longer imports edns).
- **stats PersistStore**: stats defines a local interface (`SaveStats`/`LoadStats` with raw `[]byte`) and does not import cache. `server.go`'s `statsPersistAdapter` wraps `SQLiteCache.SaveStats/LoadStats` which write directly to a `stats` table.
- **QUIC codes in internal/pool**: `QUICCodeNoError`/`InternalError`/`ProtocolError` live in `internal/pool` so both `server/client/pool` and `server/tls` can reference them without cross-dependency.
- **JoinDNSPort in dnsutil**: Moved from `config` to `internal/dnsutil` — a general-purpose utility should not live in the config package.
- **eTLS alias**: Always use `eTLS` (not `cryptotls`) for `gitlab.com/go-extension/tls`. Used in `server/tls`, `server/client`, `config`.
- **Error wrapping**: Always use `%w` in `fmt.Errorf` when wrapping errors that callers may check with `errors.Is`/`errors.As`. Use `%v` only for informational logging.

## DB Schema

The cache uses three SQLite tables (`modernc.org/sqlite`, WAL mode, mmap):

```sql
-- One row per cached DNS query. Uniqueness: (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok).
CREATE TABLE entries (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    qname      TEXT NOT NULL,       -- normalized FQDN (dnsutil.NormalizeDomain)
    qtype      INTEGER NOT NULL,    -- dns.TypeA=1, DNSKEY=48, TypeNone=0 (NS latency sentinel)
    qclass     INTEGER NOT NULL DEFAULT 1,
    ecs_addr   TEXT NOT NULL DEFAULT '',
    ecs_prefix INTEGER NOT NULL DEFAULT 0,
    dnssec_ok  INTEGER NOT NULL DEFAULT 0,
    timestamp  INTEGER NOT NULL,    -- insertion time (unix seconds)
    ttl        INTEGER NOT NULL,    -- entry TTL (min of all RR TTLs, floor 10s)
    validated  INTEGER NOT NULL DEFAULT 0
);

-- One row per DNS RR within an entry. DELETE CASCADE when entry is evicted/expired.
CREATE TABLE records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    section    TEXT NOT NULL,       -- 'answer', 'authority', 'additional'
    seq        INTEGER NOT NULL DEFAULT 0,
    name       TEXT NOT NULL,
    rtype      INTEGER NOT NULL,
    ttl        INTEGER NOT NULL,    -- original RR TTL
    rr_text    TEXT NOT NULL,       -- full presentation format (dns.New(rr_text) reconstructs RR)
    rdata_ip   TEXT,                -- A/AAAA IP for PTR reverse lookup
    latency_ms INTEGER              -- NULL = not probed; non-NULL = measured latency
);

-- Stats snapshots (JSON). Written periodically and on shutdown.
CREATE TABLE stats (
    key       TEXT PRIMARY KEY,     -- "stats:"
    data      BLOB NOT NULL,        -- JSON
    ttl       INTEGER NOT NULL,
    timestamp INTEGER NOT NULL
);
```

**Key patterns**:
- **DNS response cache**: `qtype` = original query type, records in original order
- **NS latency cache**: `qtype` = `dns.TypeNone` (0), A/AAAA records with `latency_ms` populated by probe engine. `loadRecords` orders by `latency_ms IS NULL, latency_ms ASC` so probed records sort fastest-first.
- **DNSKEY cache**: `qtype` = `dns.TypeDNSKEY`, validated=1
- **PTR reverse lookup**: `SELECT DISTINCT name FROM records r JOIN entries e ON r.entry_id = e.id WHERE r.rdata_ip = ? AND e.timestamp + e.ttl > unixepoch()`
- **Eviction**: size-based (oldest `timestamp` first) on Set; TTL-based periodic cleanup (5 min sweep)
- **Probe updates**: `UPDATE records SET latency_ms = ? WHERE entry_id = ? AND rdata_ip = ?` — no entry overwrite needed

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
      "cache": { "max_entries": 0 }
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

**QNAME minimisation CNAME corner case (RFC 9156 §2.3):**
```bash
# home.console.aliyun.com has a deep CNAME chain. The minimised query
# 'console.aliyun.com. A' returns a CNAME for console.aliyun.com — NOT
# home.console.aliyun.com. The resolver must detect the owner-name
# mismatch, retry with the full QNAME, then follow the full CNAME chain.
# Should return NOERROR with 15 answer records covering all CNAME hops.
dig @127.0.0.1 -p 15353 home.console.aliyun.com A
```

Verify hijack detection from logs: `grep -E "hijack probe detected|hijack detected|rejecting hijacked|tcp=true" /tmp/zjdns.log`
Normal domains should show `tcp=false` throughout; blocked domains should show hijack detection + `tcp=true` restart.

## KTLS Tuning

If `"local error: tls: bad record MAC"` appears, disable kernel RX offload:

```json
{ "server": { "tls": { "ktls": { "kernel_rx": false } } } }
```

Both `kernel_tx` and `kernel_rx` default to `false` (KTLS is opt-in).


