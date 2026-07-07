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
10. Run `golangci-lint run && golangci-lint fmt` before committing. Zero warnings required.
    - No global linter excludes — all suppressions are inline `//nolint:NAME // reason`
    - Every nolint comment must include the linter name and a concrete reason
    - Formatter: `gofumpt` (stricter gofmt) — imports sorted alphabetically, no blank-line groups
11. Don't waste time wrestling with indentation or formatting issues when editing
    files (e.g. tab vs space mismatches in the Edit tool). Focus on the code
    logic — `golangci-lint fmt` will fix formatting. Use `sed` or `python3`
    freely when the Edit tool struggles with whitespace.

## Build & Test

```bash
# Build
go build -o zjdns ./cmd/zjdns

# Build with version info
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns

# Cross-compile (pure Go, no CGo required)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o zjdns ./cmd/zjdns

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

# Docker
docker build -t zjdns .

# Analyze cache database (aligned columnar output like sqlite3)
./zjdns -analyze cache.db "SELECT e.qname, e.rcode, e.hit_udp FROM entries e"

# Install pre-commit hook (auto fmt + lint on commit)
sh scripts/install-hook.sh                 # Linux / macOS
pwsh scripts/install-hook.ps1              # Windows PowerShell
```

Module path: `zjdns` (Go 1.26.4, pure Go — `CGO_ENABLED=0` compatible). Zero `golangci-lint` warnings required.

Key dependencies: `codeberg.org/miekg/dns` (DNS protocol), `github.com/quic-go/quic-go` (QUIC/DoQ/DoH3), `gitlab.com/go-extension/tls` (eTLS — crypto/tls fork with KTLS), `github.com/ncruces/go-sqlite3` (pure-Go SQLite, WASM-based).

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
- **`log.NowUnix()` / `log.NowUnixNano()`** instead of `time.Now()` in cache TTL checks, DNSSEC RRSIG validation, last-access timestamps. `log.TimeCache` updates once per second via `atomic.Int64` (zero-alloc).
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
- **Code is canonical**: docs and comments must match the actual constant values. Verify, don't assume.
- **RFC 9077/9156 defaults**: `DefaultMaxNegativeTTL = 10800`, `DefaultQnameMinimiseCount = 10`, `DefaultMinimiseOneLabel = 4`.

### Constructors

- **Use `New` / `NewXxx`**: not `Build`, `Create`, `Init`, `Make`. Exception: `BuildXxx` for derived values (strings, byte slices), not type instances.
- **Return concrete types, accept interfaces**: `func NewSQLiteCache() *SQLiteCache` (concrete), but parameters accept interfaces: `func Persist(store cache.Store)`.
- **Group related params into config structs** when a constructor exceeds ~5 parameters. Use a `BackgroundConfig` or `Dependencies` struct rather than functional options unless options are truly optional.
- **Two-phase initialization** is acceptable for circular dependencies: `New()` creates the object, `SetResolver()` / `SetProber()` inject dependencies that could not exist at construction time. Document the required call order.
- **Package-level constructors with `sync.Once`**: infrastructure objects that must be a singleton use `sync.Once` inside the constructor so it is safe to call multiple times.

### Interfaces

- **Define interfaces in the consumer package**, not the producer. Example: `handler.LatencyProber` is defined in `server/handler`, satisfied implicitly by `*server/latency.Prober`.
- **Use `any` not `interface{}`**: Go 1.18+.

### File Organization

- **One file per logical concern** within a package. Split when a file exceeds ~500 lines.
- **Message vs processing split**: `handler.go` (query pipeline) + `handler_cache.go` (cache hit/miss/refresh) + `message.go` (EDNS/response helpers).
- **Main vs nsec split**: `dnssec_crypto.go` (RRSIG/DNSKEY/DS validation) + `dnssec_nsec.go` (NSEC/NSEC3 denial-of-existence, including `nsec3HashName` + `isDenialOfExistenceValid`).
- **Protocol split**: `socks5.go` (types, handshake, shared helpers) + `socks5_tcp.go` (TCP CONNECT) + `socks5_udp.go` (UDP ASSOCIATE + PacketConn wrapper).
- **Config split**: `config.go` (types, loading, defaults, DDR/Chaos) + `config_validate.go` (all validation functions).
- **Do NOT split** when the split would require exporting internal helpers or when the split crosses 2–3 tightly coupled concerns (a 400-line file is fine).

### File-Level Declaration Order

All Go source files follow a fixed declaration order. Since Go allows forward
references within a package, declarations are ordered by category, not by
dependency:

```
type    (exported first, then unexported)
const   (exported first, then unexported)
var     (exported first, then unexported)
func    (exported first, then unexported, methods grouped by receiver)
```

Within `func`: constructors (`New*`) immediately follow their type, exported
methods before unexported, methods grouped by receiver type.  Package-level
functions come after all methods.

`init()` is placed right after the `var` block it initializes.

### Concurrency

- **Pointer receivers** for any struct containing `sync.Mutex`, `sync.RWMutex`, or `atomic.*` fields.
- **`sync.Pool.Put()` zeroes state**: never read fields from an object after `Put()` — the next `Get()` caller owns it. No linter catches this.
- **Package-level mutable state** must use `sync.Once` or `atomic.Pointer` if read concurrently.
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
- **No importing `edns` from `cache`** — cache uses `config.ECSOption` directly.

## Architecture

ZJDNS is a high-performance recursive DNS server supporting DoT, DoQ, DoH, DoH3.

### Project Structure

```
zjdns/
├── cmd/zjdns/                     ← main.go, banner.go, version.go, bench_test.go (binary)
├── config/                        ← ECSConfig, ECSOption, defaults, validation
├── edns/                          ← Handler, Cookie, EDE, padding (ECSOption alias → config)
├── cache/                         ← Store interface, SQLite relational cache (entries + request_log + stats_meta + ip_latency + ptr_map tables)
├── cidr/                          ← IP filtering with tag matching
├── rewrite/                       ← Query rewrite rules
├── internal/
│   ├── cli/                       ← Flag parsing (example config moved to config.GenerateExampleConfig)
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
    ├── handler/                   ← Query pipeline (handler + handler_cache + message + pending)
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
  cache → config, dnsutil, log, pool
  cidr → config, dnsutil, log
  rewrite → config, dnsutil, log

Layer 4 (server sub-packages — import domain + internal, never server/ parent):
  server/security → cache, config, dnsutil, log
  server/client → config, edns, dnsutil, log, pool
  server/client/pool → config, dnsutil, log, pool
  server/probe → config, edns, dnsutil, internal/latency, log
  server/resolver → cache, config, edns, dnsutil, log, pool, server/client, server/security
  server/tls → config, dnsutil, log, pool
  server/handler → cache, config, edns, dnsutil, log, pool, rewrite, server/resolver

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
4. Early DNS Cookie validation (RFC 7873) — initial handshake (empty ServerCookie) allowed; short (1–15 bytes) → BADCOOKIE; 16 bytes → cryptographic validation
5. `cache.Store.Get()` — hit → serve (with CIDR filtering); miss → resolve
6. **Pending request dedup** (`pending.go`): Same-key concurrent queries coalesce — only the first reaches the resolver; followers block and receive the identical result. Closes the cache-poisoning race window.
7. `Resolver.Query()` — upstream (first-win) or recursive
8. `Guard` — DNSSEC validation + hijack detection (UDP→TCP fallback)
9. `cidr.Filter.MatchIP()` — filter A/AAAA; all filtered → REFUSED + EDE
10. Cache population, latency probes, response with server cookie

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
| `Store` | `cache` | Interface: Get/Set/RecordHit/UpdateLatency/GetLatencyLastProbe/ReverseLookup/Close | `SetOptions` carries per-entry metadata |
| `Entry` | `cache` | Cached DNS response: Answer/Authority/Additional ([]dns.RR), Timestamp, TTL, Validated |
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
| `QueryResult` | `server/resolver` | Unified result struct (Answer, Authority, Additional, Validated, ECS, Server, Fallback, Hijack, Err) — used throughout the resolver layer; `queryUpstream`, `Recursive.resolve`, and `CNAME.resolve` all return it by value |
| `Recursive` | `server/resolver` | Built-in recursive walk |
| `CryptoValidator` | `server/security` | DNSSEC chain-of-trust (RRSIG, DS, trust anchors); NSEC/NSEC3 in `dnssec_nsec.go` |
| `Guard` | `server/security` | Bundles CryptoValidator + Detector |
| `Filter` | `cidr` | CIDR-based IP matching; `MatchInfo` + unexported `rule` types |
| `Prober` | `internal/latency` | Unified probe engine (generic sorter) |
| `Prober` | `server/probe` | A/AAAA latency probe + record reordering + ProbeNSAddrs for NS/Root |
| `PendingRequests` | `server/handler` | Singleflight dedup: coalesces concurrent identical queries; leader sends upstream, followers wait for shared result |
| `MessagePool` / `BufferPool` | `internal/pool` | sync.Pool allocators; also holds `QUICCode*` constants |
| `JoinDNSPort` | `internal/dnsutil` | Utility: `ip` → `ip:53` (moved from config) |

## Logging

All logs use `zjdns/internal/log`. Default level: `info`.

**Component filtering**: `log_level` supports `level:comp1,comp2` syntax (e.g. `"debug:UPSTREAM,RECURSION"`). Messages without a `PREFIX: ` pattern always pass through.

**18 canonical prefixes**: `TLS`, `CACHE`, `UPSTREAM`, `SERVER`, `EDNS`, `RECURSION`, `SECURITY`, `TCPPOOL`, `LATENCY`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PTR`, `PANIC`.

Prefix matches logical component, not Go package. `HIJACK:`/`DNSSEC:` merged → `SECURITY:`. `DOT:`/`DOQ:`/`DOH:` merged → `TLS:`. Hot-path logs are `Debug` only.

## Notable Design Decisions

- **Cache (SQLite relational store)**: All DNS responses, NS latency data, DNSKEYs, and PTR mappings share six SQLite tables — no in-memory Go map, no gob encoding. WAL mode + mmap (16MB default) for hot-data-in-memory performance; `page_size=4096` matches OS page size. `journal_size_limit=mmap_size` caps WAL growth; `wal_autocheckpoint=4096` triggers passive checkpoint at 16MB. `synchronous=NORMAL` avoids fsync on every write. `ANALYZE` at migration populates `sqlite_stat1` for query planner; `PRAGMA optimize` runs on eviction + `Close()` to refresh statistics periodically (mostly a no-op, only runs `ANALYZE` when stats are stale). `msg_wire` BLOB stores zstd-compressed `dns.Msg` wire format; `Get()` decompresses + `Unpack()` in a single step (~0.5ms cache hits). TTL floor 10s. Negative response TTL capped per RFC 9077. `github.com/ncruces/go-sqlite3` (pure Go, no CGo, WASM-based) with `_txlock=immediate` and 4-connection pool. See [DB Schema](#db-schema) below.
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
- **Rewrite TTL + DynamicContent**: Rewrite rules pre-build RRs at `LoadRules()` time. The evaluator tracks `loadedAt`; the handler applies `ttl.DeductElapsedCyclical()` so each RR's TTL cycles independently (`origTTL - (elapsed % origTTL)`) rather than staying static. `DynamicContent func() []string` field (json:"-") on `RewriteRule` bypasses pre-building — each returned string becomes a separate TXT RR, called at query time for dynamic responses (`zjdns.stats` and `zjdns.db.{clear,clear.cache,clear.stats,clear.latency}` CH TXT). Destructive rules (`db.clear*`) are loopback-only via `IncludeClients`. Rewrite responses bypass cache (client-IP filtering).
- **ECS types in config**: Both `ECSConfig` and `ECSOption` live in `config`. `edns` has a type alias (`type ECSOption = config.ECSOption`) for backward compatibility within the edns package. This breaks the `config→edns` import (config no longer imports edns). Similarly, `handler.Question` is a type alias of `resolver.Question` to avoid duplicate struct definitions.
- **request_log ring buffer**: Append-only request journal replaces the old `hit_counters` table. `RecordRequest()` does a single INSERT — no conflict detection, no read-before-write. Stats are aggregated via SQL over rows with `id > cleared_before`; FlushDB("stats") resets the threshold without touching log rows.
- **Prepared statements in hot path**: `SQLiteCache` pre-compiles hot-path SQL statements (`stmtGetEntry`, `stmtInsertLog`, `stmtInsertLatency`, `stmtGetLastProbe`) at initialization time to avoid per-call SQL compilation overhead.
- **Example config in config package**: `GenerateExampleConfig()` lives in `config` package (not `internal/cli`) to keep `internal/` layer free of domain imports.
- **QUIC codes in internal/pool**: `QUICCodeNoError`/`InternalError`/`ProtocolError` live in `internal/pool` so both `server/client/pool` and `server/tls` can reference them without cross-dependency.
- **JoinDNSPort in dnsutil**: Moved from `config` to `internal/dnsutil` — a general-purpose utility should not live in the config package.
- **eTLS alias**: Always use `eTLS` (not `cryptotls`) for `gitlab.com/go-extension/tls`. Used in `server/tls`, `server/client`, `config`.
- **Error wrapping**: Always use `%w` in `fmt.Errorf` when wrapping errors that callers may check with `errors.Is`/`errors.As`. Use `%v` only for informational logging.
- **Protocol logging**: The `protocol` column in request_log stores the transport identifier as a string (`udp`/`tcp`/`dot`/`doq`/`doh`/`doh3`), enabling simple GROUP BY queries for protocol-level analytics.
- **Handler Question alias**: `handler.Question` is a type alias (`type Question = resolver.Question`), eliminating redundant struct conversions between handler and resolver layers.
- **RecordRequest hot-path**: `RecordRequest()` does a single append-only INSERT — no transaction, no writeMu, no conflict resolution.
- **ip_latency independence**: Latency data is not tied to cache entries — all domains sharing the same IP reuse the same row. Rows with `last_probe_time` older than `DefaultStaleMaxAge` (30 days) are cleaned up during eviction alongside stale cache entries.
- **Zero-allocation label validation**: `IsValidDomainLabels` uses `strings.IndexByte` scanning instead of `strings.Split` to avoid per-query allocation on the hot path.
- **processRR fast path**: When `value == 0 && !isElapsed && includeDNSSEC`, `processRR` returns the original RR without cloning — common on cache-miss serve paths (50+ allocs saved per response).
- **Pending request deduplication** (`server/handler/pending.go`): `singleflight`-style coalescing of concurrent identical cache misses. Key mirrors the cache lookup key (qname + qtype + qclass + ECS + DNSSEC). Leaders send the upstream query; followers block on a channel until the leader completes, then receive the same `*QueryResult`. Always enabled — zero overhead on cache hits. Reduces upstream load under high concurrent miss rates and closes the concurrent-query cache-poisoning window.
- **QueryResult unification**: The internal `result` and `terminalResult` structs (upstream + recursive helpers) are replaced by `QueryResult`, the same struct used at the public API boundary. `queryUpstream`, `Recursive.resolve`, and `CNAME.resolve` return `QueryResult` by value instead of 9–10 individual return values. This eliminates the `tooManyResultsChecker` lint and removes duplicate struct definitions.
- **Gosec inline suppression**: No global gosec excludes in `.golangci.yml`. All suppressions are inline `//nolint:gosec // Gxxx: reason` at each call site. G115 (integer overflow) covers DNS wire format conversions (TTL uint32, port uint16, label byte) — all protocol-bounded. G404 (weak random) covers DNS message IDs and ICMP echo identifiers — not cryptographic. G505 covers SHA1 for NSEC3 (RFC 5155).

## DB Schema

The cache uses six SQLite tables (`github.com/ncruces/go-sqlite3`, WAL mode, mmap, zstd compression):

```sql
-- Pure DNS response cache. Uniqueness: (qname, qtype, qclass, ecs_addr,
-- ecs_prefix, dnssec_ok). Wire format is zstd-compressed in msg_wire.
CREATE TABLE entries (
    qname      TEXT NOT NULL,
    qtype      INTEGER NOT NULL,
    qclass     INTEGER NOT NULL DEFAULT 1,
    ecs_addr   TEXT NOT NULL DEFAULT '',
    ecs_prefix INTEGER NOT NULL DEFAULT 0,
    dnssec_ok  INTEGER NOT NULL DEFAULT 0 CHECK (dnssec_ok IN (0, 1)),
    timestamp  INTEGER NOT NULL,
    ttl        INTEGER NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0,
    validated  INTEGER NOT NULL DEFAULT 0 CHECK (validated IN (0, 1)),
    msg_wire   BLOB,
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
);
CREATE INDEX idx_entries_expires ON entries(expires_at);

-- Request journal: one row per miss/stale/rewrite/error query. qname/qtype
-- are retrieved by JOINing entries via entry_id. Hits are aggregated into
-- entry_hit_counters instead. Survives FlushDB("stats").
CREATE TABLE request_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       INTEGER NOT NULL,
    entry_id        INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    protocol        TEXT NOT NULL,
    result          TEXT NOT NULL,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    rcode           INTEGER NOT NULL DEFAULT 0,
    server          TEXT NOT NULL DEFAULT '',
    hijack          INTEGER NOT NULL DEFAULT 0,
    fallback        INTEGER NOT NULL DEFAULT 0,
    dnssec_status   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_request_log_ts ON request_log(timestamp);
CREATE INDEX idx_request_log_entry ON request_log(entry_id);

-- Hit counters: aggregated per-entry+protocol+rcode. Each cache hit upserts
-- here instead of inserting into request_log, avoiding per-hit row bloat.
CREATE TABLE entry_hit_counters (
    entry_id  INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    protocol  TEXT NOT NULL,
    rcode     INTEGER NOT NULL DEFAULT 0,
    hit_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (entry_id, protocol, rcode)
) WITHOUT ROWID;

-- Stats metadata: single row tracking the last request_log.id that was
-- "cleared" by FlushDB("stats"). Resetting stats is O(1): just UPDATE.
CREATE TABLE stats_meta (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    cleared_before INTEGER NOT NULL DEFAULT 0
);

-- Lightweight PTR reverse-lookup (IP → domain).
CREATE TABLE ptr_map (
    rdata_ip TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    ttl      INTEGER NOT NULL,
    PRIMARY KEY (rdata_ip, entry_id, name)
) WITHOUT ROWID;

-- Per-IP latency measurements. Keyed by rdata_ip only — all domains
-- sharing the same IP (CDN) reuse the same row.
CREATE TABLE ip_latency (
    rdata_ip        TEXT NOT NULL,
    qtype           INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL,
    last_probe_time INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rdata_ip)
) WITHOUT ROWID;
```

**Key patterns**:
- **DNS response cache**: `qtype` = original query type, records in original wire order. All entries are cacheable. `Get()` decompresses + `Msg.Unpack()` — cache hit ~0.5ms.
- **RecordRequest split**: Cache hits upsert `entry_hit_counters` (one row per entry+protocol+rcode, no row bloat). Miss/stale/rewrite/error insert into `request_log` with entry_id FK — qname retrieved by JOINing entries for debugging. `ensureEntry()` creates lightweight stubs for rewrite/error paths so every row has a valid FK.
- **Stats aggregation**: `Stats()` UNION ALLs `entry_hit_counters` + `request_log` for rcode distribution, and combines both tables for protocol counts. `FlushDB("stats")` truncates `entry_hit_counters` and resets the `stats_meta` threshold — request_log rows survive.
- **Log bounded by cache**: `request_log.entry_id` and `entry_hit_counters.entry_id` both use `ON DELETE CASCADE` — when entries are evicted, all associated rows go with them. No separate ring-buffer needed.
- **NS latency cache**: NS/Root addresses are stored as regular TypeA/TypeAAAA entries. Latency is probed async via `ProbeNSAddrs` and stored in ip_latency (keyed by IP only); `sortAnswerByLatency` reorders records at `Get()` time.
- **DNSKEY cache**: `qtype` = `dns.TypeDNSKEY`, validated=1
- **PTR reverse lookup**: `SELECT DISTINCT pm.name, pm.ttl, e.timestamp FROM ptr_map pm JOIN entries e ON pm.entry_id = e.id WHERE pm.rdata_ip = ? AND e.expires_at + ? >= ?`
- **IP latency**: Per-IP keyed (`rdata_ip`). A single `INSERT OR REPLACE` writes `latency_ms`, `qtype` (inferred from IP format), and `last_probe_time` (via `unixepoch()`). `Prober.Start()` and `ProbeNSAddrs()` check `GetLatencyLastProbe` per-IP — if every IP in the answer was probed within `DefaultLatencyProbeMinInterval` (60s), the probe is skipped. All domains sharing the same CDN IP reuse the same latency row.
- **Eviction**: on `Set()` when count > maxEntries. Prefers entries past serve-stale age (`expires_at + staleMaxAge < now`), then oldest by timestamp. `ON DELETE CASCADE` cleans up `ptr_map`. Also prunes `ip_latency` rows with `last_probe_time` older than `defaultStaleMaxAge` (30 days). Entry count is synced from `SELECT COUNT(*)` before eviction to correct drift from INSERT OR REPLACE.
- **Dynamic queries + FlushDB**: `Store.Stats()` returns `[]string` with 6 TXT records grouped by theme (overview, sources, rcodes, anomalies, protocols, DNSSEC), queryable via `dig zjdns.stats CH TXT`. Write queries: `zjdns.db.clear` (`Clear()`, all tables), `zjdns.db.clear.cache/stats/latency` (`FlushDB(target)`, per-table). `FlushDB("stats")` only resets the stats_meta threshold — request_log rows survive. All restricted to loopback via `IncludeClients`. Wired via rewrite `DynamicContent` in `server.New()` before `LoadRules()`.
- **Analytics**: request_log single-table queries — e.g. `SELECT server, COUNT(*) FROM request_log GROUP BY server` for requests per upstream, `SELECT qname, COUNT(*) FROM request_log WHERE result='error' GROUP BY qname` for failure analysis. No JOIN needed.

## CI/CD

GitHub Actions (`.github/workflows/main.yml`) builds multi-arch Docker images (linux/amd64, linux/arm64) on a cron schedule (04:00/16:00 UTC+8 daily) and pushes to both GHCR and Docker Hub. Uses `docker/build-push-action` with digest-based multi-platform manifest merging. Also triggers on `workflow_dispatch`.

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
      "cache": {
        "max_entries": 10000,
        "db_path": "cache.db"
      },
      "latency_probe": [
        { "protocol": "ping", "timeout": 200 },
        { "protocol": "tcp", "port": 443, "timeout": 200 }
      ]
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

Port 15353 (non-privileged), pure recursive, cache enabled with latency probing, Debug log level. Start: `./zjdns -config config.debug.json`.

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

**Stats coverage verification (all result types):**
```bash
# Rewrite: stats query itself triggers a rewrite rule
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short

# PTR reverse lookup: warm a cached entry first, then query its IP in reverse
dig @127.0.0.1 -p 15353 www.baidu.com A +short > /dev/null
dig @127.0.0.1 -p 15353 -x 180.101.49.44 +short

# Verify all result types are logged (should show hit, miss, error, rewrite)
./zjdns -analyze cache.db "SELECT result, rcode, COUNT(*) FROM request_log GROUP BY result, rcode"

# Verify DNSSEC distribution
./zjdns -analyze cache.db "SELECT dnssec_status, COUNT(*) FROM request_log GROUP BY dnssec_status"

# Full stats (6 TXT records: overview, sources, rcodes, anomalies, protocols, DNSSEC)
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short

# Verify stats reset keeps request_log intact
dig @127.0.0.1 -p 15353 zjdns.db.clear.stats CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short          # entries remains, all counters zero
./zjdns -analyze cache.db "SELECT COUNT(*) FROM request_log" # log rows survive
```

Verify hijack detection from logs: `grep -E "hijack probe detected|hijack detected|rejecting hijacked|tcp=true" /tmp/zjdns.log`
Normal domains should show `tcp=false` throughout; blocked domains should show hijack detection + `tcp=true` restart.

## KTLS Tuning

If `"local error: tls: bad record MAC"` appears, disable kernel RX offload:

```json
{ "server": { "tls": { "ktls": { "kernel_rx": false } } } }
```

Both `kernel_tx` and `kernel_rx` default to `false` (KTLS is opt-in).


