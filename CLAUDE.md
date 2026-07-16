# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## HANDOVER.md

When a multi-step task is interrupted, write progress to `HANDOVER.md` so the next session can pick up where you left off. Include: what was done, what remains, key decisions made, and the next concrete step. Delete the file when the task is complete.

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
10. Run `go fix ./... && golangci-lint run && golangci-lint fmt` before committing. Zero warnings required.
    - No global linter excludes — all suppressions are inline `//nolint:NAME // reason`
    - Declaration order enforced by `decorder`: `type → const → var → func` in every file
    - Every nolint comment must include the linter name and a concrete reason
    - Formatter: `gofumpt` (stricter gofmt) — imports sorted alphabetically, no blank-line groups
11. Don't waste time wrestling with indentation or formatting issues when editing
    files (e.g. tab vs space mismatches in the Edit tool). Focus on the code
    logic — `golangci-lint fmt` will fix formatting. Use `sed` or `python3`
    freely when the Edit tool struggles with whitespace.

## Version Bumping

Use `sh scripts/bump-version.sh <patch|minor|major> <slug>` to bump the version.

**When to bump each component:**

| Component | Semantics | Examples |
|-----------|-----------|----------|
| **Z (patch)** | Bug fixes, perf improvements, refactors, lint/format fixes, dependency bumps, small feature additions | `3.2.1` — add eviction indexes; `3.2.5` — sdns:// stamp support |
| **Y (minor)** | Large new features, new protocols, new config options, breaking config schema changes | `3.3.0` — add DNS-over-HTTPS/3 probe |
| **X (major)** | Major breaking changes, removed features, fundamental architecture changes | `4.0.0` — drop legacy XSalsa20 DNSCrypt |

**Default to Z (patch)** — most changes are patch bumps. Only bump Y when the feature is substantial enough to warrant a minor release (new protocol, major new config surface, etc.).

**After bumping (if schema changed):**

**New tables / columns via `CREATE TABLE IF NOT EXISTS` in `schema.go`:**
Do NOT add a migration. The base DDL in `DB.migrate()` runs on every startup —
`IF NOT EXISTS` handles both fresh installs and existing databases. Just use
`--no-migration` when bumping.

**ALTER TABLE / data migrations (e.g. rebuild PK, drop index):**
1. Add a migration function to `database/migration.go` + entry in `migrations` slice
2. Create `database/migrations/<version>_<slug>.sql` for manual application
3. Run `go test -race -short ./...` to verify

**When no schema change is needed**, use `--no-migration`:
```bash
sh scripts/bump-version.sh patch "short-slug" --no-migration
```

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
go fix ./... && golangci-lint run && golangci-lint fmt

# Docker
docker build -t zjdns .

# Run SQL query against database (aligned columnar output like sqlite3)
# Read-only by default (PRAGMA query_only=ON); add --rw for writes with confirmation.
./zjdns --sql cache.db "SELECT e.qname, e.rcode, e.hit_udp FROM entries e"
./zjdns --sql --rw cache.db "DELETE FROM ip_latency WHERE last_probe_time < 0"

# DNS Stamp tools
./zjdns --dnsstamp --decode "sdns://..."    # Decode stamp to upstream JSON
./zjdns --dnsstamp --encode --proto doh \   # Encode fields to sdns:// stamp
    --stamp-addr 9.9.9.9 --provider-name dns.quad9.net:443 --path /dns-query

# Probe upstream server capabilities
./zjdns --probe --pipeline    tcp://8.8.8.8   # Test RFC 7766 query pipelining
./zjdns --probe --conn-reuse  tls://1.1.1.1   # Test RFC 1035 connection reuse
./zjdns --probe --idle-timeout tls://1.1.1.1  # Measure server idle timeout

# Install pre-commit hook (auto fix + fmt + lint on commit)
sh scripts/install-hook.sh                 # Linux / macOS
pwsh scripts/install-hook.ps1              # Windows PowerShell

# Bump version (see §Version Bumping)
sh scripts/bump-version.sh patch "short slug"             # + migration SQL
sh scripts/bump-version.sh patch "short slug" --no-migration  # code-only bump
```

Module path: `zjdns` (Go 1.26.4, pure Go — `CGO_ENABLED=0` compatible). Zero `golangci-lint` warnings required.

Key dependencies: `codeberg.org/miekg/dns` (DNS protocol), `github.com/quic-go/quic-go` (QUIC/DoQ/DoH3), `gitlab.com/go-extension/http` (eHTTP — net/http drop-in replacement with native eTLS, used by DoH client/server), `gitlab.com/go-extension/tls` (eTLS — crypto/tls fork with KTLS), `github.com/pion/dtls/v3` (DTLS 1.2+ — DNS-over-DTLS server/client), `github.com/ncruces/go-sqlite3` (pure-Go SQLite, WASM-based), `github.com/cloudflare/circl` (X-Wing PQ/T hybrid KEM for DNSCrypt PQC), `github.com/pjbgf/sha1cd` (SHA-1 with counter-cryptanalysis for NSEC3), `gitee.com/Trisia/gotlcp` (TLCP GB/T 38636-2020 + DTLCP GM/T 0128-2023 protocol stack — SM2/SM3/SM4, pure Go).

## Coding Standards

### Naming
- PascalCase exported, camelCase unexported. Acronyms all-caps (`DNS`, `TLS`, `QUIC`, `DNSSEC`, `SOCKS5`, etc.) except as first word (`dnssecStatus`).
- `Default` prefix reserved for value constants. `ErrXxx` / `errXxx` for sentinel errors.
- Constructors: `New`/`NewXxx`. No `Get` prefix. Bool predicates: `IsXxx`/`HasXxx`. Conversions: `ToXxx`.
- Avoid stutter: `cache.Entry` not `cache.CacheEntry`. Package-level functions over empty struct types.

### Performance
- `log.NowUnix()` instead of `time.Now()` on hot paths (zero-alloc, updates per-second).
- `strings.Builder` over `fmt.Sprintf`; `strconv.Itoa` over `fmt.Sprint`; sub-slicing over `strings.TrimSuffix`.
- `slices.SortStableFunc` over `sort.SliceStable`; `strings.EqualFold` over `strings.ToLower`.
- Hoist allocations out of loops. Pre-parse strings to uint16 at load time.

### File Organization
- One file per concern, split at ~500 lines. Declaration order: `type → const → var → func`.
- `New*` constructors immediately follow their type. Methods grouped by receiver. `init()` after the `var` block it initializes.
- All magic numbers as named constants in `config/defaults.go`. No duplicate constants per package.

### Constructors & Interfaces
- Return concrete types, accept interfaces. Group >5 params into config structs.
- Two-phase init for circular deps (`New()` then `SetXxx()`). `sync.Once` for singleton constructors.
- Define interfaces in the consumer package, not the producer.

### Concurrency
- Pointer receivers for structs with mutex/atomic fields.
- `sync.Pool.Put()` zeroes state — never read after Put.
- Every goroutine gets a context. Use `errgroup` for shared lifecycle.

### Anti-patterns
- No rate limiting or per-IP connection limits. No `Get`/`Mgr`/`Manager`/`Handler` prefixes.
- No Hungarian notation, no `snake_case`/`UPPER_SNAKE_CASE`. Use `any` not `interface{}`.
- No `server/` sub-package importing `server/` parent. No domain↔domain imports (except `edns→config`).
- No `internal/`→domain imports (except `internal/latency→config`).

## Architecture

ZJDNS is a high-performance recursive DNS server supporting TLS, QUIC, HTTPS, HTTP3.
All protocol implementations must follow their governing RFCs. Reference: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Project Structure

```
zjdns/
├── cmd/zjdns/          ← binary + CLI (flag parsing, config gen, SQL runner)
├── config/             ← ECSConfig, ECSOption, defaults, validation
├── edns/               ← EDNS handler, Cookie, EDE, padding
├── database/           ← Unified SQLite DB (schema, migration, prepared stmts)
├── cache/              ← DNS response cache (Store interface, SQLiteCache)
├── ruleset/            ← CIDR + domain tag matching engine
├── zone/               ← DNS zone rules (Evaluator, zone-file import)
├── internal/           ← log, pool, ttl, dnsutil, ipdetect, latency, pending, stamp
└── server/
    ├── server.go, bridge.go, server_tasks.go
    ├── handler/        ← query pipeline
    ├── protocol/       ← {plain,tls,tlcp,dnscrypt} server listeners
    ├── upstream/       ← {plain,tls,tlcp,dnscrypt} outbound client + pool + socks5
    └── resolver/       ← recursive walk + forward + dnssec/ + hijack/ + probe/
```

### Import Rules (strict layering, no cycles)

```
Foundation (zero zjdns imports):
  internal/log, internal/pool, internal/ipdetect, internal/stamp

Layer 1 (import only foundation):
  internal/dnsutil → log

Layer 2 (import domain foundation):
  config → dnsutil, log              (ECS types live here; edns aliases config.ECSOption)
  internal/latency → config, dnsutil, log

Layer 3 (domain packages — import config + internal/*, never each other):
  database → config, dnsutil, log        (owns SQLite infrastructure)
  edns → config, ipdetect, log, pool      (only domain→domain edge allowed)
  cache → config, database, dnsutil, log, pool
  ruleset → config
  zone → config, database, dnsutil, log

Layer 4 (server sub-packages — import domain + internal, never server/ parent):
  server/resolver/dnssec → cache, config, dnsutil, log
  server/upstream → config, edns, dnsutil, log, pool
  server/upstream/pool → config, dnsutil, log, pool
  server/resolver/probe → config, edns, dnsutil, internal/latency, log
  server/resolver → cache, config, edns, dnsutil, log, pool, server/upstream, server/resolver/dnssec, server/resolver/hijack, server/resolver/probe
  server/protocol/tls → config, dnsutil, log, pool
  server/protocol/tlcp → config, dnsutil, log, pool
  server/protocol/dnscrypt → config, dnsutil, log, pool
  server/handler → cache, config, edns, dnsutil, log, pool, zone, server/resolver

Top layer (wiring):
  server → all domain + all server sub-packages
  cmd/zjdns → cmd/zjdns/cli, config, log, server
```

**Key rules:**
- Domain packages never import other domain packages (sole exception: `edns→config`).
- `internal/` packages never import domain packages (except `internal/latency→config`, which is stable because config is foundational).
- `server/` sub-packages never import the `server/` parent.
- No circular dependencies — the graph is a DAG enforced by the compiler.

### Query Pipeline (`server/handler/handler.go:processDNSQuery`)
1. Request validation (domain/label length, ANY/AXFR/IXFR rejection)
2. `zone.Evaluator.Evaluate()` — synthetic response if zone rule matches
3. `edns.Handler` — extract ECS, DNS Cookie
4. Early DNS Cookie validation (RFC 7873/9018) — initial handshake (empty ServerCookie) allowed; short (1–15 bytes) → BADCOOKIE; 16 bytes → SipHash-2-4 cryptographic validation with timestamp check (expired >1h / future >5min → BADCOOKIE; valid → echo back; >30min → reissue)
5. `cache.Store.Get()` — hit → serve (with ruleset tag filtering); miss → resolve
6. **Pending request dedup** (`pending.go`): Same-key concurrent queries coalesce — only the first reaches the resolver; followers block and receive the identical result. Closes the cache-poisoning race window.
7. **DNS64** (RFC 6147) — after AAAA returns NODATA, issue A sub-query and synthesize AAAA records via `dns64.Synthesizer.MapAddr`
8. `Resolver.Query()` — upstream (first-win) or recursive
9. `Guard` — DNSSEC validation + hijack detection (UDP→TCP fallback)
10. `ruleset.Engine` — SQLite-backed tag matching (domain TLD+1 lookup + CIDR via net.IPNet); upstream match filtering — filter A/AAAA; all filtered → REFUSED + EDE
11. Cache population, latency probes, response with server cookie

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

### Connection Pools (`server/upstream/pool/`)
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
| `DB` | `database` | Unified SQLite DB: goroutine-safe `*sql.DB`, schema migration, 12 prepared stmts, SQLExec/SQLQueryRow/SQLQuery for consumer interfaces | Connection pool with WAL mode |
| `Options` | `database` | SQLite PRAGMA config: `MMapSizeMB`, `CacheSizeMB` | |
| `Store` | `cache` | Interface: Get/Set(int64)/RecordRequest/ReverseLookup/FlushDB/Clear/Stats/UpdateLatency/LatencyLastProbe/Close | Wraps `*database.DB` |
| `Entry` | `cache` | Cached DNS response: ID, Answer/Authority/Additional ([]dns.RR), Timestamp, TTL, Validated |
| `Server` | `server` | Core lifecycle, wiring, background tasks |
| `Handler` | `server/handler` | DNS query processing pipeline; owns `BackgroundConfig`, `LatencyProber` |
| `BackgroundConfig` | `server/handler` | Groups RefreshGroup/RefreshCtx/Ctx lifecycle params |
| `LatencyProber` | `server/handler` | Interface: Start(qname, qtype, answer, ...) — latency-probes A/AAAA records and updates latency_ms |
| `Server` | `server/protocol/tls` | TLS listeners (DoT, DoQ, DoH, DoH3, DTLS) |
| `Server` | `server/protocol/tlcp` | TLCP/DTLCP listeners: DoT and DoH over TLCP (TCP), DTLCP (GM/T 0128-2023). Uses SM2 dual certificates. |
| `Server` | `server/protocol/dnscrypt` | DNSCrypt v2 lifecycle: UDP+TCP listeners, cert TXT handshake, query encrypt/decrypt, PQ KEM + ticket resumption |
| `Certificate` | `server/protocol/dnscrypt` | DNSCrypt server certificate: Ed25519 signature, X25519 short-term key (classical) or X-Wing PQ public key (1216B) with ClientMagic + PqCertContext. Each key window holds a CertPair (Classical + PQ). |
| `ProtocolSettings` | `config` | Per-protocol port/endpoint config. A protocol is enabled when its field is non-empty. Contains `UDP`, `TCP`, `TLS` (DoT), `QUIC` (DoQ), `HTTPS` (DoH), `HTTP3` (DoH3), `TLCP` (TLCP DoT), `HTTPTLCP` (TLCP DoH), `DTLS` (RFC 8094, UDP port), `DTLCP` (GM/T 0128-2023, UDP port), `DNSCrypt`. |
| `HTTPSEndpoint` | `config` | Port + endpoint path for HTTP-based transports (DoH, DoH3, TLCP DoH). |
| `CertSettings` | `config` | Unified cert config: `Domain` (server identity), `TLS` (TLSCertificate), `TLCP` (TLCPCertificate), `DNSCrypt` (DNSCryptCertificate). |
| `TLSCertificate` | `config` | TLS certificate: `CertFile`, `KeyFile`, `SelfSigned`. |
| `TLCPCertificate` | `config` | TLCP SM2 certificate pairs: `SignCertFile`/`SignKeyFile`, `EncCertFile`/`EncKeyFile`, `SelfSigned`. |
| `DNSCryptCertificate` | `config` | DNSCrypt v2 identity keys: `PrivateKey`, `PublicKey`. Provider name auto-derived as `2.dnscrypt-cert.<cert.domain>`. Resolver encryption keys are auto-generated and rotated every 24h. Dual classical+PQ certs are always served. |
| `EncryptedQuery` / `EncryptedResponse` | `server/protocol/dnscrypt` | Public API types for client-side query encryption and response decryption. EncryptedQuery carries ClientNonce for pre-generated nonces (resumed PQ). EncryptedResponse exposes PQControl for ticket extraction. |
| `CryptoConstruction` | `server/protocol/dnscrypt` | Enum: XWingPQ (0x0003), XChacha20Poly1305 (0x0002). Both are always served per key window. XSalsa20 (0x0001) is removed — deprecated by dnscrypt-proxy. |
| `ResolverConfig` | `server/protocol/dnscrypt` | Internal config builder: provider name, Ed25519 signing keys, X25519 resolver keys. PQ keys derived deterministically. Methods: `NewCert()`, `NewPQCert()`, `NewCertPair()`, `CreateStamp()`. |
| `UpstreamServer` | `config` | Per-upstream config: `Address`, `Protocol`, `ServerName`, `SkipTLSVerify`, `NoCache`, `Match`, `Proxy`, `PublicKey`, `PQDNSCrypt` (`*bool`, default true — prefer PQ DNSCrypt certs, matching official dnscrypt-proxy). |
| `Client` | `server/upstream` | Outbound queries (UDP/TCP/DoT/DoQ/DoH/DoH3/DTLS/DTLCP/SOCKS5/DNSCrypt-UDP+TCP/TLCP/DoH-TLCP). `dnscryptState` caches per-upstream resolver state (sharedKey, secretKey/publicKey, PQ ticket + resumeSecret, expiry). TLCP uses `tlcpClientConfig` / `dialTLCPConn` (analogous to `eTLSClientConfig` / `dialTLSConn`) and `ExecuteHTTPTLCP` with custom `http.Transport.DialTLSContext`. DTLS uses `pion/dtls` for UDP-based TLS transport (RFC 8094). DTLCP uses `gitee.com/Trisia/gotlcp/dtlcp` with `net.ListenPacket` + `dtlcp.Client` (not `dtlcp.Dial` — creates connected socket incompatible with internal `WriteTo`). |
| `SOCKS5Dialer` | `server/upstream/socks5` | SOCKS5 proxy (RFC 1928/1929, TCP CONNECT + UDP ASSOCIATE) |
| `Conn` / `Pool` | `server/upstream/pool` | RFC 7766 pipelined TCP/DoT |
| `QUICPool` / `QUICConn` | `server/upstream/pool` | QUIC connection pool |
| `Resolver` | `server/resolver` | Upstream + recursive resolution; constructed via `New(Config)` |
| `Config` | `server/resolver` | Bundles QueryClient, Crypto, Hijack, EDNS, CIDRMatcher, BuildMsg, Cache, DNSSECEnforce for `New()` |
| `QueryResult` | `server/resolver` | Unified result struct — used throughout resolver and handler layers; `queryUpstream`, `Recursive.resolve`, and `CNAME.resolve` return it by value; handler uses `*QueryResult` directly (no duplicate struct) |
| `Recursive` | `server/resolver` | Built-in recursive walk |
| `CryptoValidator` | `server/resolver/dnssec` | DNSSEC chain-of-trust (RRSIG, DS, trust anchors); NSEC/NSEC3 in nsec.go |
| `Detector` | `server/resolver/hijack` | DNS hijack detection; Verdict type + IsHijackedByTLD |
| `Engine` | `ruleset` | SQLite-backed CIDR + domain tag matching; `Match(qname,ip)`, `MatchIP`. `LoadRules` accepts `RuleSetStorage` interface (satisfied by `*database.DB`) |
| `RuleSetStorage` | `ruleset` | Interface: SQLExec, SQLQueryRow, SQLQuery, BeginTx — breaks domain→domain import cycle |
| `Prober` | `internal/latency` | Unified probe engine (generic sorter) |
| `Prober` | `server/resolver/probe` | A/AAAA latency probe + record reordering + ProbeNSAddrs for NS/Root |
| `PendingRequests` | `server/handler` | Singleflight dedup: coalesces concurrent identical queries; leader sends upstream, followers wait for shared result |
| `MessagePool` / `BufferPool` | `internal/pool` | sync.Pool allocators; also holds `QUICCode*` constants |
| `JoinDNSPort` | `internal/dnsutil` | Utility: `ip` → `ip:53` (moved from config) |
| `Stamp` / `StampProtoType` | `internal/stamp` | sdns:// stamp parser/encoder: 8 protocol types, VLP hashes, bootstrap IPs. `Parse()` + `String()` round-trip. |

## Logging

All logs use `zjdns/internal/log` (package-level `Logger` instance `Default`). Default level: `info`.

**Component filtering**: `log_level` supports `level:comp1,comp2` syntax (e.g. `"debug:UPSTREAM,RECURSION"`). Messages without a `PREFIX: ` pattern always pass through.

**23 canonical prefixes**: `TLS`, `CACHE`, `DB`, `UPSTREAM`, `SERVER`, `EDNS`, `RECURSION`, `SECURITY`, `TCPPOOL`, `LATENCY`, `CONFIG`, `ZONE`, `PLAIN`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PTR`, `PANIC`, `DNSCRYPT`, `TLCP`, `RULESET`, `DNS64`.

Prefix matches logical component, not Go package. `HIJACK:`/`DNSSEC:` merged → `SECURITY:`. `DOT:`/`DOQ:`/`DOH:`/`DTLS:` merged → `TLS:`. `DTLCP:` merged → `TLCP:`. `UDP:`/`TCP:` merged → `PLAIN:`. Hot-path logs are `Debug` only.

## Notable Design Decisions

- **eHTTP for DoH**: Client and server use `gitlab.com/go-extension/http` (drop-in `net/http` with native eTLS). DoH3 uses standard `net/http` + `quic-go/http3` — KTLS doesn't apply to QUIC.
- **Unified SQLite DB** (`database/`): 10 tables, WAL + mmap, zstd-compressed wire format. `github.com/ncruces/go-sqlite3` (pure Go, no CGo). Schema migration keyed by app version with rolling `minSupportedVersion` window.
- **Global TTL** (`internal/ttl`): Stateless functions shared by cache and zone. Stale TTL uses cyclical countdown for repeated background refresh chances.
- **EDNS buffer sizing**: 1232B for upstream, 4096B for recursive (DNSSEC root zone referrals ~1400B).
- **EDNS padding**: Only for secure transports (DoT/DoQ/DoH/DoH3/DTLS/DTLCP/TLCP/HTTPTLCP). DNSCrypt has its own ISO 7816-4 padding.
- **Per-interface binding**: All listeners bind per-IP via `TryBind`; unavailable addresses are skipped with a warning.
- **QNAME minimisation (RFC 9156)**: Enabled by default, 10-step limit, QTYPE=A hides original type, CNAME owner-name mismatch detection.
- **Pool discipline**: `MessagePool.Put()` zeroes the struct — never read after Put.
- **KTLS**: Opt-in via `kernel_tx`/`kernel_rx`, eTLS for TCP, crypto/tls for QUIC. Silent fallback on non-Linux.
- **SOCKS5**: Per-upstream proxy, TCP CONNECT + UDP ASSOCIATE, 5 sentinel errors, v2ray/xray compat.
- **DNSCrypt v2**: Full implementation with PQ support (X-Wing KEM + ticket resumption). Server auto-rotates keys every 24h, client caches PQ state per-upstream. See `server/protocol/dnscrypt/` and `server/upstream/dnscrypt/`.
- **DTLCP**: GM/T 0128-2023. Works around gotlcp library bugs (connected-socket `WriteTo` ban, `Listen("udp")` unsupported).
- **DNSSEC**: IANA root KSK trust anchors (20326 + 38696). `dnssec_enforce` → SERVFAIL on bogus.
- **EDE propagation**: DNSSEC EDE codes stored atomically to survive context cancellation.
- **Zone rules**: SQLite-backed WITHOUT ROWID, wildcard + exact match in one B-tree. Zone responses bypass cache.
- **ECS types in config**: `config.ECSOption`, `edns.ECSOption` is a type alias. Same for `handler.Question = resolver.Question`.
- **Pending request dedup**: Singleflight coalescing of concurrent identical cache misses. Leader resolves, followers wait for shared result.
- **Upstream `no_cache` flag**: Per-server opt-out from cache population for untrusted upstreams.
- **RecordRequest split**: Hits → `entry_hit_counters` (upsert), misses/errors → `request_log` (insert). Denormalized qname/qtype for debug queries.
- **Prepared statements**: Hot-path SQL pre-compiled at init (entry get, log insert, latency upsert).
- **sdns:// stamps**: `normalizeStamps()` resolves stamps at load time, 8 protocol types. `internal/stamp` is zero-dependency.
- **eHTTP/eTLS aliases** enforced by `importas`. Internal packages use `z`-prefixed aliases (`zdnsutil`, `zlog`, etc.).

## DB Schema

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full schema SQL and key patterns. Summary:
- `entries` — DNS response cache (zstd-compressed wire format)
- `request_log` — miss/stale/zone/error query journal
- `entry_hit_counters` — aggregated cache hit counters
- `ptr_map` — IP→domain reverse lookup
- `ip_latency` — per-IP latency measurements
- `zone_entries` — zone rule responses (same DB file)
## CI/CD

GitHub Actions (`.github/workflows/main.yml`) builds multi-arch Docker images (linux/amd64, linux/arm64) on a cron schedule (04:00/16:00 UTC+8 daily) and pushes to both GHCR and Docker Hub. Uses `docker/build-push-action` with digest-based multi-platform manifest merging. Also triggers on `workflow_dispatch`.

## Debug Config & Testing

See [docs/debug/DEBUG.md](docs/debug/DEBUG.md) for debug config, test domains, and TLCP/DTLCP test commands.

## KTLS Tuning

KTLS is configured under `features.ktls`. Both `kernel_tx` and `kernel_rx` default to `false` (KTLS is opt-in).

If `"local error: tls: bad record MAC"` appears, disable kernel RX offload:

```json
{ "server": { "features": { "ktls": { "kernel_rx": false } } } }
```
