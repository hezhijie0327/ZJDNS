# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## HANDOVER.md

When a multi-step task is interrupted, write progress to `HANDOVER.md` so the next session can pick up where you left off. Include: what was done, what remains, key decisions made, and the next concrete step. Delete the file when the task is complete.

## Behavioral Guidelines

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

### 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

### 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

## Project Guidelines

1. **RFC references:** Check `docs/rfc/` first — the project mirrors all referenced RFCs and drafts locally.
2. Think before acting. Read existing files before writing code.
3. Be concise in output but thorough in reasoning.
4. Prefer editing over rewriting whole files.
5. Do not re-read files you have already read.
6. Test your code before declaring done.
7. Keep solutions simple and direct.
8. User instructions always override this file.
9. Commit incrementally — every batch of related changes should be committed with a descriptive message. Present changes for review before committing.
10. Run `go fix ./... && golangci-lint run && golangci-lint fmt` before committing. **Zero warnings required.**
    - All suppressions are inline `//nolint:NAME // reason` — no global linter excludes
    - Declaration order (`decorder`): `type → const → var → func` in every file
    - Formatter: `gofumpt` — imports sorted alphabetically, no blank-line groups
11. Don't wrestle with indentation in the Edit tool — focus on logic, let `golangci-lint fmt` fix formatting. Use `sed` or `python3` freely when the Edit tool struggles with whitespace.

## Version Bumping

Use `sh scripts/bump-version.sh <patch|minor|major> <slug>`.

| Component | Semantics |
|-----------|-----------|
| **Z (patch)** | Bug fixes, perf, refactors, lint, deps, small features |
| **Y (minor)** | Large features, new protocols, new config options, schema changes |
| **X (major)** | Breaking changes, removed features |

**Default to Z (patch).** Only bump Y for substantial features (new protocol, major config surface).

**After bumping (if schema changed):**
- New tables/columns via `CREATE TABLE IF NOT EXISTS` → no migration needed; use `--no-migration`
- `ALTER TABLE` / data migrations → add migration func to `database/migration.go` + entry in `migrations` slice + SQL file in `database/migrations/`

**Always amend the version bump into the feature commit:**
```bash
git reset --soft HEAD~2 && git commit  # or git commit --amend for single commit
```

## Build, Test & Lint

```bash
# Build
go build -o zjdns ./cmd/zjdns

# Cross-compile (pure Go, no CGo)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o zjdns ./cmd/zjdns

# Tests
go test ./... -short                    # all tests
go test ./server/resolver/... -v        # single package
go test ./server/resolver/... -run TestIsZoneCut -v  # single test
```

### Benchmarks

Two-tier layout:

| Location | Purpose |
|----------|---------|
| Per-package `benchmark_test.go` | Unit-level: pure functions, zero external deps |
| `cmd/zjdns/benchmark_test.go` | Integration-level: needs `server.New()`, full pipeline |

```bash
go test -bench=. -short ./...                                  # all (fast)
go test -bench=. -short -benchtime=500ms ./...                 # stable numbers
go test -bench=BenchmarkServerProcessQuery -benchtime=3s ./cmd/zjdns  # integration QPS
```

**98 benchmarks** across 14 files. Baseline: `docs/benchmark/benchmark-baseline.txt`.

```bash
# Update baseline
go test -bench=. -short -benchtime=500ms ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
```

- Pure-function micro-benchmarks → the package that owns the function
- Anything needing `server.New()`, middleware chain, or DNS pipeline → `cmd/zjdns/`

### CLI Tools

```bash
# SQL query (read-only; add --rw for writes)
./zjdns --sql cache.db "SELECT e.qname, e.rcode, e.hit_udp FROM entries e"

# DNS Stamp
./zjdns --dnsstamp --decode "sdns://..."       # decode to upstream JSON
./zjdns --dnsstamp --encode --proto doh \      # encode to sdns:// stamp
    --stamp-addr 9.9.9.9 --provider-name dns.quad9.net:443 --path /dns-query

# Probe upstream
./zjdns --probe --pipeline    tcp://8.8.8.8    # RFC 7766 pipelining
./zjdns --probe --conn-reuse  tls://1.1.1.1    # RFC 1035 connection reuse
./zjdns --probe --idle-timeout tls://1.1.1.1   # server idle timeout

# Pre-commit hook
sh scripts/install-hook.sh                     # Linux / macOS
pwsh scripts/install-hook.ps1                  # Windows
```

Module path: `zjdns` (Go 1.26.4, pure Go — `CGO_ENABLED=0` compatible).

Key dependencies: `codeberg.org/miekg/dns` (DNS), `github.com/quic-go/quic-go` (QUIC/DoQ/DoH3), `gitlab.com/go-extension/http` (eHTTP — net/http with native eTLS for DoH), `gitlab.com/go-extension/tls` (eTLS — crypto/tls fork with KTLS), `github.com/pion/dtls/v3` (DTLS 1.2+), `github.com/ncruces/go-sqlite3` (pure-Go SQLite), `github.com/cloudflare/circl` (X-Wing PQ/T KEM for DNSCrypt), `gitee.com/Trisia/gotlcp` (TLCP + DTLCP — SM2/SM3/SM4, pure Go).

## Coding Standards

### Naming
- PascalCase exported, camelCase unexported. Acronyms all-caps (`DNS`, `TLS`, `QUIC`) except as first word (`dnssecStatus`).
- `Default` prefix for value constants. `ErrXxx` for sentinel errors. Constructors: `New`/`NewXxx`. No `Get` prefix. Bool: `IsXxx`/`HasXxx`.
- Avoid stutter: `cache.Entry` not `cache.CacheEntry`.

### Performance
- `log.NowUnix()` instead of `time.Now()` on hot paths (zero-alloc).
- `strings.Builder` over `fmt.Sprintf`; `strconv.Itoa` over `fmt.Sprint`; sub-slicing over `strings.TrimSuffix`.
- `slices.SortStableFunc` over `sort.SliceStable`; `strings.EqualFold` over `strings.ToLower`.
- Hoist allocations out of loops. Pre-parse strings to uint16 at load time.

### File Organization
- One file per concern, split at ~500 lines. Declaration order: `type → const → var → func`.
- `New*` constructors immediately follow their type. All magic numbers as named constants in `config/defaults.go`.

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
- No `server/` sub-package importing `server/` parent (except `handler/middleware → handler`).
- No domain↔domain imports (except `edns→config`, `cache→database`, `zone→database`, `ruleset→database`).
- No `internal/`→domain imports (except `internal/latency→config`).

## Architecture

ZJDNS is a high-performance recursive DNS server. Full architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Audit framework: [docs/AUDIT-METHODOLOGY.md](docs/AUDIT-METHODOLOGY.md). Reports: [docs/audit/](docs/audit/).

### Project Structure

```
zjdns/
├── cmd/zjdns/          ← binary + CLI
├── config/             ← ServerConfig, ProtocolSettings, UpstreamServer, defaults
├── edns/               ← EDNS handler (ECS, Cookie, EDE, Padding)
├── database/           ← Unified SQLite DB (schema, migration, prepared stmts)
├── cache/              ← DNS response cache (Store interface, SQLiteCache, AsyncStatsWriter)
├── ruleset/            ← CIDR + domain tag matching (binary radix trie)
├── zone/               ← DNS zone rules (Evaluator, zone-file import)
├── internal/           ← log, pool, ttl, dnsutil, ipdetect, latency, pending, stamp, lrumap, ...
└── server/
    ├── handler/        ← query pipeline adapter + QueryContext
    │   └── middleware/ ← 10 composable middleware + AssembleChain
    ├── defense/        ← DNS anti-pollution (Detector, poisonguard/spoofguard/splitguard)
    ├── protocol/       ← {plain,tls,tlcp,dnscrypt} server listeners
    ├── upstream/       ← {plain,tls,tlcp,dnscrypt} outbound client + pool + SOCKS5
    └── resolver/       ← recursive walk + forward + dnssec/ + probe/
```

### Import Layers (strict DAG, no cycles)

```
Foundation (zero zjdns imports):
  internal/log, internal/pool, internal/ipdetect, internal/stamp, ...

Layer 1–2: internal/dnsutil, config, internal/latency

Layer 3 (domain packages — never import each other):
  database, edns, cache, ruleset, zone

Layer 4 (server sub-packages — never import server/ parent):
  server/resolver, server/handler, server/upstream, server/protocol/*, server/defense

Top layer (wiring):
  server → all domain + all server sub-packages
  cmd/zjdns → config, log, server
```

Key rules:
- Domain packages never import other domain packages (known exceptions: `edns→config`, `cache→database`, `cache→config`, `zone→database`, `zone→config`, `ruleset→database`, `ruleset→config`)
- `internal/` packages never import domain packages (except `internal/latency→config`)
- Type aliases: `edns.ECSOption = config.ECSOption`, `handler.Question = resolver.Question` (intentional — avoids conversion at boundaries)

### Query Pipeline (Middleware Chain)

Execution order (outermost → innermost):

1. `ResponseMiddleware` — EDNS / Cookie / EDE finalisation
2. `CacheStoreMiddleware` — cache write, request logging, latency probe
3. `ValidationMiddleware` — domain / label / ANY-AXFR-IXFR rejection
4. `ZoneMiddleware` — zone rule evaluation, synthetic response
5. `EDNSMiddleware` — ECS parsing, DNS Cookie validation (RFC 7873/9018)
6. `CacheLookupMiddleware` — fresh→serve, stale→serve+refresh, miss→delegate
7. `PTRMiddleware` — reverse PTR lookup from cache
8. `RulesetMiddleware` — CIDR-based A/AAAA record filtering
9. `DNS64Middleware` — AAAA synthesis from A records (RFC 6147)
10. `ResolutionMiddleware` — terminal: upstream (first-win) or recursive with singleflight dedup

All layers share a mutable `QueryContext`. Any layer may short-circuit by setting `qctx.Res`.

### Query Routing (`server/resolver`)
- Upstream + fallback queried concurrently via `errgroup`; first NOERROR wins
- NXDOMAIN stored as secondary fallback within each query group
- No servers configured → built-in recursive (root→TLD→authoritative)
- CNAME chain exceeded → SERVFAIL; FORMERR from auth → EDNS-free retry (RFC 6891 §6.2.2)

### Recursive Resolution
- Root hints → TLD NS → authoritative NS walk with QNAME minimisation (RFC 9156, max 10 steps)
- NS address latency-sorted cache; DNSSEC chain-of-trust at each delegation
- Zone cut detection, lame delegation detection, glue record validation

### Defense Mechanisms (per-upstream in `UpstreamServer`)

| Mechanism | Layer | Algorithm |
|-----------|-------|-----------|
| **Spoofguard** | UDP upstream | Multi-read loop: reject `AR=0+NOERROR+EDNS`; accept `AN>=2`/`NS>0`/`AD=1`; collect ambiguous (≤500ms) → pick richest |
| **Poisonguard** | Recursive | Zone-authority cross-validation on resolved answers |
| **Splitguard** | TCP upstream | Random [1,N] payload segmentation with jitter |

## Key Types

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig` | `config` | Top-level config; owns `ECSConfig`, `ProtocolSettings`, `CertSettings` |
| `UpstreamServer` | `config` | Per-upstream: `Address`, `Protocol`, `ServerName`, `NoCache`, `Match`, `Proxy`, defense flags |
| `ProtocolSettings` | `config` | Per-protocol port/endpoint: `UDP`, `TCP`, `TLS`, `QUIC`, `HTTPS`, `HTTP3`, `TLCP`, `DTLS`, `DTLCP`, `DNSCrypt` |
| `DB` | `database` | Unified SQLite DB; WAL mode, 12 prepared stmts |
| `Store` | `cache` | Interface: Get/Set/RecordRequest/ReverseLookup/FlushDB/Stats/Close |
| `Entry` | `cache` | Cached DNS response: Answer/Authority/Additional ([]dns.RR), Timestamp, TTL |
| `AsyncStatsWriter` | `cache` | Background goroutine: non-blocking channel → batched SQLite writes |
| `Map[K, V]` | `internal/lrumap` | Generic concurrent-safe bounded map with LRU eviction; used by all 4 memory caches |
| `Server` | `server` | Core lifecycle, wiring, background tasks |
| `QueryContext` | `server/handler` | Mutable struct carrying all request state through the middleware chain |
| `QueryHandler` | `server/handler` | Interface: `ServeDNS(ctx, qctx) error` |
| `Middleware` | `server/handler` | Interface: `Wrap(next QueryHandler) QueryHandler` |
| `Resolver` | `server/resolver` | Upstream + recursive resolution; constructed via `New(Config)` |
| `Recursive` | `server/resolver` | Built-in recursive walk with DNSSEC validation |
| `Client` | `server/upstream` | Outbound queries: all protocols (UDP/TCP/DoT/DoQ/DoH/DoH3/DTLS/DTLCP/TLCP/DNSCrypt/SOCKS5) |
| `Conn` / `Pool` | `server/upstream/pool` | RFC 7766 pipelined TCP/DoT connection pool |
| `Detector` | `server/defense` | DNS poison detection; `Verdict` type (Clean/Poisoned/Uncertain) |
| `Engine` | `ruleset` | CIDR + domain tag matching; CIDR uses binary radix trie O(128) |
| `Message` / `Buffer` | `internal/pool` | sync.Pool allocators for DNS messages |
| `Stamp` | `internal/stamp` | sdns:// stamp parser/encoder (8 protocol types) |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full type reference and design decisions.

## Logging

All logs use `zjdns/internal/log` (package-level `Default` logger). Default level: `info`.

**Component filtering:** `log_level` supports `"level:comp1,comp2"` syntax (e.g. `"debug:UPSTREAM,RECURSION"`).

**23 canonical prefixes:** `TLS`, `CACHE`, `DB`, `UPSTREAM`, `SERVER`, `EDNS`, `RECURSION`, `SECURITY`, `TCPPOOL`, `LATENCY`, `CONFIG`, `ZONE`, `PLAIN`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PTR`, `PANIC`, `DNSCRYPT`, `TLCP`, `RULESET`, `DNS64`.

Prefix matches logical component, not Go package. `HIJACK:`/`DNSSEC:` → `SECURITY:`. `DOT:`/`DOQ:`/`DOH:`/`DTLS:` → `TLS:`. `DTLCP:` → `TLCP:`. `UDP:`/`TCP:` → `PLAIN:`. Hot-path logs are `Debug` only.

## Key Docs

| Doc | Content |
|-----|---------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full architecture, DB schema, design decisions, type reference |
| [docs/AUDIT-METHODOLOGY.md](docs/AUDIT-METHODOLOGY.md) | Audit framework, severity definitions, fix Sprint process |
| [docs/audit/](docs/audit/) | Per-audit detailed findings and fix plans |
| [docs/debug/DEBUG.md](docs/debug/DEBUG.md) | Debug config, test domains, TLCP/DTLCP E2E tests |
| [docs/benchmark/BENCHMARK.md](docs/benchmark/BENCHMARK.md) | Benchmark & E2E test guide (dnsperf, DNSCrypt, defense) |
| [docs/rfc/](docs/rfc/) | Mirrored RFCs and drafts |
