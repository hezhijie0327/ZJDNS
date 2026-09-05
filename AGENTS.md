# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

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

Use `sh scripts/bump-version.sh <patch|minor|major>`.

| Component | Semantics |
|-----------|-----------|
| **Z (patch)** | Bug fixes, perf, refactors, lint, deps, small features |
| **Y (minor)** | Large features, new protocols, new config options, schema changes |
| **X (major)** | Breaking changes, removed features |

**Default to Z (patch).** Only bump Y for substantial features (new protocol, major config surface).

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

**133 benchmarks** across 31 test files. Baseline: `docs/benchmark/benchmark-baseline.txt`.

```bash
# Update baseline
go test -bench=. -short -benchmem -benchtime=500ms ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
```

- Pure-function micro-benchmarks → the package that owns the function
- Anything needing `server.New()`, middleware chain, or DNS pipeline → `cmd/zjdns/`

### CLI Tools

```bash
# DNS Stamp
./zjdns --dnsstamp --decode "sdns://..."       # decode to upstream JSON
./zjdns --dnsstamp --encode --proto doh \      # encode to sdns:// stamp
    --stamp-addr 9.9.9.9 --provider-name dns.quad9.net:443 --path /dns-query

# Probe upstream
./zjdns --probe --pipeline    tcp://8.8.8.8:53    # RFC 7766 pipelining
./zjdns --probe --conn-reuse  tls://1.1.1.1:853  # RFC 1035 connection reuse
./zjdns --probe --idle-timeout tls://1.1.1.1:853 # server idle timeout

# Load test client (all 12 protocols)
(cd docs && go build -o /tmp/benchclient ./benchmark/loadtest)
/tmp/benchclient -proto quic -addr 127.0.0.1:10784 -workers 32 -seconds 30

# Pre-commit hook
sh scripts/install-hook.sh                     # Linux / macOS
pwsh scripts/install-hook.ps1                  # Windows
```

Module path: `zjdns` (Go 1.27.0, pure Go — `CGO_ENABLED=0` compatible).

Key dependencies: `codeberg.org/miekg/dns` (DNS), `github.com/quic-go/quic-go` (QUIC/DoQ/DoH3), `gitlab.com/go-extension/http` (eHTTP — net/http with native eTLS for DoH), `gitlab.com/go-extension/tls` (eTLS — crypto/tls fork with KTLS), `github.com/pion/dtls/v3` (DTLS 1.2+), `github.com/cloudflare/circl` (X-Wing PQ/T KEM for DNSCrypt), `gitee.com/Trisia/gotlcp` (TLCP + DTLCP — SM2/SM3/SM4, pure Go).

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
- `New*` constructors immediately follow their type. All magic numbers as named constants in `config/defaults*.go`.

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
- No domain↔domain imports (except `edns→config`).
- No `internal/`→domain imports (except `internal/latency→config`).

## Architecture

ZJDNS is a high-performance recursive DNS server. Full architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Audit framework: [docs/AUDIT-METHODOLOGY.md](docs/AUDIT-METHODOLOGY.md). Reports: [docs/audit/](docs/audit/).

### Project Structure

```
zjdns/
├── cmd/zjdns/          ← binary + CLI
├── config/             ← ServerConfig, ProtocolSettings, UpstreamServer, defaults
├── dnscert/            ← DNSCrypt resolver-key/cert/stamp minting + config generation
├── edns/               ← EDNS handler (ECS, Cookie, EDE, Padding)
├── cache/              ← DNS response cache (Store interface, LRU-backed, two-tier spill)
├── ruleset/            ← CIDR + domain tag matching (binary radix trie)
├── zone/               ← DNS zone rules (Evaluator, zone-file import)
├── internal/           ← log, pool, ttl, dnsutil (incl. ProcessRecords), stats, ipdetect, latency, pending, spillfile, stamp, ...
└── server/
    ├── handler/        ← query pipeline adapter + QueryContext
    │   └── middleware/ ← 11 composable middleware + AssembleChain
    ├── defense/        ← DNS anti-pollution (Detector, capsguard/hopguard/poisonguard — spoofguard lives in upstream/plain, splitguard in upstream)
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
  edns, cache, ruleset, zone, dnscert

Layer 4 (server sub-packages — never import server/ parent):
  server/resolver, server/handler, server/upstream, server/protocol/*, server/defense

Top layer (wiring):
  server → all domain + all server sub-packages
  cmd/zjdns → config, log, server, dnscert (CLI config generation)
```

Key rules:
- Domain packages never import other domain packages (exception: `edns→config`).
- `internal/` packages never import domain packages (except `internal/latency→config`)
- Type aliases: `edns.ECSOption = config.ECSOption`, `handler.Question = resolver.Question` (intentional — avoids conversion at boundaries)

### Query Pipeline (Middleware Chain)

Execution order (outermost → innermost):

1. `Stats` — the single request-journal recording site; materialises the outcome classification (`qctx.Result`) set by the deciding middleware
2. `ResponseMiddleware` — EDNS / Cookie / EDE finalisation
3. `EDNSMiddleware` — ECS parsing, DNS Cookie validation (RFC 7873/9018); parse-then-validate — every qctx EDNS field is populated before any short-circuit
4. `MQTYPE` — RFC 10029 multi-QTYPE merge (recursive mode) + FORMERR (§3.3); forwarding mode also merges locally
5. `CacheStoreMiddleware` — miss-path response building, cache write (via `handler.StoreIfCacheable`), latency probe
6. `ValidationMiddleware` — domain / label / NXNAME-AXFR-IXFR rejection (RFC 9824 §3.5)
7. `ZoneMiddleware` — zone rule evaluation, synthetic response (runs before Any so rules win)
8. `AnyMiddleware` — RFC 8482 minimal ANY response (HINFO "RFC8482")
9. `CacheLookupMiddleware` — fresh→serve, stale→serve+refresh (delegates to the refreshCoordinator), miss→delegate
10. `DNS64Middleware` — AAAA synthesis from A records (RFC 6147); secondary A lookup via `handler.Secondary`
11. `ResolutionMiddleware` — terminal: upstream (first-win) or recursive with singleflight dedup

All layers share a mutable `QueryContext`. Any layer may short-circuit by setting `qctx.Res`.

> **Note:** Names like `ResponseMiddleware`, `CacheStoreMiddleware`, etc. are descriptive labels for the pipeline. The actual Go types are simply `Stats`, `Response`, `CacheStore`, `MQTYPE`, `Validation`, `Zone`, `Any`, `EDNS`, `CacheLookup`, `DNS64`, and `Resolution`.

### RFC 10029 MQTYPE (`upstream[*].mqtype`, numeric QTYPE list)
- Client: outbound queries attach `MQQUERY{config − primary}`; merged records (with RRSIGs) warm the cache; bundled types stripped from the client response **across the whole CNAME chain** (owner-independent, `stripMQBundled`); an upstream that fails/refuses the optioned query (observed: CN resolvers SERVFAILing the unknown EDNS option) is retried once optionless on BOTH the recursive and forwarding paths (§3.5)
- Server: `middleware/mqtype.go` merges per §3.4 (RCODE/AA/AD match, RR dedup, size budget that never self-triggers TC, empty-list support signal; QTx resolutions prefetched concurrently with the primary); 8 FORMERR cases §3.3
- Never: zonecut DS+NS (RFC A.3 failure), NS-walk serialization

### Query Routing (`server/resolver`)
- Upstream servers raced via `errgroup` with first NOERROR wins — fallback upstreams' results are gated behind `DefaultFallbackTimeout` (500ms, or immediately when every primary has exited without a result); the recursive walk races the latency-ranked first 6 authorities and widens to all after 75ms without a winner
- NXDOMAIN stored as secondary fallback within each query group
- Recursion is explicit-only: `protocol: "recursive"` in upstream — an empty
  upstream list resolves to SERVFAIL ("no upstream servers"), never implicit
  recursion
- CNAME chain exceeded → return partial chain + warn (no SERVFAIL); FORMERR from auth → EDNS-free retry (RFC 6891 §6.2.2)

### Recursive Resolution
- Root hints → TLD NS → authoritative NS walk with QNAME minimisation (RFC 9156 §2.3, max 10 iterations)
- **Delegation cache**: zone-cut delegations (zone → NS names + verified DS) in memory (LRU, lazy TTL expiry); subsequent queries for subdomains start from the deepest cached zone instead of root
- NS address latency-sorted cache; DNSSEC chain-of-trust at each delegation
- Zone cut detection, lame delegation detection, glue record validation

### Defense Mechanisms (per-upstream in `UpstreamServer`)

| Mechanism | Layer | Algorithm |
|-----------|-------|-----------|
| **Hopguard** | UDP upstream | IP TTL fingerprint: auto-learn baseline, reject responses with TTL outside ±2 range |
| **Spoofguard** | UDP upstream | Multi-read loop (adaptive window: 150ms single packet, 500ms multi-packet; identical repeats confirm immediately): fast-accept `AN>=2`/`NS>0`/`AD=1`; EDNS responses are candidates (richness tie-break); bare single-answer A/AAAA → collect, re-query-confirm (≤3 rounds) |
| **Poisonguard** | Recursive | Zone-authority cross-validation on resolved answers |
| **Splitguard** | TCP upstream | Random [1,4] payload segmentation (no time jitter) |
| **Capsguard** | All upstream (per-upstream `capsguard`) | `defense.RandomizeCase` flips the case bit of each ASCII letter in the outbound question (draft-vixie-dnsext-dns0x20 §5.1); `ExecuteQuery` discards responses that don't echo the randomized case and retries once unrandomized (§6.4); after `DefaultCapsGuardDowngradeAfter` (8) mismatches an address skips randomisation outright for `DefaultCapsGuardRetryAfter` (10min) — no doubled query, no per-query timing signature. Upstream-echoed record case is folded to lowercase at the resolver exit (`resolver.Query` → `dnsutil.FoldCase`, §5.4); cache-hit responses patch the stored wire back to the client's case (`handler/response.go` `patchQuestionCase`) |

## Key Types

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig` | `config` | Top-level config; owns `ECSConfig`, `ProtocolSettings`, `CertificateSettings` |
| `UpstreamServer` | `config` | Per-upstream: `Address`, `Protocol`, `ServerName`, `SkipCache`, `Match`, `Proxy`, defense flags, `MQType` (RFC 10029 bundle list) |
| `ProtocolSettings` | `config` | Per-protocol port/endpoint: `UDP`, `TCP`, `TLS`, `QUIC`, `HTTPS`, `HTTP3`, `TLCP`, `HTTPTLCP`, `DTLS`, `DTLCP`, `DNSCrypt` |
| `Store` | `cache` | Interface: Get/Set/RecordRequest (→ `internal/stats.Journal`)/FlushDB/Stats/Close |
| `Journal` / `RequestRecord` | `internal/stats` | Query statistics: pooled records, atomic counters, per-RCODE top-N journal |
| `Entry` | `cache` | Cached DNS response: Answer/Authority/Additional ([]dns.RR), Timestamp, TTL |
| `Server` | `server` | Core lifecycle, wiring, background tasks |
| `QueryContext` | `server/handler` | Mutable struct carrying all request state through the middleware chain |
| `QueryHandler` | `server/handler` | Interface: `ServeDNS(ctx, qctx) error` |
| `Wrapper` | `server/handler` | Interface: `Wrap(next QueryHandler) QueryHandler` |
| `Resolver` | `server/resolver` | Upstream + recursive resolution; constructed via `New(Config)` |
| `Recursive` | `server/resolver` | Built-in recursive walk with DNSSEC validation; in-memory delegation cache (LRU) for zone-cut skipping |
| `Client` | `server/upstream` | Outbound queries: all protocols (UDP/TCP/DoT/DoQ/DoH/DoH3/DTLS/DTLCP/TLCP/DNSCrypt/SOCKS5) |
| `Conn` / `ConnPool` | `server/upstream/pool` | RFC 7766 pipelined TCP/DoT connection pool |
| `Detector` | `server/defense` | DNS poison detection; `Verdict` type (Clean/Poisoned/Uncertain) |
| `Engine` | `ruleset` | CIDR + domain tag matching; CIDR uses binary radix trie O(128) |
| `Map[K, V]` | `internal/lrumap` | Generic concurrent-safe bounded LRU map — replaces all manual map+mutex+eviction patterns |
| `DTLSSessionStore` | `internal/lrumap` | DTLS session store backed by LRU map |
| `Message` / `Buffer` | `internal/pool` | sync.Pool allocators for DNS messages |
| `DNSStamp` | `internal/stamp` | sdns:// stamp parser/encoder (8 protocol types) |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full type reference and design decisions.

## Logging

All logs use `zjdns/internal/log` (package-level `Default` logger). Default level: `info`.

**Call-site performance contract:** bare `log.Debugf` is worry-free anywhere (~20ns / 3 small allocs when filtered — cheaper than stdlib slog; pinned by `BenchmarkDebugfFiltered`). ONLY per-query hot loops (middleware chain, protocol listeners) wrap with `if log.IsDebug()` — 1.6ns / 0 allocs (`BenchmarkDebugfGated`).

**Component filtering:** `log_level` supports `"level:comp1,comp2"` syntax (e.g. `"debug:UPSTREAM,RECURSION"`).

**canonical prefixes:** `TLS`, `CACHE`, `UPSTREAM`, `SERVER`, `EDNS`, `RECURSION`, `SECURITY`, `TCPPOOL`, `LATENCY`, `CONFIG`, `ZONE`, `PLAIN`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PANIC`, `DNSCRYPT`, `TLCP`, `RULESET`, `DNS64`, `RESPONSE`, `ANY`, `IPDETECT`, `UDPPOOL`, `DOH`, `RESOLVER`, `MQTYPE` (28 total).

Prefix matches logical component, not Go package. `HIJACK:`/`DNSSEC:` → `SECURITY:`. `DOT:`/`DOQ:`/`DOH:`/`DTLS:` → `TLS:`. `DTLCP:` → `TLCP:`. `UDP:`/`TCP:` → `PLAIN:`. Hot-path logs are `Debug` only.

## Key Docs

| Doc | Content |
|-----|---------|
| [docs/README.md](docs/README.md) | **文档索引** — 导航树、压测文档边界、约定（新文件先看这里） |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Full architecture, storage design, type reference |
| [docs/FLOWCHARTS.md](docs/FLOWCHARTS.md) | 核心功能/协议 mermaid 流程图 |
| [docs/AUDIT-METHODOLOGY.md](docs/AUDIT-METHODOLOGY.md) | Audit framework, severity definitions, fix Sprint process |
| [docs/audit/](docs/audit/) | Per-audit detailed findings and fix plans (`YYYY-MM-主题/`, see methodology §7) |
| [docs/debug/DEBUG.md](docs/debug/DEBUG.md) | Debug config, test domains, TLCP/DTLCP E2E tests, 双端压测判定标准 |
| [docs/debug/pprof-dual.sh](docs/debug/pprof-dual.sh) | 双端压测 & pprof 采集脚本（审计修复后泄漏复核） |
| [docs/benchmark/BENCHMARK.md](docs/benchmark/BENCHMARK.md) | Benchmark & E2E test guide (dnsperf, DNSCrypt, defense) |
| [docs/benchmark/LOADTEST.md](docs/benchmark/LOADTEST.md) | 全协议压测方法指南（benchclient 直连单端、pprof 双端采集、瓶颈分析） |
| [docs/benchmark/benchmark-baseline.txt](docs/benchmark/benchmark-baseline.txt) | `go test -bench` 基线（`-benchmem`，AGENTS.md 命令刷新） |
| [docs/benchmark/loadtest-baseline.txt](docs/benchmark/loadtest-baseline.txt) | benchclient 全协议 QPS/延迟基线数据（12 协议，每轮更新） |
| [docs/poc/README.md](docs/poc/README.md) | 防御机制概念验证程序（hopguard/spoofguard/splitguard/poisonguard/capsguard） |
| [docs/rfc/](docs/rfc/) | Mirrored RFCs and drafts (123 txt files) |
| [docs/rfc/GUIDELINE.md](docs/rfc/GUIDELINE.md) | RFC 精华指南 — 每个 RFC 的关键常量、协议流程、合规状态 |

## Commit & Pull Request Guidelines

- Conventional Commits: `fix:`, `perf:`, `feat:`, `chore:`, `refactor:`, `docs:`; descriptive body explaining the why; append `Co-authored-by:` trailers when applicable.
- Commit incrementally — one logical change per commit, after lint and tests pass.
- PRs: link the issue, summarize the change and verification (tests/benchmarks), and include config/log/pprof evidence for bug fixes.

### Co-Author Format

- Always add co-author information. If closing an issue in commit text, verify against `main` first: `gh issue view <issue-id>`.
- Only ONE co-author line is allowed. If multiple agents contributed, aggregate into ONE entry.

Format: `Co-authored-by: <AgentName> <Email>`

Valid examples (choose EXACTLY ONE):

```
Co-authored-by: ZCode <noreply@z.ai>
```
