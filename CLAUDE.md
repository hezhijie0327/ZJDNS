# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development

```bash
# Build
go build -o zjdns

# Build with version info
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns

# Lint
golangci-lint run && golangci-lint fmt
```

There is no test suite. Module path: `zjdns` (Go 1.25).

## Package Structure

```
zjdns/
├── main.go / version.go           # Entry point + ldflags variables
├── internal/
│   ├── log/log.go                 # LogManager, TimeCache, Level.String()
│   ├── pool/pool.go               # MessagePool, BufferPool, constants (zero deps)
│   ├── dnsutil/dnsutil.go         # NormalizeDomain, IsSecureProtocol, HandlePanic, etc.
│   └── ipdetect/ipdetect.go       # Public IP detection for auto ECS
├── config/config.go               # All types + constants + loader + validation + DDR/CHAOS
├── edns/edns.go                   # ECS, DNS Cookie, EDE (24 codes), Padding
├── cidr/cidr.go                   # CIDRManager — IP filtering with tag matching
├── rewrite/rewrite.go             # RewriteManager — domain rewrite rules
├── cache/cache.go                 # Manager interface + MemoryCache + persistence
├── stats/stats.go                 # Lock-free atomic metrics Manager
└── server/                        # Core server (tightly coupled sub-components)
    ├── server.go                  # DNSServer, query pipeline, lifecycle, signal handling
    ├── resolver.go                # QueryManager, RecursiveResolver, CNAMEHandler
    ├── query.go                   # QueryClient (UDP/TCP/DoT/DoQ/DoH/DoH3)
    ├── security.go                # SecurityManager, DNSSECValidator, HijackPrevention
    ├── tls.go                     # TLSManager, self-signed CA, secure protocol handlers
    ├── latency_probe.go           # A/AAAA latency probing and reordering
    └── ratelimit.go               # Per-IP token bucket rate limiter
```

### Dependency Graph

```
main ──→ server, config
server ──→ cache, cidr, config, edns, dnsutil, ipdetect, log, pool, rewrite, stats
cache ──→ config, edns, dnsutil, log
edns ──→ dnsutil, ipdetect, log
cidr ──→ config, dnsutil, log
rewrite ──→ config, dnsutil, log
stats ──→ cache, config, log
dnsutil ──→ log
pool, log ──→ (zero deps)

No circular dependencies.
```

## Architecture

ZJDNS is a high-performance recursive DNS server supporting DoT, DoQ, DoH, DoH3.

**Query processing pipeline** (`server/server.go:processDNSQuery`):
1. Server status check → request validation (domain length, ANY query)
2. `rewrite.Manager.Evaluate()` — synthetic response if rule matches
3. `edns.Manager` — extract ECS, DNS Cookie from request
4. `cache.Manager.Get()` — hit → serve (with CIDR filtering); miss → continue
5. `QueryManager.Query()` — upstream (first-win) or recursive resolution
6. `SecurityManager` — DNSSEC validation, hijack detection (UDP→TCP fallback)
7. `cidr.Manager.MatchIP()` — filter A/AAAA IPs; all filtered → REFUSED + EDE
8. Populate cache, start latency probes, return response

**Query routing** (`server/resolver.go:QueryManager.Query`):
- Upstream servers configured → concurrent first-win query; fallback on failure
- No upstream → built-in recursive resolver (root→TLD→authoritative walk)
- NXDOMAIN stored as secondary fallback; first NOERROR wins

**Concurrency**: All queries use "first win" — fan out to all servers via `errgroup`, cancel remaining on first success. Adaptive concurrency limits based on server count.

## Key Types (canonical names)

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig`, `ServerSettings` | `config` | Top-level config |
| `config.Manager` | `config` | Config loader (LoadConfig, GenerateExampleConfig) |
| `edns.Manager` | `edns` | EDNS option parsing/construction |
| `cidr.Manager` | `cidr` | IP filtering (New, MatchIP) |
| `rewrite.Manager` | `rewrite` | Domain rewrite (New, LoadRules, Evaluate) |
| `cache.Manager` | `cache` | Cache interface (Get, Set, SetEntry, Close) |
| `stats.Manager` | `stats` | Lock-free metrics (RecordRequest, Snapshot) |
| `DNSServer` | `server` | Core server (New, Start) |

## Key Constants

| Constant | Package | Value |
|----------|---------|-------|
| `config.IdleTimeout` | config | 4s |
| `config.DefaultTTL` | config | 10 |
| `config.DefaultCacheSize` | config | 16384 |
| `config.MaxDomainLength` | config | 253 |
| `config.RecursiveIndicator` | config | "builtin_recursive" |
| `cache.StaleMaxAge` | cache | 45 days |
| `pool.UDPBufferSize` | pool | 1232 |
| `server.OperationTimeout` | server | 3s |
| `server.MaxCNAMEChain` | server | 16 |
| `server.MaxRecursionDep` | server | 16 |

## Logging Conventions

All logs use the project-level `log` package (`zjdns/internal/log`). Default level: `info`.

**Level usage**:
| Level | Use case |
|-------|----------|
| `Error` | Component failure, data loss risk (persist failures, shutdown timeouts) |
| `Warn` | Security events (hijack detection), rare boundary conditions (CNAME loop, depth exceeded), background task failures (ECS refresh) |
| `Info` | Startup/shutdown lifecycle, configuration summary, one-time events |
| `Debug` | Hot-path detail: every query, cache hit/miss, upstream result, CIDR match |

**Prefixes** (19 canonical, one per logical component):

| Prefix | Component | Files |
|--------|-----------|-------|
| `TLS` | All TLS + secure protocols | tls.go |
| `CACHE` | Cache operations | cache.go, server.go |
| `UPSTREAM` | Outbound upstream queries | query.go, resolver.go |
| `SERVER` | Server lifecycle | server.go, main.go |
| `EDNS` | EDNS options | edns.go, server.go |
| `RECURSION` | Recursive resolution | resolver.go |
| `SECURITY` | DNSSEC, hijack detection | security.go, resolver.go |
| `LATENCY`, `STATS`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `RATELIMIT`, `PTR`, `PANIC` | One component each | respective files |

**Rules**: Prefix matches logical component, not Go package. No `HIJACK:`/`DNSSEC:` (merged→`SECURITY:`), no `DOT:`/`DOQ:`/`DOH:` (merged→`TLS:`). Hot-path logs are `Debug` only — `Warn`/`Info` on the query path would spam at scale.

## Notable Design Decisions

- **TLS config isolation**: `server/query.go` clones TLS configs per-query to prevent
  concurrent requests with different `InsecureSkipVerify`/`ServerName` from
  cross-contaminating each other.
- **Cache compression**: Full DNS records stored as zstd+gob compressed blobs;
  metadata (timestamps, ECS) kept in memory for fast expiry checks.
- **Hijack detection during recursion**: Root/TLD servers returning unauthorized
  final answers trigger automatic UDP→TCP retry; if TCP also hijacked, returns
  REFUSED + EDE.
- **HandlePanic no longer calls `os.Exit(1)`** — a single connection panic
  terminates only that goroutine, not the entire server.
- **Lock-free RNG**: `shuffleSlice` uses `math/rand/v2.IntN()` instead of a
  custom mutex-protected RNG.
- **Lock-free stats**: All 16 counters use `atomic.Uint64` on the hot path;
  `sync.Mutex` only guards snapshot assembly.
- **Config self-sufficiency**: `config.ProjectName` and `config.Version` are
  package-level vars set by `main.go` before calling `config.Manager.LoadConfig()`.
