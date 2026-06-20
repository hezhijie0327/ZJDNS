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
│   ├── log/log.go                 # Logger, TimeCache, Level.String()
│   ├── pool/pool.go               # MessagePool, BufferPool, constants (zero deps)
│   ├── dnsutil/dnsutil.go         # NormalizeDomain, IsSecureProtocol, HandlePanic, etc.
│   └── ipdetect/ipdetect.go       # Public IP detection for auto ECS
├── config/config.go               # All types + constants + loader + validation + DDR/CHAOS
├── edns/                           # EDNS(0) extensions (5 files)
│   ├── edns.go                    # Handler, NewHandler, ApplyToMessage
│   ├── ecs.go                     # ECSOption, DefaultECSConfig, ParseFromDNS
│   ├── cookie.go                  # CookieGenerator, ParseCookie
│   ├── ede.go                     # EDEOption, 24 error codes
│   └── padding.go                 # RFC 7830 response padding
├── cache/                          # DNS response cache (3 files)
│   ├── cache.go                   # Store interface, CacheEntry, helpers
│   ├── memory.go                  # MemoryCache, eviction, PTR index
│   └── persist.go                 # Disk snapshot load/save
├── cidr/cidr.go                   # CIDR Filter — IP filtering with tag matching
├── rewrite/rewrite.go             # Rewrite Evaluator — domain rewrite rules
├── stats/stats.go                 # Lock-free atomic metrics Collector
├── server/                        # Core server + sub-packages
│   ├── server.go                  # Server lifecycle, New(), Start(), shutdown
│   ├── server_handlers.go         # Query pipeline, cache hit/miss, response builders
│   ├── client/                    # Outbound query execution + connection pools
│   │   ├── client.go              # Client struct, ExecuteQuery, routing
│   │   ├── tcp.go                 # Traditional UDP/TCP + TCP fallback
│   │   ├── dot.go                 # DoT via pipelined pool
│   │   ├── doq.go                 # DoQ via QUIC pool
│   │   ├── doh.go                 # DoH via HTTP/2 transport
│   │   ├── doh3.go                # DoH3 via HTTP/3 transport
│   │   ├── tcppool.go             # RFC 7766 pipelined TCP/DoT pool (Conn, Pool)
│   │   └── quicpool.go            # QUIC connection pool (QuicPool)
│   ├── resolver/                  # DNS resolution strategies
│   │   ├── resolver.go            # Resolver struct, routing + helpers
│   │   ├── upstream.go            # First-win concurrent upstream queries
│   │   ├── recursive.go           # Recursive root→TLD→auth walk
│   │   └── cname.go               # CNAME chain resolution
│   ├── security/                  # Security features
│   │   ├── security.go            # Guard (bundles Validator + Detector)
│   │   ├── dnssec.go              # DNSSEC record-presence validation
│   │   └── hijack.go              # Hijack detection + TCP fallback trigger
│   ├── tls/                        # Secure transport listeners
│   │   ├── tls.go                  # Server struct, cert management, Start/Shutdown
│   │   ├── dot.go                  # DoT listener + per-connection handler
│   │   ├── doq.go                  # DoQ listener + stream handler
│   │   └── doh.go                  # DoH/DoH3 HTTP handlers
│   ├── latency/                    # Latency probing
│   │   └── probe.go                # A/AAAA latency probing + reordering
│   └── ratelimit/                  # Per-IP token bucket rate limiter
│       └── ratelimit.go            # Limiter (sharded, FNV-1a hash)
└── cmd/
    └── pipeline_test/             # RFC 7766 pipelining test tool
```

### Dependency Graph

```
main ──→ server, config
server ──→ cache, cidr, config, edns, dnsutil, ipdetect, log, pool, rewrite,
│          stats, client, ratelimit, resolver, security
client ──→ config, edns, dnsutil, log, pool
resolver ──→ config, edns, client, security, dnsutil, log, pool
security ──→ dnsutil, log
ratelimit ──→ log
tls (in server) ──→ config, client, dnsutil, log, pool
cache ──→ config, edns, dnsutil, log
edns ──→ dnsutil, ipdetect, log
cidr ──→ config, dnsutil, log
rewrite ──→ config, dnsutil, log
stats ──→ cache, config, log
dnsutil ──→ log
pool, log ──→ (zero deps)

No circular dependencies. Sub-packages only import what they need.
```

## Architecture

ZJDNS is a high-performance recursive DNS server supporting DoT, DoQ, DoH, DoH3.

**Query processing pipeline** (`server/server.go:processDNSQuery`):
1. Server status check → request validation (domain length, ANY query)
2. `rewrite.Evaluator.Evaluate()` — synthetic response if rule matches
3. `edns.Handler` — extract ECS, DNS Cookie from request
4. `cache.Store.Get()` — hit → serve (with CIDR filtering); miss → continue
5. `Resolver.Query()` — upstream (first-win) or recursive resolution
6. `Guard` — DNSSEC validation, hijack detection (UDP→TCP fallback)
7. `cidr.Filter.MatchIP()` — filter A/AAAA IPs; all filtered → REFUSED + EDE
8. Populate cache, start latency probes, return response

**Query routing** (`server/resolver/resolver.go:Resolver.Query`):
- Upstream servers configured → concurrent first-win query; fallback on failure
- No upstream → built-in recursive resolver (root→TLD→authoritative walk)
- NXDOMAIN stored as secondary fallback; first NOERROR wins

**TCP/DoT pipelining** (`server/client/tcppool.go`, RFC 7766):
- Client: `Pool` manages per-upstream `Conn` instances; each multiplexes
  multiple in-flight queries over a single TCP/DoT connection with out-of-order
  response matching by DNS message ID. Falls back to single-shot `ExchangeContext`
  on connection failure.
- Server: `handleDOTConnection` in `server/tls/dot.go` uses reader→worker→writer
  three-stage pipeline; `handleDNSRequest` dispatches TCP queries to goroutines
  with per-connection write mutex for concurrent out-of-order processing.

**Concurrency**: All queries use "first win" — fan out to all servers via `errgroup`, cancel remaining on first success. Adaptive concurrency limits based on server count.

## Key Types (canonical names)

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig`, `ServerSettings` | `config` | Top-level config |
| `config.Loader` | `config` | Config loader (LoadConfig, GenerateExampleConfig) |
| `edns.Handler` | `edns` | EDNS option parsing/construction |
| `cidr.Filter` | `cidr` | IP filtering (New, MatchIP) |
| `rewrite.Evaluator` | `rewrite` | Domain rewrite (New, LoadRules, Evaluate) |
| `cache.Store` | `cache` | Store interface (Get, Set, SetEntry, Close) |
| `stats.Collector` | `stats` | Lock-free metrics (RecordRequest, Snapshot) |
| `Server` | `server` | Core server (New, Start) |
| `Server` | `server/tls` | TLS listener server (DoT, DoQ, DoH, DoH3) |
| `Prober` | `server/latency` | A/AAAA latency prober |
| `Client` | `server/client` | Outbound DNS client (UDP, TCP, DoT, DoQ, DoH, DoH3) |
| `Conn` | `server/client` | Multiplexed TCP/DoT connection (RFC 7766) |
| `Pool` | `server/client` | TCP/DoT connection pool |
| `QuicPool` | `server/client` | QUIC connection pool |
| `Resolver` | `server/resolver` | DNS resolution (upstream + recursive) |
| `Recursive` | `server/resolver` | Built-in recursive resolver |
| `Guard` | `server/security` | DNSSEC + hijack detection |
| `Validator` | `server/security` | DNSSEC record-presence validation |
| `Detector` | `server/security` | DNS hijack detection |
| `Limiter` | `server/ratelimit` | Per-IP token bucket rate limiter |

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
| `client.OperationTimeout` | server/client | 3s |
| `client.DefaultMaxPipe` | server/client | 16 (max in-flight queries per connection) |
| `client.DefaultMaxConns` | server/client | 4 (max connections per upstream) |
| `resolver.MaxCNAMEChain` | server/resolver | 16 |
| `resolver.MaxRecursionDep` | server/resolver | 16 |

## Logging Conventions

All logs use the project-level `log` package (`zjdns/internal/log`). Default level: `info`.

**Level usage**:
| Level | Use case |
|-------|----------|
| `Error` | Component failure, data loss risk (persist failures, shutdown timeouts) |
| `Warn` | Rare boundary conditions (CNAME loop, depth exceeded), background task failures (ECS refresh) |
| `Info` | Startup/shutdown lifecycle, configuration summary, one-time events |
| `Debug` | Hot-path detail: every query, cache hit/miss, upstream result, CIDR match |

**Prefixes** (19 canonical, one per logical component):

| Prefix | Component | Files |
|--------|-----------|-------|
| `TLS` | All TLS + secure protocols | server/tls/*.go |
| `CACHE` | Cache operations | cache/*.go, server/server.go |
| `UPSTREAM` | Outbound upstream queries | server/client/{tcp,dot,doq,doh,doh3}.go, server/resolver/upstream.go |
| `SERVER` | Server lifecycle | server/server.go, server/server_handlers.go, main.go |
| `EDNS` | EDNS options | edns/*.go, server/server.go |
| `RECURSION` | Recursive resolution | server/resolver/recursive.go |
| `SECURITY` | DNSSEC, hijack detection | server/security/*.go, server/resolver/recursive.go |
| `TCPPOOL` | TCP/DoT connection pool | server/client/{tcppool,quicpool}.go |
| `LATENCY`, `STATS`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `RATELIMIT`, `PTR`, `PANIC` | One component each | respective files |

**Rules**: Prefix matches logical component, not Go package. No `HIJACK:`/`DNSSEC:` (merged→`SECURITY:`), no `DOT:`/`DOQ:`/`DOH:` (merged→`TLS:`). Hot-path logs are `Debug` only — `Warn`/`Info` on the query path would spam at scale.

## Notable Design Decisions

- **TLS config isolation**: `server/client/client.go` clones TLS configs per-query to prevent
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
- **RFC 7766 TCP/DoT pipelining**: Client pools `Conn` per upstream,
  multiplexing queries over shared TCP/DoT connections. Each connection runs a
  reader goroutine that dispatches responses by DNS message ID to waiting callers.
  Server processes TCP queries concurrently via async handler dispatch (plain TCP)
  or three-stage reader→worker→writer pipeline (DoT). Falls back to single-shot
  `ExchangeContext` when pipelining is not supported by the peer.
- **DoQ connection pool** (`server/client/quicpool.go`): Pools up to 4 QUIC
  connections per upstream. Multiple goroutines share connections via QUIC's
  native stream multiplexing — no capacity semaphore needed.
- **Config self-sufficiency**: `config.ProjectName` and `config.Version` are
  package-level vars set by `main.go` before calling `config.Loader.LoadConfig()`.
