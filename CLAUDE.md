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

Test suites exist for `cidr`, `edns`, `rewrite`, and `server/security` packages (37 test cases). Module path: `zjdns` (Go 1.25). Zero `golangci-lint` warnings.

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
└── server/                        # Core server + sub-packages
    ├── server.go                  # Server lifecycle, New(), Start(), shutdown
    ├── server_handlers.go         # Query pipeline, cache hit/miss, response builders
    ├── client/                    # Outbound query execution + connection pools
    │   ├── client.go              # Client struct, ExecuteQuery, routing
    │   ├── tcp.go                 # Traditional UDP/TCP + TCP fallback
    │   ├── dot.go                 # DoT via pipelined pool
    │   ├── doq.go                 # DoQ via QUIC pool
    │   ├── doh.go                 # DoH via HTTP/2 transport
    │   ├── doh3.go                # DoH3 via HTTP/3 transport
    │   ├── doh_request.go          # Shared DoH/DoH3 HTTP request builder
    │   └── pool/                  # Connection pool sub-package
    │       ├── tcp.go             # RFC 7766 pipelined TCP/DoT pool (Conn, Pool)
    │       └── quic.go            # QUIC connection pool (QuicPool, QuicConn)
    ├── resolver/                  # DNS resolution strategies
    │   ├── resolver.go            # Resolver struct, routing + helpers
    │   ├── upstream.go            # First-win concurrent upstream queries
    │   ├── recursive.go           # Recursive root→TLD→auth walk
    │   └── cname.go               # CNAME chain resolution
    ├── security/                  # Security features (4 files)
    │   ├── security.go            # Guard (bundles RecordPresence + CryptoValidator + Detector)
    │   ├── dnssec.go              # DNSSEC record-presence validation (upstream AD check)
    │   ├── dnssec_crypto.go       # Full cryptographic DNSSEC validation (RRSIG, DS, trust anchors)
    │   └── hijack.go              # Hijack detection + TCP fallback trigger
    ├── tls/                        # Secure transport listeners
    │   ├── tls.go                  # Server struct, cert management, Start/Shutdown
    │   ├── dot.go                  # DoT listener + per-connection handler
    │   ├── doq.go                  # DoQ listener + stream handler
    │   └── doh.go                  # DoH/DoH3 HTTP handlers
    ├── latency/                    # Latency probing
    │   └── probe.go                # A/AAAA latency probing + reordering
    └── ratelimit/                  # Per-IP token bucket rate limiter
        └── ratelimit.go            # Limiter (sharded, FNV-1a hash)
```

### Dependency Graph

```
main ──→ server, config
server ──→ cache, cidr, config, edns, dnsutil, ipdetect, log, pool, rewrite,
│          stats, client, ratelimit, resolver, security
client ──→ config, edns, dnsutil, log, pool, pool (in client)
resolver ──→ config, edns, client, security, dnsutil, log, pool
security ──→ dnsutil, log
ratelimit ──→ log
tls (in server) ──→ config, dnsutil, log, pool, pool (in client)
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
6. `Guard` — DNSSEC validation (crypto chain-of-trust + record-presence), hijack detection (UDP→TCP fallback)
7. `cidr.Filter.MatchIP()` — filter A/AAAA IPs; all filtered → REFUSED + EDE
8. Populate cache, start latency probes, return response

**Query routing** (`server/resolver/resolver.go:Resolver.Query`):
- Upstream servers configured → concurrent first-win query; fallback on failure
- No upstream → built-in recursive resolver (root→TLD→authoritative walk)
- NXDOMAIN stored as secondary fallback; first NOERROR wins

**TCP/DoT pipelining** (`server/client/pool/tcp.go`, RFC 7766):
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
| `Conn` | `server/client/pool` | Multiplexed TCP/DoT connection (RFC 7766) |
| `Pool` | `server/client/pool` | TCP/DoT connection pool |
| `QuicPool` | `server/client/pool` | QUIC connection pool |
| `QuicConn` | `server/client/pool` | Wrapped QUIC connection |
| `Resolver` | `server/resolver` | DNS resolution (upstream + recursive) |
| `Recursive` | `server/resolver` | Built-in recursive resolver |
| `Guard` | `server/security` | DNSSEC + hijack detection |
| `Validator` | `server/security` | DNSSEC record-presence validation (RecordPresence) |
| `CryptoValidator` | `server/security` | Full cryptographic DNSSEC (RRSIG, DS, trust anchors) |
| `Detector` | `server/security` | DNS hijack detection |
| `DNSSECError` | `server/resolver` | Typed error with RFC 8914 EDE code |
| `dnssecEDEError` | `server/resolver` | Shared constructor for DNSSECError from EDE code |
| `dnssecChain` | `server/resolver` | Trust chain state during recursive resolution |
| `ensureZoneDNSKEYs` | `server/resolver` | Explicit DNSKEY fetch at delegation steps |
| `Limiter` | `server/ratelimit` | Per-IP token bucket rate limiter |

## Key Constants

| Constant | Package | Value |
|----------|---------|-------|
| `config.IdleTimeout` | config | 4s |
| `config.DefaultTTL` | config | 10 |
| `config.DefaultMaxTTL` | config | 86400 |
| `config.DefaultCacheSize` | config | 16384 |
| `config.MaxDomainLength` | config | 253 |
| `config.RecursiveIndicator` | config | "builtin_recursive" |
| `cache.StaleMaxAge` | cache | 45 days |
| `pool.UDPBufferSize` | pool | 1232 |
| `server.OperationTimeout` | server | 3s |
| `client.OperationTimeout` | server/client/pool | 3s |
| `client.DefaultMaxPipe` | server/client/pool | 16 (max in-flight queries per connection) |
| `client.DefaultMaxConns` | server/client/pool | 4 (max connections per upstream) |
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
| `TCPPOOL` | TCP/DoT connection pool | server/client/pool/{tcp,quic}.go |
| `LATENCY`, `STATS`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `RATELIMIT`, `PTR`, `PANIC` | One component each | respective files |

**Rules**: Prefix matches logical component, not Go package. No `HIJACK:`/`DNSSEC:` (merged→`SECURITY:`), no `DOT:`/`DOQ:`/`DOH:` (merged→`TLS:`). Hot-path logs are `Debug` only — `Warn`/`Info` on the query path would spam at scale.

## Notable Design Decisions

- **TLS config isolation**: `server/client/client.go` clones TLS configs per-query to prevent
  concurrent requests with different `InsecureSkipVerify`/`ServerName` from
  cross-contaminating each other.
- **Cache persistence**: Full DNS records persisted as gob-encoded blobs (`.RR`
  interface fields zeroed before encoding to avoid type-registration errors);
  metadata (timestamps, ECS) kept in memory for fast expiry checks.
- **Cache TTL bounds**: `minTTL` enforces both minimum (10s) and maximum (86400s)
  TTL to prevent cache-poisoned entries with extreme TTLs from persisting forever.
- **Cache Get path**: Returns entry pointer directly (no deep-copy) — `expand()`
  is non-mutating (parses from `.Text` on every call), so concurrent readers
  sharing CompactRecords cannot race. Deep-copy reserved for write path only.
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
- **DoQ connection pool** (`server/client/pool/quic.go`): Pools up to 4 QUIC
  connections per upstream. Multiple goroutines share connections via QUIC's
  native stream multiplexing — no capacity semaphore needed.
- **Config self-sufficiency**: `config.ProjectName` and `config.Version` are
  package-level vars set by `main.go` before calling `config.Loader.LoadConfig()`.
- **DNSSEC chain-of-trust**: `CryptoValidator` embeds IANA root KSK trust anchors
  (key tags 20326 + 38696). The recursive resolver builds a cryptographic chain at
  each delegation step: queries parent zone for DNSKEY, verifies against trust
  anchors (root) or parent DS (non-root), then verifies child DS RRSIGs against
  verified parent DNSKEYs, queries child for DNSKEY matching verified DS, and
  finally verifies answer RRSIGs against child DNSKEY. `ensureZoneDNSKEYs()` 
  explicitly fetches DNSKEY records at each delegation step (delegation responses
  do not carry DNSKEY records). `dnssec_enforce: true` returns SERVFAIL on bogus
  delegations (e.g. dnssec-failed.org); `false` passes through without AD flag.
- **NSEC/NSEC3 verified denial**: `validateNXDOMAIN` and `validateNODATA`
  cryptographically verify RRSIGs over NSEC/NSEC3 records using the zone's
  verified DNSKEYs (RFC 5155 §8). Unsigned NSEC3 records are rejected.
- **SelfVerifyDNSKEY root-only**: `validateWithDNSSEC` only accepts self-signed
  DNSKEY RRsets for the root zone (`currentDomain == "."`). Non-root zones must
  authenticate via DS from the verified parent.
- **Upstream DNSSEC**: Non-recursive (forwarder) mode trusts the upstream
  resolver's AD flag when accompanied by DNSSEC records. Validation result
  logged at Debug level; AD flag propagated to clients and cache.
- **EDE propagation**: DNSSEC failure EDE codes are stored atomically on
  `Recursive.lastDNSSECEDECode` and read directly by `processQueryError` to avoid
  error-chain corruption from context cancellation. Upstream SERVFAIL responses
  with DNSSEC EDE codes (1-12) are captured and propagated as DNSSECError.
- **Glue record validation**: Glue A/AAAA records from delegation responses are
  validated against the parent zone (the zone that published the delegation),
  rejecting out-of-bailiwick glue. Glue is used directly when available;
  independent NS resolution is the fallback only when glue is absent.
- **DNSKEY cache lifecycle**: `GetZoneKeys` uses a dual-lock pattern (RLock for
  fast path, Lock with re-read for expiry) to prevent TOCTOU races with
  `CacheZoneKeys`. A background goroutine sweeps expired entries every 5 minutes;
  `Guard.Close()` terminates the sweeper on shutdown.
- **BufferPool pointer storage**: Buffers are stored as `*[]byte` pointers in
  `sync.Pool` to avoid interface-boxing allocations on every `Put` (SA6002).
