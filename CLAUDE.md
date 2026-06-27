# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development

```bash
# Build
go build -o zjdns

# Build with version info
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns

# Install git pre-commit hook (lint fmt + run)
cp scripts/pre-commit .git/hooks/ && chmod +x .git/hooks/pre-commit

# Lint
golangci-lint run && golangci-lint fmt
```

### Debug Test Config

`config.debug.json` is the local test configuration (not committed):

```json
{
  "server": {
    "port": "15353",
    "log_level": "debug",
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "cache": {
        "size": 4194304,
        "persist": {
          "file": "/tmp/zjdns-cache.snapshot",
          "interval": 5
        }
      },
      "latency_probe": [
        { "protocol": "ping", "timeout": 100 },
        { "protocol": "tcp", "port": 53, "timeout": 100 },
        { "protocol": "udp", "port": 53, "timeout": 100 }
      ]
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

Key points:
- Port 15353 (non-privileged, avoids conflicts with system DNS)
- Pure recursive mode (`builtin_recursive`, no external upstreams)
- Cache snapshot at `/tmp/zjdns-cache.snapshot` with 5s persist interval
- Latency probe enabled for verifying both client-facing and infrastructure probe paths
- Debug log level for full visibility into resolution, caching, and latency sorting

Start server: `./zjdns -config config.debug.json`
Test query: `dig @127.0.0.1 -p 15353 baidu.com A +short`

Test suites exist for `cache`, `cidr`, `config`, `edns`, `rewrite`, `stats`, `internal/dnsutil`, `internal/latency`, `internal/pool`, `server/resolver`, and `server/security` packages (90+ test cases + 19 benchmarks). Module path: `zjdns` (Go 1.25). Zero `golangci-lint` warnings.

Target coverage: ≥90% for utility packages (`dnsutil` 95.7%, `pool` 91.3%). New test suites added for `cache`, `config`, `stats`.

Run benchmarks: `go test -bench=. -short ./...` (unit) or `go test -bench=BenchmarkServerProcessQuery -benchtime=3s .` (QPS).

## Package Structure

```
zjdns/
├── main.go / version.go           # Entry point + ldflags variables
├── bench_test.go                  # Global benchmarks (pool, cache, DNSSEC, QPS)
├── internal/
│   ├── log/log.go                 # Logger, TimeCache, Level.String()
│   ├── pool/pool.go               # MessagePool, BufferPool, constants (zero deps)
│   ├── dnsutil/dnsutil.go         # NormalizeDomain, IsSecureProtocol, HandlePanic, etc.
│   ├── ipdetect/ipdetect.go       # Public IP detection for auto ECS
│   └── latency/                   # Unified latency probing engine (4 files)
│       ├── prober.go              # Prober, probeSlice[T] generic sorter, dedup, concurrency
│       ├── probes.go              # ICMP/TCP/UDP/HTTP/HTTPS/HTTP3 probe implementations
│       ├── dedup.go               # Probe result dedup cache (FNV hash, TTL-based)
│       └── httppool.go            # HTTP/HTTPS/HTTP3 client pool (per-proto port caching)
├── config/                         # Configuration system (2 files)
│   ├── config.go                   # Types + loader + validation + DDR/CHAOS + JoinDNSPort helper
│   └── defaults.go                 # All tunable runtime defaults (ports, timeouts, limits)
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
    ├── handler.go                # Query pipeline, cache hit/miss, response builders
    ├── client/                    # Outbound query execution + connection pools
    │   ├── client.go              # Client struct, ExecuteQuery, routing
    │   ├── tcp.go                 # Traditional UDP/TCP + TCP fallback
    │   ├── dot.go                 # DoT via pipelined pool
    │   ├── doq.go                 # DoQ via QUIC pool
    │   ├── doh.go                 # DoH via HTTP/2 transport
    │   ├── doh3.go                # DoH3 via HTTP/3 transport
    │   ├── doh_request.go          # Shared DoH/DoH3 HTTP request builder
    │   ├── socks5.go               # SOCKS5 proxy client (RFC 1928/1929, TCP+UDP)
    │   ├── ktls.go                 # KTLS config builders + DoT dial/exchange helpers
    │   └── pool/                  # Connection pool sub-package
    │       ├── tcp.go             # RFC 7766 pipelined TCP/DoT pool (Conn, Pool)
    │       └── quic.go            # QUIC connection pool (QUICPool, QUICConn)
    ├── resolver/                  # DNS resolution strategies
    │   ├── resolver.go            # Resolver struct, routing + helpers
    │   ├── upstream.go            # First-win concurrent upstream queries
    │   ├── recursive.go           # Recursive root→TLD→auth walk
    │   ├── recursive.go           # Recursive root→TLD→auth walk + CNAME chain resolution
    │   ├── dnssec_chain.go        # DNSSEC trust chain + zone cut detection (isZoneCut, getZoneCutSigner, resolveZoneCut)
    │   ├── nameserver.go          # Concurrent NS querying, suspicious response handling
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
    ├── latency/                    # Client-facing latency probe adapter
    │   └── probe.go                # Thin adapter delegating to internal/latency; SortIPsByLatency + InitInfraProber
```

### Dependency Graph

```
main ──→ server, config
server ──→ cache, cidr, config, edns, dnsutil, log, pool, rewrite, latency(server), resolver, security, stats,
client ──→ config, edns, dnsutil, log, pool, pool (in client), go-extension/tls
resolver ──→ config, edns, client, security, dnsutil, latency(server), log, pool
security ──→ dnsutil, log
tls (in server) ──→ config, dnsutil, log, pool, connpool (client/pool), go-extension/tls
cache ──→ config, edns, dnsutil, log
edns ──→ dnsutil, ipdetect, log, pool
cidr ──→ config, dnsutil, log
rewrite ──→ config, dnsutil, log
stats ──→ cache, config, log
latency (server) ──→ config, edns, dnsutil, latency(internal), log
latency (internal) ──→ config, dnsutil, log
dnsutil ──→ log
pool, log ──→ (zero deps)

No circular dependencies. Sub-packages only import what they need.
```

## Architecture

ZJDNS is a high-performance recursive DNS server supporting DoT, DoQ, DoH, DoH3.

**Query processing pipeline** (`server/handler.go:processDNSQuery`):
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
| `config.Loader` | `config` | Config loader (LoadConfig) |
| `edns.Handler` | `edns` | EDNS option parsing/construction |
| `cidr.Filter` | `cidr` | IP filtering (New, MatchIP) |
| `rewrite.Evaluator` | `rewrite` | Domain rewrite (New, LoadRules, Evaluate) |
| `cache.Store` | `cache` | Store interface (Get, Set, SetWithDNSSEC, SetEntry, ReverseLookup, Close) |
| `stats.Collector` | `stats` | Lock-free metrics (RecordRequest, Snapshot) |
| `Server` | `server` | Core server (New, Start) |
| `Server` | `server/tls` | TLS listener server (DoT, DoQ, DoH, DoH3) |
| `Prober` | `internal/latency` | Unified latency probe engine (generic sorter, dedup, HTTP pool) |
| `Prober` | `server/latency` | Thin adapter: cache reordering, SortIPsByLatency, InitInfraProber |
| `DedupCache` | `internal/latency` | Probe result dedup cache (FNV hash, TTL-based eviction) |
| `Client` | `server/client` | Outbound DNS client (UDP, TCP, DoT, DoQ, DoH, DoH3, SOCKS5 proxy) |
| `Socks5Dialer` | `server/client` | SOCKS5 proxy dialer (RFC 1928 TCP CONNECT + UDP ASSOCIATE, RFC 1929 auth) |
| `Conn` | `server/client/pool` | Multiplexed TCP/DoT connection (RFC 7766) |
| `Pool` | `server/client/pool` | TCP/DoT connection pool |
| `QUICPool` | `server/client/pool` | QUIC connection pool |
| `QUICConn` | `server/client/pool` | Wrapped QUIC connection |
| `Resolver` | `server/resolver` | DNS resolution (upstream + recursive) |
| `Recursive` | `server/resolver` | Built-in recursive resolver |
| `Guard` | `server/security` | DNSSEC + hijack detection |
| `Validator` | `server/security` | DNSSEC record-presence validation (RecordPresence) |
| `CryptoValidator` | `server/security` | Full cryptographic DNSSEC (RRSIG, DS, trust anchors) |
| `Detector` | `server/security` | DNS hijack detection |
| `DNSSECError` | `server/resolver` | Typed error with RFC 8914 EDE code |
| `dnssecEDEError` | `server/resolver` | Shared constructor for DNSSECError from EDE code |
| `dnssecChain` | `server/resolver` | Trust chain state (zoneDNSKEYs, childDS, lastEDECode, zoneCutDetected) |
| `ensureZoneDNSKEYs` | `server/resolver` | Explicit DNSKEY fetch at delegation steps |
| `resolveZoneCut` | `server/resolver` | Builds DNSSEC chain for delegated child zone on-the-fly |
| `isZoneCut` / `getZoneCutSigner` | `server/resolver` | Detects when answer RRSIGs are signed by child zone keys |
| `MessagePool` / `BufferPool` | `pool` | sync.Pool-based message and buffer allocators |
| `config.JoinDNSPort` | `config` | Helper: `net.JoinHostPort(ip, DefaultDNSPort)` |
| `recordDNSSECFailure` | `server/resolver` | Records EDE code + checks enforcement; eliminates 3x duplicated pattern |
| `captureUpstreamEDE` | `server/resolver` | Single-point EDE extraction from upstream responses |

## Key Constants

All tunable runtime defaults are centralized in `config/defaults.go`. **All numeric literals
(port numbers, buffer sizes, timeouts, limits) must be defined as named `const` or `var` —
never hardcoded inline.** When adding a new value, check if an existing constant already
covers it; if not, add one to `config/defaults.go` with a descriptive `Default` prefix.
Leaf utility packages that cannot import `config` (due to the dependency graph — see
the "Dependency Graph" section) should use local `const` blocks with the same naming
convention.

| Constant | Package | Value |
|----------|---------|-------|
| `config.DefaultDNSQueryTimeout` | config | 10s (single DNS query / dial / per-message I/O) |
| `config.DefaultBackgroundTimeout` | config | 10s (bounded wait for background tasks / shutdown) |
| `config.DefaultRecursiveResolveTimeout` | config | 30s (full recursive resolution) |
| `config.DefaultHTTPServerIdleTimeout` | config | 60s (HTTP keep-alive) |
| `config.DefaultHTTPServerWriteTimeout` | config | 10s (DoH response write) |
| `config.DefaultHTTPReadHeaderTimeout` | config | 5s (Slowloris protection) |
| `config.DefaultQUICClientIdleTimeout` | config | 60s (client QUIC idle, must exceed KeepAlive) |
| `config.DefaultQUICServerIdleTimeout` | config | 30s (server QUIC idle, RFC 9000 default) |
| `config.DefaultQUICKeepAlive` | config | 20s (QUIC keep-alive period) |
| `config.DefaultH2ReadIdleTimeout` | config | 30s (HTTP/2 ping keep-alive) |
| `config.DefaultHTTPIdleConnTimeout` | config | 5 min (HTTP transport idle) |
| `config.DefaultShutdownTimeout` | config | 15s (graceful shutdown deadline) |
| `config.DefaultCACertValidity` | config | 45 days (CA self-signed cert lifetime) |
| `config.DefaultServerCertValidity` | config | 45 days (server self-signed cert lifetime) |
| `config.DefaultCertExpiryWarnDays` | config | 14 (certificate expiry warning threshold, days) |
| `config.DefaultPrefetchThrottleInterval` | config | 3s (prefetch cooldown) |
| `config.DefaultAcceptRetryDelay` | config | 100ms (DoT/DoQ accept retry sleep) |
| `config.DefaultSweepInterval` | config | 5 min (periodic cleanup sweep) |
| `config.DefaultTTL` | config | 10 |
| `config.DefaultCacheSize` | config | 4 MB (4 * 1024 * 1024) |
| `config.DefaultStaleTTL` | config | 30s (TTL returned for expired entries) |
| `config.DefaultStaleMaxAge` | config | 30 days (max age for serve-expired, RFC 8767 §6) |
| `config.MaxDomainLength` | config | 253 |
| `config.DefaultMaxPipe` | config | 16 (max in-flight queries per connection) |
| `config.DefaultMaxConns` | config | 4 (max connections per upstream) |
| `config.DefaultMaxCNAMEChain` | config | 16 (CNAME redirection limit) |
| `config.DefaultMaxRecursionDepth` | config | 16 (recursion depth limit) |
| `config.DefaultMaxIncomingStreams` | config | 256 (QUIC stream limit) |
| `config.DefaultMaxProbes` | config | 16 (concurrent latency probes) |
| `config.DefaultNSLatencyTTL` | config | 900s (nsAddrKey TTL — NS latency sort refresh) |
| `config.DefaultLatencyProbeTimeout` | config | 100ms (per-step probe timeout) |
| `config.DefaultMaxNSEC3Iterations` | config | 150 (NSEC3 iteration cap, RFC 5155) |
| `config.DefaultSecureTransportRetries` | config | 2 (DoH/DoH3 retry count) |
| `config.DefaultTokenStoreCapacity` | config | 4 (QUIC LRU token store capacity per key) |
| `config.DefaultTokenStoreMaxEntries` | config | 10 (QUIC LRU token store max entries) |
| `config.DefaultStatsInterval` | config | 3600 (stats collection interval) |
| `config.DefaultStatsResetInterval` | config | 86400 (stats reset interval) |
| `config.DefaultTransportMax` | config | 32 (max cached transports/configs per type) |
| `config.DefaultTLSSessionCacheSize` | config | 32 (client TLS session cache entries) |
| `config.DefaultRewriteRulesCapacity` | config | 16 (rewrite rule slice pre-allocation) |
| `config.GroupOtherPermMask` | config | 0077 (TLS cert/key file permission check) |
| `config.RecursiveIndicator` | config | "builtin_recursive" (sentinel for built-in recursive mode) |
| `config.DNSSECStatusSecure` | config | "secure" (DNSSEC validation status constant) |
| `config.DNSSECStatusInsecure` | config | "insecure" |
| `config.DNSSECStatusBogus` | config | "bogus" |
| `config.DoHContentType` | config | "application/dns-message" (RFC 8484) |
| `config.ProtoUDP` / `ProtoTCP` / `ProtoTLS` | config | "udp" / "tcp" / "tls" (protocol identifiers) |
| `config.ProtoQUIC` / `ProtoHTTP` / `ProtoHTTP3` | config | "quic" / "https" / "http3" |
| `config.NextProtoDOT` | config | []string{"dot"} (ALPN for DoT) |
| `config.NextProtoDOH` | config | []string{"h2"} (ALPN for DoH) |
| `config.NextProtoDOQ` | config | []string{"doq"} (ALPN for DoQ) |
| `config.NextProtoDOH3` | config | []string{"h3"} (ALPN for DoH3) |
| `config.DefaultProxyScheme` | config | "socks5" (SOCKS5 proxy scheme) |
| `config.DefaultProxyPort` | config | "1080" (SOCKS5 proxy default port) |
| `config.DefaultProbePortDNS` | config | 53 (latency probe DNS port) |
| `config.DefaultProbePortHTTP` | config | 80 (latency probe HTTP port) |
| `config.DefaultProbePortHTTPS` | config | 443 (latency probe HTTPS port) |
| `pool.UDPBufferSize` | pool | 1232 |
| `pool.SecureBufferSize` | pool | 8192 |
| `dnsutil.DNSFramePrefixLen` | dnsutil | 2 (DNS TCP/DoT/DoQ length prefix, RFC 1035 §4.2.2) |

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
| `SERVER` | Server lifecycle | server/server.go, server/handler.go, main.go |
| `EDNS` | EDNS options | edns/*.go, server/server.go |
| `RECURSION` | Recursive resolution | server/resolver/{recursive,dnssec_chain,nameserver,zonecut}.go |
| `SECURITY` | DNSSEC, hijack detection | server/security/*.go, server/resolver/{dnssec_chain,zonecut}.go |
| `TCPPOOL` | TCP/DoT connection pool | server/client/pool/{tcp,quic}.go |
| `LATENCY`, `STATS`, `CONFIG`, `REWRITE`, `CIDR`, `PPROF`, `QUERY`, `RESULT`, `SIGNAL`, `PTR`, `PANIC` | One component each | respective files |

**Rules**: Prefix matches logical component, not Go package. No `HIJACK:`/`DNSSEC:` (merged→`SECURITY:`), no `DOT:`/`DOQ:`/`DOH:` (merged→`TLS:`). Hot-path logs are `Debug` only — `Warn`/`Info` on the query path would spam at scale.

## Notable Design Decisions

- **TLS config isolation**: `server/client/client.go` clones TLS configs per-query to prevent
  concurrent requests with different `InsecureSkipVerify`/`ServerName` from
  cross-contaminating each other.
- **Cache persistence**: Full DNS records persisted as gob-encoded blobs (`.RR`
  interface fields zeroed before encoding to avoid type-registration errors);
  metadata (timestamps, ECS) kept in memory for fast expiry checks.
- **Cache TTL floor**: `minTTL` enforces a minimum TTL of 10s (`DefaultTTL`) to
  ensure cached entries have a useful lifetime; no upper bound is enforced.
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
- **Lock-free stats**: All counters use `atomic.Uint64` on the hot path;
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
- **Zone cut detection** (`isZoneCut`): When the recursive resolver queries an
  authoritative server and receives an answer signed by a child zone's DNSKEY
  (RRSIG signer name is a proper subdomain of `currentDomain`), the answer is
  processed via `resolveZoneCut()` instead of failing validation. This function
  queries the child zone's DS and DNSKEY records directly, verifies the chain
  of trust against the parent zone's verified keys, and validates the original
  answer against the child zone's DNSKEYs. This handles cases where the same
  server hosts both parent and child zones (e.g. sigok.ippacket.stream).
- **Lame delegation detection**: When a non-authoritative response has NS records
  pointing back to the same zone (`bestMatch == currentDomain` without AA flag),
  the server returns SERVFAIL with EDE 22 (No Reachable Authority) instead of
  silently accepting the response. Matches Cloudflare/Google behavior.
- **NSEC/NSEC3 validation for NODATA**: Negative responses (no answer section)
  have their NSEC/NSEC3 records cryptographically verified against the zone's
  DNSKEYs before setting the AD flag (RFC 4035 §3.1.3).
- **BufferPool pointer storage**: Buffers are stored as `*[]byte` pointers in
  `sync.Pool` to avoid interface-boxing allocations on every `Put` (SA6002).
- **Unified latency probe engine** (`internal/latency`): All latency probing
  (user-facing A/AAAA reorder + infrastructure root/NS server ordering) shares a
  single engine with generic `probeSlice[T]` sorting, FNV-hash dedup cache (avoids
  redundant probes within TTL), HTTP/HTTPS/HTTP3 client pool reuse, and
  context-cancellable goroutine workers with bounded semaphore. The `server/latency`
  package is now a thin adapter: it holds the `CacheSetter` interface for cache
  reordering and provides `InitInfraProber()` for infrastructure-level probes.
  `SortIPsByLatency` delegates directly to the internal engine.
- **ICMP probe hardening**: Echo ID and Seq are randomly generated per probe; the
  response loop verifies both fields match before accepting a reply, preventing
  concurrent probes to the same IP from stealing each other's echo replies.
- **UDP probe is generic**: All ports send a single zero-byte datagram (valid per
  RFC 768 §3.1) for universal compatibility regardless of target service.
- **persistGen fix**: Cache persistence worker uses `Load()` + `Add(-gen)` instead
  of `Swap(0)` + `Add(gen)`, preserving Set() increments that arrive during
  `persistSnapshot()`.
- **EDE capture unified**: `captureUpstreamEDE()` extracts EDE from upstream
  responses once per query, replacing 3 identical code blocks across rcode cases.
- **DNSSEC enforcement extracted**: `recordDNSSECFailure()` consolidates the
  repeated pattern of storing the EDE code and checking `dnssec_enforce`, used
  across zone cut and delegation validation paths.
- **DoQ IP count sweep**: A periodic goroutine sweeps stale (zero-count) entries
  from `doqIPCounts` every 5 minutes to prevent unbounded map growth.
- **pprof fix**: Added `_ "net/http/pprof"` import so the pprof HTTP server
  actually registers its debug endpoints on `http.DefaultServeMux`.
- **Kernel TLS (KTLS) offload**: Client and server TCP-based TLS (DoT, DoH) use
  `gitlab.com/go-extension/tls` (drop-in `crypto/tls` replacement) with `KernelTX`/`KernelRX`
  enabled. `server/tls/tls.go` holds dual configs from the same cert — go-extension
  for TCP listeners, crypto/tls for QUIC. Client uses `DialTLSContext → eTLS.Client()`.
  KTLS is silently skipped on non-Linux or when the kernel
  TLS module is absent; QUIC (DoQ/DoH3) does not support KTLS (requires TCP).
- **SOCKS5 proxy support** (`server/client/socks5.go`): Per-upstream optional SOCKS5 proxy
  (`socks5://[user:pass@]host:port`) routes all outbound DNS queries through the proxy.
  TCP CONNECT for stream protocols (TCP, DoT, DoH) and UDP ASSOCIATE for datagram protocols
  (UDP, DoQ, DoH3). Connected UDP socket to relay (mosdns-x pattern) avoids stray datagrams.
  Pool keys include proxy URL for isolation. Built-in recursive resolver also goes through
  proxy when `builtin_recursive` upstream has `proxy` set. Zero overhead on non-proxy path.
- **Shared DNS frame prefix**: `dnsutil.DNSFramePrefixLen = 2` is the canonical
  constant for the 2-byte DNS-over-TCP/DoT/DoQ length prefix (RFC 1035 §4.2.2,
  RFC 9250). All frame read/write code in `dot.go`, `doq.go` (server+client),
  and `pool/tcp.go` uses this constant. Helper functions `WriteDNSFrame`/`ReadDNSFrame`
  in `dnsutil` provide shared frame I/O.
- **Protocol identifier constants**: `config.ProtoUDP`, `ProtoTCP`, `ProtoTLS`,
  `ProtoQUIC`, `ProtoHTTP`, `ProtoHTTP3` replace all hardcoded `"udp"`, `"tcp"`, etc.
  across the codebase. Used for `dns.Server.Net`, `net.Dialer`, upstream routing,
  and protocol comparisons. Transport aliases (`"dot"`/`"tls"`, `"doq"`/`"quic"`,
  `"doh"`/`"https"`, `"doh3"`/`"http3"`) in `executeSecureQuery` remain as switch
  labels since they represent user-facing config values that map to the same transport.
- **DNSSEC status constants**: `config.DNSSECStatusSecure`/`Insecure`/`Bogus` replace
  hardcoded `"secure"`, `"insecure"`, `"bogus"` strings in `handler.go` (12 sites)
  and `stats.go` (3 sites), ensuring consistent spelling across validation and metrics.
- **QUIC type naming**: Exported types use all-caps acronym per Go convention:
  `QUICConn`, `QUICPool`, `NewQUICPool` (not `QuicConn`/`QuicPool`). ALPN protocol
  vars follow the same rule: `NextProtoDOH`, `NextProtoDOQ`, `NextProtoDOH3`
  (consistent with `NextProtoDOT`).
