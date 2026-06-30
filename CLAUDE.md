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
   with a descriptive message to prevent data loss.
10. Present changes for review before committing. Do not commit automatically
    after each fix — wait for user confirmation.

## Coding Standards

### Naming

- **PascalCase for all exported types**: `KTLSSettings`, `TLSSettings`, not
  `KTLSsettings`. Acronyms are all-caps (URL, IP, TLS, DNS, QUIC).
- **Package-level functions over empty structs**: A type with no fields (e.g. `type Loader struct{}`)
  should be eliminated — use package-level functions instead.

### Performance (Hot Path)

- **Use `log.NowUnix()` / `log.NowUnixNano()` instead of `time.Now()`** in hot paths
  (cache TTL checks, DNSSEC RRSIG validation, last-access timestamps, cooldown maps).
  The `TimeCache` updates once per second via `atomic.Value` — sufficient for TTL
  expiry (second granularity) and ordering (eviction, cooldown). Use real `time.Now()`
  only when sub-second precision is required (metrics timing, write deadlines, nonces).
- **Avoid `fmt.Sprintf` on the query path**: use `strings.Builder` for map keys
  (transport keys, cache keys), string concatenation for simple joins, `strconv.Itoa`
  over `fmt.Sprint` for integers.
- **Use `strconv.Itoa` not `fmt.Sprint` for int→string** conversion.
- **Protocol string normalization**: `strings.ToUpper(strings.TrimSpace(protocol))` on every
  query is wasteful. Use a byte-prefix switch — all protocol strings are well-known constants.
- **Zero-allocation string trimming**: prefer sub-slicing (`s[:len(s)-1]`) over
  `strings.TrimSuffix` when the suffix is a single known byte — it does not allocate.
- **`slices.SortStableFunc` over `sort.SliceStable`**: the generics-based version avoids
  reflect-based closure dispatch per comparison. Use the `cmp(a, b) int` signature.

### Concurrency

- **Channel close safety**: never `close(ch)` in a `defer` of a goroutine that shares
  the channel with external callers. Close the channel inside the same `sync.Once`
  that closes the underlying resource, so double-close is impossible.
- **Hoist fixed-size allocations out of loops**: `make([]byte, 2)` in a connection
  read loop allocates per frame — move it before the loop.

### Constants

- **No duplicate constants in the same package**: identical values (e.g. ML-KEM
  ciphertext size 1088) defined in multiple files must be unified into a single
  definition.
- **All magic numbers must be named constants**: even "obvious" values like `64`
  (padding alignment) must have descriptive names.
- **Leaf packages that cannot import `config`** (due to dependency graph) may use
  local `const` blocks; all other numeric/timing defaults belong in
  `config/defaults.go` with a `Default` prefix.

### Anti-patterns (DO NOT implement)

- **No rate limiting**: Do not add per-client rate limiters, token buckets, or
  query throttling. The server should accept all queries unconditionally.
- **No per-IP connection limiting**: Do not add MaxConnsPerIP or any per-address
  connection counters. All listeners accept unlimited connections.

### Build & ldflags

- `version.go` vars (`CommitHash`, `BuildTime`) default to empty strings, not
  `"dirty"` / `"dev"`. `getVersion()` gracefully omits them when unset, producing
  `v2.0.0 (go1.26.0)` instead of `v2.0.0-dirty@dev (go1.26.0)`.

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
        "size": 0
      }
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
- Cache disabled (`size: 0`) to see fresh resolution every query
- Debug log level for full visibility into resolution and hijack detection

Start server: `./zjdns -config config.debug.json`

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

Test suites for `cache`, `cidr`, `config`, `edns`, `rewrite`, `stats`, `internal/dnsutil`, `internal/latency`, `internal/pool`, `server/resolver`, and `server/security` packages (90+ test cases + 19 benchmarks). Module path: `zjdns` (Go 1.26). Zero `golangci-lint` warnings.

Target coverage: ≥90% for utility packages (`dnsutil` 95.7%, `pool` 91.3%).

Run benchmarks: `go test -bench=. -short ./...` (unit) or `go test -bench=BenchmarkServerProcessQuery -benchtime=3s .` (QPS).

## Package Structure

```
zjdns/
├── main.go / version.go           # Entry point + ldflags variables
├── bench_test.go                  # Global benchmarks (pool, cache, DNSSEC, QPS)
├── cli/                           # CLI helper functions (3 files)
│   ├── parse.go                   # Flag parsing + -generate-config
│   └── config_example.go          # Example config generator
├── internal/
│   ├── log/log.go                 # Logger, TimeCache, Level.String()
│   ├── pool/pool.go               # MessagePool, BufferPool, constants (zero deps)
│   ├── dnsutil/dnsutil.go         # NormalizeDomain, ValidateDomainLabels, HandlePanic, etc.
│   ├── ipdetect/ipdetect.go       # Public IP detection for auto ECS
│   └── latency/                   # Unified latency probing engine (3 files)
│       ├── prober.go              # Prober, probeSlice[T] generic sorter, concurrency
│       ├── probes.go              # ICMP/TCP/UDP/HTTP/HTTPS/HTTP3 probe implementations
│       └── httppool.go            # HTTP/HTTPS/HTTP3 client pool (per-proto port caching)
├── config/                         # Configuration system (2 files)
│   ├── config.go                   # Types + loader + validation + DDR/CHAOS + JoinDNSPort helper
│   └── defaults.go                 # All tunable runtime defaults (ports, timeouts, limits)
├── edns/                           # EDNS(0) extensions (5 files)
│   ├── edns.go                    # Handler, NewHandler, ApplyToMessage
│   ├── ecs.go                     # ECSOption, DefaultECSConfig, ParseFromDNS
│   ├── cookie.go                  # CookieGenerator, ParseCookie, ValidateServerCookie
│   ├── ede.go                     # EDEOption, 24 error codes
│   └── padding.go                 # RFC 7830 response padding
├── cache/                          # DNS response cache (3 files)
│   ├── cache.go                   # Store interface, CacheEntry, helpers
│   ├── memory.go                  # MemoryCache, eviction, PTR index + sweeper
│   └── persist.go                 # Disk snapshot load/save
├── cidr/cidr.go                   # CIDR Filter — IP filtering with tag matching
├── rewrite/rewrite.go             # Rewrite Evaluator — domain rewrite rules
├── stats/stats.go                 # Lock-free atomic metrics Collector
└── server/                        # Core server + sub-packages
    ├── server.go                  # Server lifecycle, New(), Start(), displayInfo()
    ├── server_tasks.go            # Background tasks, signal handling, shutdown
    ├── handler.go                # Query pipeline, cache hit/miss, response builders
    ├── message.go                # EDNS response helpers, Cookie validation, buildResponse
    ├── client/                    # Outbound query execution + connection pools
    │   ├── client.go              # Client struct, ExecuteQuery, routing
    │   ├── tcp.go                 # Traditional UDP/TCP + TCP fallback
    │   ├── dot.go                 # DoT via pipelined pool
    │   ├── doq.go                 # DoQ via QUIC pool
    │   ├── doh.go                 # DoH via HTTP/2 transport
    │   ├── doh3.go                # DoH3 via HTTP/3 transport
    │   ├── doh_request.go          # Shared DoH/DoH3 HTTP request builder
    │   ├── socks5.go               # SOCKS5 proxy client (RFC 1928/1929, TCP+UDP) + SafeURL
    │   ├── ktls.go                 # KTLS config builders + DoT dial/exchange helpers
    │   └── pool/                  # Connection pool sub-package
    │       ├── tcp.go             # RFC 7766 pipelined TCP/DoT pool (Conn, Pool)
    │       └── quic.go            # QUIC connection pool (QUICPool, QUICConn)
    ├── resolver/                  # DNS resolution strategies
    │   ├── resolver.go            # Resolver struct, routing + helpers
    │   ├── upstream.go            # First-win concurrent upstream queries
    │   ├── recursive.go           # Recursive resolver core (resolve loop + CNAME chase)
    │   ├── recursive_cache.go     # NS address latency-sorted cache + probe helpers
    │   ├── dnssec_chain.go        # DNSSEC trust chain + zone cut detection
    │   ├── nameserver.go          # Concurrent NS querying, suspicious response handling
    ├── dnscrypt/                   # DNSCrypt v2 server (using AdGuardTeam/dnscrypt)
    │   ├── server.go              # Server wrapper: UDP+TCP instances, key gen, lifecycle
    │   └── handler.go             # Handler adapter: dnscrypt.Handler → DNSHandler bridge
    ├── security/                  # Security features (4 files)
    │   ├── security.go            # Guard (bundles RecordPresence + CryptoValidator + Detector)
    │   ├── dnssec.go              # DNSSEC record-presence validation (upstream AD check)
    │   ├── dnssec_crypto.go       # Full cryptographic DNSSEC (RRSIG, DS, trust anchors)
    │   └── hijack.go              # Hijack detection + TCP fallback trigger
    ├── tls/                        # Secure transport listeners
    │   ├── tls.go                  # Server struct, cert management, Start/Shutdown
    │   ├── dot.go                  # DoT listener
    │   ├── doq.go                  # DoQ listener + stream handler
    │   └── doh.go                  # DoH/DoH3 HTTP handlers
    ├── latency/                    # Client-facing latency probe adapter
    │   └── probe.go                # Thin adapter delegating to internal/latency; SortIPsByLatency + InitInfraProber
```

### Dependency Graph

```
main ──→ server, config
server ──→ cache, cidr, config, dnscrypt(server), edns, dnsutil, log, pool, rewrite, latency(server), resolver, security, stats
client ──→ config, edns, dnsutil, log, pool, pool (in client), github.com/AdguardTeam/dnscrypt
resolver ──→ config, edns, client, security, dnsutil, latency(server), log, pool
security ──→ dnsutil, log
server ──→ dnsproxy, dnscrypt
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
1. Server status check → request validation (domain length, label length, ANY/AXFR/IXFR query)
2. `rewrite.Evaluator.Evaluate()` — synthetic response if rule matches
3. `edns.Handler` — extract ECS, DNS Cookie from request
4. Early DNS Cookie validation (RFC 7873) — invalid server cookie → FORMERR immediately
5. `cache.Store.Get()` — hit → serve (with CIDR filtering); miss → continue
6. `Resolver.Query()` — upstream (first-win) or recursive resolution
7. `Guard` — DNSSEC validation (crypto chain-of-trust + record-presence), hijack detection (UDP→TCP fallback)
8. `cidr.Filter.MatchIP()` — filter A/AAAA IPs; all filtered → REFUSED + EDE
9. Populate cache, start latency probes, return response (with server cookie in EDNS)

**Query routing** (`server/resolver/resolver.go:Resolver.Query`):
- Upstream + fallback servers queried concurrently via goroutines; upstream has priority
- If upstream succeeds → return immediately (fallback cancelled / discarded)
- If upstream fails → fallback result immediately available (no sequential retry delay)
- Fallback results are cached like normal results (queried concurrently, not stale)
- No servers configured → built-in recursive resolver (root→TLD→authoritative walk)
- NXDOMAIN stored as secondary fallback within each query group; first NOERROR wins
- CNAME chain exceeded → SERVFAIL (not partial results)

**TCP/DoT pipelining** (`server/client/pool/tcp.go`, RFC 7766):
- Client: `Pool` manages per-upstream `Conn` instances; each multiplexes
  multiple in-flight queries over a single TCP/DoT connection with out-of-order
  response matching by DNS message ID. Falls back to single-shot `ExchangeContext`
  on connection failure.
- Server: `handleDOTConnection` in `server/tls/dot.go` uses reader→worker→writer
  three-stage pipeline. `handleDNSRequest` dispatches TCP queries to goroutines
  with per-connection write mutex for concurrent out-of-order processing.

**Concurrency**: All queries use "first win" — fan out to all servers via `errgroup`,
cancel remaining on first success. Adaptive concurrency limits based on server count.

## Key Types (canonical names)

| Type | Package | Notes |
|------|---------|-------|
| `ServerConfig`, `ServerSettings` | `config` | Top-level config |
| `config.LoadConfig` | `config` | Config loader (package-level function) |
| `edns.Handler` | `edns` | EDNS option parsing/construction |
| `cidr.Filter` | `cidr` | IP filtering (New, MatchIP) |
| `rewrite.Evaluator` | `rewrite` | Domain rewrite (New, LoadRules, Evaluate) |
| `cache.Store` | `cache` | Store interface (Get, Set, SetWithDNSSEC, SetEntry, ReverseLookup, Close) |
| `stats.Collector` | `stats` | Lock-free metrics (RecordRequest, Snapshot) |
| `Server` | `server` | Core server (New, Start) |
| `Prober` | `internal/latency` | Unified latency probe engine (generic sorter, HTTP pool) |
| `Prober` | `server/latency` | Thin adapter: cache reordering, SortIPsByLatency, InitInfraProber |
| `Client` | `server/client` | Outbound DNS client (UDP, TCP, DoT, DoQ, DoH, DoH3, DNSCrypt) |
| `Resolver` | `server/resolver` | DNS resolution (upstream + recursive) |
| `Recursive` | `server/resolver` | Built-in recursive resolver |
| `Guard` | `server/security` | DNSSEC + hijack detection |
| `Validator` | `server/security` | DNSSEC record-presence validation |
| `CryptoValidator` | `server/security` | Full cryptographic DNSSEC (RRSIG, DS, trust anchors) |
| `Detector` | `server/security` | DNS hijack detection |
| `DNSSECError` | `server/resolver` | Typed error with RFC 8914 EDE code |
| `MessagePool` / `BufferPool` | `pool` | sync.Pool-based message and buffer allocators |
| `config.JoinDNSPort` | `config` | Helper: `net.JoinHostPort(ip, DefaultDNSPort)` |

## Key Constants

All tunable runtime defaults are centralized in `config/defaults.go`. **All numeric literals
(port numbers, buffer sizes, timeouts, limits) must be defined as named `const` or `var` —
never hardcoded inline.** When adding a new value, check if an existing constant already
covers it; if not, add one to `config/defaults.go` with a descriptive `Default` prefix.
Leaf utility packages that cannot import `config` (due to the dependency graph — see
the "Dependency Graph" section) should use local `const` blocks with the same naming
convention. Cache key strings follow the `prefix:` convention (e.g. `dns:`, `dnskey:`, `stats:`).

| Constant | Package | Value |
|----------|---------|-------|
| `config.DefaultDNSQueryTimeout` | config | 5s (single DNS query / dial / per-message I/O; RFC 8767 §4.2: <10s) |
| `config.DefaultBackgroundTimeout` | config | 10s (bounded wait for background tasks) |
| `config.DefaultBackgroundShutdownTimeout` | config | 30s (bounded wait for background tasks during shutdown) |
| `config.DefaultRecursiveResolveTimeout` | config | 30s (full recursive resolution) |
| `config.DefaultHTTPServerIdleTimeout` | config | 60s (HTTP keep-alive) |
| `config.DefaultHTTPServerWriteTimeout` | config | 10s (DoH response write) |
| `config.DefaultHTTPReadHeaderTimeout` | config | 5s (Slowloris protection) |
| `config.DefaultQUICClientIdleTimeout` | config | 60s (client QUIC idle, must exceed KeepAlive) |
| `config.DefaultQUICServerIdleTimeout` | config | 30s (server QUIC idle, RFC 9000 default) |
| `config.DefaultQUICKeepAlive` | config | 20s (QUIC keep-alive period) |
| `config.DefaultHTTPIdleConnTimeout` | config | 5 min (HTTP transport idle) |
| `config.DefaultShutdownTimeout` | config | 15s (graceful shutdown deadline) |
| `config.DefaultInfraProbeTimeout` | config | 5s (infrastructure-level root/NS latency probe timeout) |
| `config.DefaultCACertValidity` | config | 45 days (CA self-signed cert lifetime) |
| `config.DefaultServerCertValidity` | config | 45 days (server self-signed cert lifetime) |
| `config.DefaultDNSCryptCertValidity` | config | 24h (DNSCrypt resolver certificate lifetime) |
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
| `config.DefaultMaxCNAMEChain` | config | 16 (CNAME redirection limit; exceeded → SERVFAIL) |
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
| `config.DNSSECStatusSecure` | config | "secure" (DNSSEC validation status) |
| `config.DNSSECStatusInsecure` | config | "insecure" |
| `config.DNSSECStatusBogus` | config | "bogus" |
| `config.DoHContentType` | config | "application/dns-message" (RFC 8484) |
| `config.ProtoUDP` / `TCP` / `TLS` | config | "udp" / "tcp" / "tls" |
| `config.ProtoQUIC` / `HTTP` / `HTTP3` | config | "quic" / "https" / "http3" |
| `config.ProtoDOT` / `DOQ` / `DOH` / `DOH3` / `DNSCrypt` | config | "dot" / "doq" / "doh" / "doh3" / "dnscrypt" (user config aliases) |
| `config.ProtoTLSTCP` | config | "tcp-tls" (dns.Client.Net for TLS-wrapped TCP) |
| `config.NextProtoDOT` | config | []string{"dot"} (ALPN for DoT, RFC 7858) |
| `config.NextProtoDOH` | config | []string{"h2"} (ALPN for DoH, RFC 8484) |
| `config.NextProtoDOQ` | config | []string{"doq"} (ALPN for DoQ, RFC 9250) |
| `config.NextProtoDOH3` | config | []string{"h3"} (ALPN for DoH3) |
| `config.DefaultProbePortDNS` | config | 53 (latency probe DNS port) |
| `config.DefaultProbePortHTTP` | config | 80 (latency probe HTTP port) |
| `config.DefaultProbePortHTTPS` | config | 443 (latency probe HTTPS port) |
| `config.DefaultCookieSecretSize` | config | 32 (DNS cookie secret bytes) |
| `config.DefaultPaddingBlockSize` | config | 468 (RFC 7830 padding block) |
| `config.DefaultDNSClass` | config | "IN" (default RR class) |
| `config.StatsPersistKey` | config | "stats:" (cache key for stats persistence) |
| `config.DNSRootZone` | config | "." (root zone label) |
| `pool.UDPBufferSize` | pool | 1232 (RFC 6891 recommended UDP payload size) |
| `pool.SecureBufferSize` | pool | 8192 (DNSSEC response buffer) |
| `dnsutil.DNSFramePrefixLen` | dnsutil | 2 (DNS TCP/DoT/DoQ length prefix, RFC 1035 §4.2.2) |
| `dnsutil.MaxLabelLength` | dnsutil | 63 (RFC 1035 §2.3.4 max DNS label length) |

## Logging Conventions

All logs use the project-level `log` package (`zjdns/internal/log`). Default level: `info`.

**Level usage**:
| Level | Use case |
|-------|----------|
| `Error` | Component failure, data loss risk (persist failures, shutdown timeouts) |
| `Warn` | Rare boundary conditions (CNAME loop, depth exceeded), background task failures (ECS refresh) |
| `Info` | Startup/shutdown lifecycle, configuration summary, one-time events |
| `Debug` | Hot-path detail: every query, cache hit/miss, upstream result, CIDR match |

**Prefixes** (18 canonical, one per logical component):

| Prefix | Component | Files |
|--------|-----------|-------|
| `TLS` | All TLS + secure protocols | server/tls/*.go |
| `CACHE` | Cache operations | cache/*.go, server/server.go |
| `UPSTREAM` | Outbound upstream queries | server/client/{tcp,dot,doq,doh,doh3}.go, server/resolver/upstream.go |
| `SERVER` | Server lifecycle | server/server.go, server/server_tasks.go, server/handler.go, main.go |
| `EDNS` | EDNS options | edns/*.go, server/server.go |
| `RECURSION` | Recursive resolution | server/resolver/{recursive,recursive_cache,dnssec_chain,nameserver}.go |
| `SECURITY` | DNSSEC, hijack detection | server/security/*.go, server/resolver/{dnssec_chain}.go |
| `DNSCRYPT` | DNSCrypt v2 server | server/dnscrypt/*.go |
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
- **PTR index sweeper**: A background goroutine periodically removes stale PTR
  index entries whose cache entries have been evicted, preventing unbounded
  `ptrIndex` growth over long-running deployments.
- **Hijack detection during recursion**: Root/TLD servers returning unauthorized
  final answers trigger automatic UDP→TCP retry; if TCP also hijacked, returns
  REFUSED + EDE.
- **Concurrent upstream + fallback**: When both `upstream` and `fallback` are
  configured, `Query()` launches them concurrently via separate goroutines sharing
  a cancellable context. Upstream result takes priority; if it fails, the fallback
  result is immediately available — no sequential retry delay. Fallback results are
  cached like normal results (they were queried concurrently, not stale
  second-attempt data). Single-server-mode (only upstream or only fallback) skips
  the extra goroutine to avoid coordination overhead.
- **HandlePanic no longer calls `os.Exit(1)`** — a single connection panic
  terminates only that goroutine, not the entire server.
- **DNS Cookie early validation (RFC 7873)**: Server cookies are validated in
  `processDNSQuery` BEFORE cache lookup and resolution. Invalid cookies return
  FORMERR with a fresh valid cookie immediately, preventing spoofed-source
  amplification. Valid/new cookies receive a server cookie in every EDNS response
  via `generateCookieResponse`.
- **Lock-free RNG**: `shuffleSlice` uses `math/rand/v2.IntN()` instead of a
  custom mutex-protected RNG.
- **Lock-free stats**: All counters use `atomic.Uint64` on the hot path;
  `sync.Mutex` only guards snapshot assembly.
- **RFC 7766 TCP/DoT pipelining**: Client pools `Conn` per upstream,
  multiplexing queries over shared TCP/DoT connections. Each connection runs a
  reader goroutine that dispatches responses by DNS message ID to waiting callers.
  Orphaned responses from cancelled queries are drained and returned to
  `MessagePool`. Server processes TCP queries concurrently via async handler
  dispatch (plain TCP) or three-stage reader→worker→writer pipeline (DoT).
  Falls back to single-shot `ExchangeContext` when pipelining is not supported.
- **Config self-sufficiency**: `config.ProjectName` and `config.Version` are
  package-level vars set by `main.go` before calling `config.LoadConfig()`.
- **DNSSEC chain-of-trust**: `CryptoValidator` embeds IANA root KSK trust anchors
  (key tags 20326 + 38696). The recursive resolver builds a cryptographic chain at
  each delegation step: queries parent zone for DNSKEY, verifies against trust
  anchors (root) or parent DS (non-root), then verifies child DS RRSIGs against
  verified parent DNSKEYs, queries child for DNSKEY matching verified DS, and
  finally verifies answer RRSIGs against child DNSKEY. `ensureZoneDNSKEYs()`
  explicitly fetches DNSKEY records at each delegation step. `dnssec_enforce: true`
  returns SERVFAIL on bogus delegations (e.g. dnssec-failed.org); `false`
  passes through without AD flag.
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
  validated against the parent zone, rejecting out-of-bailiwick glue. Glue is
  used directly when available; independent NS resolution is the fallback.
- **DNSKEY cache lifecycle**: `GetZoneKeys` uses a dual-lock pattern (RLock for
  fast path, Lock with re-read for expiry) to prevent TOCTOU races with
  `CacheZoneKeys`. A background goroutine sweeps expired entries every 5 minutes.
- **Zone cut detection** (`isZoneCut`): When the recursive resolver queries an
  authoritative server and receives an answer signed by a child zone's DNSKEY
  (RRSIG signer name is a proper subdomain of `currentDomain`), the answer is
  processed via `resolveZoneCut()` instead of failing validation.
- **Lame delegation detection**: Non-authoritative responses with NS records
  pointing back to the same zone without AA flag → SERVFAIL + EDE 22.
- **CNAME chain exhaustion**: Exceeding `DefaultMaxCNAMEChain` returns SERVFAIL
  instead of partial results, preventing truncated responses that could hide
  malicious redirects.
- **AXFR/IXFR blocking**: Zone transfer query types are explicitly rejected at
  request validation to prevent unauthorized zone data exposure.
- **DNS label validation**: `dnsutil.ValidateDomainLabels` enforces RFC 1035
  per-label maximum of 63 bytes, checked before resolution.
- **BufferPool pointer storage**: Buffers stored as `*[]byte` in
  `sync.Pool` to avoid interface-boxing on every `Put` (SA6002). `Put` normalizes
  the slice to full capacity before storing.
- **Unified latency probe engine** (`internal/latency`): All latency probing
  shares a single engine with generic `probeSlice[T]` sorting, HTTP/HTTPS/HTTP3
  client pool reuse, and bounded semaphore workers. The `server/latency` package
  is a thin adapter delegating to the internal engine.
- **ICMP probe hardening**: Echo ID and Seq randomly generated per probe; response
  loop verifies both fields before accepting a reply.
- **UDP probe is generic**: Single zero-byte datagram for universal compatibility
  with any target service.
- **persistGen fix**: Cache persistence uses `Load()` + `Add(-gen)` instead of
  `Swap(0)` + `Add(gen)`, preserving Set() increments during `persistSnapshot()`.
- **Protocol identifier constants**: `config.ProtoUDP`, `ProtoTCP`, etc. replace
  all hardcoded protocol strings. Transport alias constants (`ProtoDOT`, `ProtoDOQ`,
  `ProtoDOH`, `ProtoDOH3`, `ProtoTLSTCP`) cover user-facing config values.
- **Stats cache key convention**: `config.StatsPersistKey = "stats:"` follows the
  project-wide `prefix:` key format (matching `dns:`, `dnskey:`).
- **CHAOS TXT records**: `version.server`/`version.bind` expose the full version
  from `getVersion()`. `id.server`/`hostname.bind` use `os.Hostname()` with
  `ProjectName` fallback.
- **All transport protocols via dnsproxy**: The `github.com/AdguardTeam/dnsproxy`
  library handles all DNS listeners (UDP, TCP, DoT, DoQ, DoH, DoH3, DNSCrypt) and
  outbound upstream connections. Our `Server` implements `proxy.Handler` as the
  middleware chain (rewrite → cookie → cache → security → CIDR), falling through
  to dnsproxy's default resolution. Upstreams are configured via `upstream.AddressToUpstream()`.
  Recursive resolver implements `upstream.Upstream` for `builtin_recursive` support.
  `server/dnsproxy_config.go` maps our config to `proxy.Config`.
