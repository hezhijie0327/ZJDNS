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

### KTLS Tuning

If you see `"local error: tls: bad record MAC"` in logs (kernel TLS offload
corrupting record decryption on certain kernel/NIC combinations), disable
kernel RX offload:

```json
{
  "server": {
    "tls": {
      "ktls": {
        "kernel_rx": false
      }
    }
  }
}
```

Both `kernel_tx` and `kernel_rx` default to `true` (when the ktls block is
omitted). TX (encryption) is typically reliable; RX (decryption) is where
the kernel bug manifests.

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

**DNSCrypt tests (local server + client):**
```bash
# 1. Generate keys
./zjdns -generate-dnscrypt-keys -cert-ttl=86400

# 2. Start DNSCrypt server (independent port 8443)
cat > /tmp/dnscrypt_test.json << EOF
{"server":{"port":"15353","log_level":"debug","dnscrypt":{"port":"8443","provider_name":"zjdns.local","private_key":"<KEY>","cert_ttl":86400},"features":{"cache":{"size":0}}},"upstream":[{"address":"builtin_recursive"}]}
EOF
./zjdns -config /tmp/dnscrypt_test.json &

# 3. Start DNSCrypt client → server
cat > /tmp/dnscrypt_client.json << EOF
{"server":{"port":"15354","log_level":"debug","features":{"cache":{"size":0}}},"upstream":[{"address":"127.0.0.1:8443","protocol":"dnscrypt","server_name":"zjdns.local","dnscrypt_public_key":"<PUBKEY>"}]}
EOF
./zjdns -config /tmp/dnscrypt_client.json &

# 4. Test plain DNS and DNSCrypt tunnel
dig @127.0.0.1 -p 15353 www.baidu.com A +short    # plain DNS
dig @127.0.0.1 -p 15354 www.baidu.com A +short    # DNSCrypt encrypted
```

**DNSCrypt external resolver test (Quad9):**
```bash
cat > /tmp/quad9.json << EOF
{"server":{"port":"15355","log_level":"debug","features":{"cache":{"size":0}}},"upstream":[{"address":"9.9.9.9:8443","protocol":"dnscrypt","server_name":"2.dnscrypt-cert.quad9.net","dnscrypt_public_key":"67c847b8c8758cd120245543be756746df34df1d84c00b8c470368df821d863e"}]}
EOF
./zjdns -config /tmp/quad9.json &
dig @127.0.0.1 -p 15355 www.baidu.com A +short    # via Quad9 DNSCrypt
```

Test suites for `cache`, `cidr`, `config`, `edns`, `rewrite`, `stats`, `internal/dnsutil`, `internal/latency`, `internal/pool`, `server/resolver`, and `server/security` packages (90+ test cases + 19 benchmarks). Module path: `zjdns` (Go 1.26). Zero `golangci-lint` warnings.

Target coverage: ≥90% for utility packages (`dnsutil` 95.7%, `pool` 91.3%).

Run benchmarks: `go test -bench=. -short ./...` (unit) or `go test -bench=BenchmarkServerProcessQuery -benchtime=3s .` (QPS).

## Package Structure

```
zjdns/
├── main.go / version.go           # Entry point + ldflags variables
├── bench_test.go                  # Global benchmarks (pool, cache, DNSSEC, QPS)
├── cli/                           # CLI helper functions (2 files)
│   ├── dns_stamp.go               # DNS stamp (sdns://) parsing
│   └── dnscrypt_keys.go           # DNSCrypt Ed25519 key pair generation
├── internal/
│   ├── log/log.go                 # Logger, TimeCache, Level.String()
│   ├── pool/pool.go               # MessagePool, BufferPool, constants (zero deps)
│   ├── dnsutil/dnsutil.go         # NormalizeDomain, ValidateDomainLabels, HandlePanic, etc.
│   ├── ipdetect/ipdetect.go       # Public IP detection for auto ECS
│   ├── perip/perip.go             # Unified per-IP connection/concurrency limiter (Allow/Sweep)
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
    ├── server.go                  # Server lifecycle, New(), Start(), shutdown
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
    │   ├── dnscrypt.go             # DNSCrypt encrypted upstream client
    │   └── pool/                  # Connection pool sub-package
    │       ├── tcp.go             # RFC 7766 pipelined TCP/DoT pool (Conn, Pool)
    │       └── quic.go            # QUIC connection pool (QUICPool, QUICConn)
    ├── resolver/                  # DNS resolution strategies
    │   ├── resolver.go            # Resolver struct, routing + helpers
    │   ├── upstream.go            # First-win concurrent upstream queries
    │   ├── recursive.go           # Recursive root→TLD→auth walk + CNAME chain resolution
    │   ├── dnssec_chain.go        # DNSSEC trust chain + zone cut detection
    │   ├── nameserver.go          # Concurrent NS querying, suspicious response handling
    ├── security/                  # Security features (4 files)
    │   ├── security.go            # Guard (bundles RecordPresence + CryptoValidator + Detector)
    │   ├── dnssec.go              # DNSSEC record-presence validation (upstream AD check)
    │   ├── dnssec_crypto.go       # Full cryptographic DNSSEC (RRSIG, DS, trust anchors)
    │   └── hijack.go              # Hijack detection + TCP fallback trigger
    ├── tls/                        # Secure transport listeners
    │   ├── tls.go                  # Server struct, cert management, Start/Shutdown
    │   ├── dot.go                  # DoT listener + per-IP connection limiting
    │   ├── doq.go                  # DoQ listener + stream handler
    │   └── doh.go                  # DoH/DoH3 HTTP handlers
    ├── dnscrypt/                   # DNSCrypt v2 native implementation (4 files)
    │   ├── server.go               # UDP/TCP listeners
    │   ├── cert.go                 # Ed25519 certificate generation, signing, serialization
    │   ├── crypto.go               # X25519 ECDH + XSalsa20-Poly1305 encrypt/decrypt
    │   └── xsecretbox.go           # XChacha20-Poly1305 Seal/Open + HChaCha20 shared key
    ├── latency/                    # Client-facing latency probe adapter
    │   └── probe.go                # Thin adapter delegating to internal/latency; SortIPsByLatency + InitInfraProber
```

### Dependency Graph

```
main ──→ server, config
server ──→ cache, cidr, config, dnscrypt, edns, dnsutil, log, perip, pool, rewrite, latency(server), resolver, security, stats,
client ──→ config, edns, dnsutil, log, pool, pool (in client), go-extension/tls
resolver ──→ config, edns, client, security, dnsutil, latency(server), log, pool
security ──→ dnsutil, log
tls (in server) ──→ config, dnsutil, log, perip, pool, connpool (client/pool), go-extension/tls
dnscrypt (in server) ──→ config, dnsutil, log, perip, pool
cache ──→ config, edns, dnsutil, log
edns ──→ dnsutil, ipdetect, log, pool
cidr ──→ config, dnsutil, log
rewrite ──→ config, dnsutil, log
stats ──→ cache, config, log
latency (server) ──→ config, edns, dnsutil, latency(internal), log
latency (internal) ──→ config, dnsutil, log
dnsutil ──→ log
pool, log, perip ──→ (zero deps)

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
- Upstream servers configured → concurrent first-win query; fallback on failure
- No upstream → built-in recursive resolver (root→TLD→authoritative walk)
- NXDOMAIN stored as secondary fallback; first NOERROR wins
- CNAME chain exceeded → SERVFAIL (not partial results)

**TCP/DoT pipelining** (`server/client/pool/tcp.go`, RFC 7766):
- Client: `Pool` manages per-upstream `Conn` instances; each multiplexes
  multiple in-flight queries over a single TCP/DoT connection with out-of-order
  response matching by DNS message ID. Falls back to single-shot `ExchangeContext`
  on connection failure.
- Server: `handleDOTConnection` in `server/tls/dot.go` uses reader→worker→writer
  three-stage pipeline; per-IP connection limiting via `dotIPCounts` sync.Map.
  `handleDNSRequest` dispatches TCP queries to goroutines with per-connection
  write mutex for concurrent out-of-order processing.

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
| `Prober` | `internal/latency` | Unified latency probe engine (generic sorter, HTTP pool) |
| `Prober` | `server/latency` | Thin adapter: cache reordering, SortIPsByLatency, InitInfraProber |
| `Client` | `server/client` | Outbound DNS client (UDP, TCP, DoT, DoQ, DoH, DoH3, SOCKS5 proxy) |
| `Socks5Dialer` | `server/client` | SOCKS5 proxy dialer (RFC 1928 TCP CONNECT + UDP ASSOCIATE, RFC 1929 auth, SafeURL) |
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
| `MessagePool` / `BufferPool` | `pool` | sync.Pool-based message and buffer allocators |
| `Limiter` | `perip` | Per-IP connection/concurrency limiter (Allow, Sweep) |
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
| `config.DefaultDNSQueryTimeout` | config | 10s (single DNS query / dial / per-message I/O) |
| `config.DefaultBackgroundTimeout` | config | 10s (bounded wait for background tasks; increased to recursive timeout during shutdown) |
| `config.DefaultRecursiveResolveTimeout` | config | 30s (full recursive resolution) |
| `config.DefaultHTTPServerIdleTimeout` | config | 60s (HTTP keep-alive) |
| `config.DefaultHTTPServerWriteTimeout` | config | 10s (DoH response write) |
| `config.DefaultHTTPReadHeaderTimeout` | config | 5s (Slowloris protection) |
| `config.DefaultQUICClientIdleTimeout` | config | 60s (client QUIC idle, must exceed KeepAlive) |
| `config.DefaultQUICServerIdleTimeout` | config | 30s (server QUIC idle, RFC 9000 default) |
| `config.DefaultQUICKeepAlive` | config | 20s (QUIC keep-alive period) |
| `config.DefaultHTTPIdleConnTimeout` | config | 5 min (HTTP transport idle) |
| `config.DefaultShutdownTimeout` | config | 15s (graceful shutdown deadline) |
| `config.DefaultDNSCryptTCPReadTimeout` | config | 2s (DNSCrypt TCP first read deadline) |
| `config.DefaultDNSCryptTCPIdleTimeout` | config | 8s (DNSCrypt TCP subsequent read deadline) |
| `config.DefaultInfraProbeTimeout` | config | 5s (infrastructure-level root/NS latency probe timeout) |
| `config.DefaultRateLimitSweepInterval` | config | 30s (rate limiter entry sweep interval) |
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
| `config.ProtoDOT` / `DOQ` / `DOH` / `DOH3` | config | "dot" / "doq" / "doh" / "doh3" (user config aliases) |
| `config.ProtoDNSCrypt` | config | "dnscrypt" (DNSCrypt v2 protocol identifier) |
| `config.DefaultDNSCryptPort` | config | "8443" (DNSCrypt standalone port) |
| `config.DefaultDNSCryptCertTTL` | config | 365 days (DNSCrypt certificate lifetime) |
| `config.DNSCryptV2Prefix` | config | "2.dnscrypt-cert." (cert TXT query prefix) |
| `config.ProtoTLSTCP` | config | "tcp-tls" (dns.Client.Net for TLS-wrapped TCP) |
| `config.NextProtoDOT` | config | []string{"dot"} (ALPN for DoT, RFC 7858) |
| `config.NextProtoDOH` | config | []string{"h2"} (ALPN for DoH, RFC 8484) |
| `config.NextProtoDOQ` | config | []string{"doq"} (ALPN for DoQ, RFC 9250) |
| `config.NextProtoDOH3` | config | []string{"h3"} (ALPN for DoH3) |
| `config.DefaultProxyScheme` | config | "socks5" (SOCKS5 proxy scheme) |
| `config.DefaultProxyPort` | config | "1080" (SOCKS5 proxy default port) |
| `config.DefaultProbePortDNS` | config | 53 (latency probe DNS port) |
| `config.DefaultProbePortHTTP` | config | 80 (latency probe HTTP port) |
| `config.DefaultProbePortHTTPS` | config | 443 (latency probe HTTPS port) |
| `config.DefaultCookieSecretSize` | config | 32 (DNS cookie secret bytes) |
| `config.DefaultPaddingBlockSize` | config | 468 (RFC 7830 padding block) |
| `config.DefaultRateLimiterMaxEntries` | config | 10000 (max tracked client IPs) |
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

**Prefixes** (19 canonical, one per logical component):

| Prefix | Component | Files |
|--------|-----------|-------|
| `TLS` | All TLS + secure protocols | server/tls/*.go |
| `CACHE` | Cache operations | cache/*.go, server/server.go |
| `UPSTREAM` | Outbound upstream queries | server/client/{tcp,dot,doq,doh,doh3}.go, server/resolver/upstream.go |
| `SERVER` | Server lifecycle | server/server.go, server/handler.go, main.go |
| `EDNS` | EDNS options | edns/*.go, server/server.go |
| `RECURSION` | Recursive resolution | server/resolver/{recursive,dnssec_chain,nameserver}.go |
| `SECURITY` | DNSSEC, hijack detection | server/security/*.go, server/resolver/{dnssec_chain}.go |
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
- **PTR index sweeper**: A background goroutine periodically removes stale PTR
  index entries whose cache entries have been evicted, preventing unbounded
  `ptrIndex` growth over long-running deployments.
- **Hijack detection during recursion**: Root/TLD servers returning unauthorized
  final answers trigger automatic UDP→TCP retry; if TCP also hijacked, returns
  REFUSED + EDE.
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
- **Unified per-IP limiting (`internal/perip`): A single `Limiter` type with
  from IPs exceeding `DefaultMaxConnsPerIP` (64).
- **BufferPool pointer storage**: Buffers stored as `*[]byte` in
  `sync.Pool` to avoid interface-boxing on every `Put` (SA6002). `Put` normalizes
  the slice to full capacity before storing.
- **Rate limiter bound**: `DefaultRateLimiterMaxEntries` caps unique client IPs
  tracked, preventing unbounded map growth from spoofed-source floods.
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
- **Kernel TLS (KTLS) offload**: Client and server TCP-based TLS use
  `gitlab.com/go-extension/tls` (import alias `eTLS`) with `KernelTX`/`KernelRX`.
  Dual configs from same cert — eTLS for TCP, crypto/tls for QUIC. Silent fallback
  on non-Linux. Server-side KTLS is configurable via `server.tls.ktls.kernel_tx`
  and `kernel_rx` (both default `true`); set `kernel_rx: false` to work around
  kernel/NIC combos that produce `"local error: tls: bad record MAC"`.
- **SOCKS5 proxy support** (`server/client/socks5.go`): Per-upstream optional SOCKS5
  proxy routes all outbound DNS queries. TCP CONNECT for streams, UDP ASSOCIATE for
  datagrams. `SafeURL()` redacts password in logs. `socks5ReadBufPool` avoids 64 KB
  per-connection heap allocation.
- **Stats cache key convention**: `config.StatsPersistKey = "stats:"` follows the
  project-wide `prefix:` key format (matching `dns:`, `dnskey:`).
- **CHAOS TXT records**: `version.server`/`version.bind` expose the full version
  from `getVersion()`. `id.server`/`hostname.bind` use `os.Hostname()` with
  `ProjectName` fallback.
- **DNSCrypt v2** (`server/dnscrypt/` 4 files + `server/client/dnscrypt.go`):
  Native Go implementation with zero external DNSCrypt dependencies. Ed25519
  (stdlib) for long-term certificate signing; X25519 ECDH (`golang.org/x/crypto`)
  for per-session key exchange; XSalsa20-Poly1305 AEAD (default) or
  XChacha20-Poly1305 (optional) for query/response encryption. Post-quantum
  hybrid key exchange: X25519 + ML-KEM-768 (`crypto/mlkem`, Go 1.26 stdlib)
  combined via HKDF-SHA256 (`0x0101`/`0x0102` construction codes). Extended
  certificate format (1308 bytes) carries ML-KEM-768 encapsulation key.
  PQ query header prepends 1088-byte ML-KEM ciphertext. Server listens
  UDP+TCP on a standalone port (default 8443). Client caches ephemeral sessions
  per upstream for 1 hour (forward secrecy) and reuses a persistent UDP socket for
  stable 5-tuple routing. Certificates are published as DNS TXT records at
  `2.dnscrypt-cert.<provider>`. Clients default to UDP; set `dnscrypt_tcp: true`
  for TCP. Cert fetch deduplication prevents thundering herd on cache miss.
  Provider names auto-prefix with `DNSCryptV2Prefix`. Colon-formatted hex keys
  accepted everywhere. Use `-es-version xsalsa20-pq` or `xchacha20-pq` for PQC.
