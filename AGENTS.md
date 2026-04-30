# AGENTS.md - ZJDNS Development Guide

## Quick Start

```bash
# Build
go build -o zjdns

# Generate example config
./zjdns -generate-config > config.json

# Run with config
./zjdns -config config.json

# Run without config (pure recursive mode, no cache)
./zjdns

# Code quality
golangci-lint run && golangci-lint fmt
```

## Architecture Overview

**Single-package Go application** (~7.5K LOC, v1.6.0) - High-performance recursive DNS server.

- **Protocols**: UDP/TCP (53), DoT (853), DoQ (853), DoH/DoH3 (443)
- **Features**: DNSSEC validation, ECS, DNS Cookie, EDE, CIDR filtering, DNS rewrite, latency probing, DNS padding (RFC 7830), DDR (RFC 9461/9462), CHAOS TXT records
- **Cache**: Memory LRU cache with optional disk snapshot persistence (gob+zstd). Serve-expired on upstream failure (RFC 8767)
- **Security**: Hijack prevention (auto TCP fallback), lightweight DNSSEC (AD flag + record presence check)
- **Stats**: In-memory request metrics with optional file snapshot persistence and periodic reset

### Module Structure

| File               | Purpose         | Key Components                                                           |
| ------------------ | --------------- | ------------------------------------------------------------------------ |
| `main.go`          | Entry point     | CLI flags (`-config`, `-generate-config`, `-version`), server startup    |
| `version.go`       | Version info    | `Version`, `CommitHash`, `BuildTime` (set via ldflags)                   |
| `config.go`        | Configuration   | `ServerConfig` struct, `ConfigManager`, JSON validation, DDR records     |
| `cache.go`         | Cache system    | `CacheManager` interface, `MemoryCache` with disk snapshot (gob+zstd)    |
| `cidr.go`          | CIDR filtering  | `CIDRManager`, IP filtering with REFUSED + EDE response                  |
| `edns.go`          | EDNS extensions | ECS, DNS Cookie (RFC 7873/9018), EDE (RFC 8914)                          |
| `rewrite.go`       | DNS rewrite     | `RewriteManager`, domain filtering, custom response codes                |
| `security.go`      | Security        | `DNSSECValidator`, `HijackPrevention`, `SecurityManager`                 |
| `tls.go`           | TLS protocols   | `TLSManager`, DoT/DoQ/DoH/DoH3 handlers, self-signed CA                  |
| `query.go`         | Query client    | `QueryClient`, protocol-specific querying (udp/tcp/tls/quic/https/http3) |
| `resolver.go`      | Resolution      | `QueryManager`, `RecursiveResolver`, `CNAMEHandler`, `ResponseValidator` |
| `server.go`        | Server core     | `DNSServer`, protocol handlers, signal handling, stats                   |
| `stats.go`         | Statistics      | `StatsManager`, request metrics, file snapshot, periodic reset           |
| `latency_probe.go` | Latency probing | A/AAAA record speed testing, reordering by latency                       |
| `logger.go`        | Logging         | `LogManager`, `TimeCache`, RNG, global log funcs (`LogInfo`, `LogError`) |
| `pool.go`          | Memory pools    | `MessagePool` (`dns.Msg`), `BufferPool` (`[]byte`) via `sync.Pool`       |
| `utils.go`         | Utilities       | String ops, DNS record helpers, cache keys, client IP extraction         |

**Constants and types are NOT in dedicated files** - scattered across module files. Key locations: `resolver.go` (limits), `cache.go` (TTLs), `server.go` (timeouts), `pool.go` (buffers).

### Execution Flow

```
main.go → ConfigManager.LoadConfig() → NewDNSServer() → DNSServer.Start()
                                    ↓
┌─────────────────────────────────────────────────────────────┐
│ DNSServer initialization:                                   │
│ 1. EDNSManager (ECS auto-detection)                         │
│ 2. RewriteManager (domain filtering)                        │
│ 3. CIDRManager (IP filtering)                               │
│ 4. CacheManager (MemoryCache with optional disk snapshot)   │
│ 5. SecurityManager (DNSSEC + HijackPrevention)              │
│ 6. StatsManager (in-memory metrics, optional file snapshot) │
│ 7. QueryClient (protocol-specific querying)                 │
│ 8. QueryManager (upstream + recursive resolution)           │
└─────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────┐
│ Protocol Handlers (parallel via errgroup):                  │
│ - UDP Server (port 53)                                      │
│ - TCP Server (port 53)                                      │
│ - DoT Handler (port 853, TLS)                               │
│ - DoQ Handler (port 853, QUIC)                              │
│ - DoH/DoH3 Handler (port 443, HTTP/2 + HTTP/3)              │
│ - pprof (port 6060)                                         │
└─────────────────────────────────────────────────────────────┘
```

## Build & Deployment

### Cross-Platform Builds

```bash
# macOS (current)
go build -o zjdns

# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o zjdns-linux-amd64

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o zjdns-linux-arm64
```

### Docker

**Dockerfile**: Multi-stage build (golang → scratch) with CA certs bundled.

Version injection via ldflags:

```
-ldflags "-s -w -buildid= -X main.BuildTime=${BUILD_TIME} -X main.CommitHash=${COMMIT_SHA}"
```

CI via `.github/workflows/main.yml`:

- Scheduled at UTC+8 04:00 and 16:00 (`cron: "0 8,20 * * *"`)
- Pushes to GHCR and Docker Hub with `latest` tag
- Multi-platform: linux/amd64 + linux/arm64, digest merge

Dependency updates via `.github/workflows/deps.yml` (manual trigger, pins deps to `@master`).

### Go Version

**Required**: Go 1.25.1 (from `go.mod`)

**Dependencies** (pinned to master/HEAD, not released versions):

- `github.com/klauspost/compress` - zstd compression for cache snapshots
- `github.com/miekg/dns` - DNS library
- `github.com/quic-go/quic-go` - QUIC protocol
- `golang.org/x/net`, `golang.org/x/sync` - Standard extensions

## Code Style & Conventions

### Import Order

```go
import (
    // Standard library (alphabetical)
    "context"
    "fmt"
    "sync"
    "time"

    // Third-party (alphabetical)
    "github.com/klauspost/compress/zstd"
    "github.com/miekg/dns"
    "github.com/quic-go/quic-go"
    "golang.org/x/sync/errgroup"
)
```

### Naming Conventions

- **Constants**: `PascalCase` (`DefaultDNSPort`, `UDPBufferSize`, `MaxRecursionDep`)
- **Types**: `PascalCase` (`ServerConfig`, `CacheManager`, `QueryClient`)
- **Public funcs/methods**: `PascalCase` (`NewDNSServer`, `LoadConfig`)
- **Private funcs/methods**: `camelCase` (`queryUpstream`, `resolveWithCNAME`)
- **Suffixes**: `*Manager`, `*Handler`, `*Client`, `*Validator`

### Error Handling

```go
// Error chaining with context
return nil, fmt.Errorf("EDNS manager init: %w", err)

// Goroutine safety
defer HandlePanic("operation_name")

// Context-aware timeouts
ctx, cancel := context.WithTimeout(qm.server.ctx, IdleTimeout)
defer cancel()

// Structured logging (printf-style, not structured)
LogError("CACHE: failed to refresh %v", err)
```

### Concurrency Patterns

- **Atomic operations** (simple state): `atomic.Int32`, `atomic.StoreInt32`
- **errgroup** (concurrent operations): `errgroup.WithContext(ctx)` for background tasks, cache refresh
- **Mutex** (complex shared state): `sync.RWMutex` on managers (CIDRManager, StatsManager)
- **sync.Pool** (object reuse): `MessagePool` for `dns.Msg`, `BufferPool` for `[]byte`

### Memory Management

**Buffer sizes**: `UDPBufferSize=1232` (EDNS0), `TCPBufferSize=4096`, `SecureBufferSize=8192`

**Object pools**: `MessagePool` (512 cap), `BufferPool` (256 cap)

## Configuration

### Config Structure (JSON)

```json
{
  "server": {
    "port": "53",
    "pprof": "6060",
    "log_level": "info",
    "tls": {
      "port": "853",
      "cert_file": "/path/to/cert.pem",
      "key_file": "/path/to/key.pem",
      "self_signed": false,
      "https": { "port": "443", "endpoint": "/dns-query" }
    },
    "features": {
      "hijack_protection": true,
      "ddr": { "domain": "dns.example.com", "ipv4": "127.0.0.1", "ipv6": "::1" },
      "ecs_subnet": { "ipv4": "auto", "ipv6": "auto", "prefer_ipv4": true },
      "cache": {
        "size": 16384,
        "persist": { "file": "cache.snapshot", "interval": 30 },
        "prefer_stale": true
      },
      "latency_probe": [{ "protocol": "ping", "timeout": 100 }, ...],
      "stats": { "interval": 3600, "reset_interval": 86400, "file": "stats.snapshot" }
    }
  },
  "upstream": [
    { "address": "223.5.5.5:53", "protocol": "udp" },
    { "address": "223.5.5.5:853", "protocol": "tls", "server_name": "dns.alidns.com" },
    { "address": "https://223.5.5.5:443/dns-query", "protocol": "https", "server_name": "dns.alidns.com" },
    { "address": "223.6.6.6:853", "protocol": "quic", "server_name": "dns.alidns.com" },
    { "address": "https://223.6.6.6:443/dns-query", "protocol": "http3", "server_name": "dns.alidns.com" },
    { "address": "builtin_recursive", "protocol": "" }
  ],
  "fallback": [
    { "address": "builtin_recursive", "protocol": "" }
  ],
  "rewrite": [
    { "name": "blocked.example.com", "records": [{ "type": "A", "ttl": 10, "content": "127.0.0.1" }] },
    { "name": "client-specific.example.com", "include_clients": ["192.168.0.0/24"], "records": [...] },
    { "exclude_clients": ["10.0.0.100"] }
  ],
  "cidr": [
    { "file": "whitelist.txt", "tag": "file" },
    { "rules": ["192.168.0.0/16", "10.0.0.0/8"], "tag": "rules" }
  ]
}
```

**Important**: All feature configs live under `server.features`, not directly under `server`. The example config in `config.example.json` is the source of truth.

### Key Configuration Options

**Cache**: Only `MemoryCache` exists. Optional disk snapshot persistence via `server.features.cache.persist` (gob+zstd format). No external cache backend.

**Upstream vs Fallback**:

- **`upstream`**: Primary DNS servers queried first
- **`fallback`**: Secondary servers used when upstream fails
- Both support `builtin_recursive` for built-in recursive resolution

**Upstream protocols**: `udp`, `tcp`, `tls`, `quic`, `https`, `http3`, or empty for `builtin_recursive`

**ECS (EDNS Client Subnet)**: `auto` | `auto_v4` | `auto_v6` | manual CIDR. Configured under `server.features.ecs_subnet`.

**Rewrite client filtering**:

- `include_clients`: Only apply rewrite to matching client IPs/CIDRs
- `exclude_clients`: Skip rewrite for matching client IPs/CIDRs

### Critical Constants

```go
// Timeouts (server.go)
DefaultTimeout             = 2 * time.Second
OperationTimeout           = 3 * time.Second
IdleTimeout                = 4 * time.Second  // NOT 5s
DefaultLatencyProbeTimeout = 100 * time.Millisecond  // latency_probe.go
ServeExpiredClientTimeout  = 1800 * time.Millisecond // RFC 8767, NOT 500

// Limits (resolver.go)
MaxRecursionDep    = 16
MaxCNAMEChain      = 16
MaxDomainLength    = 253
RecursiveIndicator = "builtin_recursive"

// Cache (cache.go)
DefaultTTL             = 10
StaleTTL               = 30
StaleMaxAge            = 3 * 86400  // 3 days
DefaultCacheSize       = 16384

// Buffer sizes (pool.go)
UDPBufferSize    = 1232
TCPBufferSize    = 4096
SecureBufferSize = 8192
```

## Security Features

### DNSSEC Validation

**Trust anchors**: Auto-loaded from IANA root-anchors.xml (KSK 20326, KSK 38696)

**Validation** (lightweight):

1. AD Flag Check - validates Authenticated Data flag
2. DNSSEC Record Check - detects RRSIG, NSEC, NSEC3, DNSKEY, DS

AD flag propagated to clients when validation passes.

### Hijack Prevention

Root server returns final answer for non-root domain → suspected hijack:

1. Detect UDP hijack → Auto-switch to TCP retry
2. TCP also hijacked → Reject response (REFUSED + EDE)

### CIDR Filtering

Tag-based: associate upstream servers with CIDR rules via tags.
A/AAAA records checked against CIDR rules. All IPs filtered → REFUSED + EDE code 15 (Blocked) or 17 (Filtered).

### Extended DNS Errors (EDE)

Codes: `3` Stale, `5` DNSSEC Indeterminate, `6` DNSSEC Bogus, `15` Blocked, `16` Censored, `17` Filtered, `18` Prohibited.

### DNS Padding (RFC 7830)

Pads responses to 468 bytes on secure connections (DoT/DoQ/DoH) only. Configurable.

### DDR (RFC 9461/9462)

Auto-generates SVCB records for DoT/DoH/DoQ discovery via `server.features.ddr` config section.

### CHAOS TXT Records

Auto-enabled by `addChaosRecord()` in config.go. Provides `id.server`, `hostname.bind`, `version.server`, `version.bind`.

## Testing

**No test files exist.** Manual testing via `kdig`:

```bash
kdig @127.0.0.1 -p 53 example.com
kdig @127.0.0.1 -p 853 example.com +tls
kdig @127.0.0.1 -p 853 example.com +quic
kdig @127.0.0.1 -p 443 example.com +https
kdig @127.0.0.1 example.com +subnet=192.168.1.0/24
```

pprof available at `http://127.0.0.1:6060/debug/pprof/`.

## Development Workflow

1. **Before changes**: Run `golangci-lint run` to understand existing patterns
2. **During changes**: Follow conventions, add structured logging, handle errors with `%w`
3. **After changes**: `golangci-lint run && golangci-lint fmt`, verify functionality

### Git Repo Quirks

**`.gitignore`**: Ignore-everything-then-allowlist. Only `.go`, `.md`, `.example.json`, `go.mod`, `go.sum`, `Dockerfile`, `LICENSE`, `.github/` tracked. Binaries and custom configs auto-ignored.

### Key Implementation Patterns

**Query Flow**:

```
Client → Protocol Handler → DNSServer → RewriteManager → CacheManager
  ├─ Hit → Return cached
  └─ Miss → QueryManager → Upstream or RecursiveResolver → DNSSEC → CIDR → Cache + Response
```

**Protocol Handlers**: All follow the same pattern:

1. Read request into buffer from `BufferPool`
2. Parse DNS message
3. Call `server.HandleQuery()` (unified processing)
4. Write response
5. Return buffer to `BufferPool`

**Background Tasks** (via `errgroup.Group`):

- Cache prefetch (refresh expiring entries)
- Latency probing (A/AAAA speed testing)
- TLS certificate management
- Signal handling (graceful shutdown)
- Stats periodic reset (when `stats.reset_interval` configured)

## Gotchas

1. **No tests**: All verification is manual via `kdig`
2. **No linter config**: Uses default `golangci-lint` rules
3. **Single package**: All code in `main` package (no sub-packages)
4. **Global state**: Heavy use of globals - `globalLog`, `timeCache`, `globalRNG` (logger.go), `messagePool`, `bufferPool` (pool.go)
5. **No `constants.go` or `types.go`**: Constants/types scattered across module files. Key ones: `resolver.go` (limits), `cache.go` (TTLs), `server.go` (timeouts), `pool.go` (buffers)
6. **Deps pinned to HEAD**: Not released versions. Dockerfile does `go get -u ...@master` before build
7. **Vibe coding**: Self-described as not production-verified
8. **`.gitignore` is ignore-everything-then-allowlist**: Only `.go`, `.md`, `.example.json`, `go.mod`, `go.sum`, `Dockerfile`, `LICENSE`, `.github/` tracked
9. **`HandlePanic` is the goroutine safety net**: Defined in `utils.go`, used via `defer HandlePanic("op")` in all goroutines
10. **Cache is memory-only**: No Redis or external cache. Persistence is disk snapshot (gob+zstd) only
11. **Config features are nested under `server.features`**: `ddr`, `ecs_subnet`, `cache`, `latency_probe`, `stats` all live inside `server.features`, not directly under `server`
