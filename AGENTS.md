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

# Test (no test files exist yet)
go test ./...
```

## Architecture Overview

**Single-module Go application** (~7K LOC) - High-performance recursive DNS server with:

- **Protocols**: UDP/TCP (53), DoT (853), DoQ (853), DoH/DoH3 (443)
- **Features**: DNSSEC validation, ECS, DNS Cookie, EDE, CIDR filtering, DNS rewrite
- **Cache**: Memory-first with optional Redis persistence (HybridCache)
- **Security**: Hijack prevention (auto TCP fallback), lightweight DNSSEC validation (AD flag + record presence check)

### Module Structure

| File               | Purpose          | Key Components                                                          |
| ------------------ | ---------------- | ----------------------------------------------------------------------- |
| `main.go`          | Entry point      | CLI flags, config loading, server startup                               |
| `constants.go`     | Global constants | Ports, buffers, timeouts, EDE codes, root servers, ALPN                 |
| `types.go`         | Type definitions | All structs (Config, Cache, Security), interfaces                       |
| `utils.go`         | Utilities        | String ops, DNS record helpers, cache keys, client IP extraction        |
| `logger.go`        | Logging          | LogManager, TimeCache, RNG, global log funcs                            |
| `pool.go`          | Memory pools     | MessagePool (`dns.Msg`), BufferPool (`[]byte`) via `sync.Pool`          |
| `config.go`        | Configuration    | ConfigManager, JSON validation, DDR record generation                   |
| `cache.go`         | Cache system     | MemoryCache, RedisCache, HybridCache (memory-first + Redis async write) |
| `cidr.go`          | CIDR filtering   | CIDRManager, IP filtering with REFUSED + EDE response                   |
| `edns.go`          | EDNS extensions  | ECS, DNS Cookie (RFC 7873/9018), EDE (RFC 8914)                         |
| `rewrite.go`       | DNS rewrite      | RewriteManager, domain filtering, custom response codes                 |
| `security.go`      | Security         | DNSSECValidator (RRSIG/DS/DNSKEY), HijackPrevention                     |
| `tls.go`           | TLS protocols    | TLSManager, DoT/DoQ/DoH/DoH3 handlers, self-signed CA                   |
| `query.go`         | Query client     | QueryClient, protocol-specific querying                                 |
| `resolver.go`      | Resolution       | QueryManager, RecursiveResolver, CNAMEHandler, ResponseValidator        |
| `server.go`        | Server core      | DNSServer, UDP/TCP/DoT/DoQ/DoH handlers, signal handling                |
| `latency_probe.go` | Latency probing  | A/AAAA record speed testing, reordering by latency                      |

### Execution Flow

```
main.go → ConfigManager.LoadConfig() → NewDNSServer() → DNSServer.Start()
                                    ↓
┌─────────────────────────────────────────────────────────────┐
│ DNSServer initialization:                                   │
│ 1. EDNSManager (ECS auto-detection)                         │
│ 2. RewriteManager (domain filtering)                        │
│ 3. CIDRManager (IP filtering)                               │
│ 4. CacheManager (Memory/Hybrid based on Redis config)       │
│ 5. SecurityManager (DNSSEC + HijackPrevention)              │
│ 6. QueryClient (protocol-specific querying)                 │
│ 7. QueryManager (upstream + recursive resolution)           │
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

Multi-platform build via GitHub Actions (see `.github/workflows/main.yml`):

- Scheduled builds at UTC+8 04:00 and 16:00
- Pushes to GHCR and Docker Hub with `latest` tag
- Uses `docker/build-push-action` with manifest merge

**Dockerfile**: Multi-stage build (golang → scratch) with CA certificates bundled.

### Go Version

**Required**: Go 1.25.1+ (from `go.mod`)
**Tested**: Go 1.26.2 compatible

**Dependencies** (pinned to master/HEAD):

- `github.com/miekg/dns` - DNS library
- `github.com/quic-go/quic-go` - QUIC protocol
- `github.com/redis/go-redis/v9` - Redis client
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
    "github.com/miekg/dns"
    "github.com/quic-go/quic-go"
    "github.com/redis/go-redis/v9"
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

// Structured logging
LogError("CACHE: failed to refresh %v", err)
```

### Concurrency Patterns

**Atomic operations** (simple state):

```go
var closed atomic.Int32
atomic.StoreInt32(&closed, 1)
```

**errgroup** (concurrent operations):

```go
backgroundGroup, backgroundCtx := errgroup.WithContext(ctx)
cacheRefreshGroup, cacheRefreshCtx := errgroup.WithContext(ctx)
```

**Mutex** (complex shared state):

```go
type CIDRManager struct {
    mu      sync.RWMutex
    // ...
}
```

**sync.Pool** (object reuse):

```go
var MessagePool = &sync.Pool{
    New: func() interface{} {
        return new(dns.Msg)
    },
}
```

### Memory Management

**Pre-allocated buffers**:

```go
const (
    UDPBufferSize     = 1232  // EDNS0 typical size
    TCPBufferSize     = 4096
    SecureBufferSize  = 8192  // TLS/QUIC
    DoHMaxRequestSize = 8192
)
```

**Object pools** (reduce GC pressure):

- `MessagePool` - `dns.Msg` instances (512 capacity)
- `BufferPool` - `[]byte` buffers (256 capacity)

## Configuration

### Config Structure (JSON)

```json
{
  "server": {
    "port": "53",
    "pprof": "6060",
    "log_level": "info",
    "default_ecs_subnet": "auto",  // auto | auto_v4 | auto_v6 | manual CIDR
    "memory_cache_size": 10000,
    "ddr": { "domain": "dns.example.com", "ipv4": "127.0.0.1", "ipv6": "::1" },
    "tls": { "port": "853", "cert_file": "...", "key_file": "...", "self_signed": false },
    "features": { "hijack_protection": true },
    "latency_probe": [{ "protocol": "ping", "timeout": 100 }, ...]
  },
  "redis": {
    "address": "127.0.0.1:6379",
    "password": "",
    "database": 0,
    "key_prefix": "zjdns:"
  },
  "upstream": [
    { "address": "223.5.5.5:53", "protocol": "udp" },
    { "address": "223.5.5.5:853", "protocol": "tls", "server_name": "dns.alidns.com" },
    { "address": "https://223.5.5.5:443/dns-query", "protocol": "https" },
    { "address": "builtin_recursive", "protocol": "" }  // Use built-in recursive resolver
  ],
  "rewrite": [
    { "name": "blocked.example.com", "records": [{ "type": "A", "ttl": 10, "content": "127.0.0.1" }] }
  ],
  "cidr": [
    { "file": "whitelist.txt", "tag": "file" },
    { "rules": ["192.168.0.0/16", "10.0.0.0/8"], "tag": "rules" }
  ]
}
```

### Key Configuration Options

**Cache modes**:

- **No Redis** (`redis.address` empty) → Pure `MemoryCache` (default)
- **With Redis** → `HybridCache` (memory-first reads, write-through async to Redis)

**HybridCache behavior**:

- **Read**: Memory cache first → fall back to Redis on miss
- **Write**: Update memory immediately + async write to Redis
- **Auto-fill**: Redis hits automatically populate memory cache

**Upstream modes**:

- **Upstream servers configured** → Forward queries to upstream
- **No upstream** → Pure recursive resolution from root servers
- **`builtin_recursive`** → Use built-in recursive resolver (with DNSSEC, hijack protection)

**ECS (EDNS Client Subnet)**:

- `auto` - Auto-detect from client IP (both IPv4/IPv6)
- `auto_v4` - IPv4 only
- `auto_v6` - IPv6 only
- Manual CIDR (e.g., `192.168.1.0/24`)

### Critical Constants

```go
// Timeouts
DefaultTimeout             = 2 * time.Second
OperationTimeout           = 3 * time.Second
IdleTimeout                = 5 * time.Second
DefaultLatencyProbeTimeout = 100 * time.Millisecond

// Limits
MaxRecursionDep = 16      // Maximum recursion depth
MaxCNAMEChain   = 16      // Maximum CNAME chain length
MaxDomainLength = 253     // Maximum domain name length

// DNS Cookie (RFC 7873)
DefaultCookieClientLen = 8   // 8 bytes
DefaultCookieServerLen = 16  // 16 bytes

// Cache
DefaultTTL             = 10
StaleTTL               = 30
StaleMaxAge            = 30 * 86400  // 30 days
ServeExpiredClientTimeout = 500       // RFC 8767 (500ms < 1.8s recommended)
```

## Security Features

### DNSSEC Validation

**Trust anchors**: Auto-loaded from IANA root-anchors.xml (KSK 20326, KSK 38696)

**Validation** (lightweight):

1. **AD Flag Check**: Validates Authenticated Data flag in responses
2. **DNSSEC Record Check**: Detects DNSSEC record types (RRSIG, NSEC, NSEC3, DNSKEY, DS)

**Caching**: DNSKEY/DS cached with regular DNS responses (unified CacheManager)

**AD flag**: Propagated to clients when validation passes

### Hijack Prevention

**Detection**: Root server returns final answer for non-root domain → suspected hijack

**Mitigation flow**:

1. Detect UDP hijack → Auto-switch to TCP retry
2. TCP also hijacked → Reject response entirely (REFUSED + EDE)

### CIDR Filtering

**Tag-based**: Associate upstream servers with CIDR rules via tags

**Filtering**: A/AAAA records checked against CIDR rules

**Response**: All IPs filtered → REFUSED + EDE code 15 (Blocked) or 17 (Filtered)

### Extended DNS Errors (EDE)

Supported codes (RFC 8914):

- `3` - Stale Answer
- `5` - DNSSEC Indeterminate
- `6` - DNSSEC Bogus
- `15` - Blocked
- `16` - Censored
- `17` - Filtered
- `18` - Prohibited

## Testing

**No test files exist** in the repository.

Manual testing via `kdig`:

```bash
# Basic DNS
kdig @127.0.0.1 -p 53 example.com

# DoT
kdig @127.0.0.1 -p 853 example.com +tls

# DoQ
kdig @127.0.0.1 -p 853 example.com +quic

# DoH
kdig @127.0.0.1 -p 443 example.com +https

# With ECS
kdig @127.0.0.1 example.com +subnet=192.168.1.0/24
```

## Development Workflow

1. **Before changes**: Run `golangci-lint run` to understand existing patterns
2. **During changes**: Follow conventions, add structured logging, handle errors with `%w`
3. **After changes**: `golangci-lint run && golangci-lint fmt`, verify functionality

### Git Repo Quirks

**`.gitignore`**: Ignore-everything-then-allowlist pattern:

- Only `.go`, `.md`, `.json`, `go.mod`, `go.sum`, `Dockerfile`, `LICENSE`, `.github/` tracked
- Binaries, configs, logs automatically ignored

**CI/CD**:

- Dependency updates via `.github/workflows/deps.yml` (manual trigger, creates PR)
- Docker builds via `.github/workflows/main.yml` (scheduled + manual)

## Key Implementation Patterns

### Query Flow (simplified)

```
Client Query → Protocol Handler → DNSServer
                                    ↓
                            RewriteManager (check rewrite rules)
                                    ↓
                            CacheManager (check cache)
                            ├─ Hit → Return cached
                            └─ Miss → QueryManager
                                         ├─ Upstream mode → queryUpstream()
                                         └─ Recursive mode → RecursiveResolver
                                              ↓
                                      Root → TLD → Authoritative
                                              ↓
                                      DNSSEC validation
                                              ↓
                                      CIDR filtering
                                              ↓
                                      Cache + Response
```

### Protocol-Specific Handlers

All handlers follow similar pattern:

1. Read request into buffer from `BufferPool`
2. Parse DNS message
3. Call `server.HandleQuery()` (unified processing)
4. Write response
5. Return buffer to `BufferPool`

### Background Tasks

Managed via `errgroup.Group`:

- Cache prefetch (refresh expiring entries)
- Latency probing (A/AAAA record speed testing)
- TLS certificate management
- Signal handling (graceful shutdown)

## Gotchas

1. **No tests**: All verification is manual via `kdig` or integration testing
2. **No linter config**: Uses default `golangci-lint` rules
3. **Single package**: All code in `main` package (no sub-packages)
4. **Global state**: Heavy use of global variables for managers/pools
5. **Vibe coding**: Project self-describes as "Vibe Coding product with complex code structure" - not production-verified
6. **Go version**: `go.mod` specifies 1.25.1, but tested with 1.26.2

## References

- **RFC 7871**: EDNS Client Subnet (ECS)
- **RFC 7873**: DNS Cookie
- **RFC 7830**: DNS Padding
- **RFC 7858**: DNS over TLS (DoT)
- **RFC 8484**: DNS over HTTPS
- **RFC 8767**: Serving Stale DNS Responses
- **RFC 8914**: Extended DNS Errors
- **RFC 9018**: DNS Cookie update
- **RFC 9250**: DNS over QUIC
- **RFC 9461/9462**: Discovery of Designated Resolvers (DDR)
