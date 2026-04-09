# AGENTS.md - ZJDNS Development Guide

## Build Commands

### Basic Build

```bash
go build -o zjdns
GOOS=linux GOARCH=amd64 go build -o zjdns-linux-amd64
GOOS=linux GOARCH=arm64 go build -o zjdns-linux-arm64
```

### Code Quality

```bash
golangci-lint run && golangci-lint fmt
```

### Testing

```bash
go test ./...
go test -v ./...
go test -cover ./...
go test -bench=. ./...
```

### Development

```bash
./zjdns -generate-config > config.json
./zjdns -config config.json
```

## Code Style

### File Structure

Modular structure organized by functionality:

- `constants.go` - Global constants (Network, Buffer, Protocol, Timing, Cache, QUIC, Logging, Root Servers, ALPN)
- `types.go` - All type definitions (Config, Cache, Security types)
- `utils.go` - Utility functions (string handling, DNS records, cache keys, config generation)
- `logger.go` - Log management (LogManager, TimeCache, RNG)
- `pool.go` - Object pools (MessagePool, BufferPool) + global variable initialization
- `config.go` - Config loading, validation, DDR records
- `cache.go` - Cache implementations (NullCache, RedisCache, CacheEntry methods)
- `cidr.go` - CIDR filtering logic
- `edns.go` - EDNS/ECS management
- `rewrite.go` - DNS rewrite rules
- `security.go` - Security (DNSSECValidator, HijackPrevention, SecurityManager)
- `tls.go` - TLS/DoT/DoQ/DoH/DoH3 management
- `query.go` - DNS query client (QueryClient)
- `resolver.go` - Query management and recursive resolution
- `server.go` - DNS server lifecycle (DNSServer)
- `main.go` - Entry point only

### Imports

Standard library → Third-party → Internal, all alphabetically sorted:

```go
import (
    "context"
    "fmt"
    "sync"

    "github.com/miekg/dns"
    "github.com/redis/go-redis/v9"
)
```

### Naming

- Constants: `PascalCase` (`DefaultDNSPort`, `UDPBufferSize`)
- Types: `PascalCase` (`ServerConfig`, `CacheManager`)
- Functions: `PascalCase` public, `camelCase` private
- Methods: `PascalCase` public, `camelCase` private
- Patterns: `*Manager`, `*Handler`, `*Client` suffixes

### Error Handling

- Use `fmt.Errorf("operation: %w", err)` for error chaining
- `defer HandlePanic("operation")` for goroutine safety
- Context-aware error handling preferred
- Structured logging: `LogError("MODULE: message %v", err)`

### Concurrency

- Atomic operations for simple state: `atomic.StoreInt32(&closed, 1)`
- `errgroup.Group` for concurrent operations
- Always propagate context for cancellation
- Mutex for complex shared state

### Memory

- Object pools: `MessagePool` for `dns.Msg`, `BufferPool` for bytes
- Pre-allocated buffers: `UDPBufferSize = 1232`, `SecureBufferSize = 8192`
- Use `sync.Pool` for frequently allocated objects

### Configuration

- JSON with struct tags
- Comprehensive validation with clear errors
- Sensible defaults for all options

### Logging

- Consistent prefixes: `CONFIG:`, `CACHE:`, `QUERY:`, `TLS:`
- Levels: error, warn, info, debug
- Avoid logging in hot paths

### Key Constants

- Timeouts: `DefaultTimeout = 2s`, `OperationTimeout = 3s`
- Limits: `MaxRecursionDep = 16`, `MaxCNAMEChain = 16`, `DefaultCookieClientLen = 8`

## Module Organization

| File           | Purpose           | Key Types/Functions                                   |
| -------------- | ----------------- | ----------------------------------------------------- |
| `constants.go` | Global constants  | Port numbers, buffer sizes, timeouts, protocol limits, EDE codes, DNS Cookie constants, Root Trust Anchors (IANA KSK 20326/38696) |
| `types.go`     | Type definitions  | All structs and interfaces (Config, Cache, Security, CookieOption, EDEOption, RootTrustAnchor, ZoneCache)  |
| `utils.go`     | Utility functions | String ops, DNS record helpers, cache key generation, client IP extraction  |
| `logger.go`    | Logging           | LogManager, TimeCache, RNG, global log functions      |
| `pool.go`      | Memory pools      | MessagePool, BufferPool with sync.Pool                |
| `config.go`    | Configuration     | ConfigManager, validation, DDR records                |
| `cache.go`     | Cache             | NullCache, RedisCache, CacheEntry methods             |
| `cidr.go`      | CIDR filtering    | CIDRManager, IP filtering logic, REFUSED with EDE                         |
| `edns.go`      | EDNS/ECS/Cookie/EDE | EDNSManager, ECS option handling, CookieGenerator, EDE helpers (RFC 7873, 8914) |
| `rewrite.go`   | DNS rewriting     | RewriteManager, domain rewrite rules, EDE for blocked responses           |
| `security.go`  | Security          | DNSSECValidator (chain of trust validation, RRSIG verification, ZoneCache), HijackPrevention, SecurityManager |
| `tls.go`       | TLS protocols     | TLSManager, DoT/DoQ/DoH/DoH3 handlers, self-signed CA                     |
| `query.go`     | Query client      | QueryClient, protocol-specific querying with EDE propagation               |
| `resolver.go`  | Resolution        | QueryManager, RecursiveResolver, CNAMEHandler, EDE code propagation        |
| `server.go`    | Server core       | DNSServer, UDP/TCP/DoT/DoQ/DoH handlers, Cookie & EDE response generation  |
| `main.go`      | Entry point       | Main function only                                                        |

## Development Workflow

1. Before changes: `golangci-lint run`, understand patterns
2. During changes: follow conventions, add logging/error handling
3. After changes: `golangci-lint run && golangci-lint fmt`, test functionality

## Configuration

JSON sections: server, redis, upstream, rewrite, cidr
Generate example: `./zjdns -generate-config > config.json`

## Best Practices

- Performance: Object pools, proper buffers, atomic operations
- Security: Validate certificates (unless disabled), input validation
- Testing: Unit tests, integration tests, benchmarks
- Memory: Context for cancellation, proper cleanup
