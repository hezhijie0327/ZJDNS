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
- Single file (`main.go`) with clear comment sections
- Constants grouped by purpose (Network, Buffer, Protocol, Timing)
- Types organized by functionality (Config, Cache, Security)
- Implementation sections follow type definitions

### Imports
Standard library → Third-party → Internal, all alphabetically sorted.

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

## Architecture

### Core Flow
DNSServer → QueryManager → QueryClient → CacheManager → SecurityManager

### Protocols
- Traditional: UDP/TCP on port 53
- Secure: DoT/DoQ (853), DoH/DoH3 (443)
- Fallback: UDP to TCP for truncated responses

### Key Constants
- Timeouts: `DefaultTimeout = 2s`, `OperationTimeout = 3s`
- Limits: `MaxRecursionDep = 16`, `MaxCNAMEChain = 16`

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