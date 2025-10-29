# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZJDNS is a high-performance recursive DNS resolution server written in Go that supports:

- Traditional DNS (UDP/TCP) on port 53
- Secure DNS protocols: DoT (853), DoQ (853), DoH/DoH3 (443)
- Redis caching with TTL management and stale cache serving
- DNSSEC validation, ECS support, and hijack protection
- CIDR-based filtering and DNS rewrite rules
- Self-signed TLS certificate generation

**Important**: This is a single-file architecture project (main.go ~126KB) with comprehensive DNS functionality.

## Build and Development Commands

### Basic Operations

```bash
# Build the binary
go build -o zjdns

# Generate example configuration
./zjdns -generate-config > config.json

# Start with default configuration (recursive mode, no cache)
./zjdns

# Start with configuration file (recommended)
./zjdns -config config.json

# Show version
./zjdns -version
```

### Development Tools

```bash
# Run code quality checks and formatting
golangci-lint run && golangci-lint fmt

# Install golangci-lint (if not installed)
brew install golangci-lint
```

### Testing DNS Resolution

```bash
# Traditional DNS test
kdig @127.0.0.1 -p 53 example.com

# DoT test
kdig @127.0.0.1 -p 853 example.com +tls

# DoQ test
kdig @127.0.0.1 -p 853 example.com +quic

# DoH test
kdig @127.0.0.1 -p 443 example.com +https
```

### Performance Monitoring

```bash
# pprof profiling endpoint
curl http://127.0.0.1:6060/debug/pprof/

# Memory usage analysis
curl http://127.0.0.1:6060/debug/pprof/heap
```

## Architecture Overview

### Core Components

The entire application is contained in `main.go` with these key structs:

- **DNSServer**: Main server orchestrator
- **QueryManager**: DNS query processing and upstream selection
- **SecurityManager**: TLS, DNSSEC, and hijack protection
- **CacheManager**: Redis caching interface (RedisCache/NullCache)
- **EDNSManager**: EDNS Client Subnet (ECS) handling
- **RewriteManager**: DNS rewrite rules for blocking/custom responses
- **CIDRManager**: IP-based filtering and routing
- **QueryClient**: Upstream DNS query handling

### Protocol Support

- **UDP/TCP DNS**: Traditional DNS on port 53
- **DoT (DNS over TLS)**: TLS-wrapped DNS on port 853
- **DoQ (DNS over QUIC)**: QUIC-based DNS on port 853
- **DoH (DNS over HTTPS)**: HTTP/2 on port 443
- **DoH3 (DNS over HTTP/3)**: HTTP/3 over QUIC on port 443

### Query Processing Flow

1. Receive DNS query (any protocol)
2. Apply rewrite rules if configured
3. Check cache (Redis or null)
4. If cache miss: query upstream servers or recursive resolution
5. Apply security filters (CIDR, DNSSEC validation)
6. Cache response and return to client

## Configuration Structure

Key configuration sections in `config.json`:

- **server**: Basic settings, ports, TLS configuration, DDR settings
- **redis**: Cache backend configuration (optional - can run without Redis)
- **upstream**: List of upstream DNS servers with protocol-specific settings
- **rewrite**: DNS rewrite rules for custom responses
- **cidr**: CIDR filtering rules for access control

### Upstream Configuration

Supports mixed upstream strategies:

- Traditional DNS servers (UDP/TCP)
- Secure DNS servers (DoT/DoQ/DoH)
- Built-in recursive resolver (`builtin_recursive`)

### Redis Caching (Optional)

- Can run in "no cache mode" for testing
- Redis mode recommended for production
- Supports stale cache serving when upstream is unavailable
- ECS-aware cache partitioning

## Development Guidelines

### Code Style

- Use `golangci-lint` for code quality checks
- Run `golangci-lint fmt` for code formatting
- Ensure all checks pass before committing

### Key Dependencies

- `github.com/miekg/dns`: Core DNS library
- `github.com/quic-go/quic-go`: QUIC protocol for DoQ/DoH3
- `github.com/redis/go-redis/v9`: Redis client for caching
- `golang.org/x/net`: HTTP/2 and networking utilities
- `golang.org/x/sync`: ErrGroup for goroutine management

### Testing

- No formal test suite currently exists
- Use manual DNS testing with kdig or similar tools
- Test all protocols (UDP, TCP, DoT, DoQ, DoH) during development
- Verify Redis caching functionality when enabled

### Adding New Features

- All code is in `main.go` - maintain the single-file architecture
- Follow the existing pattern of managers for new functionality
- Ensure graceful shutdown handling for new components
- Add appropriate configuration options to the JSON schema
- Consider thread safety when modifying shared data structures

## Important Notes

- **Single File Architecture**: The entire codebase is in `main.go` (~126KB)
- **Production Warning**: This is marked as a "Vibe Coding product" not fully production-tested
- **Security**: Includes hijack protection, DNSSEC validation, and TLS certificate management
- **Performance**: Optimized for concurrent query processing with Redis caching
- **Observability**: Includes structured logging and pprof integration
