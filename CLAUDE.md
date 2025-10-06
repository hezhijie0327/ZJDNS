# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZJDNS is a high-performance recursive DNS server written in Go that supports:
- Recursive DNS resolution with intelligent protocol fallback (UDP/TCP)
- Redis caching with stale cache serving
- DNSSEC validation with AD flag propagation
- Secure DNS protocols: DoT (DNS over TLS), DoQ (DNS over QUIC), DoH/DoH3 (DNS over HTTPS)
- EDNS Client Subnet (ECS) for geo-aware resolution
- DNS hijacking prevention with TCP fallback
- DNS rewriting capabilities for domain filtering/redirection
- Network quality testing for result optimization
- DDR (Discovery of Designated Resolvers) via SVCB records

## Build and Development Commands

### Building
```bash
# Build the binary
go build -o zjdns -trimpath -ldflags "-s -w -buildid="

# Build for production (uses Docker multi-stage build)
docker build -t zjdns .
```

### Running
```bash
# Generate example configuration
./zjdns -generate-config > config.json

# Start with default configuration (pure recursive, no cache)
./zjdns

# Start with configuration file
./zjdns -config config.json
```

### Code Quality
```bash
# Run linter and formatter
golangci-lint run
golangci-lint fmt
```

### Testing
Since this is a single-file Go application, use standard Go testing:
```bash
go test -v
go test -race
go test -cover
```

## Architecture

This is a monolithic Go application contained in `main.go` with a modular internal structure:

### Core Components

- **DNSServer**: Main server struct that orchestrates all DNS protocols
- **ConfigManager**: Handles JSON configuration loading and validation
- **ConnectionPool**: Manages persistent connections to upstream servers
- **CacheManager**: Dual-mode caching (NullCache for testing, RedisCache for production)
- **QueryClient**: Unified client for DNS queries with protocol fallback
- **UpstreamManager**: Manages upstream DNS server configurations

### Protocol Handlers

- **Traditional DNS**: UDP/TCP on port 53
- **DoT (DNS over TLS)**: TLS on port 853
- **DoQ (DNS over QUIC)**: QUIC protocol implementation
- **DoH/DoH3**: HTTP/2 and HTTP/3 on port 443

### Security & Enhancement Modules

- **EDNSManager**: Handles EDNS0 options, ECS, and padding
- **DNSSECValidator**: Validates DNSSEC signatures
- **HijackPrevention**: Detects and mitigates DNS hijacking attempts
- **IPFilter**: CIDR-based IP filtering for trusted/untrusted clients
- **DNSRewriter**: Domain rewriting and response customization
- **SpeedTester**: Network quality testing for result optimization

### Supporting Infrastructure

- **RequestTracker**: Per-request tracing and performance monitoring
- **ResourceManager**: Memory and connection management with object pools
- **TaskManager**: Goroutine pool management for concurrent operations
- **TLSManager**: Certificate management for secure protocols

## Configuration

The server uses JSON configuration with these key sections:
- Network settings (ports, protocols)
- Upstream DNS servers
- Redis cache configuration
- Security settings (DNSSEC, TLS certificates)
- ECS and padding configuration
- IP filtering rules
- DNS rewriting rules

## Dependencies

Key external dependencies:
- `github.com/miekg/dns`: Core DNS protocol implementation
- `github.com/redis/go-redis/v9`: Redis client for caching
- `github.com/quic-go/quic-go`: QUIC protocol for DoQ
- `github.com/dgraph-io/ristretto/v2`: In-memory caching
- `golang.org/x/net`: Extended networking capabilities

## Development Notes

- This is a single-file application (~180KB) with all functionality in `main.go`
- Uses extensive logging with configurable levels (ERROR, WARN, INFO, DEBUG)
- Implements comprehensive error handling and panic recovery
- Supports both development (no cache) and production (Redis) modes
- Includes Docker multi-stage builds for minimal container images
- Has GitHub Actions for automated building and container publishing

## Security Considerations

The codebase includes several security features that should be preserved:
- DNS hijacking detection and prevention
- DNSSEC validation support
- TLS certificate management for secure protocols
- IP-based access control
- Request rate limiting through connection pooling
- Memory safety through object pool management