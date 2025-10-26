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
# Build the binary with version info
VERSION=$(git describe --tags --always 2>/dev/null || echo "1.0.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
go build -o zjdns -trimpath -ldflags "-s -w -buildid= -X main.Version=${VERSION} -X main.CommitHash=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

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

#### Testing

```bash
# Run tests (this project has no external test files - testing is done through integration)
go test -v
go test -race
go test -cover

# Build and run a quick functional test
go build -o zjdns && ./zjdns -generate-config

# Test DNS resolution functionality
dig @127.0.0.1 -p 53 example.com
dig @127.0.0.1 -p 853 example.com +tls
```

## Architecture

This is a monolithic Go application contained in `main.go` (~180KB) with a modular internal structure:

### Core Components

- **DNSServer**: Main server struct that orchestrates all DNS protocols
- **ConfigManager**: Handles JSON configuration loading and validation
- **CacheManager**: Interface for caching (NullCache for testing, RedisCache for production)
- **QueryManager**: High-level query orchestration and management
- **QueryClient**: Unified client for DNS queries with protocol fallback
- **UpstreamHandler**: Manages upstream DNS server configurations and selection
- **ConnPool**: Connection pooling for managing persistent connections to upstream servers

### Protocol Handlers

- **Traditional DNS**: UDP/TCP on port 53
- **DoT (DNS over TLS)**: TLS on port 853
- **DoQ (DNS over QUIC)**: QUIC protocol implementation
- **DoH/DoH3**: HTTP/2 and HTTP/3 on port 443

### DNS Processing Engine

- **RecursiveResolver**: Core recursive DNS resolution logic
- **CNAMEHandler**: Handles CNAME chain resolution and loop detection
- **ResponseValidator**: Validates and processes DNS responses
- **QueryClient**: Low-level DNS query execution with protocol fallback

### Security & Enhancement Modules

- **SecurityManager**: Coordinates all security-related features
- **EDNSManager**: Handles EDNS0 options, ECS, and padding
- **DNSSECValidator**: Validates DNSSEC signatures
- **HijackPrevention**: Detects and mitigates DNS hijacking attempts
- **CIDRManager**: CIDR-based IP filtering with file-based rules
- **RewriteManager**: Domain rewriting and response customization
- **SpeedTestManager**: Network quality testing for result optimization

### Supporting Infrastructure

- **RequestTracker**: Per-request tracing and performance monitoring
- **TLSManager**: Certificate management for secure protocols
- **RootServerManager**: Dynamic root server management with latency testing
- **IPDetector**: Client IP detection for ECS support
- **LogManager**: Structured logging with configurable levels

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
- `golang.org/x/net`: Extended networking capabilities

## Development Notes

- This is a single-file application (~180KB) with all functionality in `main.go`
- Uses extensive logging with configurable levels (ERROR, WARN, INFO, DEBUG)
- Implements comprehensive error handling and panic recovery
- Supports both development (no cache) and production (Redis) modes
- Includes Docker multi-stage builds for minimal container images
- Has GitHub Actions for automated building and container publishing
- No external test files - testing is done through integration and manual validation
- Uses Go 1.25.1 with cutting-edge dependencies for latest DNS protocol support
- Configuration is generated dynamically via `-generate-config` flag

## Key Architecture Patterns

- **Atomic Operations**: Uses `atomic.Value` and `atomic.Int32/Bool` for thread-safe state management
- **Interface-based Design**: CacheManager interface allows multiple cache implementations
- **Connection Pooling**: ConnPool manages persistent connections with different protocols (HTTP/2, QUIC)
- **Structured Logging**: LogManager provides leveled logging with color support
- **Configuration Management**: JSON-based configuration with automatic example generation

## Deployment & Build Process

### Container Builds

The project uses automated multi-stage Docker builds defined in `Dockerfile`:

- **Build stage**: Compiles with Go 1.25.1, includes CA certificates, sets build metadata
- **Rebase stage**: Copies only necessary components to intermediate scratch
- **Final stage**: Minimal scratch image with just the binary and certificates
- **Automated publishing**: GitHub Actions build and publish to Docker Hub and GHCR
- **Multi-platform**: Supports linux/amd64 and linux/arm64 architectures

### Build Information

Build metadata is embedded via ldflags:

- `main.Version`: Git tag or "1.0.0" fallback
- `main.CommitHash`: Git short commit hash or "dev"
- `main.BuildTime`: UTC timestamp of build

## Security Considerations

The codebase includes several security features that should be preserved:

- DNS hijacking detection and prevention with TCP fallback
- DNSSEC validation support with AD flag propagation
- TLS certificate management for secure protocols (DoT/DoQ/DoH)
- CIDR-based IP filtering with file-based rule management
- Request rate limiting through connection pooling
- Memory safety through object pool management
- DNS rewriting capabilities for domain filtering/redirection
- DDR (Discovery of Designated Resolvers) support via SVCB records
