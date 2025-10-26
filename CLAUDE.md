# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZJDNS is a high-performance recursive DNS server written in Go that supports:

- Recursive DNS resolution with intelligent protocol fallback (UDP/TCP)
- Redis caching with stale cache serving and ECS-aware caching
- DNSSEC validation with AD flag propagation
- Secure DNS protocols: DoT (DNS over TLS), DoQ (DNS over QUIC), DoH/DoH3 (DNS over HTTPS)
- EDNS Client Subnet (ECS) with auto-detection modes
- DNS hijacking prevention with TCP fallback
- CIDR-based IP filtering with file-based rules
- DNS rewriting capabilities for domain filtering/redirection
- Network quality testing for result optimization
- DDR (Discovery of Designated Resolvers) via SVCB records
- Advanced connection pooling with protocol-specific pools

## Build and Development Commands

### Building

```bash
# Build binary with version info
VERSION=$(git describe --tags --always 2>/dev/null || echo "1.0.0")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
go build -o zjdns -trimpath -ldflags "-s -w -buildid= -X main.Version=${VERSION} -X main.CommitHash=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

# Build for production (uses Docker multi-stage build)
docker build -t zjdns .

# Build for testing without version metadata
go build -o zjdns
```

### Running and Testing

```bash
# Generate example configuration
./zjdns -generate-config > config.json

# Start with default configuration (pure recursive, no cache)
./zjdns

# Start with configuration file
./zjdns -config config.json

# Quick functional test
go build -o zjdns && ./zjdns -generate-config

# Test DNS resolution functionality
dig @127.0.0.1 -p 53 example.com
dig @127.0.0.1 -p 853 example.com +tls
curl -k "https://127.0.0.1:443/dns-query?dns=$(base64 <<< $(dig +short example.com))"
```

### Code Quality

```bash
# Run linter and formatter
golangci-lint run
golangci-lint fmt

# Run tests (this project has no external test files - testing is done through integration)
go test -v
go test -race
go test -cover

# Performance monitoring with pprof
curl http://127.0.0.1:6060/debug/pprof/
curl http://127.0.0.1:6060/debug/pprof/heap
```

## Architecture

This is a monolithic Go application (~180KB) contained entirely in `main.go` with a modular internal structure.

### Core Components

**DNSServer** - Main server orchestrator with background task groups:

- `backgroundGroup`: Handles long-running background tasks
- `cacheRefreshGroup`: Manages cache refresh operations
- `shutdownCoordinator`: Graceful shutdown management

**Modular Managers**:

- **ConfigManager**: JSON configuration loading and validation
- **CacheManager**: Interface-based caching (RedisCache/NullCache)
- **QueryManager**: High-level query orchestration
- **UpstreamHandler**: Manages upstream DNS server configurations
- **ConnPool**: Protocol-specific connection pooling (HTTP/2, HTTP/3, QUIC, TLS)

### Advanced Features

**SpeedTestManager**: Network quality testing with multi-protocol support

- ICMP, TCP, UDP latency testing
- Result caching and concurrent processing
- Integration with result sorting

**RootServerManager**: Dynamic root server optimization

- Real-time latency-based sorting
- Automatic failover and performance monitoring
- Integration with recursive resolver

**CIDRManager**: Advanced IP filtering

- File-based rule loading with labels
- Association with upstream servers via labels
- A/AAAA record filtering with REFUSED responses

**RequestTracker**: Comprehensive request tracing

- Unique ID generation per request
- Performance timing and step logging
- DEBUG level detailed logging, INFO level summaries

### Protocol Implementation

All DNS protocols are implemented in the single file:

- **Traditional DNS**: UDP/TCP on port 53 with automatic TCP fallback
- **DoT**: DNS over TLS on port 853
- **DoQ**: DNS over QUIC on port 853 (shared with DoT)
- **DoH/DoH3**: DNS over HTTPS/HTTP3 on port 443

### Security & Enhancement Modules

- **SecurityManager**: Coordinates DNSSEC validation, hijacking prevention
- **EDNSManager**: Handles ECS, padding, EDNS0 options
- **TLSManager**: Self-signed CA, dynamic certificate generation
- **RewriteManager**: Domain-based response rewriting
- **IPDetector**: Client IP detection for ECS support

### Performance Optimizations

**Memory Management**:

- DNS message pooling with size limits (1000 messages, 50 slice capacity)
- Real-time memory monitoring (30-second intervals, 500MB GC trigger)
- Controlled query concurrency (MaxSingleQuery: 5) with first-winner strategy

**Concurrency Control**:

- Fixed worker pools to prevent goroutine explosion
- errgroup for background task management
- Direct goroutine usage on critical paths to reduce context switching

**Connection Optimization**:

- Protocol-specific connection pools
- TLS session caching
- Connection lifecycle management with automatic cleanup

## Configuration Structure

Key configuration sections (JSON):

- **server**: Network settings, ports, protocol flags, ECS configuration
- **redis**: Cache configuration with connection pooling
- **speedtest**: Network testing parameters (ICMP/TCP/UDP)
- **upstream**: DNS servers with labels and protocols
- **rewrite**: Domain-based response modification rules
- **cidr**: IP filtering rules with file paths and labels
- **tls**: Certificate configuration for secure protocols
- **ddr**: Discovery of Designated Resolvers settings

## Dependencies

Core external dependencies:

- `github.com/miekg/dns`: DNS protocol implementation
- `github.com/redis/go-redis/v9`: Redis client
- `github.com/quic-go/quic-go`: QUIC protocol for DoQ
- `golang.org/x/net`: Extended networking

## Development Notes

### Single-File Architecture

All functionality is contained in `main.go` (~180KB). When making changes:

1. **Understand the component hierarchy** - managers are nested structs with clear separation
2. **Follow atomic patterns** - extensive use of `atomic.Value`, `atomic.Int32`, `atomic.Bool`
3. **Respect connection pooling** - connections are managed through ConnPool with protocol-specific pools
4. **Maintain thread safety** - all state changes must be atomic or mutex-protected

### Configuration Management

- Configuration is generated dynamically via `-generate-config` flag
- All configuration sections have defaults for zero-config startup
- File-based CIDR rules support hot-reloading

### Testing Approach

- No external test files - integration testing through DNS queries
- Use dig, curl, and browser testing for validation
- Performance testing through pprof endpoints
- Functional testing with various DNS record types and protocols

### Deployment

- Docker multi-stage builds create minimal scratch images
- Automated GitHub Actions build for multiple architectures (amd64/arm64)
- Build metadata embedded via ldflags for version tracking
- Container includes CA certificates for TLS operations

### Key Patterns to Preserve

- **Atomic State Management**: Use atomic operations for all shared state
- **Interface-Based Design**: CacheManager interface allows multiple implementations
- **Connection Reuse**: All external connections go through ConnPool
- **Structured Logging**: LogManager provides leveled logging with color support
- **Graceful Shutdown**: Proper cleanup of all resources and connections
- **Context Cancellation**: Use contexts for cancellation throughout the codebase

### Security Considerations

The codebase includes critical security features that must be preserved:

- DNS hijacking detection with automatic TCP fallback
- CIDR-based IP filtering with strict REFUSED responses
- DNSSEC validation support with AD flag propagation
- TLS certificate management for all secure protocols
- Memory safety through comprehensive resource cleanup
- Request rate limiting through connection pooling and concurrency control
