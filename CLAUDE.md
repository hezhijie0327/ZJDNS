# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is ZJDNS Server, a high-performance recursive DNS resolver written in Go. It supports advanced features like Redis caching, DNSSEC validation, ECS (EDNS Client Subnet), and secure protocols like DoT/DoQ/DoH.

## Code Architecture and Structure

The system follows a modular architecture with these key components:

- DNS Server (`dns_server.go`): Main server logic handling DNS requests
- Configuration (`config.go`): Configuration parsing and management
- Cache System (`cache_null.go`, `cache_redis.go`): Dual-mode caching (null/Redis)
- Security Features: DNSSEC validation, ECS management, DNS hijacking prevention
- Secure DNS: DoT/DoQ/DoH implementations
- Connection Management: Connection pooling for both secure and regular connections
- Upstream Management: Handling upstream DNS servers
- Network Quality Testing: Speed testing for optimal response sorting

The architecture flows from request handler → DNS rewriter → cache manager → connection pool → query engine, with various specialized managers for different features.

## Common Development Commands

### Building
```bash
# Standard build
go build -o zjdns

# Build with optimizations (as in Dockerfile)
go build -o zjdns -trimpath -ldflags "-s -w -buildid="
```

### Running
```bash
# Generate example config
./zjdns -generate-config > config.json

# Run with config
./zjdns -config config.json

# Run with default config
./zjdns
```

### Docker Build
```bash
# Build Docker image
docker build -t zjdns .
```

### Dependency Management
```bash
# Update dependencies to latest
go get -u github.com/miekg/dns@master
go get -u github.com/redis/go-redis/v9@master
go get -u github.com/quic-go/quic-go@master
go mod tidy
```

### Linting
```bash
# Install golangci-lint (if not installed)
brew install golangci-lint

# Run linter
golangci-lint run

# Format code
golangci-lint fmt
```

## Key Implementation Details

1. **DNS Hijacking Prevention**: Detects unauthorized responses from root servers and automatically retries with TCP
2. **Protocol Fallback**: Automatically switches from UDP to TCP when responses are truncated
3. **ECS Support**: Implements EDNS Client Subnet with auto-detection capabilities
4. **Security Protocols**: Full support for DoT, DoQ, and DoH with shared certificate management
5. **Caching Strategy**: Dual-mode caching with Redis support and intelligent TTL management
6. **Network Quality Testing**: Multi-protocol speed testing with result caching and sorting