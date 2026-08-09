# Benchmark & E2E Test Guide

> **定位**：Go 单元/集成 benchmark + 外部客户端（dnsperf / DNSCrypt-proxy）的 E2E。
> 全协议出口压测见 [LOADTEST.md](LOADTEST.md)（benchclient 直连单端）；
> ZJDNS 客户端 ↔ 服务端全链路压测见 [DEBUG.md 双端压测章节](../debug/DEBUG.md#双端压测--pprof-采集zjdns--zjdns)。
> 三份文档的边界见 [docs/README.md](../README.md)。

## Prerequisites

```bash
# Build ZJDNS
go build -o /tmp/zjdns ./cmd/zjdns

# Build dnscrypt-proxy (must compile from source for PQ support)
cd /path/to/dnscrypt-proxy/dnscrypt-proxy && go build -o /tmp/dnscrypt-proxy .

# Install dnsperf (macOS)
brew install dnsperf
```

## Go Benchmarks

```bash
# All benchmarks (fast)
go test -bench=. -short ./...

# Integration QPS benchmark
go test -bench=BenchmarkServerProcessQuery -benchtime=3s -count=3 ./cmd/zjdns

# Update baseline
go test -bench=. -short -benchtime=500ms ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
```

## dnsperf QPS Benchmark (Zone Cache)

Minimal config for pure zone-lookup QPS:

```bash
# Config: /tmp/zjdns-bench.json
{
  "server": {
    "log_level": "error",
    "protocol": { "udp": "10533" },
    "zone": [
      { "name": "www.baidu.com",
        "answer": [{ "type": 1, "ttl": 3600, "content": "1.2.3.4" }] }
    ],
    "features": { "cache": { "max_entries": 0 } }
  }
}

# Test data: /tmp/dnsperf-data.txt
echo "www.baidu.com A" > /tmp/dnsperf-data.txt

# Run
/tmp/zjdns -config /tmp/zjdns-bench.json > /dev/null 2>&1 &
sleep 2
dnsperf -s 127.0.0.1 -p 10533 -d /tmp/dnsperf-data.txt -c 100 -l 30 -Q 500000
pkill -f zjdns
```

## DNSCrypt E2E Test (ZJDNS ↔ dnscrypt-proxy)

### Post-Quantum (X-Wing KEM)

```bash
# Start ZJDNS DNSCrypt server (dual-cert: classical + PQ)
/tmp/zjdns -config docs/debug/dnscrypt/zjdns-server.json > /tmp/zjdns.log 2>&1 &
sleep 2

# Start dnscrypt-proxy with PQ enabled (default)
/tmp/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-pq.toml > /tmp/proxy-pq.log 2>&1 &
sleep 4

# Query through proxy
dig @127.0.0.1 -p 13053 www.baidu.com A +short
dig @127.0.0.1 -p 13053 www.example.com A +short

# Expected server logs:
#   DNSCRYPT: PQ initial query       ← first query, X-Wing KEM
#   DNSCRYPT: PQ ticket issued       ← resumption ticket
#   DNSCRYPT: PQ resumed query       ← second query, ticket reuse

pkill -f dnscrypt-proxy
```

### Classical (XChacha20-Poly1305)

```bash
/tmp/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-classic.toml > /tmp/proxy-classic.log 2>&1 &
sleep 4

dig @127.0.0.1 -p 13153 www.baidu.com A +short
dig @127.0.0.1 -p 13153 www.example.com A +short

# Expected server logs:
#   DNSCRYPT: classical query        ← XChacha20-Poly1305

pkill -f dnscrypt-proxy
pkill -f zjdns
```

## Defense E2E Tests

### Poisonguard (recursive poison detection)

```bash
/tmp/zjdns -config docs/debug/defense/poisonguard.json > /tmp/poison.log 2>&1 &
sleep 3

dig @127.0.0.1 -p 10533 www.google.com A +short

# Expected log: poison probe detected … forcing TCP

pkill -f zjdns
```

### Spoofguard (upstream UDP anti-spoof)

```bash
/tmp/zjdns -config docs/debug/defense/spoofguard.json > /tmp/spoof.log 2>&1 &
sleep 3

dig @127.0.0.1 -p 10533 www.baidu.com A +short

pkill -f zjdns
```

### Hopguard (UDP IP TTL fingerprint)

```bash
/tmp/zjdns -config docs/debug/defense/hopguard.json > /tmp/hopguard.log 2>&1 &
sleep 3

dig @127.0.0.1 -p 10533 www.baidu.com A +short

# Expected log: hopguard IP_RECVTTL … enabled (Linux) / not available (Windows)
# TTL mismatch → packet dropped silently; TTL match → passed to content analysis

pkill -f zjdns
```

### Splitguard (TCP segmentation)

```bash
/tmp/zjdns -config docs/debug/defense/splitguard.json > /tmp/split.log 2>&1 &
sleep 3

dig @127.0.0.1 -p 10533 www.google.com A +short

pkill -f zjdns
```

## TLCP / DTLCP E2E Tests

```bash
# TLCP DoH loopback
/tmp/zjdns -config docs/debug/loopback/server.json > /dev/null 2>&1 &
sleep 4
/tmp/zjdns -config docs/debug/loopback/client-http-tlcp.json > /dev/null 2>&1 &
sleep 3
dig @127.0.0.1 -p 13553 www.baidu.com A +short
pkill -f zjdns

# DTLCP loopback
/tmp/zjdns -config docs/debug/loopback/server.json > /dev/null 2>&1 &
sleep 4
/tmp/zjdns -config docs/debug/loopback/client-dtlcp.json > /dev/null 2>&1 &
sleep 3
dig @127.0.0.1 -p 14653 www.baidu.com A +short
pkill -f zjdns
```
