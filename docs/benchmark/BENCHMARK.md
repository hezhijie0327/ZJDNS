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

外部真实客户端压测（dnsperf ≥ 2.14 支持 `-m udp|tcp|dot|doh`）。
dnsperf 与 ZJDNS 同机时 UDP 结果受客户端 CPU 饱和约束（见下「解读」）。

### 1. Zone 命中配置（纯服务端 QPS）

```bash
# Config: /tmp/zjdns-bench.json（UDP + TCP 同端口）
{
  "server": {
    "log_level": "error",
    "protocol": { "udp": "10533", "tcp": "10533" },
    "features": { "cache": { "entries": { "limit": { "mem": 100 } } } }
  },
  "zone": [
    { "name": "www.baidu.com",
      "answer": [{ "type": 1, "ttl": 3600, "content": "1.2.3.4" }] }
  ]
}

# Test data: /tmp/dnsperf-data.txt
echo "www.baidu.com A" > /tmp/dnsperf-data.txt

# Run (UDP)
chmod 600 /tmp/zjdns-bench.json
/tmp/zjdns -config /tmp/zjdns-bench.json > /dev/null 2>&1 &
sleep 2
dnsperf -s 127.0.0.1 -p 10533 -d /tmp/dnsperf-data.txt -c 100 -l 30 -Q 500000
pkill -f zjdns
```

TCP 用同一端口加 `-m tcp`。

### 2. DoT / DoH（需要 dnsperf 信任的证书链）

dnsperf 校验服务端证书，`self_signed: true` 无法通过 — 用 openssl 生成
CA + 服务端证书，`SSL_CERT_FILE` 指向 CA：

```bash
# /tmp/zjdns-dnsperf-certs/
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem \
  -days 2 -subj "/CN=ZJDNS Test CA"
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost"
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\n' > san.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 2 -extfile san.cnf

# Config: /tmp/zjdns-bench-dot.json
# 注意: certificate 必须嵌在 server 下（顶层会被忽略），
# 且启用安全协议时 server.certificate.domain 为必填项。
{
  "server": {
    "log_level": "error",
    "protocol": { "tls": "10554" },
    "features": { "cache": { "entries": { "limit": { "mem": 100 } } } },
    "certificate": {
      "domain": "localhost",
      "tls": {
        "cert_file": "/tmp/zjdns-dnsperf-certs/server.pem",
        "key_file": "/tmp/zjdns-dnsperf-certs/server.key"
      }
    }
  },
  "zone": [
    { "name": "www.baidu.com",
      "answer": [{ "type": 1, "ttl": 3600, "content": "1.2.3.4" }] }
  ]
}

# Run (DoT)
chmod 600 /tmp/zjdns-bench-dot.json
/tmp/zjdns -config /tmp/zjdns-bench-dot.json > /dev/null 2>&1 &
sleep 2
SSL_CERT_FILE=/tmp/zjdns-dnsperf-certs/ca.pem \
  dnsperf -s 127.0.0.1 -p 10554 -d /tmp/dnsperf-data.txt \
    -c 100 -l 30 -Q 500000 -m dot -O tls-sni=localhost
pkill -f zjdns
```

DoH：把 protocol 换成 `"https": {"port": "10555", "endpoint": "/dns-query"}`，
加 `-m doh -O doh-uri=https://localhost/dns-query -O tls-sni=localhost`。

### 3. 参考数据（v4.4.6, Apple M4 Max, 同机回环）

| 协议 | c | QPS | 平均延迟 | 完成 |
|------|---|-----|---------|------|
| UDP | 100 | 111,885 | 0.68 ms | 100% / 0 lost |
| UDP | 8 | 97,984 | 0.33 ms | 100% |
| TCP | 100 | 188,573 | 0.28 ms | 100% |
| TCP | 8 | 387,597 | 0.23 ms | 100% |
| DoT | 100 | 181,195 | 0.39 ms | 100% |
| DoH (H2) | 100 | 103,076 | 0.78 ms | 100% |

### 4. 解读

- **同机 UDP ≈ 客户端饱和值**：dnsperf 与服务器抢占同机 CPU，
  c=100 与 c=8 结果倒挂即客户端受限的信号 — 测服务器 UDP 真实上限需跨机。
- **TCP c=8 >> c=100 不代表降速**：dnsperf 每连接打满 pipelining 深度，
  少连接少锁竞争；低并发高 QPS 是 RFC 7766 pipelining 生效的直接证据。
- DoT 与裸 TCP 几乎持平说明 TLS 加解密在 writer/worker 模型下不是瓶颈。
- 判定标准：完成率 100%、0 lost、无 SERVFAIL；延迟看 Avg 与 StdDev。

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
