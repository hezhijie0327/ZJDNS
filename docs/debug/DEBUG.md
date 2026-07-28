# Testing & Debug Config

## Directory Layout

```
docs/debug/
├── DEBUG.md                # this file
├── loopback/               # ZJDNS ↔ ZJDNS protocol loopback tests
│   ├── server.json         # server: all protocols + self-signed TLS + DNSCrypt + TLCP/DTLCP
│   ├── server-dnssec.json  # server: dnssec_enforce=true, recursive mode
│   ├── server-hijack.json   # server: poisonguard + splitguard, recursive mode
│   ├── client-udp.json     # client: UDP → server
│   ├── client-tcp.json     # client: TCP → server
│   ├── client-tls.json     # client: TLS → server
│   ├── client-https.json   # client: HTTPS → server
│   ├── client-http3.json   # client: HTTP3 → server
│   ├── client-quic.json    # client: QUIC → server
│   ├── client-dtls.json    # client: DTLS → server
│   ├── client-tlcp.json     # client: TLCP → server
│   ├── client-http-tlcp.json  # client: HTTP over TLCP → server
│   ├── client-dtlcp.json   # client: DTLCP → server
│   ├── client-dnscrypt.json       # client: DNSCrypt (PQ preferred) → server
│   └── client-dnscrypt-classic.json  # client: DNSCrypt (classic only) → server
├── routedns/               # ZJDNS ↔ RouteDNS tests
│   └── dtls-client.toml    # RouteDNS DTLS client → ZJDNS DTLS server
│                            #   Prerequisite: generate cert with
│                            #   openssl req -x509 -newkey ec ... -out /tmp/zjdns-certs/cert.pem
│                            #   and configure ZJDNS to use the same cert
├── dnscrypt/               # ZJDNS ↔ DNSCrypt-proxy tests
│   ├── zjdns-server.json          # ZJDNS DNSCrypt server (dual-cert: classical + PQ)
│   ├── proxy-pq.toml              # DNSCrypt-proxy client (pqdnscrypt=true, default)
│   └── proxy-classic.toml         # DNSCrypt-proxy client (pqdnscrypt=false)
├── defense/                # Anti-pollution defense scenarios
│   ├── spoofguard.json              # forwarding UDP + spoofguard (8.8.8.8)
│   ├── splitguard.json              # forwarding TCP + splitguard (8.8.8.8)
│   ├── hopguard.json                # forwarding UDP + hopguard (TTL-based, 8.8.8.8)
│   ├── hopguard-spoofguard.json     # forwarding UDP + hopguard + spoofguard (8.8.8.8)
│   ├── spoofguard-socks5.json           # forwarding UDP + spoofguard over SOCKS5 proxy
│   ├── poisonguard.json             # recursive + poisonguard (content detection)
│   └── recursive-defense.json       # recursive all four: poisonguard + spoofguard + splitguard + hopguard
└── upstream/               # ZJDNS → external upstream tests
    ├── alidns-tls.json      # AliDNS via TLS
    ├── alidns-https.json    # AliDNS via HTTPS
    ├── alidns-http3.json    # AliDNS via HTTP3
    ├── alidns-quic.json     # AliDNS via QUIC
    ├── quad9-dnscrypt.json  # Quad9 via DNSCrypt
    └── dnspod-http-tlcp.json  # DNSpod via HTTP over TLCP (国密)
```

RouteDNS, DNSCrypt-proxy, and AdGuard DNS Proxy are external tools tested
against ZJDNS. RouteDNS and DNSCrypt-proxy have config files in `routedns/`
and `dnscrypt/` respectively; dnsproxy is CLI-only (flags inline).

## Prerequisites

```bash
# Build ZJDNS
go build -o /tmp/zjdns ./cmd/zjdns
```

### DNSCrypt-proxy (external)

> [!IMPORTANT]
> **Must be built from source.** Homebrew's `dnscrypt-proxy` (2.1.18) packages an
> older Go compiler that lacks the X-Wing PQ KEM implementation. Only the
> source build supports `pqdnscrypt`.

```bash
git clone https://github.com/dnscrypt/dnscrypt-proxy.git /tmp/dnscrypt-proxy
cd /tmp/dnscrypt-proxy
go build -o dnscrypt-proxy ./dnscrypt-proxy
# Binary: /tmp/dnscrypt-proxy/dnscrypt-proxy
```

### RouteDNS (external)

> [!IMPORTANT]
> **Must be built from source.** No prebuilt binaries are distributed.

```bash
git clone https://github.com/folbricht/routedns.git /tmp/routedns
cd /tmp/routedns
go build -o routedns ./cmd/routedns
# Binary: /tmp/routedns/routedns
```

RouteDNS DTLS **requires a pre-generated CA certificate**. ZJDNS uses
`self_signed: true` which generates an in-memory cert each startup — RouteDNS
cannot verify this without the matching CA cert on disk. See § RouteDNS DTLS
Test below for setup instructions.

### AdGuard DNS Proxy (external)

```bash
git clone https://github.com/AdguardTeam/dnsproxy.git /tmp/dnsproxy
cd /tmp/dnsproxy
go build -o dnsproxy .
# Binary: /tmp/dnsproxy/dnsproxy
```

### TLS / TLCP Certificates

ZJDNS loopback and upstream tests use `self_signed: true` and
`skip_tls_verify: true` — no external cert generation needed.

### macOS Notes

- **Do not use port 5353** — reserved by mDNSResponder.
- **dig may time out on UDP** when the server binds to multiple IPs
  (127.0.0.1, ::1, external). This is a macOS kernel UDP-loopback quirk,
  not a ZJDNS bug. Workaround: use TCP (`+tcp`) or query via a ZJDNS
  forwarding client (see Loopback Tests below). Linux is unaffected.

## Loopback Tests (ZJDNS ↔ ZJDNS)

Start the server once (all protocols):

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
sleep 3
```

### Client Ports Reference

| Client Config | Client Port | Protocol | Server Port |
|---------------|:-----------:|----------|:-----------:|
| `client-udp.json` | 10553 | UDP | 10533 |
| `client-tcp.json` | 10653 | TCP | 10533 |
| `client-tls.json` | 10753 | DoT | 10853 |
| `client-https.json` | 10853 | DoH | 10443 |
| `client-http3.json` | 13953 | DoH3 | 10444 |
| `client-quic.json` | 10953 | DoQ | 10784 |
| `client-dtls.json` | 14953 | DTLS | 10434 |
| `client-tlcp.json` | 14553 | TLCP | 10850 |
| `client-http-tlcp.json` | 13553 | TLCP DoH | 10440 |
| `client-dtlcp.json` | 14653 | DTLCP | 8542 |
| `client-dnscrypt.json` | 12444 | DNSCrypt (PQ) | 12443 |
| `client-dnscrypt-classic.json` | 12445 | DNSCrypt (classic) | 12443 |

### Quick Tests

```bash
# Direct to server (TCP recommended on macOS — see Prerequisites)
dig @127.0.0.1 -p 10533 www.baidu.com A +short +tcp

# Via forwarding clients — start one client, query it, kill it
# Example: DTLS
/tmp/zjdns -config docs/debug/loopback/client-dtls.json &
sleep 2
dig @127.0.0.1 -p 14953 www.baidu.com A +short
pkill -f "client-dtls"
```

## DNSSEC Test

验证 DNSSEC 强制验证（bogus → SERVFAIL，valid → NOERROR）：

```bash
/tmp/zjdns -config docs/debug/loopback/server-dnssec.json &
sleep 2

# Bogus signature → SERVFAIL
dig @127.0.0.1 -p 12733 sigfail.ippacket.stream A +short
# Expected: SERVFAIL (no answer)

# Valid signature → NOERROR
dig @127.0.0.1 -p 12733 sigok.ippacket.stream A +short
# Expected: valid A record

pkill -f "server-dnssec"
```

### Offline KSK (CDS fallback)

部分域名（如 `jellyfin.org`）使用 offline KSK 部署：KSK 签名 DNSKEY RRset
但不在其中发布，仅有 ZSK 在 DNSKEY set 中。验证器须通过 CDS (RFC 7344) 确认委托链。

```bash
/tmp/zjdns -config docs/debug/loopback/server-dnssec.json &
sleep 2

# Offline KSK — must resolve via CDS fallback
dig @127.0.0.1 -p 12733 repo.jellyfin.org A +short
# Expected: valid A record (68.183.204.194), NOT SERVFAIL

dig @127.0.0.1 -p 12733 jellyfin.org DNSKEY +short
# Expected: single ZSK (flags=256), no KSK published — CDS fallback activates

pkill -f "server-dnssec"
```

## Defense Tests

防御机制分为 forwarding 和 recursive 两类场景，独立测试：

### Spoofguard (forwarding UDP EDNS OPT gate)

```bash
/tmp/zjdns -config docs/debug/defense/spoofguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# EDNS-gate + richness: 查询带 EDNS，非 EDNS 响应直接丢弃，EDNS 响应间选 richest
# 预期日志: "UPSTREAM: UDP spoofguard rejected non-EDNS response" → "UPSTREAM: UDP spoofguard EDNS candidate"

pkill -f "spoofguard"
```

### Spoofguard + SOCKS5 (forwarding UDP over proxy)

```bash
# Start a SOCKS5 proxy (e.g. go-socks5)
go run github.com/things-go/go-socks5/cmd/socks5@latest -addr :11080 &
sleep 1

/tmp/zjdns -config docs/debug/defense/spoofguard-socks5.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# Same detection logic over SOCKS5 UDP ASSOCIATE
# Expected: "UPSTREAM: UDP spoofguard rejected non-EDNS response" → "UPSTREAM: UDP spoofguard fast return"

pkill -f "spoofguard-socks5"
pkill -f "socks5"
```

### HopGuard (forwarding UDP IP TTL 检测)

```bash
/tmp/zjdns -config docs/debug/defense/hopguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# IP 层 TTL 指纹：首个响应记录基线 TTL，后续响应 TTL 偏离 ±2 → 丢弃
# 与 GFW 注入点的 TTL 不同（靠近用户 vs 真实服务器远端）
# 预期日志: "UPSTREAM: hopguard TTL/HopLimit capture not available on" (Linux 正常启用, Windows 降级提示)
#   → TTL 不匹配时: 静默丢弃 (continue, 不输出 WARN)

pkill -f "hopguard"
```

### HopGuard + Spoofguard (IP TTL + DNS 内容双层过滤)

```bash
/tmp/zjdns -config docs/debug/defense/hopguard-spoofguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# TTL 检查作为前置过滤器，先于 spoofguard 内容分析
# TTL 不匹配 → 直接丢弃; TTL 匹配 → 进入 spoofguard EDNS 门控
# 两个信号正交: IP 层 (路由拓扑) + DNS 层 (报文格式)

pkill -f "hopguard-spoofguard"
```

### Splitguard (forwarding TCP 分段)

```bash
/tmp/zjdns -config docs/debug/defense/splitguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short +tcp

# TCP DNS 帧被拆成小段发送，DPI 首包看不到完整域名 → 绕过 RST

pkill -f "splitguard"
```

### Poisonguard (recursive 越权检测)

```bash
/tmp/zjdns -config docs/debug/defense/poisonguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# 递归每跳验证响应内容，检测 root/TLD 服务器越权返回 A/AAAA
# 劫持时触发 TCP 回退
# 预期日志: "poison detected" / "tcp=true"

pkill -f "poisonguard"
```

### Recursive Defense (recursive 四层全开)

```bash
/tmp/zjdns -config docs/debug/defense/recursive-defense.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# hopguard: 每跳 UDP IP TTL 指纹验证
# spoofguard: 每跳 UDP EDNS OPT 门控
# poisonguard: 内容检测 + 劫持触发 TCP 回退
# splitguard: TCP 回退时分段抗 RST

pkill -f "recursive-defense"
```

## RouteDNS DTLS Test (ZJDNS ↔ RouteDNS)

> [!IMPORTANT]
> RouteDNS DTLS requires a CA certificate on disk. ZJDNS generates a new self-signed
> cert in memory on every startup, so the cert must be extracted and saved before
> RouteDNS can connect. Alternatively, configure ZJDNS with a fixed cert via
> `certificate.tls.cert_file` / `certificate.tls.key_file`.

### Setup (one-time)

```bash
# Generate a self-signed ECDSA cert that both ZJDNS and RouteDNS will use
mkdir -p /tmp/zjdns-certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/zjdns-certs/key.pem -out /tmp/zjdns-certs/cert.pem \
  -days 30 -nodes -subj "/CN=zjdns-test.local"
```

### Test

Start ZJDNS with the fixed cert (requires a custom config that uses `cert_file`
instead of `self_signed`), or use `self_signed` and extract the cert manually.

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
sleep 3
/tmp/routedns/routedns docs/debug/routedns/dtls-client.toml &
sleep 2
dig @127.0.0.1 -p 12053 www.baidu.com A +short
```

## DNSCrypt Tests (ZJDNS ↔ DNSCrypt-proxy)

The server always serves both classical (XChacha20Poly1305) and post-quantum
(X-Wing KEM) certificates simultaneously. The proxy chooses which to use.

### Post-Quantum (pqdnscrypt=true, default)

```bash
/tmp/zjdns -config docs/debug/dnscrypt/zjdns-server.json &
sleep 3
/tmp/dnscrypt-proxy/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-pq.toml &
sleep 3
dig @127.0.0.1 -p 13053 www.baidu.com A +short
# Expected log: "using the post-quantum X-Wing key exchange"
pkill -f "dnscrypt-proxy"
```

### Classic (pqdnscrypt=false)

```bash
/tmp/dnscrypt-proxy/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-classic.toml &
sleep 3
dig @127.0.0.1 -p 13153 www.baidu.com A +short
# Expected: uses XChacha20-Poly1305 (classical only)
pkill -f "dnscrypt-proxy"
```

### Loopback (ZJDNS ↔ ZJDNS)

ZJDNS server has DNSCrypt enabled by default (`server.json`). Use the
ZJDNS DNSCrypt forwarding clients:

```bash
# PQ preferred (default)
/tmp/zjdns -config docs/debug/loopback/client-dnscrypt.json &
sleep 2
dig @127.0.0.1 -p 12444 www.baidu.com A +short
pkill -f "client-dnscrypt"

# Classical only
/tmp/zjdns -config docs/debug/loopback/client-dnscrypt-classic.json &
sleep 2
dig @127.0.0.1 -p 12445 www.baidu.com A +short
pkill -f "client-dnscrypt-classic"
```

## Upstream Protocol Tests

### AliDNS (TLS / HTTPS / HTTP3 / QUIC)

```bash
# tls=11553  https=11653  quic=11753  http3=13653

/tmp/zjdns -config docs/debug/upstream/alidns-tls.json &
dig @127.0.0.1 -p 11553 www.baidu.com A +short
pkill -f "alidns-tls"

/tmp/zjdns -config docs/debug/upstream/alidns-https.json &
dig @127.0.0.1 -p 11653 www.baidu.com A +short
pkill -f "alidns-https"

/tmp/zjdns -config docs/debug/upstream/alidns-quic.json &
dig @127.0.0.1 -p 11753 www.baidu.com A +short
pkill -f "alidns-quic"

/tmp/zjdns -config docs/debug/upstream/alidns-http3.json &
dig @127.0.0.1 -p 13653 www.baidu.com A +short
pkill -f "alidns-http3"
```

## TLCP / DTLCP (国密) Tests

The main loopback server (`server.json`) has TLCP + DTLCP enabled alongside all
other protocols. No separate server config needed.

### TLCP Loopback (ZJDNS ↔ ZJDNS)

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
sleep 3

# TLCP DoT
/tmp/zjdns -config docs/debug/loopback/client-tlcp.json &
sleep 2
dig @127.0.0.1 -p 14553 www.baidu.com A +short
pkill -f "client-tlcp"

# TLCP DoH
/tmp/zjdns -config docs/debug/loopback/client-http-tlcp.json &
sleep 2
dig @127.0.0.1 -p 13553 www.baidu.com A +short
pkill -f "client-http-tlcp"
```

### DTLCP Loopback (ZJDNS ↔ ZJDNS)

```bash
/tmp/zjdns -config docs/debug/loopback/client-dtlcp.json &
sleep 2
dig @127.0.0.1 -p 14653 www.baidu.com A +short
pkill -f "client-dtlcp"
```

### DNSpod TLCP HTTPS (External Upstream)

> [!NOTE]
> Uses a direct IP address to avoid DNS resolution chicken-and-egg (TLCP
> connection requires resolving the hostname, which requires DNS).
> `server_name` still sends the correct SNI for the TLS handshake.

```bash
/tmp/zjdns -config docs/debug/upstream/dnspod-http-tlcp.json &
sleep 2
dig @127.0.0.1 -p 15553 www.baidu.com A +short
pkill -f "dnspod-http-tlcp"
```

### Quad9 (DNSCrypt)

> [!NOTE]
> Quad9 DNSCrypt (9.9.9.9:8443) may be unreachable from some networks
> (e.g. GFW blocks non-standard ports). If certificate fetch fails with
> "no valid dnscrypt certificate", the network blocks the connection.

```bash
/tmp/zjdns -config docs/debug/upstream/quad9-dnscrypt.json &
sleep 4
dig @127.0.0.1 -p 11853 www.baidu.com A +short +time=5
```

## AdGuard DNS Proxy DoH3 Test

Test ZJDNS DoH3 interoperability with [AdGuard DNS Proxy](https://github.com/AdguardTeam/dnsproxy):

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
sleep 3

# dnsproxy: listen on UDP/TCP 53530, forward via DoH3 to ZJDNS
# h3:// scheme selects HTTP/3 directly (no --http3 flag needed)
# --insecure needed because ZJDNS uses a self-signed cert
# -l / -p: separate listen IP and port (not host:port format)
/tmp/dnsproxy/dnsproxy \
  -l 0.0.0.0 \
  -p 53530 \
  -u h3://127.0.0.1:10444/dns-query \
  --insecure \
  > /tmp/dnsproxy.log 2>&1 &
sleep 3

dig @127.0.0.1 -p 53530 example.com A +short
# Expected: valid A record

pkill -f dnsproxy
```

> [!NOTE]
> dnsproxy uses `h3://` scheme for HTTP/3 (not `https://` + `--http3` flag).
> Listen address uses separate `-l` (IP) and `-p` (port) flags, not `host:port`.

## Debug Config

For interactive debugging, create `config.debug.json` (not committed):

```json
{
  "server": {
    "log_level": "debug",
    "protocol": {
      "udp": "15353",
      "tcp": "15353"
    },
    "features": {
      "dnssec_enforce": true,
      "cache": {
        "max_entries": 10000,
        "db_path": "cache.db"
      },
      "latency_probe": [
        { "protocol": "ping", "timeout": 200 },
        { "protocol": "tcp", "port": 443, "timeout": 200 }
      ]
    }
  },
  "upstream": [
    { "protocol": "recursive", "poisonguard": true, "splitguard": true }
  ]
}
```

Port 15353 (non-privileged), pure recursive, cache enabled with latency probing. Start: `./zjdns -config config.debug.json`.

### Test Domains

Verify hijack detection: `grep -E "hijack probe|hijack detected|tcp=true" /tmp/zjdns.log`.

```bash
# Poisonguard — hijack detection → TCP fallback
dig @127.0.0.1 -p 15353 www.google.com www.youtube.com chatgpt.com A +short

# Normal resolution (no fallback)
dig @127.0.0.1 -p 15353 www.baidu.com dns.weixin.qq.com.cn updates.cdn-apple.com A +short

# DNSSEC (requires dnssec_enforce: true)
dig @127.0.0.1 -p 15353 sigfail.ippacket.stream A +short   # bogus → SERVFAIL
dig @127.0.0.1 -p 15353 sigok.ippacket.stream A +short     # valid → NOERROR

# EDNS FORMERR retry
dig @127.0.0.1 -p 15353 zhijie-online.mail.protection.outlook.com A +short

# QNAME minimisation CNAME corner case (RFC 9156 §2.3)
dig @127.0.0.1 -p 15353 home.console.aliyun.com A

# Stats + DB ops
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.db.clear.stats CH TXT +short
./zjdns --sql cache.db "SELECT result, rcode, COUNT(*) FROM query_log GROUP BY result, rcode"
```

### TLCP (国密) Test

```bash
# External upstream (DNSPod, requires skip_tls_verify)
./zjdns -config <(echo '{"server":{"protocol":{"udp":"53535"}},"upstream":[{"address":"https://sm2.doh.pub/dns-query","protocol":"doh-tlcp","server_name":"sm2.doh.pub","skip_tls_verify":true}]}') &

# Self-hosted TLCP server (self-signed SM2 certs)
./zjdns -config <(echo '{"server":{"protocol":{"tlcp":"8530","http_tlcp":{"port":"4430","endpoint":"/dns-query"}},"certificate":{"domain":"tlcp.local","tlcp":{"self_signed":true}},"features":{"cache":{"max_entries":0}}},"upstream":[{"protocol": "recursive"}]}') &

# TLCP HTTPS loopback
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"https://127.0.0.1:4430/dns-query","protocol":"doh-tlcp","server_name":"ZJDNS TLCP","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short

# DTLCP loopback (use [::1] on Windows)
./zjdns -config <(echo '{"server":{"protocol":{"dtlcp":"8542"},"certificate":{"domain":"dtlcp.local","tlcp":{"self_signed":true}},"features":{"cache":{"max_entries":0}}},"upstream":[{"protocol": "recursive"}]}') &
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"127.0.0.1:8542","protocol":"dtlcp","server_name":"dtlcp.local","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short
```

## SQL Debug Queries

日常排查用 SQL 查询，直接对 cache.db 执行（服务运行中可读，加 `--rw` 可写）：

```bash
# 必须指定 --sql 参数格式：./zjdns --sql <db_path> "<query>"
# 或者 docker exec -it zjdns /zjdns --sql /data/cache.db "<query>"

./zjdns --sql cache.db "SELECT qname, COUNT(*) AS cnt FROM query_log GROUP BY qname ORDER BY cnt DESC LIMIT 20"
```

### 排查 SERVFAIL 域名

找出**只出 SERVFAIL 从未成功**的域名——这种往往是被误判的 DNSSEC bogus、上游不通等问题：

```bash
docker exec -it zjdns /zjdns --sql /data/cache.db "
    SELECT qname, COUNT(*) AS servfail_count
    FROM query_log
    WHERE rcode = 2
        AND qname NOT IN (
            SELECT DISTINCT qname FROM query_log WHERE rcode = 0
        )
    GROUP BY qname
    ORDER BY servfail_count DESC
"
```

### 按 rcode 分布

```bash
./zjdns --sql cache.db "
    SELECT rcode, COUNT(*) AS cnt
    FROM query_log
    GROUP BY rcode
    ORDER BY cnt DESC
"
```

### 最近 SERVFAIL 详情

```bash
./zjdns --sql cache.db "
    SELECT timestamp, qname, qtype, server, response_ms
    FROM query_log
    WHERE rcode = 2
    ORDER BY timestamp DESC
    LIMIT 20
"
```
