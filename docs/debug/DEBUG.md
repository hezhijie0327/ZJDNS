# Testing & Debug Config

## Directory Layout

```
docs/debug/
├── testing.md              # this file
├── loopback/               # ZJDNS ↔ ZJDNS protocol loopback tests
│   ├── server.json         # server: UDP/TCP/TLS/QUIC/HTTPS + DTLS + self-signed TLS
│   ├── server-dnssec.json  # server: dnssec_enforce=true
│   ├── server-tlcp.json    # server: TLCP + HTTP over TLCP + DTLCP (self-signed SM2)
│   ├── client-udp.json     # client: UDP → server
│   ├── client-tcp.json     # client: TCP → server
│   ├── client-tls.json     # client: TLS → server
│   ├── client-https.json   # client: HTTPS → server
│   ├── client-http3.json   # client: HTTP3 → server
│   ├── client-quic.json    # client: QUIC → server
│   ├── client-dtls.json    # client: DTLS → server
│   ├── client-http-tlcp.json  # client: HTTP over TLCP → server
│   └── client-dtlcp.json   # client: DTLCP → server
├── routedns/               # ZJDNS ↔ RouteDNS tests
│   └── dtls-client.toml    # RouteDNS DTLS client → ZJDNS DTLS server
├── dnscrypt/               # ZJDNS ↔ DNSCrypt-proxy tests
│   ├── zjdns-server.json          # ZJDNS DNSCrypt server (dual-cert: classical + PQ)
│   ├── proxy-pq.toml              # DNSCrypt-proxy client (pqdnscrypt=true, default)
│   ├── 
│   └── proxy-classic.toml         # DNSCrypt-proxy client (pqdnscrypt=false)
├── defense/                # Anti-pollution defense scenarios
│   ├── poisonguard.json    # recursive + poisonguard + splitguard
│   ├── spoofguard.json     # upstream UDP + spoofguard (8.8.8.8)
│   └── splitguard.json     # upstream TCP + splitguard (8.8.8.8)
└── upstream/               # ZJDNS → external upstream tests
    ├── alidns-tls.json      # AliDNS via TLS
    ├── alidns-https.json    # AliDNS via HTTPS
    ├── alidns-http3.json    # AliDNS via HTTP3
    ├── alidns-quic.json     # AliDNS via QUIC
    ├── quad9-dnscrypt.json  # Quad9 via DNSCrypt
    └── dnspod-http-tlcp.json  # DNSpod via HTTP over TLCP (国密)
```

## Prerequisites

> [!IMPORTANT]
> DNSCrypt-proxy and RouteDNS **must be built from source**.  Distribution packages
> (Homebrew, etc.) may ship older versions that lack required features such as
> `pqdnscrypt`.

```bash
# Build ZJDNS
go build -o /tmp/zjdns ./cmd/zjdns

# Build RouteDNS (for DTLS test) — must compile from source
cd /path/to/routedns && go build -o /tmp/routedns ./cmd/routedns

# Build DNSCrypt-proxy (for DNSCrypt test) — must compile from source
cd /path/to/dnscrypt-proxy/dnscrypt-proxy && go build -o /tmp/dnscrypt-proxy .
```

TLS certificates use the built-in `self_signed` feature — no external cert generation needed.

## Loopback Tests (ZJDNS ↔ ZJDNS)

Start the server (UDP, TCP, TLS, QUIC, HTTPS):

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
```

Test each client protocol:

```bash
# Direct UDP/TCP (dig against server directly)
dig @127.0.0.1 -p 10533 www.baidu.com A +short
dig @127.0.0.1 -p 10533 www.baidu.com A +short +tcp

# Via forwarding clients
# Individual client tests
# Ports: udp=10553 tcp=10653 tls=10753 https=10853 quic=10953 http3=13953 dtls=14953

# HTTP3 loopback
/tmp/zjdns -config docs/debug/loopback/client-http3.json &
sleep 2
dig @127.0.0.1 -p 13953 www.baidu.com A +short
pkill -f "client-http3"

# DTLS loopback
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
dig @127.0.0.1 -p 12533 sigfail.ippacket.stream A +short
# Expected: SERVFAIL (no answer)

# Valid signature → NOERROR
dig @127.0.0.1 -p 12533 sigok.ippacket.stream A +short
# Expected: valid A record

pkill -f "server-dnssec"
```

## Defense Tests

三层防污染机制独立测试，所有配置位于 `docs/debug/defense/`。

### Poisonguard (递归越权检测)

```bash
/tmp/zjdns -config docs/debug/defense/poisonguard.json &
sleep 2

# 被劫持域名 → 检测 fake A/AAAA → TCP 回退
dig @127.0.0.1 -p 10533 www.google.com A +short
dig @127.0.0.1 -p 10533 www.youtube.com A +short

# 预期日志: "hijack probe" / "hijack detected" / "tcp=true"

pkill -f "poisonguard"
```

### Spoofguard (上游 UDP 防欺骗)

```bash
/tmp/zjdns -config docs/debug/defense/spoofguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short
dig @127.0.0.1 -p 10533 www.youtube.com A +short

# 预期日志: "UDP multi-read collected" — 假包先到，真包最后，取尾部

pkill -f "spoofguard"
```

### Splitguard (TCP 分段)

```bash
/tmp/zjdns -config docs/debug/defense/splitguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short
dig @127.0.0.1 -p 10533 www.youtube.com A +short

# TCP DNS 帧被拆成小段发送，DPI 首包看不到完整域名 → RST 绕过

pkill -f "splitguard"
```

## RouteDNS DTLS Test (ZJDNS ↔ RouteDNS)

Start ZJDNS server with DTLS enabled:

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
```

Start RouteDNS as DTLS client:

```bash
/tmp/routedns docs/debug/routedns/dtls-client.toml &
```

Query through RouteDNS (UDP→DTLS→ZJDNS→recursive):

```bash
dig @127.0.0.1 -p 12053 www.baidu.com A +short
```

## DNSCrypt Tests (ZJDNS ↔ DNSCrypt-proxy)

The server always serves both classical (XChacha20Poly1305) and post-quantum
(X-Wing KEM) certificates simultaneously. The client chooses which to use.

### Post-Quantum (pqdnscrypt=true, default)

```bash
/tmp/zjdns -config docs/debug/dnscrypt/zjdns-server.json &
/tmp/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-pq.toml &
sleep 4
dig @127.0.0.1 -p 13053 www.baidu.com A +short
# Expected: uses X-Wing PQ key exchange
```

### Classic (pqdnscrypt=false)

```bash
/tmp/zjdns -config docs/debug/dnscrypt/zjdns-server.json &
/tmp/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-classic.toml &
sleep 3
dig @127.0.0.1 -p 13153 www.baidu.com A +short
# Expected: uses XChacha20-Poly1305 (classical only)
```

### Loopback (ZJDNS ↔ ZJDNS)

```bash
# PQ preferred (default)
/tmp/zjdns -config docs/debug/loopback/server.json &
/tmp/zjdns -config docs/debug/loopback/client-dnscrypt.json &
sleep 2
dig @127.0.0.1 -p 12444 www.baidu.com A +short

# Classical only
/tmp/zjdns -config docs/debug/loopback/client-dnscrypt-classic.json &
sleep 2
dig @127.0.0.1 -p 12445 www.baidu.com A +short
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

### TLCP Loopback (ZJDNS ↔ ZJDNS)

```bash
# Start TLCP server (TLCP TLS + TLCP HTTPS with self-signed SM2 certs)
/tmp/zjdns -config docs/debug/loopback/server-tlcp.json &
sleep 2

# TLCP HTTPS loopback client
/tmp/zjdns -config docs/debug/loopback/client-http-tlcp.json &
sleep 2
dig @127.0.0.1 -p 13553 www.baidu.com A +short

pkill -f "server-tlcp\|client-http-tlcp"
```

### DTLCP Loopback (ZJDNS ↔ ZJDNS)

Uses the same server as TLCP (server-tlcp.json has DTLCP enabled alongside TLCP).

```bash
/tmp/zjdns -config docs/debug/loopback/server-tlcp.json &
sleep 2

/tmp/zjdns -config docs/debug/loopback/client-dtlcp.json &
sleep 2
dig @127.0.0.1 -p 14553 www.baidu.com A +short

pkill -f "server-tlcp\|client-dtlcp"
```

### DNSpod TLCP HTTPS (External Upstream)

```bash
/tmp/zjdns -config docs/debug/upstream/dnspod-http-tlcp.json &
sleep 2
dig @127.0.0.1 -p 15553 www.baidu.com A +short

pkill -f "dnspod-http-tlcp"
```

### Quad9 (DNSCrypt)

```bash
/tmp/zjdns -config docs/debug/upstream/quad9-dnscrypt.json &
sleep 4
dig @127.0.0.1 -p 11853 www.baidu.com A +short +time=5
```

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
      "defense": { "poisonguard": true, "spoofguard": true, "splitguard": true },
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
    { "address": "builtin_recursive" }
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
./zjdns --sql cache.db "SELECT result, rcode, COUNT(*) FROM request_log GROUP BY result, rcode"
```

### TLCP (国密) Test

```bash
# External upstream (DNSPod, requires skip_tls_verify)
./zjdns -config <(echo '{"server":{"protocol":{"udp":"53535"}},"upstream":[{"address":"https://sm2.doh.pub/dns-query","protocol":"doh-tlcp","server_name":"sm2.doh.pub","skip_tls_verify":true}]}') &

# Self-hosted TLCP server (self-signed SM2 certs)
./zjdns -config <(echo '{"server":{"protocol":{"tlcp":"8530","http_tlcp":{"port":"4430","endpoint":"/dns-query"}},"certificate":{"domain":"tlcp.local","tlcp":{"self_signed":true}},"features":{"defense": {}","cache":{"max_entries":0}}},"upstream":[{"address":"builtin_recursive"}]}') &

# TLCP HTTPS loopback
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"https://127.0.0.1:4430/dns-query","protocol":"doh-tlcp","server_name":"ZJDNS TLCP","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short

# DTLCP loopback (use [::1] on Windows)
./zjdns -config <(echo '{"server":{"protocol":{"dtlcp":"8542"},"certificate":{"domain":"dtlcp.local","tlcp":{"self_signed":true}},"features":{"defense": {}","cache":{"max_entries":0}}},"upstream":[{"address":"builtin_recursive"}]}') &
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"127.0.0.1:8542","protocol":"dtlcp","server_name":"dtlcp.local","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short
```
