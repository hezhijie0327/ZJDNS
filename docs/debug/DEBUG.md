# Testing & Debug Config

## Directory Layout

```
docs/debug/
├── DEBUG.md                # this file
├── domains.txt             # 186 domains (sorted, deduped) for batch tests
├── loopback/               # ZJDNS ↔ ZJDNS protocol loopback tests
│   ├── server.json         # server: all protocols + self-signed TLS + DNSCrypt + TLCP/DTLCP
│   ├── server-dnssec.json  # server: dnssec_enforce=true, recursive mode
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
│   ├── client-dnscrypt.json              # client: DNSCrypt (PQ preferred) → server
│   ├── client-dnscrypt-classic.json       # client: DNSCrypt (classical only) → server
│   └── client-dnscrypt-ephemeral.json     # client: DNSCrypt + ephemeral_keys + PQ → server
├── routedns/               # ZJDNS ↔ RouteDNS tests
│   └── dtls-client.toml    # RouteDNS DTLS client → ZJDNS DTLS server
│                            #   Prerequisite: generate cert with the openssl
│                            #   command in the toml's header (SAN IP:127.0.0.1,
│                            #   cert outside /tmp) and configure ZJDNS to use it
├── dnscrypt/               # ZJDNS ↔ DNSCrypt-proxy tests
│   ├── zjdns-server.json          # ZJDNS DNSCrypt server (dual-cert: classical + PQ)
│   ├── proxy-pq.toml                     # DNSCrypt-proxy client (pqdnscrypt=true, default)
│   ├── proxy-classic.toml                # DNSCrypt-proxy client (pqdnscrypt=false)
│   └── proxy-classic-ephemeral.toml      # DNSCrypt-proxy client (classical + ephemeral keys)
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

> [!NOTE]
> **Windows (Git Bash)**: `pkill` is unavailable — use `taskkill //F //IM zjdns.exe` (or
> record the PID and `taskkill //F //PID <pid>`). Config paths like `/tmp/...` are
> Unix-style; on Windows use `C:/Users/<user>/AppData/Local/Temp/...` (Go
> binaries resolve `/tmp` as a Windows path and will fail to find the file).
> Prefix `openssl -subj` with `MSYS_NO_PATHCONV=1` to prevent Git Bash from
> rewriting the path.

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

## Loopback Tests (ZJDNS ↔ ZJDNS)

Start the server once (all protocols):

```bash
/tmp/zjdns -config docs/debug/loopback/server.json &
sleep 3
```

### Client Ports Reference

All forwarding clients accept queries on both **UDP and TCP** (same port).
The "Protocol" column is the upstream forwarding protocol.

| Client Config | Client Port | Upstream | Server Port |
| `client-udp.json` | 10553 | UDP | 10533 |
| `client-tcp.json` | 10653 | TCP | 10533 |
| `client-tls.json` | 10753 | DoT | 10853 |
| `client-https.json` | 11853 | DoH | 10443 |
| `client-http3.json` | 13953 | DoH3 | 10444 |
| `client-quic.json` | 10953 | DoQ | 10784 |
| `client-dtls.json` | 14953 | DTLS | 10434 |
| `client-tlcp.json` | 14553 | TLCP | 10850 |
| `client-http-tlcp.json` | 13553 | TLCP DoH | 10440 |
| `client-dtlcp.json` | 14653 | DTLCP | 8542 |
| `client-dnscrypt.json` | 12444 | DNSCrypt (PQ) | 12443 |
| `client-dnscrypt-classic.json` | 12445 | DNSCrypt (classical) | 12443 |
| `client-dnscrypt-ephemeral.json` | 12446 | DNSCrypt + ephemeral_keys + PQ | 12443 |
| `client-dnscrypt-ephemeral-classical.json` | 22544 | DNSCrypt + ephemeral_keys (classical only) | 12443 |

> [!NOTE]
> Forwarding client configs set `tcp` to the same port as `udp`. Without it,
> the default TCP port 53 (privileged) makes non-root startup fail with
> "no available tcp addresses for port 53".

### Quick Tests

**Test methodology**: The server listens on both UDP and TCP for 10533 — `dig`
works with either.  Forwarding clients (`client-*.json`) also listen on both
UDP and TCP (same port) and forward queries over the configured upstream
protocol (TLS/QUIC/HTTPS/etc.).

```bash
# Direct to server — UDP or TCP both work.
dig @127.0.0.1 -p 10533 www.baidu.com A +short

# Forwarding clients — UDP (dig default) or +tcp, same port.
/tmp/zjdns -config docs/debug/loopback/client-tls.json &
sleep 2
dig @127.0.0.1 -p 10753 www.baidu.com A +short          # UDP (default)
dig @127.0.0.1 -p 10753 www.baidu.com A +short +tcp     # TCP
pkill -f "client-tls"
```

### Connection Pool Tests (连接复用验证)

验证每个协议只建立 **1 个连接** 服务多次查询（RFC 7766 管道化 / socket 复用），
而不是每次查询都 dial。统计依据：pool 日志里的 "dialed" 计数应为 1、
"falling back" 应为 0（0 次降级到每查询连接）。

```bash
# 1. 构建 + 启动全协议 server（DTLS 10434 / DTLCP 8542 / DNSCrypt 12443 等）
go build -o /tmp/zjdns ./cmd/zjdns
/tmp/zjdns -config docs/debug/loopback/server.json &
sleep 3

# 2. 逐个 client 配置（端口见下表），每个发 5 次查询，然后统计 pool 日志
#    统计口径（5 次查询下应全部命中）:
#    - ConnPool 类 (tcp/tls/dtls/tlcp/dtlcp):  "TCPPOOL: dialed new connection" = 1
#    - UDPPool 类 (udp/dnscrypt):               "UDPPOOL: dialed new socket" = 1
#    - DoQ (quic):                              "UPSTREAM: dialed new QUIC connection" = 1
#    - DoH/DoH3/DoH-TLCP (http keep-alive):     lsof -nP -p <pid> 的连接数 = 1
#    - 所有协议:                                 "falling back" = 0

/tmp/zjdns -config docs/debug/loopback/client-dtls.json &
sleep 2
for i in 1 2 3 4 5; do dig @127.0.0.1 -p 14953 www.baidu.com A +short +time=3 +tries=1; done
grep -c "TCPPOOL: dialed new connection" /tmp/zjdns.log   # 期望 1
grep -c "falling back" /tmp/zjdns.log                     # 期望 0
pkill -f "client-dtls"

# DoH 系列无 pool 日志，用 lsof 数连接:
/tmp/zjdns -config docs/debug/loopback/client-https.json &
sleep 2
for i in 1 2 3 4 5; do dig @127.0.0.1 -p 11853 www.baidu.com A +short +time=3 +tries=1; done
lsof -nP -p $! | grep -c "ESTABLISHED"                    # 期望 1 (HTTP keep-alive 复用)
pkill -f "client-https"
```

> [!NOTE]
> 日志里的 "ERROR" 匹配多为 `rcode=NOERROR` 误匹配——统计前先 `grep -i "error" | grep -v NOERROR` 排除。
> DTLS 的连接复用在 Windows 上无 control-message 支持（hopguard 降级），但连接池本身不受影响。

### RFC Feature Tests

```bash
# RFC 9606 RESINFO: auto-enabled together with DDR (config/load.go shouldEnableDDR).
dig @127.0.0.1 -p 10533 resolver.arpa TYPE261 +noall +answer   # qnamemin exterr=... infourl=...

# RFC 8482 minimal ANY: HINFO "RFC8482" instead of REFUSED/full zone.
dig @127.0.0.1 -p 10533 example.com ANY +short

# RFC 9824: NXNAME(128) queries MUST NOT be forwarded — REFUSED + EDE 30.
dig @127.0.0.1 -p 10533 example.com TYPE128 +short

# RFC 9715: oversized responses are truncated (TC=1) at 1400 bytes and the
# client retries over TCP.  Serve a large answer via a zone rule, then:
dig @127.0.0.1 -p 10533 big.test A +bufsize=4096 +ignore   # expect "tc" flag
dig @127.0.0.1 -p 10533 big.test A +bufsize=4096           # TCP retry, full answer

# NXDOMAIN propagation: miss and cache-hit must both report NXDOMAIN.
dig @127.0.0.1 -p 10533 nonexistent-xyz12345.com A +short  # NXDOMAIN (repeat → hit)
```

## DNSSEC Test

Verifies DNSSEC enforcement (bogus → SERVFAIL, valid → NOERROR):

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

### Offline KSK (SEP relaxation + CDS fallback)

Some domains deploy with an offline KSK: the KSK signs the DNSKEY RRset but
is never published in it — only the ZSK appears in the DNSKEY set.

Two complementary mechanisms make validation succeed:

1. **SEP-only DS matching** (`VerifyDelegationDS` / `SelfVerifyDNSKEY`):
   the SEP bit is a deployment convention (RFC 4034 §2.1.2), not a validation
   requirement. A DS digest matching any DNSKEY suffices; the SEP flag is not
   required. This works for `jellyfin.org` (its DS is computed from the ZSK,
   so the SEP relaxation matches directly).

2. **CDS/CDNSKEY fallback** (`verifyOfflineKSK` → `verifyViaCDS` / `verifyViaCDNSKEY`):
   when the DS is computed from a KSK that is never published in the DNSKEY
   RRset (a true offline KSK), the CDS/CDNSKEY records of the child zone are
   queried (RFC 7344) and matched against the parent DS by full SHA-256
   digest. This fallback is **intentionally kept** — digest matching is
   cryptographically equivalent to standard DS validation; do not remove it.

```bash
/tmp/zjdns -config docs/debug/loopback/server-dnssec.json &
sleep 2

# Offline KSK — DNSSEC chain validation
dig @127.0.0.1 -p 12733 jellyfin.org DNSKEY +short
# Expected: single ZSK (flags=256), no KSK published
#   → SEP relaxation: ZSK directly matches parent DS

# A-record lookups may time out when the authoritative NS is unreachable
# (jellyfin uses Gandi NS; out-of-bailiwick resolution takes longer) — a
# network limitation, not a DNSSEC issue.

pkill -f "server-dnssec"
```

## Defense Tests

Defense mechanisms are split into forwarding and recursive scenarios, tested independently:

### Spoofguard (forwarding UDP EDNS OPT gate)

```bash
/tmp/zjdns -config docs/debug/defense/spoofguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# EDNS-gate + richness: the query carries EDNS, non-EDNS responses are
# dropped, and the richest EDNS response wins.
# Expected log: "UPSTREAM: UDP spoofguard rejected non-EDNS response" → "UPSTREAM: UDP spoofguard EDNS candidate"

pkill -f "spoofguard"
```

### Spoofguard + SOCKS5 (forwarding UDP over proxy)

```bash
# Start a SOCKS5 proxy.
# NOTE: things-go/go-socks5 v0.1.1 ships no cmd/socks5 binary — run its
# _example server (binds :10800; edit the port to 11080 first):
#   mkdir -p /tmp/socks5srv && cp $(go env GOMODCACHE)/github.com/things-go/go-socks5@v0.1.1/_example/main.go /tmp/socks5srv/
#   cd /tmp/socks5srv && go mod init socks5srv && go mod tidy && sed -i 's/:10800/:11080/' main.go && go run .
# (or any SOCKS5 server listening on 127.0.0.1:11080)
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

### HopGuard (forwarding UDP IP TTL detection)

```bash
/tmp/zjdns -config docs/debug/defense/hopguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# IP-layer TTL fingerprint: the first response records a baseline TTL;
# later responses deviating by more than ±2 are dropped.
# GFW injection points sit closer to the user than the real server, so their
# TTL differs.
# Expected log: "UPSTREAM: hopguard TTL/HopLimit capture not available on"
# (enabled on Linux; degraded notice on Windows)
#   → on TTL mismatch: silently dropped (continue, no WARN)

pkill -f "hopguard"
```

### HopGuard + Spoofguard (IP TTL + DNS content, two layers)

```bash
/tmp/zjdns -config docs/debug/defense/hopguard-spoofguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# TTL check acts as a pre-filter ahead of spoofguard content analysis.
# TTL mismatch → dropped; TTL match → spoofguard EDNS gate.
# The two signals are orthogonal: IP layer (routing topology) + DNS layer
# (packet format)

pkill -f "hopguard-spoofguard"
```

### Splitguard (forwarding TCP segmentation)

```bash
/tmp/zjdns -config docs/debug/defense/splitguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# Splitguard segments frames internally when the server forwards over TCP;
# independent of the client using UDP or TCP

pkill -f "splitguard"
```

### Poisonguard (recursive out-of-zone detection)

```bash
/tmp/zjdns -config docs/debug/defense/poisonguard.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# Every recursion hop validates response content, detecting root/TLD servers
# answering A/AAAA outside their authority.
# Hijacking triggers a TCP fallback.
# Expected log: "poison detected" / "tcp=true"

pkill -f "poisonguard"
```

### Recursive Defense (recursive, all four layers)

```bash
/tmp/zjdns -config docs/debug/defense/recursive-defense.json &
sleep 2

dig @127.0.0.1 -p 10533 www.google.com A +short

# hopguard: per-hop UDP IP TTL fingerprint validation
# spoofguard: per-hop UDP EDNS OPT gate
# poisonguard: content detection + hijack-triggered TCP fallback
# splitguard: segmentation on the TCP fallback to resist RST

pkill -f "recursive-defense"
```

## RouteDNS DTLS Test (ZJDNS ↔ RouteDNS)

> [!IMPORTANT]
> RouteDNS DTLS requires a CA certificate on disk. ZJDNS generates a new self-signed
> cert in memory on every startup, so the cert must be extracted and saved before
> RouteDNS can connect. Alternatively, configure ZJDNS with a fixed cert via
> `certificate.tls.cert_file` / `certificate.tls.key_file`.

> [!WARNING]
> **ZJDNS serves DTLS 1.3 only** (a pion dual-stack negotiation bug deadlocks
> the handshake — see `server/protocol/tls/dtls.go`). RouteDNS's DTLS client
> builds a default `dtls.Config{}` (1.2+1.3) with no version option, so the
> current RouteDNS release **cannot connect**. ZJDNS ↔ ZJDNS DTLS (loopback)
> and pure-1.3 clients work; revisit once RouteDNS exposes a DTLS version
> knob or pion fixes the dual-stack path.

### Setup (one-time)

```bash
# Generate a self-signed ECDSA cert that both ZJDNS and RouteDNS will use
# NOTE: on Windows Git Bash, prefix with MSYS_NO_PATHCONV=1 so the -subj
# path is not rewritten to a Windows path.
mkdir -p /tmp/zjdns-certs
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout /tmp/zjdns-certs/key.pem -out /tmp/zjdns-certs/cert.pem \
  -days 30 -nodes -subj "/CN=zjdns-test.local" -addext "subjectAltName=IP:127.0.0.1"
```

### Test

ZJDNS must use the same certificate as RouteDNS.  The default `server.json`
uses `self_signed: true` (ephemeral cert) — RouteDNS can't verify that.
Create a config with `cert_file`/`key_file` pointing to the generated cert:

```bash
# Create a DTLS-only server config with the fixed certificate.
# NOTE: on Windows, replace /tmp/zjdns-certs/... with the Windows absolute
# path (e.g. C:/Users/<user>/AppData/Local/Temp/zjdns-certs/...).
cat > /tmp/zjdns-dtls-server.json << 'CONF'
{
  "server": {
    "log_level": "debug",
    "protocol": { "udp": "10533", "tcp": "10533", "dtls": "10434" },
    "certificate": {
      "domain": "zjdns-test.local",
      "tls": { "cert_file": "/tmp/zjdns-certs/cert.pem", "key_file": "/tmp/zjdns-certs/key.pem" }
    }
  },
  "upstream": [{ "protocol": "recursive" }]
}
CONF

/tmp/zjdns -config /tmp/zjdns-dtls-server.json &
sleep 3
/tmp/routedns/routedns docs/debug/routedns/dtls-client.toml &
sleep 2
dig @127.0.0.1 -p 12053 www.baidu.com A +short
```

## DNSCrypt Tests (ZJDNS ↔ DNSCrypt-proxy)

## DNSCrypt Features (v3.7.12)

| Feature | RFC | Config | Default |
|---------|-----|--------|---------|
| Deterministic response padding | §5.4.5 | built-in | SHA-256(sharedKey, clientNonce) |
| Server TC truncation | §5.4.6 | built-in | truncate + TC, never silent |
| TCP 4096 response cap | §5.4.7 | built-in | enforced |
| Cert TC + classical preserve | §5.5/§11.3 | built-in | PQ omitted → TC=true |
| EWMA adaptive query sizing | §5.4.2 | built-in | decay minQueryLen on small responses |
| Client TC doubling | §5.4.2 | built-in | O(log n) escalation |
| Shared key cache | §8 | built-in | 2000-entry LRU |
| PQ downgrade protection | §11.9 | `pqdnscrypt: true` | refuses classical fallback |
| Ephemeral keys | dnscrypt-proxy | `ephemeral_keys: true` | per-query X25519 key pair |
| Weak key rejection | §13.7 | built-in | all-zero X25519 point rejected |

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
# Classical + ephemeral_keys (per-query forward secrecy)
	/tmp/dnscrypt-proxy/dnscrypt-proxy -config docs/debug/dnscrypt/proxy-classic-ephemeral.toml &
	sleep 3
	dig @127.0.0.1 -p 13253 www.baidu.com A +short
	# Expected: per-query X25519 key pairs
	pkill -f "dnscrypt-proxy"
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

# Ephemeral keys (per-query forward secrecy) — PQ preferred
/tmp/zjdns -config docs/debug/loopback/client-dnscrypt-ephemeral.json &
sleep 2
dig @127.0.0.1 -p 12446 www.baidu.com A +short
pkill -f "client-dnscrypt-ephemeral"

# Ephemeral keys + classical only (no PQ downgrade protection)
/tmp/zjdns -config docs/debug/loopback/client-dnscrypt-ephemeral-classical.json &
sleep 2
dig @127.0.0.1 -p 22544 www.baidu.com A +short
pkill -f "client-dnscrypt-ephemeral-classical"
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

## TLCP / DTLCP (GuoMi / ShangMi) Tests

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

### 其他配置键速查（config.example.json 有示例但无专文）

| 键 | 位置 | 说明 |
|----|------|------|
| `features.dns64.prefer_ipv4`（默认 true） | `config/ecs.go:95,136` | ECS 查询偏好 IPv4（缺失时默认 true） |

### Test Domains

Verify hijack detection: `grep -E "poison detected|poisonguard triggered TCP fallback|tcp=true" /tmp/zjdns.log`.

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

# Stats
dig @127.0.0.1 -p 15353 zjdns.whoami CH TXT +short        # 客户端源 IP（a8f15d4）
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.stats.clear CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.cache.clear CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.ptr.clear CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.latency.clear CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.querylog.clear CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.dnscrypt.clear CH TXT +short

# DNSCrypt 证书窗口持久化在 zjdns.dnscrypt（server/protocol/dnscrypt/persist_file.go）
ls -la /tmp/zjdns-persist/zjdns.dnscrypt
```

## Query Stats & Debug

查询统计（`query_stats`）和查询日志（`query_log`）是纯内存实现（`cache/statsjournal.go`）：原子计数器 + 每种 RCODE 的 top-N 域名 journal，重启后归零。整个服务器无 SQLite——缓存/延迟/委派（lrumap）、规则（快照）全部内存化，唯一的持久化是 DNSCrypt 状态文件（`zjdns.dnscrypt`）。

```bash
# 实时统计（聚合计数）
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short
# 示例输出：
# "entries=4 total=6 avg=0.0ms"
# "hit=2(33.3%) miss=4(66.7%)"

# 每 RCODE top-N 域名（NXDOMAIN/SERVFAIL 排查）
dig @127.0.0.1 -p 15353 zjdns.stats.rcode CH TXT +short
# 示例输出：
# "top-rcode0: www.baidu.com.=1 www.qq.com.=1 ..."
# "top-rcode3: nonexistent.example.com.=3"

# 重置计数器 / 清空 journal（CHAOS 控制端点，仅限回环地址）
dig @127.0.0.1 -p 15353 zjdns.stats.clear CH TXT +short
dig @127.0.0.1 -p 15353 zjdns.querylog.clear CH TXT +short
```

整个服务器**无数据库、无 SQL 工具**——所有数据在内存（`lrumap` 缓存/延迟/委派 + `statsjournal` 统计 + 快照规则）。日常排查全部通过 `zjdns.stats` 完成。

### 排查 SERVFAIL 域名

找出**只出 SERVFAIL 从未成功**的域名——这种往往是被误判的 DNSSEC bogus、上游不通等问题。先用 `.stats` 看 `top-rcode2`（SERVFAIL）的域名，再确认对应缓存条目：

```bash
dig @127.0.0.1 -p 15353 zjdns.stats CH TXT +short | grep top-rcode2
```

### TLCP (Guomi / Shangmi) Test

```bash
# External upstream (DNSPod, requires skip_tls_verify)
./zjdns -config <(echo '{"server":{"protocol":{"udp":"53535"}},"upstream":[{"address":"https://sm2.doh.pub/dns-query","protocol":"http-tlcp","server_name":"sm2.doh.pub","skip_tls_verify":true}]}') &

# Self-hosted TLCP server (self-signed SM2 certs)
./zjdns -config <(echo '{"server":{"protocol":{"tlcp":"8530","http_tlcp":{"port":"4430","endpoint":"/dns-query"}},"certificate":{"domain":"tlcp.local","tlcp":{"self_signed":true}}},"upstream":[{"protocol": "recursive"}]}') &

# TLCP HTTPS loopback
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"https://127.0.0.1:4430/dns-query","protocol":"http-tlcp","server_name":"ZJDNS TLCP","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short

# DTLCP loopback (use [::1] on Windows)
./zjdns -config <(echo '{"server":{"protocol":{"dtlcp":"8542"},"certificate":{"domain":"dtlcp.local","tlcp":{"self_signed":true}}},"upstream":[{"protocol": "recursive"}]}') &
./zjdns -config <(echo '{"server":{"protocol":{"udp":"55454"}},"upstream":[{"address":"127.0.0.1:8542","protocol":"dtlcp","server_name":"dtlcp.local","skip_tls_verify":true}]}') &
dig @127.0.0.1 -p 55454 www.baidu.com A +short
```
