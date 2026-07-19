# Port Sharing Tests

ZJDNS supports running multiple encrypted DNS protocols on the same port, with
automatic per-connection (TCP) or per-packet (UDP) protocol detection.

## How It Works

### TCP Detection (per-connection)

The shared TCP listener peeks at the first 5 bytes (TLS/TLCP record layer header)
of each new connection:

| Byte 1 (major version) | Protocol | Typical Use |
|-------------------------|----------|-------------|
| `0x03` | TLS | DoT (RFC 7858), DoH (RFC 8484) |
| `0x01` | TLCP | GB/T 38636-2020 DoT, TLCP DoH |
| other | raw TCP | DNSCrypt, plain DNS, etc. |

TLS and TLCP connections are fully handshaked before dispatch. Raw connections
(e.g. DNSCrypt TCP) pass through unmodified.

When both DoT and DoH share a port, ALPN negotiation (`"dot"` / `"h2"`) routes
to the correct handler.

### UDP Detection (per-packet)

Three code paths depending on protocol composition:

**Demux (QUIC present):** A packet-level demultiplexer classifies each datagram:

| Order | Classifier | Protocol | Detection |
|-------|------------|----------|-----------|
| 1 | `IsQUICPacket()` | QUIC (DoQ, DoH3) | Fixed Bit (0x40) set, reserved bits (0x0C) clear |
| 2 | `ClassifyRecordHeader(p) == 0xFE` | DTLS (RFC 8094) | DTLS record header major version |
| 3 | `ClassifyRecordHeader(p) == 0x01` | DTLCP (GM/T 0128-2023) | DTLCP record header |
| 4 | `IsDNSCryptPacket()` | DNSCrypt | Cert handshake / query magic |

**SharedUDPListener (DTLS + DTLCP, no QUIC):** A per-client stateful listener
detects the protocol on each client's first datagram and creates a virtual socket.

**HTTP3 + DNSCrypt (no QUIC on the DTLS port):** Binary demux: QUIC packets
(HTTP3) vs everything else (DNSCrypt).

## Directory Layout

```
docs/debug/port-sharing/
├── README.md                    # this file
│
├── server-tcp-dot.json          # TLS + TLCP on TCP 20853 (DoT)
├── server-tcp-doh.json          # HTTPS + HTTP-TLCP on TCP 20443 (DoH)
├── server-tcp-doh-dnscrypt.json # HTTPS + HTTP-TLCP + DNSCrypt on TCP 20444
├── server-udp-dod.json          # QUIC + DTLS on UDP 20854
├── server-udp-dod-dtlcp.json    # QUIC + DTLS + DTLCP on UDP 20854
├── server-udp-dod-all.json      # QUIC + DTLS + DTLCP + DNSCrypt on UDP 20854
├── server-udp-h3-dnscrypt.json  # HTTP3 + DNSCrypt on UDP 20445
├── server-udp-dtls-dtlcp.json   # DTLS + DTLCP on UDP 20856 (no QUIC)
├── server-all.json              # All combinations simultaneously
│
├── client-tls.json              # UDP:21553 → TLS DoT → 127.0.0.1:20853
├── client-tlcp.json             # UDP:21554 → TLCP DoT → 127.0.0.1:20853
├── client-https.json            # UDP:21555 → HTTPS DoH → 127.0.0.1:20443
├── client-http-tlcp.json        # UDP:21556 → HTTP-TLCP DoH → 127.0.0.1:20443
├── client-dnscrypt-tcp.json     # UDP:21557 → DNSCrypt TCP → 127.0.0.1:20444
├── client-quic.json             # UDP:21558 → QUIC DoQ → 127.0.0.1:20854
├── client-dtls.json             # UDP:21559 → DTLS → 127.0.0.1:20854
├── client-dtlcp.json            # UDP:21560 → DTLCP → 127.0.0.1:20854
├── client-dnscrypt-udp.json     # UDP:21561 → DNSCrypt UDP → 127.0.0.1:20854
├── client-http3.json            # UDP:21562 → HTTP3 DoH3 → 127.0.0.1:20445
├── client-dtls-nq.json          # UDP:21563 → DTLS → 127.0.0.1:20856 (no QUIC)
├── client-dtlcp-nq.json         # UDP:21564 → DTLCP → 127.0.0.1:20856 (no QUIC)
├── client-https-dns.json        # UDP:21565 → HTTPS DoH → 127.0.0.1:20444
├── client-http-tlcp-dns.json    # UDP:21566 → HTTP-TLCP DoH → 127.0.0.1:20444
├── client-dnscrypt-h3.json      # UDP:21567 → DNSCrypt UDP → 127.0.0.1:20445
└── client-http3-dns.json        # UDP:21568 → HTTP3 DoH3 → 127.0.0.1:20445
```

## Port Map

| Shared Port | Transport | Protocols | Detection Mechanism |
|-------------|-----------|-----------|---------------------|
| 20853 | TCP | TLS + TLCP | Record header (0x03 vs 0x01) |
| 20443 | TCP | HTTPS + HTTP-TLCP | Record header (0x03 vs 0x01) |
| 20444 | TCP | HTTPS + HTTP-TLCP + DNSCrypt | Record header + raw fallthrough |
| 20854 | UDP | QUIC + DTLS (+ DTLCP + DNSCrypt) | Packet demux (up to 4 classifiers) |
| 20445 | UDP | HTTP3 + DNSCrypt | Packet demux (QUIC / DNSCrypt binary) |
| 20856 | UDP | DTLS + DTLCP | Per-client listener (no QUIC) |
| 20533 | UDP+TCP | plain DNS | Not shared (baseline) |

## Prerequisites

```bash
go build -o /tmp/zjdns ./cmd/zjdns
```

All certs use `self_signed: true` — no external CA needed.

## Tests

### 1. TCP: DoT Record Header Detection (TLS + TLCP)

Two protocols (TLS and TLCP) share a single TCP port. The server auto-detects
which protocol each client speaks based on the record layer header.

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-tcp-dot.json &
sleep 2

# Test via TLS DoT client (record header 0x03)
/tmp/zjdns -config docs/debug/port-sharing/client-tls.json &
dig @127.0.0.1 -p 21553 www.baidu.com A +short
pkill -f "client-tls"

# Test via TLCP DoT client (record header 0x01)
/tmp/zjdns -config docs/debug/port-sharing/client-tlcp.json &
dig @127.0.0.1 -p 21554 www.baidu.com A +short
pkill -f "client-tlcp"

# Verify: both clients connected to the same TCP port 20853
grep 'SHARED: DoT' /tmp/zjdns.log
# Expected: "DoT TLS connection" and "DoT TLCP connection" intermixed on port 20853

pkill -f "server-tcp-dot"
```

### 2. TCP: DoH Dispatch (HTTPS + HTTP-TLCP)

HTTPS and TLCP HTTPS share the same TCP port for DoH. The HTTP server dispatches
both TLS and TLCP connections identically at the HTTP/1.1 level.

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-tcp-doh.json &
sleep 2

# Test via HTTPS DoH client
/tmp/zjdns -config docs/debug/port-sharing/client-https.json &
dig @127.0.0.1 -p 21555 www.baidu.com A +short
pkill -f "client-https"

# Test via TLCP HTTPS DoH client
/tmp/zjdns -config docs/debug/port-sharing/client-http-tlcp.json &
dig @127.0.0.1 -p 21556 www.baidu.com A +short
pkill -f "client-http-tlcp"

grep 'SHARED: DoH' /tmp/zjdns.log
# Expected: HTTP server started on shared port 20443 (TLS + TLCP)

pkill -f "server-tcp-doh"
```

### 3. TCP: DoH + DNSCrypt (HTTPS + HTTP-TLCP + DNSCrypt)

The most complex TCP sharing: TLS/TLCP connections are handshaked and dispatched
to DoH; DNSCrypt connections pass through as raw TCP (no TLS handshake).

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-tcp-doh-dnscrypt.json &
sleep 2

# Test HTTPS DoH on shared port 20444
/tmp/zjdns -config docs/debug/port-sharing/client-https-dns.json &
dig @127.0.0.1 -p 21565 www.baidu.com A +short
pkill -f "client-https-dns"

# Test TLCP DoH on shared port 20444
/tmp/zjdns -config docs/debug/port-sharing/client-http-tlcp-dns.json &
dig @127.0.0.1 -p 21566 www.baidu.com A +short
pkill -f "client-http-tlcp-dns"

# Test DNSCrypt TCP on shared port 20444 (raw connection, no TLS)
/tmp/zjdns -config docs/debug/port-sharing/client-dnscrypt-tcp.json &
dig @127.0.0.1 -p 21557 www.baidu.com A +short
pkill -f "client-dnscrypt-tcp"

grep 'SHARED' /tmp/zjdns.log
# Expected: DoH server + DNSCrypt handler on same port 20444
pkill -f "server-tcp-doh-dnscrypt"
```

### 4. UDP: DoQ + DTLS (QUIC Fixed Bit vs DTLS Record)

Two protocols sharing a UDP port. The demux distinguishes QUIC (Fixed Bit set,
reserved bits clear) from DTLS (record header 0xFE).

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-udp-dod.json &
sleep 2

# Test DoQ on shared UDP port 20854
/tmp/zjdns -config docs/debug/port-sharing/client-quic.json &
dig @127.0.0.1 -p 21558 www.baidu.com A +short
pkill -f "client-quic"

# Test DTLS on shared UDP port 20854
/tmp/zjdns -config docs/debug/port-sharing/client-dtls.json &
dig @127.0.0.1 -p 21559 www.baidu.com A +short
pkill -f "client-dtls"

grep 'SHARED' /tmp/zjdns.log
# Expected: Shared UDP listener on port 20854 (2-route demux)
pkill -f "server-udp-dod"
```

### 5. UDP: DoQ + DTLS + DTLCP (Three-Way Demux)

All three UDP-based TLS-family protocols share one port. The demux adds a DTLCP
classifier (record header 0x01).

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-udp-dod-dtlcp.json &
sleep 2

/tmp/zjdns -config docs/debug/port-sharing/client-quic.json &
dig @127.0.0.1 -p 21558 www.baidu.com A +short
pkill -f "client-quic"

/tmp/zjdns -config docs/debug/port-sharing/client-dtls.json &
dig @127.0.0.1 -p 21559 www.baidu.com A +short
pkill -f "client-dtls"

/tmp/zjdns -config docs/debug/port-sharing/client-dtlcp.json &
dig @127.0.0.1 -p 21560 www.baidu.com A +short
pkill -f "client-dtlcp"

grep 'SHARED' /tmp/zjdns.log
# Expected: Shared UDP listener on port 20854 (3-route demux)
pkill -f "server-udp-dod-dtlcp"
```

### 6. UDP: DoQ + DTLS + DTLCP + DNSCrypt (Full Four-Way Demux)

All four UDP protocols on one port. The DNSCrypt classifier is a catch-all
that matches packets not claimed by QUIC/DTLS/DTLCP.

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-udp-dod-all.json &
sleep 2

# All four protocols share UDP port 20854
/tmp/zjdns -config docs/debug/port-sharing/client-quic.json &
dig @127.0.0.1 -p 21558 www.baidu.com A +short
pkill -f "client-quic"

/tmp/zjdns -config docs/debug/port-sharing/client-dtls.json &
dig @127.0.0.1 -p 21559 www.baidu.com A +short
pkill -f "client-dtls"

/tmp/zjdns -config docs/debug/port-sharing/client-dtlcp.json &
dig @127.0.0.1 -p 21560 www.baidu.com A +short
pkill -f "client-dtlcp"

/tmp/zjdns -config docs/debug/port-sharing/client-dnscrypt-udp.json &
dig @127.0.0.1 -p 21561 www.baidu.com A +short
pkill -f "client-dnscrypt-udp"

grep 'SHARED' /tmp/zjdns.log
# Expected: Shared UDP listener on port 20854 (4-route demux)
pkill -f "server-udp-dod-all"
```

### 7. UDP: HTTP3 + DNSCrypt (DoH3 + DNSCrypt Binary Demux)

HTTP3 (QUIC transport) and DNSCrypt share a UDP port without DoQ. Uses a
binary classifier: QUIC packets → HTTP3, everything else → DNSCrypt.

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-udp-h3-dnscrypt.json &
sleep 2

# Test DoH3 on shared UDP port 20445
/tmp/zjdns -config docs/debug/port-sharing/client-http3-dns.json &
dig @127.0.0.1 -p 21568 www.baidu.com A +short
pkill -f "client-http3-dns"

# Test DNSCrypt UDP on shared UDP port 20445
/tmp/zjdns -config docs/debug/port-sharing/client-dnscrypt-h3.json &
dig @127.0.0.1 -p 21567 www.baidu.com A +short
pkill -f "client-dnscrypt-h3"

grep 'SHARED' /tmp/zjdns.log
# Expected: Shared UDP listener on port 20445 (HTTP3+DNSCrypt binary demux)
pkill -f "server-udp-h3-dnscrypt"
```

### 8. UDP: DTLS + DTLCP without QUIC (Shared UDP Listener)

When DTLS and DTLCP share a port but QUIC is absent, a per-client stateful
listener is used instead of the packet demux. Each client's first datagram
determines the protocol, and a virtual per-client socket is created.

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-udp-dtls-dtlcp.json &
sleep 2

# Test DTLS on port 20856 (no QUIC demux)
/tmp/zjdns -config docs/debug/port-sharing/client-dtls-nq.json &
dig @127.0.0.1 -p 21563 www.baidu.com A +short
pkill -f "client-dtls-nq"

# Test DTLCP on port 20856 (no QUIC demux)
/tmp/zjdns -config docs/debug/port-sharing/client-dtlcp-nq.json &
dig @127.0.0.1 -p 21564 www.baidu.com A +short
pkill -f "client-dtlcp-nq"

grep 'SHARED' /tmp/zjdns.log
# Expected: DTLS and DTLCP handled via SharedUDPListener (not Demux)
pkill -f "server-udp-dtls-dtlcp"
```

### 9. All-In-One: Full Sharing Matrix

The `server-all.json` config combines all sharing code paths simultaneously:

| Port | Transport | Protocols | Code Path |
|------|-----------|-----------|-----------|
| 20853 | TCP | TLS + TLCP | `SharedTCPListener` (record header) |
| 20443 | TCP | HTTPS + HTTP-TLCP | `SharedTCPListener` (record header) |
| 20854 | UDP | QUIC + DTLS + DTLCP + DNSCrypt | `Demux` (4 classifiers) |
| 20445 | UDP | HTTP3 | standalone (no sharing on this port) |
| 20533 | UDP+TCP | plain DNS | standalone |

```bash
/tmp/zjdns -config docs/debug/port-sharing/server-all.json &
sleep 2

# TCP 20853: TLS DoT + TLCP DoT
/tmp/zjdns -config docs/debug/port-sharing/client-tls.json &
dig @127.0.0.1 -p 21553 www.baidu.com A +short
pkill -f "client-tls"

/tmp/zjdns -config docs/debug/port-sharing/client-tlcp.json &
dig @127.0.0.1 -p 21554 www.baidu.com A +short
pkill -f "client-tlcp"

# TCP 20443: HTTPS DoH + HTTP-TLCP DoH
/tmp/zjdns -config docs/debug/port-sharing/client-https.json &
dig @127.0.0.1 -p 21555 www.baidu.com A +short
pkill -f "client-https"

/tmp/zjdns -config docs/debug/port-sharing/client-http-tlcp.json &
dig @127.0.0.1 -p 21556 www.baidu.com A +short
pkill -f "client-http-tlcp"

# UDP 20854: DoQ + DTLS + DTLCP + DNSCrypt (four-way demux)
/tmp/zjdns -config docs/debug/port-sharing/client-quic.json &
dig @127.0.0.1 -p 21558 www.baidu.com A +short
pkill -f "client-quic"

/tmp/zjdns -config docs/debug/port-sharing/client-dtls.json &
dig @127.0.0.1 -p 21559 www.baidu.com A +short
pkill -f "client-dtls"

/tmp/zjdns -config docs/debug/port-sharing/client-dtlcp.json &
dig @127.0.0.1 -p 21560 www.baidu.com A +short
pkill -f "client-dtlcp"

/tmp/zjdns -config docs/debug/port-sharing/client-dnscrypt-udp.json &
dig @127.0.0.1 -p 21561 www.baidu.com A +short
pkill -f "client-dnscrypt-udp"

# UDP 20445: DoH3 (standalone in this config)
/tmp/zjdns -config docs/debug/port-sharing/client-http3.json &
dig @127.0.0.1 -p 21562 www.baidu.com A +short
pkill -f "client-http3"

# Verify sharing is active
grep 'Shared' /tmp/zjdns.log
# Expected:
#   SERVER: Shared TCP listener on port 20853
#   SERVER: Shared TCP listener on port 20443
#   SERVER: Shared UDP listener on port 20854

pkill -f "server-all"
```

## Verifying Port Sharing

After each test, check the logs for sharing-related messages:

```
SERVER: Shared TCP listener on port 20853
SERVER: Shared UDP listener on port 20854
SHARED: DoT TLS connection from ...
SHARED: DoT TLCP connection from ...
SHARED: DoH server started on ... (HTTP/1.1, TLS + TLCP)
```

Run concurrent queries to verify multiplexing:

```bash
# Start the all-in-one server
/tmp/zjdns -config docs/debug/port-sharing/server-all.json &

# Run multiple clients concurrently — all share the same ports
/tmp/zjdns -config docs/debug/port-sharing/client-tls.json &
/tmp/zjdns -config docs/debug/port-sharing/client-quic.json &
/tmp/zjdns -config docs/debug/port-sharing/client-https.json &
sleep 2

dig @127.0.0.1 -p 21553 www.baidu.com A +short &
dig @127.0.0.1 -p 21558 www.baidu.com A +short &
dig @127.0.0.1 -p 21555 www.baidu.com A +short &
wait

pkill -f "client-tls\|client-quic\|client-https\|server-all"
```

## Port Reference

| Client Config | Listen Port | Upstream Port | Protocol |
|---------------|-------------|---------------|----------|
| client-tls.json | 21553 | 20853 | TLS DoT |
| client-tlcp.json | 21554 | 20853 | TLCP DoT |
| client-https.json | 21555 | 20443 | HTTPS DoH |
| client-http-tlcp.json | 21556 | 20443 | HTTP-TLCP DoH |
| client-dnscrypt-tcp.json | 21557 | 20444 | DNSCrypt TCP |
| client-quic.json | 21558 | 20854 | QUIC DoQ |
| client-dtls.json | 21559 | 20854 | DTLS |
| client-dtlcp.json | 21560 | 20854 | DTLCP |
| client-dnscrypt-udp.json | 21561 | 20854 | DNSCrypt UDP |
| client-http3.json | 21562 | 20445 | HTTP3 DoH3 |
| client-dtls-nq.json | 21563 | 20856 | DTLS (no QUIC) |
| client-dtlcp-nq.json | 21564 | 20856 | DTLCP (no QUIC) |
| client-https-dns.json | 21565 | 20444 | HTTPS DoH |
| client-http-tlcp-dns.json | 21566 | 20444 | HTTP-TLCP DoH |
| client-dnscrypt-h3.json | 21567 | 20445 | DNSCrypt UDP |
| client-http3-dns.json | 21568 | 20445 | HTTP3 DoH3 |
