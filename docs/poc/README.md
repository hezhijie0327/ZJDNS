# ZJDNS Defense Mechanism POC Programs

Three standalone proof-of-concept programs demonstrating ZJDNS's DNS anti-pollution
defense mechanisms. Each is a self-contained Go program with rich terminal output.

## Quick Start

```bash
# HopGuard: IP TTL fingerprinting
go run ./hopguard

# Spoofguard: UDP multi-read GFW injection detection
go run ./spoofguard

# Splitguard: TCP segmentation for DPI evasion
go run ./splitguard
```

All programs clear the terminal and render color output. Run with `-h` for usage.

---

## HopGuard — IP TTL Fingerprinting

**File:** `hopguard/main.go`
**Source:** `server/defense/hopguard.go`

### Problem
The GFW injects fake DNS responses from a different network location than the real
upstream server. These injected responses arrive with a different IP-layer TTL
(Time-to-Live) value.

### How It Works
1. **Learning phase:** Collect 32 TTL samples from trusted responses (filtered by
   Spoofguard first). Build a histogram.
2. **Adaptive threshold:** `threshold = max(mode_frequency / 4, 4)` — the most
   common TTL (mode) always passes; only nearby TTLs meeting the threshold join
   the trusted set.
3. **Enforcement phase:** Responses with TTL outside `trusted ± 2` are rejected.
4. **Periodic rebuild:** Every 32 samples, histogram counts are decayed by ×¾,
   preventing stale baselines from persisting after routing changes.

### Demo Output
```
┌──────┬─────┬────────┬──────────┐
│  #   │ TTL │ Source │ Verdict  │
├──────┼─────┼────────┼──────────┤
│ 1    │ 52  │ REAL   │ LEARN    │
│ 2    │ 57  │ GFW    │ LEARN    │  ← learning phase: accept all
...
│ 45   │ 51  │ REAL   │ LEARN    │
├──────┴─────┴────────┴──────────┤
│  ▲ ARMED — trusted baselines established  │
├──────┬─────┬────────┬──────────┤
│ 46   │ 44  │ GFW    │ REJECT ✗ │  ← GFW TTL outside trusted range
│ 47   │ 52  │ REAL   │ PASS ✓   │
```

### Key Insight
> GFW-injected responses cannot match the real server's TTL because they come
> from a different network location. TTL is an IP-layer property that GFW cannot
> forge without sitting on the same network path.

---

## Spoofguard — UDP Multi-Read GFW Detection

**File:** `spoofguard/main.go`
**Source:** `server/upstream/plain/udp.go` (`processPacket`, `pickBest`)

### Problem
The GFW injects fake DNS responses over UDP. These fakes are bare A/AAAA records
without EDNS (OPT pseudo-record) and without CNAME chains.

### How It Works
1. **Multi-read loop:** After sending a UDP query, keep reading datagrams for a
   500ms window. Both GFW fakes and the real response arrive.
2. **Detection rules (in priority order):**
   - **AN≥2, NS>0, AD=1** → immediate fast-return (authoritative signal)
   - **EDNS-bearing NOERROR** → collect as ambiguous candidate
   - **Non-EDNS single-answer** → REJECT (canonical GFW signature)
   - **Non-EDNS with CNAME or multi-answer** → fallback candidate (real server
     without EDNS support — rare)
3. **Candidate selection:** After the collect window, compare EDNS candidates.
   Prefer the one with more answer records. Random tie-break to prevent
   deterministic tail-win exploitation.

### Demo Output
```
── Multi-Read Loop ──
[+ 30ms] Datagram #1 arrives
         GFW fake #1 — bare A record
         EDNS: NO    Answers: [A 93.46.8.89]   CNAME: false
         → REJECT (GFW: bare record, no EDNS, no CNAME)

[+ 60ms] Datagram #2 arrives
         GFW fake #2 — bare AAAA record
         EDNS: NO    Answers: [AAAA 2001:db8::1]   CNAME: false
         → REJECT (GFW: bare record, no EDNS, no CNAME)

[+110ms] Datagram #3 arrives
         Real: 8.8.8.8 — EDNS + A record
         EDNS: YES   Answers: [A 142.250.80.4]   CNAME: false
         → COLLECT (EDNS candidate #1)

── Collect window expired (500ms) ──
Selected: Real: 8.8.8.8 — EDNS + A record (returned to client)
GFW fakes rejected: 2
```

### Key Insight
> GFW injection has a detectable signature: bare A/AAAA records without EDNS.
> Real DNS servers include EDNS (OPT RR) per RFC 6891. Spoofguard exploits this
> protocol-level difference.

---

## Splitguard — TCP Segmentation for DPI Evasion

**File:** `splitguard/main.go`
**Source:** `internal/dnsutil/tcpframe.go` (`WriteTCPMsgSegmented`)

### Problem
DPI (Deep Packet Inspection) systems monitor TCP streams for DNS query byte
patterns (e.g., `www.google.com`). When a domain matches a blacklist, the DPI
blocks the connection.

### How It Works
1. The DNS-over-TCP message (2-byte length prefix + payload) is split into
   multiple `write()` calls, each sending a small random-sized segment.
2. **Segment sizing:** Each segment carries `[1, segSize]` random bytes
   (default `segSize=4`). Random sizing prevents the DPI from fingerprinting
   a fixed segmentation pattern.
3. **First segment** includes the 2-byte DNS length prefix per RFC 1035.
4. **TCP_NODELAY** is enabled to ensure segments are sent immediately, not
   batched by Nagle's algorithm.
5. The DNS server sees a normal TCP stream — TCP reassembly is transparent.

### Demo Output
```
Normal TCP Write:
  Single write():  00 20 1A 2B 01 00 00 01 00 00 00 00 00 00 03 77 77 77 ...
  Structure: [LEN=32] [ID=0x1A2B RD=1] [www] [google] [com] [QTYPE=A]
  ┌─ DPI Sees ────────────────────────────────────────────┐
  │ Complete domain labels: [www] [google] [com]          │
  │ → DPI matches blacklist → BLOCKS connection           │
  └───────────────────────────────────────────────────────┘

Splitguard (segSize=4):
  write(1)   5B: 00 20 1A 2B 01          ← length prefix + partial header
  write(2)   4B: 00 00 01 00              ← raw bytes
  write(3)   3B: 00 00 00                 ← raw bytes
  ...
  write(12)  1B: 01                       ← raw bytes

  ┌─ DNS Server Receives (TCP reassembly) ───────────────┐
  │ TCP stream: 00 20 1A 2B 01 00 00 01 ...              │
  │ Structure: [LEN=32] [ID=0x1A2B RD=1] [www] [google] [com] [QTYPE=A] │
  │ → Server processes query normally, returns A record   │
  └───────────────────────────────────────────────────────┘

Normal:    00201a2b010000010000000000000377777706676f6f676c6503636f6d0000010001
           ↑ DPI sees complete domain → blocks

Splitguard: 00201a2b01│00000100│000000│000003│777777│06676f6f│676c│650363│6f6d│...
           ↑ DPI sees 12 isolated fragments → cannot match
```

### Key Insight
> DPI operates on individual TCP segments. By splitting the DNS message into
> segments smaller than any domain label, no single segment contains a complete
> domain name. TCP reassembly at the server reconstructs the full message
> transparently.

---

## Architecture Notes

These POC programs mirror the actual ZJDNS implementation:

| POC | Source Package | Key Type/Function |
|-----|---------------|-------------------|
| HopGuard | `server/defense/` | `HopGuard.Validate()` / `HopGuard.Feed()` |
| Spoofguard | `server/upstream/plain/` | `processPacket()` / `pickBest()` |
| Splitguard | `internal/dnsutil/` | `WriteTCPMsgSegmented()` |

All three mechanisms are configurable per-upstream in `config.UpstreamServer`:

```go
type UpstreamServer struct {
    HopGuard   bool `json:"hopguard,omitzero"`
    Spoofguard bool `json:"spoofguard,omitzero"`
    Splitguard bool `json:"splitguard,omitzero"`
    // ...
}
```
