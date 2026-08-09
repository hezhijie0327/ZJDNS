# ZJDNS Defense Mechanism POC Programs

Four standalone proof-of-concept programs demonstrating ZJDNS's DNS anti-pollution
defense mechanisms. Each is a self-contained Go program with rich terminal output.

## Quick Start

```bash
# HopGuard: IP TTL fingerprinting
go run ./hopguard

# Spoofguard: UDP multi-read GFW injection detection
go run ./spoofguard

# Splitguard: TCP segmentation for DPI evasion
go run ./splitguard

# Poisonguard: root/TLD hijack detection on the recursive walk
go run ./poisonguard
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
Scenario A: Google directly (no warm-up) → NOT ARMED (only 12 real samples)
  Result: 8/8 GFW fakes PASSED — still learning, can't reject yet

Scenario B: Baidu warm-up → Google → ▲ ARMED, trusted TTLs: 51,52,53 (±2)
  Result: 8/8 GFW fakes REJECTED — already armed from Baidu warm-up
```

### Key Insight
> GFW-injected responses cannot match the real server's TTL because they come
> from a different network location. TTL is an IP-layer property that GFW cannot
> forge without sitting on the same network path.

---

## Spoofguard — UDP Multi-Read GFW Detection

**File:** `spoofguard/main.go`
**Source:** `server/upstream/plain/udp.go` (`processPacket`, `pickBest`, `executeUDPCollect`)

### Problem
The GFW injects fake DNS responses over UDP. Measured pattern: **two** bare
single-answer A/AAAA records without EDNS arrive ~6-8ms after the query; the real
response arrives 65-180ms later, multi-answer (AN≥2) for major sites.

### How It Works
1. **Multi-read loop:** After sending a UDP query, keep reading datagrams for a
   500ms window. Both GFW fakes and the real response arrive.
2. **Detection rules (in priority order):**
   - **AN≥2, NS>0, AD=1** → immediate fast-return (authoritative signal)
   - **EDNS-bearing NOERROR** → collect as candidate (always preferred)
   - **Non-EDNS + CNAME** → safe fallback (GFW does not inject CNAME chains)
   - **Non-EDNS + bare single-answer A/AAAA** → AMBIGUOUS:
     - only **one** response received → serve directly (no injection signal —
       GFW always injects two fakes)
     - **≥2 responses** received → injection suspected → **re-query over UDP**;
       a matching repeat (same answer records) confirms the real answer — GFW
       fakes vary per packet, the real answer is deterministic. Never served
       unconfirmed (bounded by `DefaultSpoofguardConfirmRounds = 3`).
3. **Candidate selection:** After the collect window, EDNS candidates are
   preferred; the richer answer wins; random tie-break prevents deterministic
   tail-win exploitation.

### Demo Output (scenarios 1–5)
```
Scenario 1: www.google.com — fakes + real EDNS → real EDNS wins (CLEAN)
Scenario 3: www.google.com — no-EDNS real + fake → re-query →
  Confirmed: round 1 and round 2 real answers match → served real
Scenario 4: www.google.com — lone injection (2 fakes/round) →
  No matching confirmation across 3 rounds → query fails, nothing served
Scenario 5: github.com — clean single-answer no-EDNS →
  Served directly (1 response, no injection signal)
```

### Key Insight
> GFW fakes are bare single-answer A/AAAA records without EDNS, injected in pairs.
> Multi-read + fast-return recovers the real (multi-answer) response; for the
> ambiguous single-answer case, a matching re-query confirms the deterministic
> real answer over pure UDP — the fake is never served.

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
Normal:    00201a2b010000010000000000000377777706676f6f676c6503636f6d0000010001
           ↑ DPI sees complete domain → blocks

Splitguard: 00201a2b01│00000100│000000│000003│777777│06676f6f│676c│650363│6f6d│...
           ↑ DPI sees 13 isolated fragments → cannot match
```

### Key Insight
> DPI operates on individual TCP segments. By splitting the DNS message into
> segments smaller than any domain label, no single segment contains a complete
> domain name. TCP reassembly at the server reconstructs the full message
> transparently.

---

## Poisonguard — Root/TLD Hijack Detection

**File:** `poisonguard/main.go`
**Source:** `server/defense/poisonguard.go` (`Detector.Validate`, `Detector.IsPoisonedByTLD`)

### Problem
The GFW injects bare A/AAAA records into UDP responses — including responses from
root and TLD servers, which would **never** legitimately return data records for a
subdomain. The recursive walk knows which server it is talking to, so injection
at these levels is unambiguous.

### How It Works
1. **Validate(zone, qname, response):** classify each Answer record by server level:
   - **Root server:** root-servers.net glue, TLD NS/DS + DNSSEC proofs → CLEAN;
     any other data record for a subdomain → **POISONED**
   - **TLD server:** TLD apex, child delegation/proof (NS/DS/RRSIG/NSEC/NSEC3) →
     CLEAN; data records for a child name → **POISONED**
   - **Authoritative server:** content cannot distinguish real from injected →
     **UNCERTAIN** (the blind spot — covered by Spoofguard's re-query confirmation)
2. **RRSIG exemption:** an answer carrying a matching RRSIG is DNSSEC-signed and
   cannot be forged → CLEAN.
3. **TLD probe (`IsPoisonedByTLD`):** the full qname (RD=0, UDP) is sent to a
   TLD server; an A/AAAA answer for it → **POISONED → force the current
   authoritative-layer query over TCP** (the whole walk restarts over TCP
   only when a hop validation returns VerdictPoisoned; a poisoning seen at
   any hop also forces subsequent CNAME targets over TCP).

### Demo Output (scenarios 1–7)
```
Root server A for subdomain        → POISONED → restart the walk over TCP
TLD server A/AAAA/CNAME for child  → POISONED → restart the walk over TCP
Root NS/DS delegation + proofs     → CLEAN (no false positive)
TLD DS for signed child            → CLEAN (no false positive)
Signed answer (RRSIG present)      → CLEAN
Authoritative A (real or fake)     → UNCERTAIN (blind spot)
TLD probe: injected A → force TCP  → true; legitimate referral → false
```

### Key Insight
> Root and TLD servers never return data records for a subdomain — the observed
> GFW signature is exactly what those levels never produce legitimately.
> Detection forces a UDP→TCP retry; the authoritative blind spot is covered by
> Spoofguard (re-query confirmation) and HopGuard (TTL fingerprint).

---

## Architecture Notes

These POC programs mirror the actual ZJDNS implementation:

| POC | Source Package | Key Type/Function |
|-----|---------------|-------------------|
| HopGuard | `server/defense/` | `HopGuard.Validate()` / `HopGuard.Feed()` |
| Spoofguard | `server/upstream/plain/` | `processPacket()` / `pickBest()` / `executeUDPCollect()` |
| Splitguard | `internal/dnsutil/` | `WriteTCPMsgSegmented()` |
| Poisonguard | `server/defense/` | `Detector.Validate()` / `Detector.IsPoisonedByTLD()` |

All four mechanisms are configurable per-upstream in `config.UpstreamServer`:

```go
type UpstreamServer struct {
    Poisonguard bool `json:"poisonguard,omitzero"`
    Spoofguard  bool `json:"spoofguard,omitzero"`
    Splitguard  bool `json:"splitguard,omitzero"`
    HopGuard    bool `json:"hopguard,omitzero"`
    // ...
}
```
