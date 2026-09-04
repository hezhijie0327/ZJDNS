# ZJDNS Defense Mechanism POC Programs

Standalone proof-of-concept programs demonstrating ZJDNS's DNS anti-pollution
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

# CapsGuard: DNS 0x20 question-case randomization + echo verification
go run ./capsguard
```

All programs clear the terminal and render color output. Run with `-h` for usage.

## Real-Network Mode

Every POC also supports `-real` to query a live upstream and observe the
defense against real GFW pollution (measured from a CN network):

```bash
go run ./hopguard    -real -server 8.8.8.8:53
go run ./spoofguard  -real -server 8.8.8.8:53 -qname www.google.com
go run ./splitguard  -real -server 8.8.8.8:53
go run ./poisonguard -real -qname www.google.com          # queries root/TLD servers
go run ./capsguard -real -server 8.8.8.8:53 -qname wWw.GoOgLe.CoM
```

Real-mode observations on 8.8.8.8 (2026-08, CN network): google queries are
GFW-polluted (fake IPs from Facebook/Twitter segments); spoofguard's AN≥2
fast-return picks the real 8-answer response over single-answer fakes,
splitguard's segmented TCP survives the GFW RST that kills plain TCP,
poisonguard flags the injected A record from a TLD server.

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
   preventing stale baselines from persisting after routing changes. When every
   baseline has decayed away, hopguard disarms and re-enters learning.
5. **Drift recovery (1-in-16 sampling):** Validate-rejected TTLs are fed back
   into the histogram on a uniform 1-in-16 sample — a legitimate TTL shift
   (anycast reroute / PoP change) re-arms on the new TTL instead of locking
   the server into SERVFAIL, while attacker-injected TTLs are diluted 16× and
   can never win the mode competition.

### Demo Output
```
Scenario A: Google directly (no warm-up) → NOT ARMED (only 12 real samples)
  Result: 8/8 GFW fakes PASSED — still learning, can't reject yet

Scenario B: Baidu warm-up → Google → ▲ ARMED, trusted TTLs: 51,52,53 (±2)
  Result: 8/8 GFW fakes REJECTED — already armed from Baidu warm-up

Scenario C: anycast reroute (TTL 52→40) → REJECTING… sampled feeds rebuild…
  → RE-ARMED @ 40 — traffic flows again (1-in-16 rejection sampling)
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
1. **Multi-read loop:** After sending a UDP query, keep reading datagrams in an
   **adaptive collect window** — 150ms after a single datagram (nothing to
   compare; authorities answer a query once), the full 500ms once a second
   datagram arrives (a possible injected peer). Injected domains are gated
   upstream by the TLD poison probe and the poisonguard verdict, so the short
   single-candidate wait keeps that defense intact.
2. **Detection rules (in priority order):**
   - **AN≥2, NS>0, AD=1** → immediate fast-return (authoritative signal)
   - **EDNS-bearing NOERROR** → collect as candidate (always preferred);
     two **identical** EDNS answers confirm the deterministic real response
     immediately (GFW fakes vary per packet) — no window wait
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

### Demo Output (scenarios 1–6)
```
Scenario 1: www.google.com — fakes + real EDNS → real EDNS wins (CLEAN)
Scenario 3: www.google.com — no-EDNS real + fake → re-query →
  Confirmed: round 1 and round 2 real answers match → served real
Scenario 4: www.google.com — lone injection (2 fakes/round) →
  No matching confirmation across 3 rounds → query fails, nothing served
Scenario 5: github.com — clean single-answer no-EDNS →
  Served directly (1 response, no injection signal)
Scenario 6: www.example.com — server retransmit, two identical EDNS answers →
  Confirmed at +90ms (identical repeat), window skipped
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

## CapsGuard — DNS 0x20 Question-Case Randomization

**File:** `capsguard/main.go`
**Source:** `server/defense/capsguard.go` (`RandomizeCase`) + `server/upstream/client.go` (`ExecuteQuery`)

### Problem
DNS responses carry no transaction identity beyond the 16-bit ID. The GFW
injects fake responses that don't know the per-query randomized question case —
but every legitimate DNS response MUST echo the query name byte-for-byte
(RFC 4343 §3). Case randomization turns the question itself into
unpredictable transaction entropy.

### How It Works
1. **Randomization (§5.1):** each ASCII letter in the outbound question carries
   1 random bit — the case bit is flipped with 50% probability
   (draft-vixie-dnsext-dns0x20).
2. **Echo verification:** the response must echo the question case exactly;
   a mismatch means the responder never saw the real query → discard.
3. **§6.4 fallback:** after a mismatch, the query is retried once with the
   original case so case-rewriting middleboxes keep service working.
4. **Consecutive-mismatch downgrade:** 8 *consecutive* mismatches (a success
   resets the counter) skip randomization for that upstream entirely for the
   retry window — a permanently non-compliant upstream stops paying the
   per-query retry cost.
5. **PTR exemption:** reverse-lookup queries skip echo verification — some
   middleboxes (Cisco DNS guard) legitimately rewrite reverse qnames.
6. **Cache hits** patch the stored wire back to the client's question case
   (`handler/response.go` `patchQuestionCase`).

### Demo Output (scenarios A–E)
```
Scenario A: 0x20-capable server       → every query accepted first try (0 retries)
Scenario B: case-rewriting middlebox  → DISCARD + §6.4 unrandomized retry per query
Scenario C: spoofer (wrong echo)      → every attempt discarded → SERVFAIL
Scenario D: persistent middlebox      → query 8 downgrades: queries 9+ skip
                                         randomization (no retry, no doubled RTT)
Scenario E: PTR through middlebox     → accepted — PTR exempt from 0x20 check
```

### Key Insight
> The spoofer must guess the per-query case pattern — 2^n bits of entropy where
> n is the number of ASCII letters in the question. Legitimate servers echo the
> question transparently, so verification costs zero extra round-trips.

---

## Architecture Notes

These POC programs mirror the actual ZJDNS implementation:

| POC | Source Package | Key Type/Function |
|-----|---------------|-------------------|
| HopGuard | `server/defense/` | `HopGuard.Validate()` / `HopGuard.Feed()` |
| Spoofguard | `server/upstream/plain/` | `processPacket()` / `pickBest()` / `executeUDPCollect()` |
| Splitguard | `internal/dnsutil/` | `WriteTCPMsgSegmented()` |
| Poisonguard | `server/defense/` | `Detector.Validate()` / `Detector.IsPoisonedByTLD()` |
| Capsguard | `server/defense/` + `server/upstream/` | `RandomizeCase()` / `ExecuteQuery()` |

All mechanisms are configurable per-upstream in `config.UpstreamServer`:

```go
type UpstreamServer struct {
    Poisonguard bool `json:"poisonguard,omitzero"`
    Spoofguard  bool `json:"spoofguard,omitzero"`
    Splitguard  bool `json:"splitguard,omitzero"`
    HopGuard    bool `json:"hopguard,omitzero"`
    CapsGuard   bool `json:"capsguard,omitzero"`
    // ...
}
```
