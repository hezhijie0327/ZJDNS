# Defense Audit: server/defense/*

## Summary
- Files audited: 2 (hopguard.go, poisonguard.go)
- CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 3

## State Machine Audit

### HopGuard
| Module | States | Transitions | Escape paths | Dead states? |
|--------|--------|-------------|--------------|--------------|
| HopGuard | `learning` → `armed` → `enforcement` | learning: all TTLs pass, histogram accumulates; armed: rebuild at multiples of 32 samples triggers threshold-based promotion from histogram to trusted set | **NONE** — once armed, a server whose IP TTL changes (anycast reroute, PoP change) is permanently rejected for A/AAAA queries; no escape path exists (see CRITICAL-1) | No |
| `serverState` inside LRU | `active` → `evicted` | eviction at LRU capacity (256 entries) | evicted state is GC'd when no goroutine holds its pointer | No |

### PoisonGuard (Detector)
| Module | States | Transitions | Escape paths | Dead states? |
|--------|--------|-------------|--------------|--------------|
| Detector | Stateless — pure classification function | N/A (no state) | N/A | `VerdictUncertain` is dead code (acknowledged placeholder for multi-vantage-point analysis) |

## Background Goroutine Audit
| File | Goroutine | Owner | Cancel | HandlePanic | Status |
|------|-----------|-------|--------|-------------|--------|
| _(none)_ | HopGuard and PoisonGuard have zero background goroutines — entirely call-driven via Validate/Feed | | | | |

## Findings

### CRITICAL

#### [CRITICAL-1] [架构设计] [内存安全] hopguard.go:60-86 + 92-138 + server/upstream/plain/udp.go:218-234 — TTL change causes permanent A/AAAA outage; Validate gates Feed, preventing self-recovery

- **Problem**: When a server's IP TTL (or Hop Limit) changes due to anycast routing changes, server reconfiguration, or path changes, the new TTL is permanently rejected by `Validate` with no self-recovery mechanism. The root cause is a feedback loop in the multi-read loop:

  ```
  Read packet with new TTL=64
    → Validate(64) returns false (not within ±2 of any trusted TTL)
    → continue (packet skipped, processPacket never called)
    → Feed is NEVER called
    → histogram[64] is never incremented
    → rebuildTrusted never sees TTL=64
    → TTL=64 NEVER becomes trusted
  ```

  The old TTL (e.g., 100) remains in the trusted set forever because histogram entries are never aged, but the server no longer sends TTL=100. All A/AAAA responses from this upstream are rejected. Non-A/AAAA queries bypass hopguard (they don't enter the multi-read path), so they work — the outage is specific to A/AAAA.

  **Trace**:
  - `hopguard.go:61` — early return for nil/0 TTL (not this case)
  - `hopguard.go:72-86` — Validate checks trusted set via passTrusted; TTL=64 in [98,102]? No → returns false
  - `udp.go:218-221` — Validate returns false → `continue` (packet dropped, Feed never called)
  - `udp.go:232-234` — Feed is only called on the return path after processPacket returns a value

- **Risk**: Any upstream server that changes its IP TTL (e.g., Google 8.8.8.8 switches anycast PoP, Cloudflare 1.1.1.1 traffic reroutes) permanently fails A/AAAA queries until the process restarts. In GFW environments where customers configure upstreams that may route differently at different times, this creates a silent outage.

- **Fix**: Decouple recording from validation. Feed MUST record ALL observed TTLs into the histogram regardless of Validate's result. The histogram must include both trusted and untrusted TTLs. Only Validate uses the trusted set. Additionally, add histogram aging or a sliding window to prevent stale TTLs from permanently inflating the adaptive threshold.

  The simplest fix: in `Feed`, always record the TTL (remove the implicit gating where Feed is never called for rejected TTLs). This means either:
  1. Move `Feed` call to BEFORE the `Validate` check in udp.go (not recommended — Feed should happen per-TTL, not per-packet that happens to be captured)
  2. **Better**: Call `Feed` for every packet that enters the loop, regardless of Validate — or have Feed called with ALL observed TTLs, not just the winner's TTL

  The most correct approach: `Feed` should accept all observations. The histogram accumulates ALL TTLs. `Validate` gates on the trusted set (which is recomputed periodically). The adaptive threshold naturally prevents GFW TTLs (scattered, low repeat count) from becoming trusted, while allowing legitimate new server TTLs (clustered, high repeat count) to be promoted over time.

### HIGH

#### [HIGH-1] [架构设计] hopguard.go:35, 100, 238-246 — Histogram is append-only with no aging mechanism

- **Problem**: Histogram entries are never aged, decayed, or pruned. A TTL that was observed 10,000 times during the learning phase but has not been seen in a month maintains count=10,000 forever. The adaptive threshold `max(maxCount/4, 4)` can become arbitrarily large (e.g., threshold = 2500 from maxCount=10000). A new legitimate TTL for the same server would need to accumulate 2500+ observations to become trusted.

  Combined with CRITICAL-1, even if the recording gating is fixed, the lack of aging means recovery from a TTL change takes `threshold * rebuild_interval` observations — potentially thousands of queries.

- **Risk**: Slow adaptation to legitimate TTL changes. High false-positive rejection window during transitions. Server may appear "flaky" after routing changes.

- **Fix**: Implement histogram aging. Options:
  1. **Sliding window**: Only consider the last N samples for each TTL (circular buffer per TTL)
  2. **Decay factor**: Multiply all counts by a decay factor (e.g., 0.9) every N samples
  3. **Time-based**: Decay entries older than a configurable window
  4. **Simple reset**: When rebuilding, only keep entries with count >= some fraction of maxCount, and halve all counts to give newer observations more weight

  The simplest fix with minimal code change: on each `rebuildTrusted`, apply a decay factor to ALL histogram entries (e.g., `count = count * 3 / 4`). This naturally reduces the influence of stale TTLs while preserving recent ones. Combined with the CRITICAL-1 fix (always record), this allows recovery in O(threshold) samples rather than never.

#### [HIGH-2] [代码质量] poisonguard.go:139-154 — classifyRoot flags legitimate root server records for non-glue, non-delegation types as poison

- **Problem**: `classifyRoot` only recognizes two categories of legitimate records at root level:
  1. A/AAAA records for names under `root-servers.net` (glue)
  2. NS/DS records for TLDs (delegation)

  Everything else with `name != "."` returns `VerdictPoisoned`. This means:
  - SOA records for root-servers.net
  - RRSIG/NSEC/NSEC3 records for root-servers.net
  - ANY other RR type for root-servers.net

  would be flagged as poisoned.

  Example: querying a root server for `root-servers.net` SOA (a legitimate query — the root servers ARE authoritative for root-servers.net). The SOA record in the Answer section would be classified. `classifyRoot("root-servers.net", 6)` → not glue (type check), not delegation (type check), name != "." → `VerdictPoisoned`.

- **Risk**: Low in practice — DNS recursive resolution never queries root servers for root-servers.net metadata. The root servers are only queried for TLD delegations. However, if DNSSEC validation produces RRSIG records alongside delegation NS records at root level, and the RRSIG name matches a non-TLD query name, it could trigger a false positive.

- **Fix**: Expand the clean classification to include any record type where `isRootServerGlue` returns true (i.e. names under root-servers.net for ALL types, not just A/AAAA), OR change the default to `VerdictUncertain` for recognized-but-unexpected record types. The simplest fix:

  ```go
  func (d *Detector) classifyRoot(name string, rrtype uint16) Verdict {
      // All records for root-servers.net are legitimate (glue, SOA, RRSIG, etc.)
      if dnsutil.IsBelow(dnsutil.Fqdn(rootServersDomain), dnsutil.Fqdn(name)) {
          return VerdictClean
      }
      // NS/DS records for TLDs are legitimate root delegations.
      if (rrtype == dns.TypeNS || rrtype == dns.TypeDS) && d.isTLD(name) {
          return VerdictClean
      }
      if name != "." {
          return VerdictPoisoned
      }
      return VerdictClean
  }
  ```

### MEDIUM

#### [MEDIUM-1] [架构设计] hopguard.go:199-214 — ±2 fluctuation tolerance is tight; high-TTL-variance servers may over-reject

- **Problem**: The `passTrusted` function checks if an observed TTL is within `[trustedTTL - 2, trustedTTL + 2]` clamped to `[1, 255]`. This 5-value window (e.g., [98, 102] for TTL=100) works for stable single-path connections but may be too tight for:
  - Servers behind load balancers that rewrite TTL
  - Anycast PoPs with different per-hop TTL paths
  - Servers with intentional TTL randomization for DDoS resilience

- **Risk**: False rejections for legitimate servers with modest TTL variance (e.g., TTL oscillating between 100, 101, 102, 103, 104). Each rejection causes the multi-read loop to skip the packet and keep waiting, increasing latency.

- **Fix**: Consider making the fluctuation configurable per-server, or increase to ±3. The current value of 2 was empirically determined from "four tested international upstreams" (per comment line 193) but may not generalize.

#### [MEDIUM-2] [架构设计] poisonguard.go:173-175 — isTLD misses multi-label TLDs (co.uk, com.au, ne.jp, etc.)

- **Problem**: `isTLD` checks `dnsutil.Labels(domain) == 1`. This correctly identifies single-label TLDs like "com", "org", "cn". However, many ccTLDs delegate registry operations to multi-label domains:
  - `co.uk` (2 labels) — Nominet UK registry
  - `com.au` (2 labels) — auDA registry
  - `ne.jp` (2 labels) — JPNIC registry
  - `com.cn` (2 labels) — CNNIC registry

  These multi-label zones operate as TLDs in practice. A server authoritative for `co.uk` that returns A records for a subdomain like `www.example.co.uk` would NOT be flagged as poisoned — it falls through to the authoritative case and returns `VerdictUncertain`.

- **Risk**: GFN/middlebox injection at the registry level (e.g., `co.uk` nameservers returning fake A for `www.example.co.uk`) is not detected. The recursive resolver would need to rely on other defenses (spoofguard, hopguard) that may not be enabled.

- **Fix**: This is a design limitation of the single-label heuristic. A proper fix requires a comprehensive public-suffix list or zone-cut database. The comment on line 73 should at least document this limitation: `isTLD(zone) → TLD server (e.g. "com", "cn") — NOTE: multi-label zones like "co.uk" are not recognized as TLDs`.

  Alternatively, add a configurable list of multi-label TLD zones that the detector should treat as TLDs.

#### [MEDIUM-3] [性能] hopguard.go:116-118, 130-136 — rebuildTrusted triggered by sample count, not time; idle servers rebuild rarely

- **Problem**: `rebuildTrusted` fires every 32 sample increments. For high-traffic servers, this is frequent (e.g., every 32ms under 1000 QPS). For idle servers (1 query per 5 minutes), rebuilds happen every ~2.5 hours. During the long interval, if all trusted TTLs become invalid and the CRITICAL-1 fix is not applied, the outage persists for hours.

- **Risk**: Slow recovery on low-traffic servers when combined with CRITICAL-1. On high-traffic servers, unnecessary lock contention (rebuildTrusted holds st.mu while iterating the histogram).

- **Fix**: Two-tier triggering — rebuild every N samples OR every T duration, whichever comes first. For example, rebuild every 32 samples with a minimum of 60 seconds between rebuilds.

### LOW

#### [LOW-1] [性能] hopguard.go:218-235 — trustedKeys allocates per rejection for debug logging

- **Problem**: `trustedKeys()` allocates a `[]int` slice and a `strings.Builder` every time a rejection is logged. Since this is called only on the rejection path (which should be rare) and only at Debug level, the allocation is acceptable but unnecessary.

- **Fix**: Pre-build the trusted set string on each `rebuildTrusted` call (when the trusted set changes) and cache it. Or simply accept the allocation — the rejection path is not hot.

#### [LOW-2] [文档质量] hopguard.go:184-196 — trustThreshold doc says "modeCount" but code uses "maxCount"

- **Problem**: The comment on `trustThreshold` says `max(4, modeCount/4)` but the variable in the code is `maxCount`. Since `maxCount` IS the mode's frequency in a histogram, this is technically correct but terminologically confusing.

- **Fix**: Rename to `modeCount` in the function body, or update the comment to say "maxCount".

#### [LOW-3] [代码质量] poisonguard.go:41-46 — VerdictUncertain is dead code (acknowledged)

- **Problem**: `VerdictUncertain` is defined as a Verdict value and returned by `classify` for authoritative-level responses, but no caller checks for it. The only actionable signal is `VerdictPoisoned`. The code itself acknowledges this: "No caller checks VerdictUncertain (VerdictPoisoned is the only actionable signal). Retained as a placeholder for future multi-vantage-point analysis."

- **Risk**: None — this is explicit technical debt. But it adds code surface (a Verdict value, a String case) that is never exercised.

- **Fix**: Either remove it (simplifies the API) or add a TODO with a tracking issue number. Current documentation is adequate.

## Per-Dimension Summary

| Dimension | hopguard.go | poisonguard.go |
|-----------|-------------|----------------|
| 1. Code Quality | Clean. No dead/redundant/duplicate code. | `VerdictUncertain` is dead code (acknowledged). |
| 2. Memory Safety | **CRITICAL** — Validate gates Feed, preventing new TTLs from entering histogram. No unbounded growth (histogram ≤ 256 entries, LRU ≤ 256 states). | Stateless — no memory safety issues. |
| 3. Lock Correctness | Mutex protects each serverState. LRU provides internal sync. TOCTOU between Get and Lock is safe (pointer remains valid; orphaned states are harmless). | No locks needed (stateless). |
| 4. Coupling | Imports `internal/log`, `internal/lrumap` — both foundation packages. Clean. | Imports `internal/log`, `dns`, `dnsutil` — clean. |
| 5. Architecture | **CRITICAL** — no escape path for TTL changes. **MEDIUM** — tight ±2 tolerance. | Clean state machine. Multi-label TLD blind spot (MEDIUM). |
| 6. Performance | O(1) on hot path (LRU lookup + mutex + 1-2 trusted TTL checks). Rebuild O(256) every 32 samples. | O(n) where n = Answer section (usually 1-10). Acceptable. |
| 7. Panic Detection | None found. Map writes on initialized maps. No bare assertions. No division by zero. | None found. Nil response checked. No bare assertions. |
| 8. Error Handling | N/A — defense functions return bool/uint8. No sentinel errors. | N/A — pure classification, no errors returned. |
| 9. Context | No context param — acceptable for in-memory operations. | No context param — acceptable for pure computation. |
| 10. Goroutines | None. Call-driven from caller's goroutine. | None. |
| 11. Resources | No Close() needed. LRU + states GC'd on HopGuard dereference. | No resources. |
| 12. Log Quality | Debug level for rejections and learning progress. `UPSTREAM:` prefix. No spam. | Debug level for poison detection. `SECURITY:` prefix. |
| 13. Documentation | Algorithm well-documented. Adaptive threshold formula clear. | Excellent. States limitations explicitly. |
| 14. Parameter Validation | Nil check on h, zero TTL early return. No serverIP validation (empty = LRU miss). | Nil response check. No zone/name validation (empty = root). |
| 15. Constants | 3 named constants: fluctuation, capacity, minSamples. Good. | 1 named constant: rootServersDomain. Good. |
| 16. RFC Consistency | N/A (custom defense). | N/A (custom defense). |
| 17. Comment Accuracy | trustThreshold doc says "modeCount" vs "maxCount" (LOW). | Accurate. Dead code comment is honest. |
| 18. Function Order | type→const→var→func. `NewHopGuard` after const block. Receiver methods grouped. Correct. | type→const→var→func. `NewDetector` not needed (zero-value struct). Receiver methods grouped. Correct. |

## Cross-File Dependencies

| Dependency | Type | Direction | Notes |
|------------|------|-----------|-------|
| `hopguard.go` ← `internal/lrumap` | Foundation | one-way | LRU map for server state storage |
| `hopguard.go` ← `internal/log` | Foundation | one-way | Debug logging |
| `poisonguard.go` ← `internal/log` | Foundation | one-way | Debug logging |
| `poisonguard.go` ← `dns` / `dnsutil` | External | one-way | DNS types and name normalization |
| `udp.go` → `hopguard.go` | Consumer → Producer | one-way | Calls Validate, Feed, Confident |
| `client.go` → `hopguard.go` | Consumer → Producer | one-way | Creates NewHopGuard |

No import layer violations. Defense package sits at Layer 4 (server sub-packages), importing only foundation packages and external DNS library.

## Recommendations by Priority

1. **[CRITICAL] Fix feed gating**: Decouple TTL recording from validation. `Feed` must record every observed TTL, not just the winner's TTL. The histogram needs all data to correctly compute the adaptive threshold. This is the single highest-risk finding.

2. **[HIGH] Add histogram aging**: After fixing feed gating, add decay or sliding-window pruning to prevent stale TTL counts from permanently inflating the adaptive threshold.

3. **[HIGH] Expand classifyRoot glue check**: Accept all record types under root-servers.net, not just A/AAAA.

4. **[MEDIUM] Document or fix multi-label TLD blind spot**: At minimum, document in the `isTLD` and `Validate` function comments that multi-label zones like `co.uk` are not treated as TLD-level zones.

5. **[MEDIUM] Consider configurable fluctuation**: Make `hopGuardFluctuation` tunable per-upstream or per-server.
