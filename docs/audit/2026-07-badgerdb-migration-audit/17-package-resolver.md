# 17 · Resolver 包深度审计

> 审计 Agent：Phase 1 · Resolver
> 覆盖：server/resolver/* 全部 17 个非测试文件，~3000 行


Now I have all the data I need for the comprehensive audit. Let me compile the report.

---

# Audit Report: server/resolver/, server/resolver/dnssec/, server/resolver/probe/

**Date:** 2026-07-29
**Files audited:** 17 non-test .go files across 3 packages
**Lines of code reviewed:** ~3000

## Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH     | 0 |
| MEDIUM   | 5 |
| LOW      | 8 |

The resolver codebase is well-structured with thorough comments, proper error handling, and solid concurrency patterns. No CRITICAL or HIGH severity issues were found. The MEDIUM findings are edge cases requiring specific misconfiguration or future-aware fragility, not active bugs.

---

## MEDIUM Findings

### M1 — Potential nil interface panic when poisonguard enabled but detector nil

**Files:** `server/resolver/recursive.go:274`, `server/resolver/recursive.go:98`, `server/resolver/recursive.go:141`, `server/resolver/dnssec_chain.go:163`, `server/resolver/dnssec_chain.go:284`, `server/resolver/dnssec_chain.go:327`, `server/resolver/dnssec_chain.go:423`

**Category:** panic-detection, safety

**Description:** The `Resolver.Config.PoisonDetector` field (`defense.Detector` interface) is passed as `r.resolver.validator.Poisonguard` to `queryNameserversConcurrent`. Inside that function, when `r.poisonguard` is true, `detector.Validate()` is called. If `cfg.PoisonDetector` was nil and poisonguard was enabled for a recursive upstream, calling an interface method on a nil interface value causes a runtime panic.

The relevant flow:
1. `Config.PoisonDetector` is stored in `r.validator.Poisonguard` (resolver.go:185)
2. `ConfigureServers` sets `r.recursive.poisonguard = ... || s.Poisonguard` (resolver.go:203)
3. Every recursive query passes `r.resolver.validator.Poisonguard` as the `detector` parameter
4. Inside `queryNameserversConcurrent`, `detector.Validate()` is called when poisonguard is true (nameserver.go:110, 136, 390)

**Failure scenario:** User configures `{protocol: "recursive", poisonguard: true}` without setting up a `PoisonDetector` in the resolver Config. The first poisoned-looking response from a nameserver triggers a nil pointer panic.

**Fix:** Add an explicit nil check in `queryNameserversConcurrent` before calling `detector.Validate()`, or validate in `ConfigureServers` that all activated defense mechanisms have non-nil detectors:

```go
if r.poisonguard && detector == nil {
    // Option A: silently disable
    return nil
    // Option B: error during configuration (preferred)
}
```

---

### M2 — Fragile use-after-Put slice aliasing (intentional but undocumented contract)

**Files:** `server/resolver/recursive_helpers.go:97-104`, `:174-176`, `:200-209`

**Category:** code-quality, safety

**Description:** Multiple return paths alias `response.Ns` and `response.Extra` into `QueryResult` after calling `pool.DefaultMessage.Put(response)`:

```go
// recursive_helpers.go:97-104
nsSlice, extraSlice := response.Ns, response.Extra   // alias
pool.DefaultMessage.Put(response)                     // Put
return &QueryResult{Authority: nsSlice, Additional: extraSlice, ...}  // used after Put
```

The pool `Put` (pool.go:104) deliberately only zeroes the `dns.Msg{}` struct (setting slice headers to nil) without zeroing or reusing the backing arrays. The comment in pool.go explicitly acknowledges this pattern and references `recursive_helpers.go processAnswerWithDNSSEC`.

**Risk:** While safe today due to the specific pool zeroing strategy (only slice headers, not backing arrays), this inverts the `never read after Put` principle from CLAUDE.md. A future change to the pool implementation that reuses backing arrays (e.g., `answer[:0]` instead of `answer = nil`) would silently corrupt `QueryResult.Answer/Authority/Additional`.

In contrast, `collectBestNSMatch` (recursive_helpers.go:46-49) correctly deep-copies before Put, creating an inconsistency.

**Fix:** Either deep-copy in all paths (consistent with `collectBestNSMatch`), or add an explicit `//nolint:sa6002 // intentional: pool only zeroes headers` at each alias site to document the dependency.

---

### M3 — Context.Background() fallback in probe paths may leak goroutines

**File:** `server/resolver/probe/probe.go:144-145`, `:182`

**Category:** context-propagation, goroutine-lifecycle

**Description:** Both `Prober.probeAndReorder` and `ProbeNSAddrs` fall back to `context.Background()` when the provided context is nil:

```go
if ctx == nil {
    ctx = context.Background()
}
```

`context.Background()` has no cancellation or timeout. If the probe engine blocks or stalls (e.g., on a UDP socket that never responds), the goroutine runs indefinitely. In `ProbeNSAddrs` (line 227-229), a `context.WithTimeout` is layered on top when `ctx` is non-nil, but the Background() fallback bypasses this timeout.

**Failure scenario:** A DNS server sends a SYN-ACK but never sends data, or the path MTU causes fragmentation. The UDP probe hangs until kernel timeout (~30-120s depending on platform), and the probing goroutine cannot be externally cancelled.

**Fix:** Use `context.WithTimeout(context.Background(), config.DefaultNSProbeTimeout)` instead of bare `context.Background()`:

```go
if ctx == nil {
    var cancel context.CancelFunc
    ctx, cancel = context.WithTimeout(context.Background(), config.DefaultNSProbeTimeout)
    defer cancel()
}
```

---

### M4 — `probeTLDForPoison` only probes the first TLD server

**File:** `server/resolver/recursive.go:260`

**Category:** performance, correctness

**Description:** The function `probeTLDForPoison` (called at authoritative zone resolution to detect GFW injection) sends a probe to `tldServers[0]` only. If that single TLD server is unreachable, slow, or has a transient issue, the probe fails silently and no TCP fallback is triggered:

```go
server := &config.UpstreamServer{
    Address:  tldServers[0],            // single server
    Protocol: config.ProtoUDP,
    Proxy:    r.resolver.recursiveProxyURL,
}
```

**Failure scenario:** TLD servers `["a.gtld-servers.net", "b.gtld-servers.net"]` are available, but `a.gtld-servers.net` is overloaded or packet lossy. `probeTLDForPoison` returns false, the authoritative query proceeds over UDP, and a GFW-injected response is accepted.

**Fix:** Iterate over `tldServers` with a short timeout per server, returning true if any probe is positive.

---

### M5 — Unbounded `rootHints` map panic risk in high-cardinality parsing

**File:** `server/resolver/root_hints.go:82-93`

**Category:** panic-detection, memory-safety

**Description:** The `loadRootHintsFromFile` function builds maps (`nsNames`, `aRecords`) from a BIND zone file without any size cap. A malformed or malicious named.root file with millions of records could cause OOM. While the file comes from a trusted source (IANA internic.net), the `strings.SplitSeq` over the entire file content also buffers the full file in memory.

**Risk:** Low in practice (IANA's named.root is well-formed and small). But the function lacks any input validation or size bounds.

**Fix:** Add a maximum record count limit (e.g., 500 NS records, 2000 A/AAAA records) and reject files exceeding these bounds.

---

## LOW Findings

### L6 — `recordDNSSECFailure` naming inconsistency

**File:** `server/resolver/dnssec_chain.go:443-452`

**Category:** code-quality, documentation

**Description:** The function named `recordDNSSECFailure` has dual responsibilities: (1) recording the EDE code into `lastDNSSECEDECode`, and (2) determining whether to reject the response based on `DNSSECEnforce`. When `DNSSECEnforce` is false, the function records the EDE code but returns nil (no error and no explicit record of the action taken). The name implies only recording, but the function also controls enforcement.

**Fix:** Rename to `handleDNSSECValidationResult` or split into `recordEDECode` + `shouldRejectBogus`.

---

### L7 — `root_hints.go` file parsing uses deprecated zone tokenizer

**File:** `server/resolver/root_hints.go:77`

**Category:** code-quality, performance

**Description:** The parser uses `dns.New(line)` for each line of the zone file. This creates a full DNS record parser for every line, including lines that are blank or comments (skipped at line 74-75 but after `strings.SplitSeq` has already allocated). A `dns.Token`-based parser would be more efficient and idiomatic for zone file parsing.

**Fix:** Use `dns.ParseZone()` reader pattern instead of line-by-line `dns.New()`.

---

### L8 — Missing package doc comment in dnssec/

**Files:** `server/resolver/dnssec/crypto.go`, `server/resolver/dnssec/extract.go`, `server/resolver/dnssec/nsec.go`, `server/resolver/dnssec/trust_anchor.go`, `server/resolver/dnssec/validate.go`

**Category:** documentation

**Description:** None of the five files in the `dnssec` package have a package-level doc comment. The adjacent `probe` package has one (`probe.go:1-2`), and the `resolver` package has one (`resolver.go:1-2`). Per Go conventions, at least one file in the package should contain a `// Package dnssec ...` comment.

**Fix:** Add a package doc comment to one file, e.g., `crypto.go`:
```go
// Package dnssec provides DNSSEC record extraction, cryptographic validation,
// NSEC/NSEC3 denial-of-existence proofs, and trust-anchor management.
```

---

### L9 — ValidateNODATAWithNSEC accesses Crypto without nil guard

**File:** `server/resolver/recursive_helpers.go:117`

**Category:** safety

**Description:** `r.resolver.validator.Crypto.IsResponseValid(response, ...)` is called without guarding on `validator.Crypto == nil`. Currently safe because `ensureZoneDNSKEYs` (called on line 114) returns early when crypto is nil, leaving `chain.zoneDNSKEYs` empty, and the call on line 116 only executes when `len(chain.zoneDNSKEYs) > 0`. However, this is a fragile invariant — a code change that sets `zoneDNSKEYs` via another path (e.g., direct assignment) would introduce a nil pointer panic.

**Fix:** Add `if r.resolver.validator.Crypto == nil { return validated }` at the top of `validateNODATAWithNSEC`.

---

### L10 — No SOA-based terminal detection for non-referral responses

**File:** `server/resolver/recursive.go`, loop body (lines 118-243)

**Category:** RFC-consistency, correctness

**Description:** The delegation loop checks for NS records (referral) and answer records (final answer) but does not explicitly handle the terminal case where a response has SOA in Authority (NXDOMAIN or NODATA with SOA). The current flow works because `collectBestNSMatch` finds no NS records and returns a terminal result with Authority/Additional slices. But the logic is implicit: when no NS records exist and no answer records exist, the response (including SOA in Authority) is returned as-is via the `len(nsResult.addrs) == 0` path at line 228-232. This could produce slightly confusing behavior if a response has both SOA and NS records (CNAME chase fails).

**Fix:** Add explicit SOA detection to produce better error messages and more predictable behavior.

---

### L11 — `minimiseSteps` counter could overflow

**File:** `server/resolver/qname_minimise.go:65-109`

**Category:** code-quality

**Description:** The `minimiseSteps` counter (int, passed by value) is bounded only by the recursion depth in practice. If a pathological delegation chain triggers many minimisation steps, the counter could become very large. The `labelsToAdd` function would eventually saturate (returning `remainingLabels` when `stepsTaken >= minimisationCount`). No functional impact, but the parameter could be `uint16` with a cap.

**Fix:** Add an explicit cap in the loop body: `if minimiseSteps > 1000 { minimiseSteps = config.DefaultQnameMinimiseCount }`.

---

### L12 — Root-hint cold-start writes empty DNSKEY entries on first cache miss

**File:** `server/resolver/ns_addresses.go:93`

**Category:** performance

**Description:** When `getRootServers()` runs on cold start and the cache returns empty for a root name (line 90-92), it calls `cacheRootHint`. If the root name has no addresses (shouldn't happen for valid named.root, but possible with a corrupted file), it writes empty TypeA/TypeAAAA entries to the cache. On subsequent calls, the empty cache entry prevents the fallback to `allRootAddrs()`.

**Fix:** Guard `cacheRootHint` on non-empty `addrs`:

```go
if len(cached) == 0 && len(addrs) > 0 {
    cacheRootHint(r.cache, name, addrs)
    ...
}
```

---

### L13 — `CapValidatedTTL` allocates a temporary slice each call

**File:** `server/resolver/dnssec/nsec.go:235`

**Category:** performance

**Description:** `for _, sections := range [][]dns.RR{answer, authority, additional}` creates a 3-element heap-allocated slice literal on every call. This function is called during DNSSEC validation, which is off the critical path, but the allocation is gratuitous.

**Fix:** Use a manually-inlined loop for the three sections instead of the slice literal.

---

## Cross-Dimension Summary

| Dimension | Findings |
|-----------|----------|
| 1. Code quality (dead/redundant/duplicate/inefficient) | L6, L7, L10, L11, L12, L13 |
| 2. Memory safety (leaks, unbounded growth, sync.Pool misuse) | M2, M5 |
| 3. Lock correctness (data race, deadlock, ordering) | None |
| 4. Coupling (import violations, unnecessary dependencies) | None |
| 5. Architecture design (god package, naming, type aliases) | L6, L8 |
| 6. Performance (QPS bottleneck, allocation hotspots) | L13 |
| 7. Panic detection (nil deref, bounds, map write, use-after-Put) | M1, M2, M5, L9 |
| 8. Error handling (%w chain, errors.Is/As, sentinel) | None |
| 9. Context propagation (first param, cancel, Background/TODO) | M3 |
| 10. Goroutine lifecycle (HandlePanic, owner, cancel, errgroup) | M3, M4 |
| 11. Resource lifecycle (Close idempotency, New/Close symmetry) | None |
| 12. Log quality (level, spam, context completeness) | None |
| 13. Documentation quality (godoc, comment accuracy) | L6, L8 |
| 14. Parameter validation (nil/empty/zero, ParseIP nil, _ discard) | M1, L9 |
| 15. Constant extraction (magic numbers, RFC values, cross-package dup) | None |
| 16. RFC consistency | L10 |
| 17. Function ordering (decorder) | None (CONFIRMED: all files follow type→const→var→func) |
| 18. BadgerDB storage (TTL, WriteBatch, key encoding, prefix scan) | Not applicable (no direct DB access in resolver) |

## Files NOT Reviewed (Test Files)

All non-test .go files were audited. Test files are excluded by request.

---

**Bottom line:** The resolver packages are production-quality with thorough defensive coding. The most actionable finding is M1 (nil detector panic under specific misconfiguration). All other findings are either documentation improvements or theoretical fragility that would require additional changes in other packages to manifest.