# Round 3 Audit: Resolver Layer

**Audit date:** 2026-07-25
**Scope:** `server/resolver/` (forward, recursive, nameserver, ns_addresses, zonecut, qname_minimise, dnssec, probe)
**Audit dimensions:** Code quality, memory safety, lock correctness, coupling, architecture, performance, panic detection

---

## Finding R3-RES-01: `activeConnections` atomic is write-only dead code in `queryNameserversConcurrent`

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` lines 39, 60-61
**Severity:** LOW
**Category:** dead-code
**Component:** `queryNameserversConcurrent`

### Problem
The `activeConnections atomic.Int32` at line 39 is incremented (`Add(1)`) at line 60 and decremented (`Add(-1)`) at line 61, but its value is never loaded or read anywhere in this function. The atomic operations consume CPU cache-line contention on every goroutine entry/exit for zero observable effect. A sibling function `processUpstreamResponse` in `forward.go` uses `activeConnections.Load()` for debug logging (line 274), confirming this was intended for similar use, but the nameserver.go variant is incomplete.

### Risk if unfixed
Unnecessary atomic operations on a shared cache line, but negligible in practice. Primarily a code-quality signal.

### Fix
Remove the `activeConnections` variable and its `Add` calls, or add a `defer` log statement that reads it (matching forward.go).

---

## Finding R3-RES-02: CryptoValidator nil check inconsistency — recursive loop may NPD

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive.go` line 88 (guarded) vs `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec_chain.go` line 29 (unguarded)
**Severity:** MEDIUM
**Category:** panic
**Component:** `Recursive.resolve`, `isValidWithDNSSEC`

### Problem
The root-domain query path at `recursive.go` line 87-90 guards `crypto` with a nil check before calling `crypto.RootKeys()`, but the main recursive loop at line 163 calls `r.isValidWithDNSSEC(response, currentDomain, chain)` unconditionally. Inside `isValidWithDNSSEC` at `dnssec_chain.go` line 29, `crypto := r.resolver.validator.Crypto` is used without nil check at lines 36, 52, 59, 70, 76 — any of these panics if `Crypto` is nil.

In production, `CryptoValidator` is always constructed in `server.New()`, so this never fires. However, the inconsistent guard creates a latent nil-pointer dereference path that a refactor could trigger (e.g., conditional DNSSEC initialization).

### Risk if unfixed
Panic if `Config.Crypto` is nil and a recursive query enters the delegation loop (non-root domain). The root path would also panic, so the NPD merely depends on which path is exercised first.

### Fix
Either guard `isValidWithDNSSEC` with a nil return at its entry, or ensure all callers check before calling. Since the production invariant is that Crypto is always set, a panic-recover guard is over-engineering — simply document the invariant and add a defensive nil-check + debug log:

```go
func (r *Recursive) isValidWithDNSSEC(...) bool {
    if r.resolver.validator.Crypto == nil {
        return false
    }
    ...
}
```

---

## Finding R3-RES-03: NXDOMAIN+CNAME heuristic treats nil `dns.RR` entry as non-alias (false poison flag)

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` lines 92-98
**Severity:** LOW
**Category:** defense / panic
**Component:** `queryNameserversConcurrent`

### Problem
When a non-authoritative NXDOMAIN response contains a nil entry in the Answer section, the type-switch at line 93:

```go
for _, rr := range result.Response.Answer {
    switch rr.(type) {
    case *dns.CNAME, *dns.DNAME:
    default:
        hasNonAlias = true
    }
}
```

matches `nil` against the `default` arm, setting `hasNonAlias = true`. This causes a legitimate response (e.g., an NXDOMAIN with a CNAME chain where one empty RR was produced by truncation or parsing) to be incorrectly flagged as poison.

### Risk if unfixed
False-positive poison detection on uncommon but valid responses, causing a spurious TCP fallback or record loss. The impact is bounded because the primary NXDOMAIN defense is deferral (NOERROR always wins), and this check only triggers when AA=0.

### Fix
Skip nil RRs explicitly:

```go
for _, rr := range result.Response.Answer {
    if rr == nil {
        continue
    }
    switch rr.(type) {
```

---

## Finding R3-RES-04: FORMERR retry path accepts unvalidated response when poisonguard is disabled

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` lines 149-153, 382-391
**Severity:** MEDIUM
**Category:** defense
**Component:** `retryWithoutEDNS`

### Problem
When a nameserver returns FORMERR, the resolver retries without EDNS options per RFC 6891 Section 6.2.2. The retry response is sent to `resultChan` and calls `cancel()`, which cancels all other outstanding queries. The only validation on the retry response is:

```go
if r.poisonguard {
    v := detector.Validate(currentDomain, normalizedQname, retryResult.Response)
    if v == defense.VerdictPoisoned {
        ...
    }
}
```

When `r.poisonguard` is `false` (the default for most deployments), the retry response bypasses ALL validation. An on-path attacker can:
1. Send a FORMERR to the recursive resolver
2. When the resolver retries without EDNS, inject a spoofed response
3. The response is accepted as valid and sent to `resultChan`

The `retryWithouEDNS` function also uses `context.CancelFunc` (line 355), not `CancelCauseFunc`, so the cancellation reason is lost — the errgroup returns a generic "context canceled" error rather than a diagnostic.

### Risk if unfixed
On-path attacker can inject arbitrary DNS responses when the resolver encounters a FORMERR from the legitimate server and poisonguard is disabled.

### Fix
Either:
- Enable poisonguard by default for the recursive resolver, or
- Add a minimal validation gate (at minimum, check that the response's question matches the query + rcode is plausible) even when poisonguard is disabled, or
- Do not call `cancel()` in `retryWithoutEDNS` — let the retry result compete with other responses through `resultChan` without prematurely terminating peer queries.

The last option is the safest: remove `cancel()` from `retryWithoutEDNS` and let the normal first-wins logic apply.

---

## Finding R3-RES-05: `resolveNextNameservers` may undercount addresses when cache has partial results

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive_ns.go` lines 38-57
**Severity:** MEDIUM
**Category:** recursive
**Component:** `resolveNextNameservers`

### Problem
The function first checks the cache for all NS names at line 39-56. If ANY NS name has cached addresses, `len(result.addrs) > 0` at line 54 short-circuits the glue/extraction fallback at line 61-77:

```go
if len(result.addrs) == 0 {  // line 61
    // fall back to glue records
}
```

This means: if NS1.example.com has cached addresses but NS2.example.com and NS3.example.com do not, only NS1's addresses are used. NS2 and NS3 are silently dropped, even though their addresses could be extracted from the referral glue or resolved independently.

This causes missed delegation targets and potentially incomplete resolution (if the cached NS fails but other NS names were available).

### Risk if unfixed
Partial NS address set causes unnecessary query failures when the cached nameserver is unreachable but glue/resolved addresses for other NS names would succeed. In the worst case, all cached addresses fail and the delegation is lost even though other nameservers exist.

### Fix
Track which NS names have cache hits and which need fallback. Merge glue/resolved addresses for NS names that were NOT satisfied by cache, rather than bailing on the first cache hit. For example:

```go
var result resolvedNSAddrs
missing := make([]*dns.NS, 0, len(bestNSRecords))
for _, ns := range bestNSRecords {
    nsName := dnsutil.Fqdn(ns.Ns)
    cached := r.lookupNSAddrsFromCache(nsName, nil)
    if len(cached) > 0 {
        result.addrs = append(result.addrs, cached...)
    } else {
        missing = append(missing, ns)
    }
}
// Then fall back to glue for missing NS names
```

---

## Finding R3-RES-06: `tryRRSIGRetry` replaces response sections under pooled retry references — subtle lifecycle coupling

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec_chain.go` lines 359-361
**Severity:** LOW
**Category:** memory-safety
**Component:** `tryRRSIGRetry`

### Problem
When an RRSIG validation fails with `ErrMissingRRSIG`, the resolver retries the query against a different authoritative server. If the retry succeeds, the function replaces the original response's sections with the retry response's sections:

```go
response.Answer = retryResp.Answer
response.Ns = retryResp.Ns
response.Extra = retryResp.Extra
return true
```

Then `defer pool.DefaultMessage.Put(retryResp)` (line 350) zeros the `retryResp` struct and returns it to the pool. The original `response` continues to reference the same backing arrays through the copied slice headers. The pool's `Put()` zeroes the struct (`*msg = dns.Msg{}`) — the backing arrays are separate heap allocations and are NOT freed. The caller's `response` still has valid slice references.

**Analysis: This is safe.** The backing arrays remain alive because `response.Answer` (etc.) still reference them. The pool zeroes only the struct fields, not the backing arrays. No use-after-free occurs.

However, the lifecycle coupling is fragile: if a future change adds backing-array pooling for `[]dns.RR` inside the pool or the upstream client, the `response` would silently hold dangling references.

### Risk if unfixed
None under current pool implementation. Future pool changes could silently break this code.

### Fix
Copy the RR slices explicitly before disposing of `retryResp`:

```go
response.Answer = append([]dns.RR(nil), retryResp.Answer...)
response.Ns = append([]dns.RR(nil), retryResp.Ns...)
response.Extra = append([]dns.RR(nil), retryResp.Extra...)
```

This allocates new backing arrays and decouples the response from the retry lifecycle. The three small allocations per RRSIG-retry event are negligible.

---

## Finding R3-RES-07: DNSKEY cache TTL uses minimum across all keys — short-TTL key penalises all keys

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec/extract.go` lines 140-145
**Severity:** LOW
**Category:** inefficiency
**Component:** `CacheZoneKeys`

### Problem
When caching DNSKEYs for a zone, the TTL is computed as the minimum non-zero TTL across all DNSKEY records:

```go
ttl := config.DefaultDNSKeyCacheTTL
for _, k := range keys {
    if k != nil && int(k.Header().TTL) > 0 && int(k.Header().TTL) < ttl {
        ttl = int(k.Header().TTL)
    }
}
```

A single DNSKEY with a short TTL (e.g., 60 seconds in preparation for a roll) reduces the cache lifetime for all DNSKEYs, including the long-lived KSK. This forces the resolver to re-query DNSKEYs more frequently than necessary, increasing resolution latency and load on authoritative servers.

### Risk if unfixed
Increased DNSKEY query rate during key rollover periods. The resolver re-fetches the full DNSKEY RRset every time the shortest-TTL key expires.

### Fix
Use the maximum TTL (or a percentile like the 75th percentile) instead of the minimum. The short-TTL key's expiration doesn't invalidate the longer-lived keys; the cache entry as a whole should reflect the zone's intended refresh rate:

```go
var maxTTL int
for _, k := range keys {
    if k != nil && int(k.Header().TTL) > maxTTL {
        maxTTL = int(k.Header().TTL)
    }
}
if maxTTL == 0 {
    maxTTL = config.DefaultDNSKeyCacheTTL
}
```

---

## Finding R3-RES-08: `zoneCutDetected` state persists across delegation levels, but is effectively benign

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec_chain.go` line 24 (decl), line 328 (set), `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive_helpers.go` line 148 (check), line 149 (clear)
**Severity:** LOW
**Category:** recursive
**Component:** `dnssecChain`

### Problem
The `zoneCutDetected` field on `dnssecChain` is set to `true` at `dnssec_chain.go` line 328 (in `validateOrRetry`) and cleared to `false` at `recursive_helpers.go` line 149 (in `processAnswerWithDNSSEC`). It is not cleared at the start of each loop iteration in `Recursive.resolve`.

If `validateOrRetry` sets `zoneCutDetected = true` but the next call to `processAnswerWithDNSSEC` returns `nil` (at line 142-143 because `len(response.Answer) == 0`), the flag persists into the next delegation level. However, `processAnswerWithDNSSEC` returns `nil` before reaching the `zoneCutDetected` check at line 148, so a stale flag does not affect behavior in the current iteration. It could affect a SUBSEQUENT iteration where the response DOES have answer records — but at that point the flag was either already cleared (by the previous iteration's clear at line 149) or is being set by the current iteration's `validateOrRetry` call.

**Analysis: The lifecycle is currently correct**, but it is non-obvious and fragile. A future refactoring that reorders the checks could easily introduce a stale-flag bug.

### Risk if unfixed
Code maintenance hazard. No runtime impact in the current code.

### Fix
Clear `zoneCutDetected` at the start of each loop iteration in `Recursive.resolve` (recursive.go around line 114), making the state explicitly scoped to a single iteration:

```go
for {
    chain.zoneCutDetected = false
    select {
    case <-ctx.Done():
        ...
    }
    ...
}
```

---

## Finding R3-RES-09: NXDOMAIN+CNAME heuristic may reject legitimate non-authoritative multi-type answers

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` lines 80-98
**Severity:** LOW
**Category:** defense
**Component:** `queryNameserversConcurrent`

### Problem
The heuristic at lines 80-98 rejects NXDOMAIN responses with non-CNAME/DNAME answer records when the AA flag is absent. This is intended to catch GFW-style injection, but it also rejects legitimate NXDOMAIN responses where an authoritative server returns answer records without setting AA (a configuration error on the server side, but valid per the DNS protocol).

### Risk if unfixed
False rejections on misconfigured but otherwise legitimate servers. The impact is bounded because the NXDOMAIN deferral mechanism (line 127-146) provides the primary defense, and the AA=0 check is a secondary heuristic.

### Fix
The existing comment at lines 85-87 acknowledges this limitation. This is an accepted design tradeoff. The key is that the comment correctly identifies it as insufficient — no code change needed. However, the check could be gated by `r.poisonguard` to only apply when poisonguard is active:

```go
if rcode == dns.RcodeNameError && r.poisonguard && len(result.Response.Answer) > 0 && !result.Response.Authoritative {
```

---

## Finding R3-RES-10: NS address cache entries are never explicitly re-resolved, only latency-probed

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/ns_addresses.go` lines 116-137, 143-159
**Severity:** LOW
**Category:** recursive / memory
**Component:** `lookupNSAddrsFromCache`

### Problem
When cached NS addresses expire or approach expiration, `lookupCachedRRs` returns `needsRefresh=true` which triggers the caller to launch a background latency probe (`probe.ProbeNSAddrs`). However, this probe only measures network latency — it does NOT re-resolve the NS name's A/AAAA records. If a nameserver's IP address has changed, the resolver continues to use the stale cached address until the cache entry is evicted by TTL expiration and a fresh resolution happens on the next cache miss.

For root hints, the `refreshEntry` callback re-writes entries from the hardcoded hints, but for regular NS names learned from delegation responses, `refreshEntry` is `nil` and no re-resolution occurs.

### Risk if unfixed
The resolver may use stale NS addresses for up to the DNSKEY cache TTL (or until the next full resolution of that NS name). In the worst case, a nameserver that changes its glue addresses is unreachable until the cache entry expires naturally.

### Fix
Add a conditional re-resolution trigger in the `needsRefresh` path: when a cached NS address entry is expired or within the prefetch window, enqueue a background DNS query for the NS name (TypeA/TypeAAAA) in addition to the latency probe. This matches the pattern used for regular A/AAAA records in the cache middleware.

---

## Finding R3-RES-11: CNAME resolver re-walks from root for every CNAME target

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive.go` line 302 (in `CNAME.resolve`)
**Severity:** LOW
**Category:** inefficiency
**Component:** `CNAME.resolve`

### Problem
Each CNAME chain target is resolved via a fresh call to `c.resolver.recursive.resolve(ctx, currentQuestion, ecs, 0, forceTCP)` with `depth=0`, starting the recursive walk from the root. If a CNAME target shares the same zone hierarchy as the original query (e.g., `www.example.com` CNAME `cdn.example.com`), the resolver re-queries root, TLD, and zone servers — all of which were just contacted for the original name.

For chains of 3-5 CNAMEs (the typical maximum), this multiplies the query cost by the chain length, even when the targets are in the same zone.

### Risk if unfixed
Increased resolution latency and load on root/TLD servers for CNAME chains.

### Fix
The current architecture makes cross-zone caching of delegation state complex. A lightweight fix: try the previous iteration's authoritative nameservers first (before going to root) when the CNAME target is in the same zone. This is a moderate refactor. Alternatively, note this as a known limitation in the architecture docs.

---

## Finding R3-RES-12: Error context lost in `queryNameserversConcurrent` return

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` lines 201-202
**Severity:** LOW
**Category:** inefficiency (observability)
**Component:** `queryNameserversConcurrent`

### Problem
When all nameservers fail, the error at line 202 is a generic "no successful response":

```go
return nil, verdict, errors.New("no successful response")
```

The root cause (timeout, connection refused, FORMERR, SERVFAIL) is only available in debug logs, not in the returned error. At `recursive.go` line 157-159, this error is wrapped as:

```go
return QueryResult{Cacheable: true, Poisoned: poisonSeen, Err: fmt.Errorf("query %s: %w", currentDomain, err)}
```

The caller sees "query example.com: no successful response" which does not convey why the resolution failed.

### Risk if unfixed
Operational difficulty diagnosing resolution failures. The error surfaces to the client as a SERVFAIL with no diagnostic subcode.

### Fix
Collect the first non-nil error from the errgroup and include it in the returned error:

```go
var firstErr atomic.Pointer[error]
// in each goroutine:
if result.Error != nil {
    firstErr.CompareAndSwap(nil, &result.Error)
}
// in the return path:
return nil, verdict, fmt.Errorf("no successful response: %w", *firstErr.Load())
```

---

## Finding R3-RES-13: `pending.Group` in probe.go never removes completed keys on error-free early return

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/probe/probe.go` lines 216-221
**Severity:** LOW
**Category:** memory
**Component:** `ProbeNSAddrs`

### Problem
The `nsPending.Start(key)` / `nsPending.Done(key)` pairing is correct when the probe proceeds past the deduplication gate. However, the `p.Pending` (Prober-internal) uses `p.pending.Start` / `p.pending.Done` and the NS variant uses `nsPending`. Both correctly defer `Done`. However, if the function takes a very early return (e.g., `key` duplicate), `Done` is NOT called — and shouldn't be, because `Start` returned false. Correct.

**Wait — re-read.** The `lsPending` (Prober) at lines 124-126:
```go
if !p.pending.Start(key) {
    log.Debugf(...)
    return
}
```
This skips `Done` when `Start` returns false. Correct. Then at line 132:
```go
p.bgGroup(func() error {
    defer p.pending.Done(key)
    ...
})
```
`Done` is deferred inside the background goroutine, so it's always called after the probe completes. Correct.

For `nsPending` at lines 217-221:
```go
if !nsPending.Start(key) {
    return
}
defer nsPending.Done(key)
```
`Done` is deferred after a successful `Start`. Correct.

**Analysis: No leak.** The `pending.Group` only holds map entries for keys whose `Start` returned `true`, and each such key has a deferred `Done`. Keys are cleaned up on probe completion.

### Verdict
No issue — this finding is withdrawn upon closer analysis. The pending group lifecycle is correct.

---

## Finding R3-RES-14: `resolveNSAddrType` allocates header-only AAAA records from Additional section without caching

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` lines 426-433
**Severity:** LOW
**Category:** inefficiency
**Component:** `resolveNSAddrType`

### Problem
When resolving A records for a nameserver, the function also collects AAAA records from the Additional section at lines 427-433:

```go
if qtype == dns.TypeA {
    for _, rrec := range qr.Additional {
        if aaaa, ok := rrec.(*dns.AAAA); ok && strings.EqualFold(aaaa.Header().Name, nsName) {
            *nsAddrs = append(*nsAddrs, net.JoinHostPort(...))
        }
    }
}
```

These AAAA glue records are appended to the address list and sent to the callers, but they are NOT returned in the `addrs` return value (only in `*nsAddrs`). The answer records returned by `resolveNSAddrType` are used for caching (lines 285-289 in `resolveNSAddressesConcurrent`). Since the AAAA glue from Additional is not included in the returned answer records, it is not cached. On subsequent queries, the resolver must re-resolve the AAAA records.

### Risk if unfixed
The AAAA addresses from glue are used by the current query but not persisted in the cache. Subsequent queries must re-resolve them, doubling query load for dual-stack NS lookups.

### Fix
Append AAAA glue records to the returned `answer` slice so they are cached:

```go
case *dns.AAAA:
    if strings.EqualFold(aaaa.Header().Name, nsName) {
        *nsAddrs = append(*nsAddrs, ...)
        if qtype == dns.TypeA {
            answer = append(answer, rrec)
        }
    }
```

---

## Finding R3-RES-15: `ShuffleSlice` modifies input slice in-place — no defensive copy at one call site

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` line 335
**Severity:** LOW
**Category:** code-quality
**Component:** `resolveNSAddressesConcurrent`

### Problem
At `nameserver.go` line 335, `ShuffleSlice(allAddresses)` is called under `allMu` lock. The slice is local to the function and is not shared, so the mutation is safe. However, at `forward.go` lines 30-33:

```go
shuffled := make([]*config.UpstreamServer, len(servers))
copy(shuffled, servers)
ShuffleSlice(shuffled)
```

The forward.go call site correctly copies before shuffling. The nameserver.go call site does not need a copy because `allAddresses` is a local. **No bug here.**

### Verdict
No issue — the slice ownership is correctly local at that point. Removed from findings.

---

## Summary

| ID | Severity | Category | File | Issue |
|----|----------|----------|------|-------|
| R3-RES-01 | LOW | dead-code | nameserver.go:39,60-61 | `activeConnections` write-only in `queryNameserversConcurrent` |
| R3-RES-02 | MEDIUM | panic | recursive.go:88 / dnssec_chain.go:29 | Inconsistent `Crypto` nil guard — loop path panics if nil |
| R3-RES-03 | LOW | defense / panic | nameserver.go:92-98 | Nil RR entry causes false poison detection |
| R3-RES-04 | MEDIUM | defense | nameserver.go:149-153,382-391 | FORMERR retry accepted unvalidated when poisonguard disabled |
| R3-RES-05 | MEDIUM | recursive | recursive_ns.go:38-57 | Partial cache results skip glue fallback for uncached NS names |
| R3-RES-06 | LOW | memory-safety | dnssec_chain.go:359-361 | `tryRRSIGRetry` response slice coupling — safe today, fragile |
| R3-RES-07 | LOW | inefficiency | dnssec/extract.go:140-145 | DNSKEY cache TTL uses minimum across keys |
| R3-RES-08 | LOW | recursive | dnssec_chain.go:24,328 / recursive_helpers.go:148-149 | `zoneCutDetected` not reset across loop iterations |
| R3-RES-09 | LOW | defense | nameserver.go:80-98 | NXDOMAIN+CNAME heuristic always active regardless of poisonguard |
| R3-RES-10 | LOW | recursive | ns_addresses.go:116-159 | Expired NS addresses only get latency probe, not re-resolution |
| R3-RES-11 | LOW | inefficiency | recursive.go:302 | CNAME resolver re-walks from root for each chain target |
| R3-RES-12 | LOW | inefficiency | nameserver.go:201-202 | Generic error message loses root cause |
| R3-RES-14 | LOW | inefficiency | nameserver.go:426-433 | AAAA glue from Additional section not cached |

**Total: 12 findings** (0 CRITICAL, 2 MEDIUM, 10 LOW)

### Summary of Key Risks

1. **Most operationally significant:** Finding R3-RES-04 (FORMERR retry bypasses validation) — an on-path attacker can exploit this to inject responses when poisonguard is disabled. Fix: remove `cancel()` from `retryWithoutEDNS`.

2. **Most architecturally significant:** Finding R3-RES-05 (partial NS cache results skip other NS names) — causes silent loss of failover nameservers when any one NS has cached addresses.

3. **Most latent risk:** Finding R3-RES-02 (inconsistent Crypto nil check) — would cause a hard panic if `CryptoValidator` is ever nil, blocking all recursive resolution.

4. **Most likely to cause operational confusion:** Finding R3-RES-12 (generic error message) — the "no successful response" error provides no diagnostic signal for root cause analysis.

Overall, the resolver layer is well-structured with robust defense mechanisms. The top-priority fix is R3-RES-04 (FORMERR retry) followed by R3-RES-05 (partial NS cache).
