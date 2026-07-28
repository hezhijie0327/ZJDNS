# Resolver Audit: server/resolver/*

## Summary
- Files audited: 17 (resolver + 6 dnssec + 1 probe)
- CRITICAL: 0, HIGH: 2, MEDIUM: 5, LOW: 5, INFO: 3

## Scope

All non-test Go source files under `server/resolver/` and `server/resolver/dnssec/`:

| File | Lines | Purpose |
|------|-------|---------|
| resolver.go | 283 | Core types, Config, New, concurrency limits |
| forward.go | 335 | Upstream forwarding, NXDOMAIN fallback, EDE passthrough, CIDR filtering |
| recursive.go | 374 | Recursive walk, CNAME chasing, TCP fallback via poisonguard |
| recursive_helpers.go | 221 | Zone-cut matching, QNAME minimisation, lame delegation, NSEC NODATA |
| recursive_ns.go | 117 | NS address resolution (cache->glue->independent) |
| nameserver.go | 440 | Concurrent authoritatives, NXDOMAIN deferral, FORMERR retry |
| ns_addresses.go | 162 | Latency-sorted root/NS cache, cache helpers |
| root_hints.go | 109 | named.root parser, once-loader |
| zonecut.go | 182 | Zone cut detection, DS/DNSKEY verification chain |
| qname_minimise.go | 126 | RFC 9156: labels-to-add, proportional distribution |
| dnssec_chain.go | 444 | DNSSEC trust chain, DS verification, offline KSK (RFC 7344 CDS), RRSIG retry |
| dnssec/crypto.go | 300 | Cryptogrphic VerifyRRset, VerifyDelegationDS, IsResponseValid |
| dnssec/extract.go | 186 | CollectRRSIGs, FindDNSKEYs/DS/CDS/NSEC/NSEC3 helpers |
| dnssec/nsec.go | 271 | NSEC/NSEC3 denial-of-existence, ancestor delegation, TTL cap |
| dnssec/trust_anchor.go | 107 | IANA root-anchors.xml parser, RFC 5011 revoke check |
| dnssec/validate.go | 36 | Lightweight AD+record-presence check |
| probe/probe.go | 259 | Latency probing for A/AAAA, NS probe dedup |

---

## Findings

### [HIGH] [Panic检测] resolver.go:162 — Missing nil validation for required Config fields in New

- **Problem**: `Resolver.New` accepts `Config` with several required fields (`EDNS`, `BuildMsg`, `QueryClient`, `Cache`) but never validates they are non-nil. If any of these is nil, the first call to the corresponding method panics:
  - `r.edns.ParseFromDNS()` at forward.go:269 / recursive.go:112,168 (nil EDNS)
  - `r.buildMsg()` at forward.go:89 / nameserver.go:43 (nil BuildMsg)
  - `r.queryClient.ExecuteQuery()` at forward.go:90 / nameserver.go:77 (nil QueryClient)
  - `r.cache.Get/Set` at nameserver.go:41+ / recursive_ns.go:109+ (nil Cache)
- **Risk**: Panic at runtime on first query processed by a misconfigured resolver. The `server.initDNSResolver` always passes valid instances, but the API contract is not enforced at the boundary.
- **Fix**: Add nil checks for `cfg.EDNS`, `cfg.BuildMsg`, `cfg.QueryClient`, and `cfg.Cache` in `New`. Return nil (or better, change `New` to return `(*Resolver, error)` for a clear error message).

### [HIGH] [内存安全] recursive_helpers.go:158,187 — Pooled dns.Msg not Put on DNSSEC enforcement early-return paths

- **Problem**: In `processAnswerWithDNSSEC`, two early-return paths leak the `response *dns.Msg` from the pool:
  1. **Line 162** (`if err := r.recordDNSSECFailure(...); err != nil`): When zone cut resolution succeeds but `recordDNSSECFailure` returns an error (DNSSECEnforce + childDS exists + validation failed), the function returns without `pool.DefaultMessage.Put(response)`.
  2. **Line 187** (`if r.resolver.DNSSECEnforce && chain.lastEDECode != ...`): When a bogus delegation is rejected by DNSSEC enforcement, the function returns without `pool.DefaultMessage.Put(response)`.
- **Risk**: Every DNSSEC-enforced bogus-delegation response leaks one `*dns.Msg` (~hundreds of bytes). In steady-state operation with aggressive DNSSEC enforcement against zones with misconfigured delegations, the leak accumulates across all concurrent queries, degrading pool efficiency and increasing GC pressure.
- **Fix**: Add `pool.DefaultMessage.Put(response)` before both early returns. Prefer `defer`-based cleanup at the function entry instead of manual Put at each exit — refactor to a `defer` pattern that captures a `responseDone` flag.

### [MEDIUM] [参数校验] resolver.go:155-175 — New returns nil on nil Config, forcing nil checks on all consumers

- **Problem**: `New` returns `nil` when `cfg == nil`. The zero-value pattern forces nil-receiver checks on exported methods, but these checks are inconsistently applied:
  - `Recursive()`: nil-check present
  - `DNSSECEDECode()`: nil-check present
  - `UpstreamEDEOption()`: nil-check present
  - `UpstreamServers()`: **no** nil-check — `r.upstream.list()` panics on nil receiver
  - `Query()`: **no** nil-check — `r.upstream.list()` panics on nil receiver
- **Risk**: Inconsistent nil safety. A caller that doesn't check `New`'s return value (or wraps it in a helper that doesn't propagate nil) gets a panic when calling `UpstreamServers()` or `Query()`.
- **Fix**: Either: (a) remove the nil-return pattern and instead have `New` always return a valid resolver with sensible defaults, or (b) add nil-receiver guards to every exported method. Option (a) is preferred — the zero-value Resolver should be safe to use.

### [MEDIUM] [架构设计] forward.go:81-88 — Secure protocol list requires manual sync with config.Protocol

- **Problem**: The `isSecure` detection in `queryUpstream` is a hard-coded list of protocol strings:
  ```go
  isSecure := server.Protocol == config.ProtoTLS ||
      server.Protocol == config.ProtoQUIC || ...
  ```
  The comment reads: "Keep this list in sync with config.Protocol when adding new transports." There is no compile-time assertion or registration mechanism. A new encrypted protocol added to `config.Protocol` but missing from this list would:
  - Not get EDNS padding (passed as `isSecure=false` to `buildMsg`)
  - Still work functionally (falls through to the `default` case)
- **Risk**: EDNS padding disabled for new encrypted protocols until someone manually updates this list.
- **Fix**: Add a protocol-registration function on the config side (e.g., `func IsSecureProtocol(p Protocol) bool`) or define protocol properties in the config package where the protocol constants live.

### [MEDIUM] [Goroutine生命周期] recursive_ns.go:112-114 — Background goroutines capture Recursive resolver pointer

- **Problem**: `cacheGlueRecords` launches background goroutines for NS latency probing:
  ```go
  go func() { probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()
  ```
  These goroutines capture `r.ctx` and `r.cache` from the `*Recursive` receiver. The `*Recursive` is owned by the `*Resolver` which is owned by `*Server`. If the server shuts down, `r.ctx` (the lifecycle context) is cancelled, but the goroutines may still be in-flight. The `r.cache` reference keeps the cache alive.
  - Similarly `ns_addresses.go:94` and `ns_addresses.go:335` fire probes with `r.ctx`.
- **Risk**: During server shutdown, probe goroutines race against `r.cache.Close()`. The cache's `UpdateLatency` and `Set` methods could panic or corrupt state after close.
- **Fix**: These goroutines should check `r.ctx.Done()` before using the cache, or the probe functions should accept the lifecycle context and return early on cancellation. The `ProbeNSAddrs` function already accepts a context parameter — it should use it.

### [MEDIUM] [代码质量] nameserver.go:360 — `cancel` parameter in retryWithoutEDNS is dead code

- **Problem**: The `cancel context.CancelFunc` parameter at `retryWithoutEDNS(nameserver.go:360)` is passed from `queryNameserversConcurrent` (line 152: `r.retryWithoutEDNS(queryCtx, resultChan, cancel, ...)`) but is never called inside `retryWithoutEDNS`. The FORMERR retry never signals cancellation to the errgroup.
- **Risk**: If the FORMERR retry produces the first valid response, other errgroup goroutines continue running unnecessarily. They detect `queryCtx.Done()` only when the parent function returns (with `defer cancel()`). This wastes resources but does not affect correctness.
- **Fix**: Either (a) call `cancel()` after sending the successful retry to `resultChan`, or (b) remove the parameter if cancellation is intentionally deferred to the parent.

### [MEDIUM] [内存安全] recursive_ns.go:108 — Mixed A/AAAA glue records cached under wrong type key

- **Problem**: `cacheGlueRecords` determines the cache key type from `records[0]`:
  ```go
  qtype := dns.RRToType(records[0])
  r.cache.Set(nsName, qtype, dns.ClassINET, nil, false, records, nil, nil, false)
  ```
  But `records` is accumulated from `response.Extra` for a single NS name and may contain both A and AAAA glue. If `records[0]` is A, the AAAA records are stored in the TypeA cache entry. A subsequent `lookupCachedRRs(nsName, TypeAAAA)` finds nothing, but `lookupNSAddrsFromCache` merges both types, so all addresses are still returned.
- **Risk**: Wrong cache type keys for mixed-family glue. Functionally correct due to read-side merging (`lookupNSAddrsFromCache` queries both TypeA and TypeAAAA), but the cache entry has mismatched metadata.
- **Fix**: Separate A and AAAA glue records before caching. Either split in `resolveNextNameservers` or in `cacheGlueRecords`.

### [LOW] [函数排序] recursive_helpers.go:105 — Context parameter not first in validateNODATAWithNSEC

- **Problem**: `validateNODATAWithNSEC(response *dns.Msg, ctx context.Context, ...)` has `ctx` as the second parameter. Go convention and internal style both mandate `ctx` be the first parameter.
- **Fix**: Move `ctx` to the first parameter position.

### [LOW] [性能] forward.go:58-59 — Redundant pointer copy in goroutine closure

- **Problem**:
  ```go
  srv := servers[(startIdx+i)%len(servers)]
  server := srv
  ```
  The second assignment `server := srv` copies a pointer unnecessarily. The range variable shadow pattern already produced a unique local `srv` — `server` adds no value.
- **Fix**: Use `srv` directly in the goroutine closure: `g.Go(func() error { ... server := srv ... }).`

### [LOW] [常量提取] resolver.go:134-138 — dnssecEDEError takes uint64 but immediately narrows to uint16

- **Problem**: `dnssecEDEError(edeCode uint64)` accepts `uint64` but immediately converts to `uint16` (bounded by protocol, OK). All callers cast the argument to `uint64` (e.g., `uint64(opt.InfoCode)`). The signature forces callers to add casts that belong inside the function.
- **Fix**: Accept `uint16` directly. The callers already have the value as `uint16` — the cast to `uint64` is only needed because the parameter expects `uint64`.

### [LOW] [RFC一致性] qname_minimise.go:116-124 — minimisationQtype returns TypeA for meta-types

- **Problem**: `minimisationQtype` returns `dns.TypeA` as the default for any QTYPE not in the DS/NSEC/NSEC3/OPT/TSIG/TKEY/ANY/AXFR/IXFR list. For meta-types like `TypeOPT`, `TypeTSIG`, `TypeTKEY`, this produces a TypeA minimised query instead of rejecting them. In practice these types are rejected by the validation middleware before reaching the resolver, so this path is unreachable in production.
- **Fix**: (Optional) Add an explicit reject list to return `TypeA` only for legitimate data types, or leave as-is since the validation middleware gates these.

### [LOW] [文档质量] recursive.go:40-42 — CNAME struct rationale comment references "same file" but CNAME is in recursive.go, not a separate file

- **Problem**: The comment on `CNAME` struct reads: "Defined in the same file as Recursive because CNAME resolution depends directly on recursive resolution (c.resolve -> r.resolve). Splitting into a separate file would add unnecessary indirection without reducing coupling." This is accurate and clear.
- **Recommendation**: While not incorrect, this is an INFO-level observation — the comment correctly explains the design choice. No change needed.

### [INFO] [架构设计] resolver.go:90-93 — UpstreamClient interface defined in consumer package (correct)

- **Observation**: `UpstreamClient` is defined in `resolver` (the consumer package), not in `upstream` (the producer). This matches the project guideline "Define interfaces in the consumer package, not the producer." Correct.

### [INFO] [性能] nameserver.go:43-45 — baseMsg created once for all concurrent NS queries

- **Observation**: `baseMsg := r.resolver.buildMsg(...)` creates a single template message, and each errgroup goroutine copies it via `baseMsg.Copy()`. This avoids rebuilding the message N times. Good pattern.

### [INFO] [RFC一致性] nameserver.go:128-148 — NXDOMAIN deferral for anti-GFW

- **Observation**: The NXDOMAIN deferral pattern (storing NXDOMAIN as secondary, never cancelling the errgroup on NXDOMAIN) is an intentional anti-GFW measure. GFW can inject fake NXDOMAIN faster than real NOERROR responses, so deferring NXDOMAIN ensures legitimate NOERROR has time to arrive. The pattern is correctly implemented with `atomic.Pointer` CAS and cleanup on NOERROR receipt.

---

## Detailed Analysis

### Memory Safety: Pooled Message Lifecycle

The pool implementation (`internal/pool/pool.go:97-101`) zeroes the struct on Put:
```go
func (m *Message) Put(msg *dns.Msg) {
    *msg = dns.Msg{}  // struct zeroed, but backing arrays survive via other references
    m.pool.Put(msg)
}
```

After careful analysis, **no use-after-Put bugs were found** in the resolver package. When a `*dns.Msg` is Put, the struct's slice headers are zeroed, but any copies of those slice headers held by `QueryResult` or atomic pointers continue to reference the original backing arrays. The backing arrays remain alive for GC purposes. This is safe.

The two memory leak findings (HIGH) are the only memory-related issues — they fail to Put at all, not misuse-after-Put.

### Concurrency Safety

- `errgroup`-based concurrent NS/upstream queries: Correct. First-wins pattern with `resultChan` (buffered, cap=1). NXDOMAIN deferred via `atomic.Pointer`. FORMERR retry via `retryWithoutEDNS`.
- `upstreamSet` uses `atomic.Pointer` for server list. Snapshot semantics: `list()` returns a slice value (header copy), so concurrent `store()` does not affect in-flight queries.
- `lastDNSSECEDECode` / `lastUpstreamEDE`: Atomic stores. Correct.
- QNAME minimisation steps: Local integer on the resolve stack, not shared.
- Root hints: `sync.Once` for lazy loading. Correct.

### Recursive Walk

- **Max depth**: `config.DefaultMaxRecursionDepth = 16`. Checked at `resolve` entry (recursive.go:56). Depth incremented for NS address sub-resolutions. Correct.
- **Zone cut detection**: RRSIG signer-name comparison in `getZoneCutSigner`. Cross-zone records stripped by `stripCrossZoneRecords`. Correct.
- **Lame delegation**: Detected when `bestMatch == currentDomain` and response is non-authoritative with empty answer. Correct.
- **Glue validation**: Glue records accepted from `response.Extra` only if their owner name is below the parent zone (recursive_ns.go:78: `dnsutil.IsBelow(fqParDom, rrecNameFq)`). Correct.
- **NXDOMAIN cut (RFC 8020)**: Handled at recursive.go:182 — minimised NXDOMAIN exposes full QNAME. Correct.
- **FORMERR retry (RFC 6891 §6.2.2)**: Implemented in `retryWithoutEDNS`. Creates bare query without EDNS options. Validates retry response with poison guard. Correct.

### DNSSEC

- **Chain of trust**: Built correctly through `dnssecChain` — parent DNSKEYs -> DS RRSIG -> child DNSKEYs -> answer RRSIGs.
- **Zone cut verification**: `resolveZoneCut` queries DS + DNSKEY for the child zone, verifies DS RRSIG against parent DNSKEYs, verifies DNSKEY self-signature via DS match. Supports offline KSK (RFC 7344) via CDS query.
- **NSEC/NSEC3**: Full denial-of-existence verification (RFC 4035 §3.1.3, RFC 6840 §4.1/§4.3, RFC 5155 §9.2). Ancestor delegation NSEC/NSEC3 correctly excluded.
- **RRSIG retry**: Single retry for missing RRSIGs (`tryRRSIGRetry`). Does not retry on bogus signatures.
- **Trust anchors**: IANA root-anchors.xml parser. RFC 5011 §2.1 revoke flag checked. Expiration validated.

### QNAME Minimisation (RFC 9156)

- **Algorithm**: Proportional distribution after `DefaultMinimiseOneLabel` single-label steps. `DefaultQnameMinimiseCount = 10` steps max. Correct per RFC 9156 §2.3.
- **Fallback**: Full QNAME exposed when minimised query returns NXDOMAIN or non-matching answer. Correct per RFC 9156 §2.3.
- **QTYPE**: `TypeA` for most queries except DS/NSEC/NSEC3/OPT/TSIG/TKEY/ANY/AXFR/IXFR (RFC 9156 §2.1). Correct.

### Error Handling

- Wrapping: Inconsistent. Some errors use `fmt.Errorf("...: %w", err)` (good), others use `errors.New("...")` or `fmt.Errorf("...")` without wrapping. The `ErrCIDRFilterRefused` sentinel error is used with `errors.Is` — correct.
- `DNSSECError` struct does not implement `Is()`/`Unwrap()`, so `errors.Is(err, DNSSECError{...})` never matches. But callers only check `err != nil`, so this is safe.
- EDE codes from upstream SERVFAIL are captured and propagated via `lastUpstreamEDE`.

### Context Propagation

- All I/O-bound functions take `ctx` as first parameter (except `validateNODATAWithNSEC` — noted as LOW finding).
- `resolve` checks `ctx.Done()` on each delegation loop iteration.
- `queryNameserversConcurrent` creates two-level context: `deadlineCtx` (with timeout) and `queryCtx` (cancellable for first-wins). Correct.
- `probeTLDForPoison` creates its own timeout context. Correct.
- `retryWithoutEDNS` creates its own timeout context. Correct.

### Logging

- All logs use RECURSION, SECURITY, or UPSTREAM canonical prefixes (matching CLAUDE.md guidelines).
- All hot-path logs are `Debugf` — no info/warn/error on normal-resolution hot paths.
- DNSSEC validation details logged at Debug level only.
- Log quality is excellent throughout.
