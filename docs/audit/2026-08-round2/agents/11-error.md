# error 审计

> agent: `a2433faf7edbc9778`

发现数: 9

## errc-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get() reads pre-packed BLOB TTL-offset table without checking the 0x02 format marker — pre-upgrade cache entries (plain zstd blob) cause a slice-bounds panic on every lookup
- **描述**: New pre-packed Get() (commit ba1f78c/b5f91ff) does `numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))` with no `msgWire[0] == cacheFormatPrePacked` guard. Entries written by any version before v3.11.9 stored `msgWire := zdnsutil.Compress(msg.Data)` — a raw zstd frame, no marker. For such rows msgWire[0]=0x28 (zstd magic) and msgWire[1:3]=0xB5 0x2F → numOffsets=46383; the loop `offsets[i] = binary.BigEndian.Uint16(msgWire[3+i*2:])` (line 270) then slices far past the blob → runtime slice-bounds panic, recovered only by HandlePanic at the protocol layer, dropping the query. There is no DB migration (database.Version never assigned — H8) and no startup flush, so old rows survive the upgrade; every query hitting one panics until the entry is evicted (up to DefaultMaxCacheableTTL=7 days). The isZstdCompressed() compatibility comment (line 109) shows the developer intended old-format compatibility but the offset table is parsed before any format discrimination.
- **风险**: Upgrade crash: any DNS query served from a pre-v3.11.9 cache DB panics per request (request dropped, stack-trace spam), until old entries expire. Deterministic for every old-format entry since the zstd magic bytes are fixed.
- **修复**: In Get(), before reading msgWire[1:3]: `if len(msgWire) < 3 || msgWire[0] != cacheFormatPrePacked { ... }` — handle legacy format as a plain zstd blob (decompress + unpack as the old Get did) or return a miss with a one-time Warn; alternatively add a startup migration that rewrites or clears legacy rows.

## errc-02 — HIGH

- **位置**: `server/handler/middleware/chain.go:141`
- **类别**: ordering
- **摘要**: MQTYPE middleware is wrapped INSIDE CacheStore, so on the primary cache-miss path (the dominant recursive-mode path) merge() runs before qctx.Res exists and RFC 10029 merging never executes
- **描述**: Execution order in AssembleChain is Response → CacheStore → MQTYPE → Validation → ... → Resolution (MQTYPE Wrap at line 141, CacheStore Wrap at line 148 — each later Wrap is outer). On a cache miss, Resolution sets only qctx.ResolutionResult/Resolved; MQTYPE.post (`mqtype.go:77-80`) sees `qctx.Res == nil` and returns without merging; CacheStore.post (buildSuccess, cache_store.go:52) builds qctx.Res only afterwards. So local RFC 10029 merging and the mandatory MQTYPE-Response option are silently skipped on every miss — the feature only works when the primary is a cache hit or zone match. This contradicts mqtype.go:21-22's own comment ('The middleware runs after CacheStore (the primary response exists) but before Response'). The chain.go:56-67 execution-order comment also omits MQTYPE entirely. The unit tests (mqtype_test.go) stub `next` to set qctx.Res directly, so they never exercise the real chain ordering. Forwarding mode is unaffected (Resolution attaches the option, upstream merges, buildSuccess echoes MQResponse).
- **风险**: RFC 10029 local merge is dead on the primary path for a recursive resolver (cache miss = the common case): clients never receive merged types nor the MQTYPE-Response option, so the feature silently does nothing in the mode it was built for.
- **修复**: Move the MQTYPE Wrap call after the CacheStore Wrap call in chain.go (between CacheStore and Response, matching the design comment), and update the chain.go execution-order doc comment to include MQTYPE. Add an integration test exercising the real chain on a cache-miss primary.

## errc-03 — HIGH

- **位置**: `server/handler/middleware/response.go:73`
- **类别**: rfc
- **摘要**: On the cache-hit path, Response's qctx.Res.Unpack() replaces Answer/Ns/Extra from the pre-packed wire, silently discarding the RRs MQTYPE.merge just added — while the MQRESPONSE option still advertises them (RFC 10029 §3.4 violation)
- **描述**: On a cache hit, CacheLookup sets qctx.Res = buildFromPrePacked(...) — a pooled dns.Msg with Data=wire, Answer=nil (handler/response.go:37-57). MQTYPE.merge then appends merged RRs: `msg.Answer = mergeRRs(msg.Answer, qr.Answer)` etc. (mqtype.go:180-182). Back in Response.Wrap, the fast path is skipped for MQ queries (shouldAddEDNS is always true — `len(qctx.Req.Pseudo) > 0` at response.go:120), so line 73 calls qctx.Res.Unpack(), which in miekg/dns v0.6.89 (msg.go:399-411) REPLACES m.Answer/m.Ns/m.Extra from the wire — the merged RRs are lost. Pseudo is untouched (the pre-packed wire carries no OPT — Set strips it via cloneRRsNoOPT), so MQRESPONSE survives and the client receives a response claiming the additional types were merged while the records are absent — an RFC 10029 §3.4 mismatch between MQTYPE-Response and the response content.
- **风险**: Cache-hit MQ queries return protocol-violating responses: types listed in MQTYPE-Response but not present in the answer sections; clients that trust the option mis-handle the reply. The merge feature produces wrong results on the one path where it currently runs.
- **修复**: After merge(), the pre-packed Data must be invalidated so Response re-packs from fields: set `msg.Data = nil` in merge() (or have the hit path mark the message dirty), so the final Pack includes the merged RRs; alternatively skip Unpack when the message was mutated (merge populated Answer). Add a test with a real pre-packed entry through the full Response+MQTYPE pair.

## errc-04 — MEDIUM

- **位置**: `cache/store.go:223`
- **类别**: validation
- **摘要**: Regression: new Get() removed the internal dnsutil.Canonical(qname) the old Get performed, but callers dns64.go:46 and mqtype.go:131 pass the raw-case qd.Header().Name — mixed-case queries silently miss the cache
- **描述**: Old Get() (pre-93611d5 baseline, store.go:100) started with `qname = dnsutil.Canonical(qname)`; the new zero-copy Get() dropped it and documents 'The caller must pass a canonical qname' (store.go:221-222). qctx.Qname is canonical (handler.go:148: strings.ToLower of the FQDN), but DNS64 (dns64.go:46 `qname := qd.Header().Name`, used at line 57) and MQTYPE (mqtype.go:131, used at line 204) pass the client's original case — SQLite string equality is case-sensitive, so any query sent with non-lowercase letters misses entries cached under the canonical key. DNS64's A-record cache lookup — the optimization added to avoid a full upstream query per AAAA miss — silently degrades to network resolution for mixed-case names. Set() still canonicalizes internally, so the stored keys are canonical and no duplicate rows appear; only the read side is broken.
- **风险**: Perf regression on DNS64 and MQ additional-type lookups for mixed-case query names; silent cache misses with no log to hint at the cause.
- **修复**: Canonicalize in Get() as before (the perf cost of strings.Map on a cold cache-key is negligible vs. a missed hit), or fix the two callers to use qctx.Qname / dnsutil.Canonical and enforce the contract with a test.

## errc-05 — MEDIUM

- **位置**: `cache/store.go:415`
- **类别**: error-wrap
- **摘要**: lookupIPLatencies swallows the StmtIPLatency.Query error and per-row Scan errors with no log at all — latency ordering silently degrades with zero trace
- **描述**: In the new single-batch latency lookup: `rows, err := s.db.StmtIPLatency.Query(argsPtr[:]...); if err != nil { return latencies }` (line 415-418) — the error is dropped silently (empty latency map → no sorting, response served in stored order). Similarly the per-row `if err := rows.Scan(&ip, &lat); err == nil { latencies[ip] = lat }` (line 424-426) silently skips rows. This runs on the cache-hit hot path only when hasLatencyData is set, so a Debug log costs nothing. Compare with the sibling code that does log failures (line 428-430 logs rows.Err(); line 254 logs the entry query error).
- **风险**: A failing latency query (DB busy/closed race during shutdown) silently disables latency-ordered answers with no diagnostic; operators cannot distinguish 'no latency data' from 'latency lookup broken'.
- **修复**: Add `log.Debugf("CACHE: latency lookup failed: %v", err)` (and optionally a counter) on the Query error path, and log skipped Scan rows at Debug.

## errc-06 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:204`
- **类别**: validation
- **摘要**: resolve() discards Get()'s expired flag and uses possibly-expired cache entries as fresh — their RRs are merged with full original TTLs and re-cached via Set (line 188), promoting stale data to a fresh lifetime
- **描述**: `if entry, found, _ := m.store.Get(qname, qt, qclass, ecsOpt, dnssecOK); found && entry.Unpack() == nil` (line 204) ignores the third return value (isExpired). An entry past its TTL but still within the serve-stale window (staleCutoff) is treated as fresh: entry.Unpack() yields RRs with their ORIGINAL (unadjusted) TTLs — no TTL deduction happens on this path (TTL adjustment only occurs via buildFromPrePacked's TTLOffsets on the primary serve path) — and since the cache-hit QueryResult sets Cacheable: true, `m.store.Set(qname, qt, ...)` (line 188) re-caches those records with a full fresh TTL (minTTL of the unadjusted RRs). The stale-answer EDE (RFC 8914 code 16) is not set either, so the client has no indication the data is stale.
- **风险**: Expired DNS data is served as fresh in MQTYPE-Response merges and its lifetime is extended in the cache — repeated MQ queries can keep stale records alive indefinitely, poisoning the additional-type cache.
- **修复**: Check the expired flag: `found && !isExpired && entry.Unpack() == nil` (or apply RemainingTTL to the merged RRs), and only Set() back when the entry was fresh; add a test with an expired entry.

## errc-07 — LOW

- **位置**: `cache/store.go:314`
- **类别**: error-wrap
- **摘要**: Get()'s latency path does a bare `_ = entry.Unpack()` with no comment and no log — an unpack failure (corrupt pre-packed wire) silently disables latency sorting
- **描述**: Line 314: `_ = entry.Unpack()` — the error is discarded with no inline reason comment (violating the repo's '_' discipline, §6.2-4) and no log. If Unpack fails, entry.Answer stays nil, sortAnswerByLatency no-ops, and the entry is served with its stored wire order — correct behavior but entirely silent. rebuildResponseWire (cache.go:124) at least comments its own `_ = msg.Unpack()`; this one is bare. The related ns_addresses.go:243 `_ = entry.Unpack()` in lookupCachedRRs has the same problem (unpack failure silently returns 'no addrs' → forces a network query).
- **风险**: Corrupt cache rows degrade silently with no diagnostic; a later refactor changing Unpack's signature could silently change semantics.
- **修复**: Add a comment with the reason and a Debug log on error (e.g. 'CACHE: unpack failed for entry %d — skipping latency sort'), in both store.go:314 and ns_addresses.go:243.

## errc-08 — LOW

- **位置**: `server/resolver/ns_addresses.go:243`
- **类别**: pool-leak
- **摘要**: Get() consumers that only Unpack the entry (mqtype.go:204, dns64.go:57, ns_addresses.go:243) never release the pool-owned TTLOffsets slice — pool churn on every such lookup
- **描述**: Get() acquires a TTL-offset slice from ttloOffsetsPool for every hit (store.go:268, AcquireTTLOffsets) and the contract (store.go:101-107, comment at 121: 'pool-owned — release with releaseTTLOffsets when done') requires the consumer to return it via ReleaseTTLOffsets. Only buildFromPrePacked (handler/response.go:41) releases; the three Unpack-based consumers — mqtype.go:204, dns64.go:57, ns_addresses.go:243 — drop the slice, so each lookup misses the pool on the next Get and allocates a fresh 8-cap []uint16. Old Get returned entries whose Answer came from a pooled message, so this churn is new with the pre-packed format. Minor on these cold paths (MQ queries, DNS64 AAAA misses, NS address lookups), but silent.
- **风险**: Pool misses and per-lookup allocations on three paths; if a hot path ever starts calling these patterns (e.g. mqtype volume grows), the churn scales with query rate.
- **修复**: Release TTLOffsets in each Unpack-style consumer (defer cache.ReleaseTTLOffsets(entry.TTLOffsets) after the merge/synthesis/extraction completes), or document that Get transfers ownership only when ResponseWire is served.

## errc-09 — LOW

- **位置**: `server/handler/middleware/mqtype.go:192`
- **类别**: dead-code
- **摘要**: `if len(completed) > 0 || len(mq.Types) > 0` — the second clause is always true because validate() FORMERRs empty type lists, so the condition reduces to a constant
- **描述**: merge() is only reached after validate() passes, and validate() returns errMQTypeEmpty when len(mq.Types)==0 (line 104-106). Therefore at line 192 `len(mq.Types) > 0` is always true and the MQTYPE-Response option is unconditionally appended. The intended behavior (RFC 10029 §3.4: return the option even with an empty completed list) is correct, but the expression misleads a reader into thinking there is a conditional path where the option is omitted.
- **风险**: Misleading dead condition: a future edit may 'fix' it to `len(completed) > 0` and accidentally break the always-return semantics.
- **修复**: Replace the condition with a plain append (always return the option after a valid MQTYPE-Query), keeping a comment citing §3.4.

