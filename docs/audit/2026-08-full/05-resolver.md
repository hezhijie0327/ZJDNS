# 05-resolver.md — server/resolver/*

Phase 1 package audit of the recursive resolution stack. Method: AUDIT-METHODOLOGY.md §1.1 (18 dimensions), §1.3, §4.1, §6.1/§6.2. Every file read in full; test files used as reference only. No code modified.

## Inventory

| File | Lines | Contents |
|------|-------|----------|
| `server/resolver/resolver.go` | 285 | Resolver/Validator/QueryResult/Question types, `New`, `ConfigureServers`, `Query`, `concurrencyLimit`, `ShuffleSlice` |
| `server/resolver/recursive.go` | 533 | Recursive walk loop, root-domain branch, QNAME minimisation driver, CNAME chain, `walkDedupKey`, TLD poison probe |
| `server/resolver/recursive_helpers.go` | 311 | `collectBestNSMatch`, `applyQnameMinimisation`, `isApexSOANODATA`, `advanceApexZoneCut`, `checkLameDelegation`, `validateNODATAWithNSEC`, `processAnswerWithDNSSEC`, `shouldRetryMinimisedQname` |
| `server/resolver/recursive_ns.go` | 146 | `resolveNextNameservers` (cache→glue→resolution), `cacheGlueRecords` |
| `server/resolver/nameserver.go` | 619 | `queryNameserversConcurrent` (errgroup fan-out, NXDOMAIN deferral, poison gates, FORMERR retry), `resolveNSAddressesConcurrent`, `resolveNSAddrType`, `responseEchoesQuestion` |
| `server/resolver/delegation_cache.go` | 263 | `storeDelegation`, `lookupDelegation`, `applyDelegationStart`, `ancestorZones`, `parentSideType`, `minDelegationTTL`, DS pack/unpack |
| `server/resolver/dnssec_chain.go` | 647 | `dnssecChain`, `isValidWithDNSSEC`, `updateDNSSECChain`, `verifyNoDSInParent`, `ensureZoneDNSKEYs`, `fetchZoneDNSKEYs`, `verifyDelegationDSRRSIG`, `validateOrRetry`, offline-KSK (CDS/CDNSKEY) |
| `server/resolver/zonecut.go` | 347 | `stripCrossZoneRecords`, `getZoneCutSigner`, `resolveZoneCut`, `resolveChildNameservers` |
| `server/resolver/qname_minimise.go` | 145 | `minimiseQNAME`, `labelsToAdd` (RFC 9156 §2.3 schedule), `minimisationQtype` |
| `server/resolver/ns_addresses.go` | 259 | Latency-sorted NS/root address cache, `getRootServers` memo, `sortAddrsByLatency`, `lookupNSAddrsFromCache`, `cacheRootHint` |
| `server/resolver/root_hints.go` | 108 | named.root load via `sync.Once`, `LoadRootHints` |
| `server/resolver/mqtype_ctx.go` | 26 | `WithMQType`/`MQTypeFromContext` (RFC 10029 pass-through) |
| `server/resolver/dnssec/crypto.go` | 381 | `CryptoValidator`, `VerifyRRset` (EDE 7/8 manual window), `VerifyDelegationDS`, `SelfVerifyDNSKEY`, `IsResponseValid`, `isAnswerSectionValid` |
| `server/resolver/dnssec/extract.go` | 212 | CollectRRSIGs/FindRRSIGs/FindDNSKEYs/FindDS/CDS/CDNSKEY, `canonicalCompare`, `isDomainInRange`, DNSKEY cache (ZoneKeys/CacheZoneKeys) |
| `server/resolver/dnssec/nsec.go` | 549 | NSEC/NSEC3 denial-of-existence, closest-encloser, Opt-Out handling, `CapValidatedTTL` |
| `server/resolver/dnssec/trust_anchor.go` | 154 | root-anchors.xml parse, RFC 7958 §3.2 digest/keytag cross-check, RFC 5011 revoke skip |
| `server/resolver/dnssec/validate.go` | 43 | `IsResponseValid` (AD-flag based, forwarding) |
| `server/resolver/probe/probe.go` | 294 | `Prober` (client A/AAAA latency), `TryProbeNSAddrs`/`ProbeNSAddrs` (NS/root), `nsPending` singleflight |

Cross-package verification: resolver constructed at `server/init.go:35` (Crypto/Poisonguard always non-nil in production; zero-value `defense.Detector{}` at `server/server.go:225`); `Query` consumed by `server/handler/middleware/resolution.go:58,69` and `mqtype.go:286-289`; "never cache bogus" enforced downstream at `server/handler/middleware/cache_store.go:36` (`dnssecCacheable`) + `:133`; `CapValidatedTTL` called at `cache_store.go:136`; probe used by resolver + `server/server.go` only (internal/latency does NOT import probe — no cycle); `pending` shared with handler middleware — no cycle. Pool contract verified at `internal/pool/pool.go` (`Put` zeroes the whole `dns.Msg` struct; backing arrays survive via captured slice headers). Delegation SQL freshness verified at `database/stmts.go:166` (`AND expires_at > unixepoch()`). RFC archive: all RFC numbers referenced in these files are present in `docs/rfc/` (10029, 9824, 9156, 4033-4035, 5155, 6840, 6604, 7344, 7958, 5011, 5452, 8767, 6891, 8914, 2181, 4343, 3597, 1034/1035 — all present).

## Findings

### CRITICAL

None.

### HIGH

- [race/memory] `server/resolver/recursive.go:194` — `Truncated: response.Truncated` is read AFTER `pool.DefaultMessage.Put(response)` at :193 (root-domain query branch). `Put` zeroes the entire `dns.Msg` struct (`internal/pool/pool.go` `*msg = dns.Msg{}`) and may hand it to another goroutine; the read races with that reuse. | risk: data race on a hot path; the client can receive a garbage/zeroed TC bit (missed TCP-retry or spurious truncation), and `-race` CI would flag it | fix: capture `truncated := response.Truncated` alongside `rcode` at :191, use the local in the `QueryResult` literal.

### MEDIUM

- [correctness] `server/resolver/delegation_cache.go:222-231` + `recursive.go:155-160` — a fresh delegation-cache start seeds the walk with snapshot NS addresses (`resolveDelegationAddrs` falls back to stored addrs); if those servers are dead/stale, the walk fails with SERVFAIL and there is NO fallback to restart from root. | risk: transient SERVFAIL for the entire zone for up to the record's min-NS-TTL (often hours) after NS address changes | fix: on `queryNameserversConcurrent` failure in `resolve()` while `currentDomain != "."` and a delegation-cache start was applied, delete the stale row (or retry once from root).
- [comment-vs-code] `server/resolver/forward.go:357-361` — comment claims "NODATA / NXDOMAIN ... empty Answer with NSEC/NSEC3 denial-of-existence proof in Authority" is filtered by `len(qr.Answer) == 0 && len(qr.Authority) == 0`, but that condition only matches responses with BOTH sections empty; NODATA/NXDOMAIN with SOA+NSEC in Authority are forwarded as first-wins results. | risk: maintenance confusion; if the filter is intended to drop NODATA/NXDOMAIN in the recursive-upstream branch, the check is wrong (it never fires for real denials) | fix: either delete the check (fully-empty responses are already useless) or flip/repair the condition + comment to match intent.
- [dead-code/inefficiency] `server/resolver/ns_addresses.go:108-112` and `:251-253` — duplicated nested call `if probe.TryProbeNSAddrs(...) { if probe.TryProbeNSAddrs(...) { go ... } }`; the inner call is redundant (pure gate, no side effects — probe.go:185). | risk: dead code; one extra function call per root-refresh/probe path | fix: collapse to a single `if`.
- [constants] `server/resolver/probe/probe.go:280-282` — magic literals `Timeout: 100` (ms) in `defaultNSProbeSteps`; `DefaultProbePortDNS` is a named constant but the timeouts are not. | risk: violates constants discipline (audit §1.1 常量提取) | fix: named consts in `config/defaults.go` (e.g. `DefaultNSProbeStepTimeoutMs`).

### LOW

- [dead-code] `server/resolver/delegation_cache.go:17-25,205` — `delegationRecord.timestamp` and `.ttl` are scanned at :205 but never read afterwards (freshness is enforced in SQL via `expires_at`). | fix: drop the fields/columns from the scan or use them for diagnostics.
- [validation] `server/resolver/dnssec_chain.go:241,333,593,624`, `zonecut.go:312`, `nameserver.go:481,587` — uncommented `_` discards of `defense.Verdict` (and `_ = g.Wait()` at nameserver.go:481); audit rule 6.1-11 requires a comment (`// _ = verdict: poison already gated per-response in queryNameserversConcurrent`). Forward.go:147 has the comment; these do not. | fix: add comments (behavior is benign — poison rejection is already applied per-response inside `queryNameserversConcurrent`).
- [correctness] `server/resolver/dnssec/crypto.go:368-381` — `groupRRset` keys on the raw wire owner name; RFC 4343-legal mixed-case owner names split one RRset into two groups, and both groups then fail RRSIG verification (RRset must be complete) → false "bogus". `FindRRSIGs` is case-insensitive (`dns.EqualName`) but the grouping is not. | risk: rare false negatives on case-preserving authoritative servers | fix: canonicalise the owner name in `rrsetKey` construction.
- [correctness] `server/resolver/recursive.go:485-500` — `resolveInner` keeps any answer record whose type equals the original QTYPE regardless of owner, and drops `qr.Truncated` from the merged result (client never sees TC on CNAME chains). | risk: loose filtering could surface unrelated owner data; TC loss affects client retry logic | fix: restrict the type-only match to the current CNAME target name; propagate `Truncated`.
- [inefficiency] `server/resolver/nameserver.go:282-504` — `resolveNSAddressesConcurrent` dedups addresses only within one NS name (`uniqAddrs` at :433-442); the same IP reached via different NS names (common with registrar shared DNS) is queried multiple times per level. | fix: global dedup of `allAddresses` before `ShuffleSlice`.
- [rfc] `server/resolver/dnssec/crypto.go:149-173` — DS digest type 1 (SHA-1) and RRSIG algorithms 5/7 are accepted without an RFC 8624 note; acceptance of legacy SHA-1 is required for validation of existing zones (RFC 8624 targets signers), but the deliberate compat stance is undocumented. | fix: add a comment referencing RFC 8624 §3.1.
- [comment] `server/resolver/recursive.go:22-23` (`dnsutil.IsBelow` bailiwick glue check in `recursive_ns.go:81`) — the parent-zone glue gate is correct (glue owner must share the parent hierarchy; out-of-hierarchy glue rejected) but undocumented at the call site; verified semantics: `IsBelow(parent, glue)` — in-bailiwick child-zone glue passes because it is also below the parent. | fix: comment the bailiwick rationale at `recursive_ns.go:75-87`.

## Package observations

### server/resolver (core)
- **Pool ownership discipline is otherwise exemplary** — every `queryNameserversConcurrent` response is Put exactly once by the resolve loop (all 12 exit paths traced); `collectBestNSMatch`/`checkLameDelegation`/`processAnswerWithDNSSEC` deep-copy `Ns`/`Extra` before Put; `baseMsg` is returned by the wait goroutine after `g.Wait()` so queued workers never read a recycled message. The single exception is finding H1.
- **Recursion/walk correctness is strong**: qname minimisation schedule (RFC 9156 §2.3) is cumulative with the zone-rebase fix; the loop is provably bounded (`minimiseSteps` increments every minimised iteration; full QNAME at count 10); NXDOMAIN deferral + poison gates; RFC 5452 §9.3 question-echo on every path including the FORMERR retry; RFC 6604 §3 NXDOMAIN+CNAME gate; RFC 6891 §6.2.2 EDNS-free retry; delegation SQL enforces freshness; walkGroup/dnskeyGroup/addrGroup singleflight keys cannot self-deadlock (internal walks bypass the group); goroutines all carry `defer HandlePanic` and are errgroup/`wg`-tracked; errgroup limits set (`DefaultMaxConcurrentNS`=6 for NS fan-out, adaptive tier for upstreams).
- Systemic pattern to watch: the walk-verbosity (`allRRSections` copy per level, per-iteration `dnsutil.Canonical` calls) is acceptable at walk frequency; the true hot path (NS-address cache hits) was already reduced to a single `GetTypes` SQL.
- `handleRecursiveQuery` (forward.go:348) sends NXDOMAIN/NODATA as first-wins without the NXDOMAIN-deferral used by the recursive walk — intentional divergence for upstream fan-out, but worth a comment.

### server/resolver/dnssec
- **Chain-of-trust is carefully built**: `verifyDNSKEYWithDS` enforces RFC 4035 §5.2 both steps (DS digest match AND matched-key signature over the whole RRset — mitigates key-tag-only attacks); missing-DS requires an authenticated NSEC/NSEC3 denial (never bare NODATA); unverifiable delegations are bogus, never insecure; stale-parent-key fallback is deliberately removed (fail closed); offline-KSK (RFC 7344 CDS/CDNSKEY) is documented as intentional defense-in-depth with full-digest binding.
- NSEC3: closest-encloser per RFC 5155 §8.3 with next-closer-cover enforcement; covered-name NODATA fails closed unless the covering record has Opt-Out (R3-M14 regression fixed); iterations capped at 150 (§10.3); ancestor-delegation exclusion per RFC 6840 §4.1 with the DS-query exception correctly scoped.
- "Never cache bogus" holds end-to-end: resolver sets EDE 6/7/8/1/12 + `Validated=false`, middleware `dnssecCacheable` blocks caching, and stale EDE 6 from a previous level is cleared on clean validation (`validateOrRetry`).
- `CapValidatedTTL` (RFC 4035 §5.3.3) is applied only on the validated cache path (cache_store.go:136) — correct placement.
- Note: `isAnswerSectionValid` cross-zone skip relies on signer-below-verified-key-zone; mixed-case owner grouping (L4) is the only gap found.

### server/resolver/probe
- `TryProbeNSAddrs`/`ProbeNSAddrs` split is clean (synchronous gate vs background work); `nsPending` singleflight is deliberately global (correct for cross-query NS sharing); per-call `latency.New` in `ProbeNSAddrs` is gated by min-interval + singleflight so churn is bounded; `ctx == nil → background` guards present; only the magic timeout literals (M4) stand out.

### Verdict
No CRITICAL. One HIGH data race (H1) in the root-domain query branch — single-line fix. Two MEDIUM correctness items (stale-delegation fallback, forward.go filter/comment mismatch). The resolver stack is otherwise in strong shape: pool discipline, DNSSEC fail-closed behavior, singleflight correctness, and RFC conformance are all consistently above the project baseline.
