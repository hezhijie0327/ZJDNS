# 07-defense.md — server/defense/*

Phase 1 package audit — 2026-08-08. All 18 dimensions applied to every file in scope, read in full.

## Inventory

| File | Lines | Role |
|------|-------|------|
| `server/defense/hopguard.go` | 286 | HopGuard — per-upstream IP TTL fingerprint learning/validation (LRU-capped states) |
| `server/defense/poisonguard.go` | 220 | Detector — zone-authority violation detection (VerdictClean/Poisoned/Uncertain) |
| `server/defense/hopguard_test.go` | 205 | Test-only (reference) |
| `server/defense/poisonguard_test.go` | 448 | Test-only (reference) |
| `server/defense/benchmark_test.go` | 61 | Test-only (reference) |

Cross-package verification: `go test -race -short ./server/defense/...` passes. Callers verified: `server/upstream/plain/udp.go` (Validate/Feed/Confident, lines 254-279 collect path, 472-489 multi-read path), `server/resolver/{recursive,nameserver,delegation_cache}.go` (Detector.Validate, IsPoisonedByTLD, Verdict). `internal/ipttl/ipttl.go` read for interplay only — findings deferred to its owning agent.

## Findings

### MEDIUM

- [MEDIUM/state-machine] hopguard.go:64-65,104-106 + upstream/plain/udp.go:472-489 — Feed runs before ID/length validation and before spoofguard acceptance, violating the documented contract "Feed is called only after spoofguard confirms the response is clean" | risk: in the multi-read path stale/ID-mismatched datagrams and spoofguard-rejected fakes still enter the histogram; during learning Validate passes everything, so an attacker flooding one fixed low TTL can win the mode (tie-break favors the *smaller* TTL, modeTTL hopguard.go:190) and arm the guard on its own TTL — the udp.go:465-471 comment claims this is prevented, but the only real protection is mode competition | fix: move Feed after the ID/length check and spoofguard acceptance, or feed Validate-rejected TTLs at a low probability so the histogram keeps seeing real traffic; correct the docstring
- [MEDIUM/availability] hopguard.go:69-102,139-148 — once armed, any legitimate TTL drift beyond the ±2 window (anycast PoP shift, load-balanced upstream rewriting TTL) is hard-rejected → the query ends in "no UDP response received" SERVFAIL, and the rejected TTLs never re-enter the histogram (Validate gates Feed), so the 5-min time-based rebuild (hopguard.go:135-138) and the samples%32 rebuild both see only stale TTLs; recovery takes ~8 rebuild cycles (256 feeds) of passing traffic via the 3/4 decay | risk: sustained partial outage on routing changes; the comment at hopguard.go:46-47 promises per-upstream configurability that does not exist | fix: probabilistic feed of rejected TTLs, a consecutive-rejection disarm counter, and/or configurable window
- [MEDIUM/false-positive] poisonguard.go:189-203 — classifyTLD flags A/AAAA/CNAME data for child names as VerdictPoisoned even when the TLD server hosts the child zone authoritatively; the documented real precedent (CNNIC serving com.cn from cn servers) is exempted only for NS/RRSIG/NSEC proofs, not data | risk: every query for such domains forces the TCP fallback (recursive.go:227-232) plus the probeTLDForPoison path (recursive.go:390) with no way to distinguish | fix: exempt data RRsets accompanied by a validating RRSIG (signer == child zone) when DNSSEC validation succeeds, or document the exemption as a config option

### LOW

- [LOW/false-negative] hopguard.go:70-74 + upstream/plain/udp.go:266,486 — `ttlConfident` (fast-accept of ambiguous EDNS candidates, bypassing the spoofguard collect window) fires whenever the guard is armed, even when the packet's TTL is 0 (TTL-less read, ipttl.ErrNoControlMessage), where no TTL evidence exists at all | risk: collect-window bypass on platforms where control messages are delivered intermittently | fix: require `Confident && ttl != 0` at the call sites
- [LOW/state-machine] hopguard.go:135-148 — the time-based rebuild and the samples%32 rebuild can both fire within one Feed call, applying the 3/4 decay twice and rebuilding twice | risk: none material; skews decay timing | fix: single rebuild per Feed invocation
- [LOW/state-machine] hopguard.go:107-167 + upstream/plain/udp.go:258,279,476,489 — every query feeds its TTL at least twice (per-packet feed + adoption feed via pickBestTTL), so the "32 samples" arming threshold is reached after ~16 queries and all histogram counts are doubled | risk: learning phase shorter than intended; threshold arithmetic is ratio-based so tolerant | fix: document or drop the duplicate adoption feed
- [LOW/logging] poisonguard.go:93 — `dns.TypeToString[dns.RRToType(rr)]` yields an empty string for unknown RR types in the poison-detection debug log | risk: cosmetic | fix: fall back to the numeric type

## Package observations

**State machine (verified against prior fixes 6fefc14 / 8e51759 — no regression):** learning → armed → rebuild → disarm (all-TTL decay, hopguard.go:141-144) → re-learning is coherent: disarm implies an empty histogram (trusted empty ⟺ mode==0 ⟺ histogram empty after rebuildTrusted), so re-learning starts clean. The ±2 clamp, boundary tests, and TTL=0 pass-through are correct. Poisonguard's delegation/proof exemptions (NS/DS/RRSIG/NSEC/NSEC3, RFC 4035 §3.1.1) are correctly scoped: `delegationOrProof && isTLD(name)` at root, `delegationOrProof && IsBelow(zone, name)` at TLD; data records for child names remain flagged as designed. `IsBelow` returning true on equal names is harmless (name != zone pre-checked). Root zone handling is correct via `dnsutil.Canonical` (adds trailing dot: Canonical(".") = "." — verified in miekg/dns v0.6.91-0.20260805153854; tests passing zone="" also exercise this).

**Concurrency:** per-server-state `sync.Mutex` covers all fields; `Validate`/`Feed`/`Confident` lock consistently; lrumap handles the shared LRU; race test passes. The Get→LoadOrStore TOCTOU and LRU eviction of in-flight states produce only benign orphans. No lock-drop windows, no deadlock risk.

**Memory:** bounded by design — LRU capacity 256 server states (hopguard.go:48), histogram ≤256 keys; no unbounded per-client state. This dimension is a PASS (the audit focus item).

**Error handling / panic:** nil-receiver guards on Validate/Feed/Confident, nil-response guard, nil-RR defensive skip (poisonguard.go:85-86). No discarded errors, no `_` parameters, no bare type assertions, no goroutines or context use in the package (stateless, synchronous).

**Logging:** all per-query logs are Debug; the per-rejection trustedKeys allocation is IsDebug-gated (hopguard.go:98); one-shot Warnf for capture unavailability is rate-limited via hopguardWarned sync.Map; prefixes UPSTREAM/SECURITY match the canonical list; poison log carries zone/type/qname/RR context. No hot-path spam.

**Constants:** all magic numbers named (fluctuation=2, capacity=256, minSamples=32, 5-min rebuild, clamp bounds). The ±2 window is empirical, not RFC-derived — flagged in M2.

**RFC:** heuristics gate but never alter RFC 1035 wire behavior (rejection → fallback transport or error; TCP fallback is a valid transport). No compliance violations found.

**Ordering/architecture:** declaration order type → const → func correct; NewHopGuard immediately follows the types; methods aggregated; imports respect the layer DAG (only internal/log, internal/lrumap, miekg/dns). No dead code. `modeTTL` tie-break favoring the smaller TTL is the only adversarial lever noted (M1).

**Tests:** 16 hopguard + 26 poisonguard test cases cover learning/enforcement/disarm, threshold adaptation, boundary clamps, nil guards, TTL=0, LRU separation, root/TLD exemptions, and real-world regressions (weixin/qq.com.cn, Google-at-root). Coverage is strong; no gaps affecting the findings above.
