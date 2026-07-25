# Debug-Level Logging Coverage Audit

**Date:** 2026-07-25
**Scope:** Every `log.Debugf` / `log.IsDebug` call in production `.go` files
**Method:** Read every key file and cross-reference against critical code paths.

---

## Executive Summary

The codebase has **~200 Debug-level log statements** across production code. Coverage is **good** in the core resolver (forward + recursive + nameserver + DNSSEC chain) and the anticensorship subsystem (spoofguard). Coverage is **sparse** in the validation middleware, the protocol listener startup paths, config loading, cache Get/Set operations, and several upstream transport sub-packages. The single most impactful gap is the `Validation` middleware, which silently rejects queries without any log.

---

## Package-by-Package Analysis

### 1. `server/handler/middleware/` -- Query Pipeline

**Debug Coverage: ADEQUATE**

**What's logged (good):**
- `resolution.go:65` -- "RESOLVER: resolving %s %s" on every resolution start
- `resolution.go:28` -- "RESOLVER: resolver not set" (nil-guard)
- `cache_lookup.go:232` -- "CACHE: refresh skipped" (dedup gate)
- `cache_store.go:100` -- "CACHE: populating cache for %s"
- `cache_store.go:124` -- "RESULT: ... rcode=NOERROR, answer=%d, validated=%t"
- `cache_store.go:153` -- "CACHE: serving cached result for %s"
- `cache_store.go:165` -- "RESULT: ... rcode=SERVFAIL, no stale cache available"
- `cache_store.go:208` -- "RESULT: ... rcode=REFUSED, blocked by CIDR filtering"
- `cache_store.go:133` -- "UPSTREAM: passing through EDE %d"
- `cache_store.go:176,184` -- DNSSEC EDE logs
- `zone.go:37,48,60,85` -- Zone rule evaluation, match, block, synthetic
- `edns.go:34,44,47,56,65,75` -- EDNS unpack, ECS parse, cookie validation
- `response.go:50,88,98` -- Response ECS, cookie validation, cookie renewal
- `ptr.go:59` -- "PTR: reverse lookup"
- `dns64.go:70` -- "DNS64: synthesized N AAAA records"
- `pending.go:111,121` -- Pending-request dedup follower/wait/timeout

**What's missing (gaps):**
- **`middleware/validation.go:21-53` -- NO debug logs at all.** When a query is rejected for domain-too-long, invalid label, ANY, AXFR, or IXFR, there is zero indication in the logs. This is the most visible gap in the entire pipeline.
- **`middleware/cache_lookup.go:46-48` -- Cache miss (`!found`) is silent.** No log saying "CACHE: miss for %s". This is a common performance diagnostic path.
- **`middleware/cache_lookup.go:54-74` -- Fresh cache hit is silent.** Only the prefetch-start condition is logged (via `tryStartRefresh`). A fresh-hit log would help differentiate the fast path during perf analysis.
- **`middleware/cache_lookup.go:81-116` -- Stale-cache serving paths have no Debug log.** The `CanServeExpired` branch, the `preferStale` path, and the foreground-refresh timeout all complete silently. The caller (`cache_store.go`) logs later, but the decision to serve stale vs delegate back is opaque.
- **`middleware/cache_lookup.go:147-175` -- Foreground refresh succeeds or fails silently.** The `serveExpiredWithRefresh` function logs nothing about whether the background refresh got a new result or failed. Only the `RecordRequest` call logs outcome to SQLite (not visible as a Debug log line).
- **`middleware/cache_store.go:29-53` -- No log for the "already handled" early-return paths (`CacheServed`, `ZoneMatched`, `Res != nil`).** These are expected (they mean an upstream middleware short-circuited), but a debug log would help trace the pipeline.
- **`middleware/resolution.go:46-63` -- Singleflight dedup leader/follower decision is not logged.** The `pending.Join` call inside the `Resolution` middleware logs nothing about whether this query is the leader or a follower. The follower log is in `pending.go` (separate package), hiding this from the middleware trace.

**Verdict: Add Debug logs to `validation.go`, and to the cache miss/cache hit paths in `cache_lookup.go`. The remaining gaps are minor.**

---

### 2. `server/handler/handler.go` -- Pipeline Entry Point

**Debug Coverage: GOOD**

**What's logged (good):**
- `handler.go:125-132` -- "QUERY: client IP=%s query=%s type=%s" on every incoming query (gated by `log.IsDebug()`)
- `handler.go:164-172` -- "RESULT: %s %s | rcode=%s time=%v answer=%d authority=%d additional=%d ad=%t" with full message dump (gated by `log.IsDebug()`)

**What's missing (gaps):**
- `handler.go:108-112` -- Closed handler returning SERVFAIL is silent.
- `handler.go:114-123` -- Nil/empty question returning FORMERR is silent.
- `handler.go:148-153` -- Dropped query (ErrDrop) is silent.
- `handler.go:155-162` -- Chain error + no response returning SERVFAIL is silent.

**Verdict: Minor gaps. The query/result logs cover the common paths. The silent-edge cases (closed handler, empty question, chain error) are rare and less actionable for troubleshooting.**

---

### 3. `server/upstream/` + Sub-packages -- Outbound Queries

**Debug Coverage: GOOD** (with sub-package variation)

**What's logged (good):**
- `client.go:127` -- "UPSTREAM: querying %s (%s) for %s" on every upstream query
- `client.go:139-206` -- Full DNSCrypt TCP fallback, UDP-to-TCP fallback, per-query result success/failure with rcode, answer count, duration, server
- `plain/udp.go:271-383` -- Exhaustive spoofguard multi-read decision logging (fast return, accept, reject, non-EDNS fallback, EDNS candidate, pickBest choices with richness comparison)
- `plain/tcp.go:26,50` -- Splitguard activation, pipelined query failure
- `pool/tcp.go:210-243` -- Read errors, invalid message length, unpack errors
- `pool/tcp.go:418-433` -- Pool capacity, dial tracking
- `pool/quic.go:142` -- New QUIC connection dialed
- `tls/client.go:216-285` -- Pre-warm results for DoT/DoQ/DoH/DoH3
- `tls/tls.go:36` -- Pipelined DoT failure fallback
- `tls/quic.go:70` -- Pooled DoQ failure + retry
- `tls/dtls.go:91` -- DTLS query success
- `tlcp/tlcp.go:21` -- TLCP query failure
- `tlcp/dtlcp.go:92` -- DTLCP query success
- `dnscrypt/cert.go:26-29` -- DNSCrypt cert truncation retry
- `dnscrypt/client.go:132-158` -- PQ resume derivation failure, ticket stored, decrypted, min-query-len
- `dnscrypt/crypto.go:26-51` -- PQ resumed/cached/fresh query
- `dnscrypt/state.go:157-161` -- PQ vs classical selection
- `socks5/tcp.go:50` -- "UPSTREAM: SOCKS5 connected"

**What's missing (gaps):**
- **`client.go:212-238` -- `executeSecureQuery` logs nothing about which protocol is selected.** The switch dispatches silently. If a user misconfigures `ProtoDTLS` vs `ProtoDTLCP`, there's no trace.
- **`plain/udp.go:72-182` -- `executeUDPMultiRead` connection setup is silent.** When spoofguard is active but no proxy dialer is present, the entire connection plus multi-read loop runs with only the first `processPacket` call producing output.
- **`plain/udp.go:186-213` -- SOCKS5 UDP exchange (`exchangeViaProxyUDP`) has zero Debug logs.** If the proxy fails, the error propagates without any context.
- **`tls/quic.go:22-106` -- `ExecuteQUIC` has only one Debug log** (for the pooled failure/retry path). Successful QUIC queries from a fresh dial (lines 74-106) produce no log. The pooled retry path (detect 0-RTT rejection) also logs nothing about the rejection.
- **`tls/dtls.go` (entire file) -- `ExecuteDTLS` has no Debug logs at all** (only the caller `client.go` logs the result). If DTLS connection setup fails, there's no context.
- **`socks5/tcp.go` and `socks5/udp.go` -- SOCKS5 tunnel-level operations have zero Debug logs.** Only the SOCKS5 "connected" event is logged. Authentication failures, relay errors, and UDP association issues are silent.
- **`tlcp/client.go` and `tlcp/dtlcp.go` (upstream) -- Very sparse.** Only one Debug log each. Compare with the TLS client which has detailed per-protocol logs.

**Verdict: Strengthen the DTLS, DTLCP, TLCP upstream client paths. Add a protocol-selection log in `executeSecureQuery`. Add SOCKS5 relay debug logging for troubleshooting proxy setups.**

---

### 4. `server/resolver/` + `server/resolver/dnssec/` -- Recursive Resolution

**Debug Coverage: EXCELLENT**

**What's logged (good):**
- `forward.go:44` -- "UPSTREAM: querying N servers for %s" with addresses
- `forward.go:132-135` -- All servers failed, with/without EDE
- `forward.go:175` -- "UPSTREAM: captured EDE %d" from upstream
- `forward.go:269` -- "UPSTREAM: DNSSEC validation result=%t"
- `forward.go:276` -- "UPSTREAM: First win achieved, terminating N remaining connections"
- `nameserver.go:100,110,136` -- Poison detection/rejection at per-nameserver level
- `nameserver.go:155` -- "RECURSION: ns=%s rcode=%s"
- `nameserver.go:158` -- "RECURSION: ns=%s error=%v"
- `nameserver.go:174` -- "RECURSION: NS query errgroup: %v"
- `nameserver.go:201` -- "RECURSION: all N nameservers failed"
- `nameserver.go:316` -- "RECURSION: NS address resolution errgroup: %v"
- `nameserver.go:356-377` -- FORMERR retry logging
- `nameserver.go:386` -- Poisoned FORMERR retry
- `recursive.go:84` -- "RECURSION: depth=%d, querying %s ..." with full context
- `recursive.go:100,147` -- Poisonguard TCP fallback at root and TLD level
- `recursive.go:210` -- "RECURSION: zone=%s, N NS names -> N addresses"
- `recursive.go:261` -- Poison probe detection
- `recursive.go:294` -- "RECURSION: CNAME step N/N: resolving %s %s"
- `recursive.go:351` -- "RECURSION: CNAME chain: %s -> %s"
- `recursive_helpers.go:68` -- QNAME minimisation step
- `recursive_helpers.go:86` -- Lame delegation detection
- `recursive_helpers.go:159,163` -- Zone cut DNSSEC validation failure
- `recursive_ns.go:55` -- NS cached sorted
- `zonecut.go:47` -- Cross-zone record stripping
- `zonecut.go:130,158,162,168` -- Zone cut DS/DNSKEY/validation
- `dnssec_chain.go:44-361` -- **25 Debug logs** covering every DNSSEC chain-of-trust step (DNSKEY query, DS verification, RRSIG validation, zone cut detection, trust anchor loading, retry logic)
- `dnssec/crypto.go:121,155,220,234,270` -- Key tag matching, self-verification, RRSIG validation
- `dnssec/validate.go:15,18` -- AD-flag validation
- `dnssec/trust_anchor.go:69-92` -- Trust anchor loading (expired, parse failures, key flags)
- `probe/probe.go:77-171` -- Every latency probe skip reason and result
- `resolver.go:332` -- "UPSTREAM: primary upstream failed for %s, waiting for concurrent fallback"

**What's missing (gaps):**
- **`forward.go:22-24` -- "no upstream servers" returns silently.** `queryUpstream` with empty servers array returns an error without logging. Callers usually handle this, but the first indication of misconfiguration is a SERVFAIL response to the client.
- **`forward.go:101-113` -- errgroup Wait error is logged at Warn.** The "RECURSION" errgroup error at line 102 is logged as Warn instead of Debug. This may be too verbose for normal operation.
- **`recursive.go:116-118` -- Loop exit via `ctx.Done()` is silent.** When the recursive loop exits because the context was cancelled, there's no log. The caller sees a `ctx.Err()` error but no detail about which delegation level was active.
- **`resolver.go:272-276` -- Pure-recursive (no servers) path is silent.** When resolving via built-in recursive because no upstream/fallback is configured, there's no Debug log indicating this choice.

**Verdict: Excellent overall -- the strongest package in the codebase. Minor gaps in silent error returns. Consider adding a context-done log in the recursive loop.**

---

### 5. `server/protocol/*` -- Inbound Protocol Handlers

**Debug Coverage: ADEQUATE** (varies by protocol)

**What's logged (good):**
- `tls/server.go:91-94` -- Raw TCP accept errors and new connections
- `tls/server.go:122` -- "TLS: Using certificate from files"
- `tls/server.go:358` -- "TLS: ClientHello from %s, SNI=%s, supported curves=%d"
- `tls/tls.go:72,77,87` -- DoT accept, handler start, non-eTLS.Conn detection
- `tls/tls.go:119,169,237` -- Write errors, read length errors, pack errors
- `tls/dtls.go:74-164` -- Accept errors, SetReadDeadline, short read, unpack/pack errors, response too large, write errors (7 logs)
- `tls/http3.go:82` -- Connection error
- `tls/quic.go:204` -- DoQ response failure
- `tlcp/tlcp.go:76,94,106` -- Accept error, read error, write error
- `tlcp/dtlcp.go:66,246,279,297,304,316,324,333` -- Handshake error, accept error, SetReadDeadline, short read, unpack/pack errors, response too large, write error (8 logs)
- `tlcp/server.go:72` -- "TLCP: Using SM2 certificates from files"
- `tlcp/http_tlcp.go:99` -- DoH pack error
- `dnscrypt/server.go:117,381,473,496` -- Key pair generation, rotation, cert window, query handling
- `dnscrypt/crypto.go:78-129` -- PQ ticket, PQ resume, PQ initial, classical query
- `dnscrypt/tcp.go:66,100,105,121,130` -- Accept error, read error, handling error, handshake response, decrypted query
- `dnscrypt/udp.go:73,85,113,128,131,133,139,142,152` -- All errors and state transitions

**What's missing (gaps):**
- **`plain/server.go:31-36` -- Start/shutdown has no Debug logs.** The plain UDP and TCP listeners start silently (only shutdown logs at Info level). No log at Debug for "PLAIN: starting UDP on :53".
- **`tls/server.go:122`** -- Only the "from files" path logs. The embedded certificate path is silent.
- **`tlcp/server.go`** -- No Debug log for TLCP listener start.
- **`dnscrypt/server.go`** -- No Debug log for DNSCrypt listener start.
- **Protocol listener startup across the board** -- All listener `Start()` methods lack Debug-level startup logging. Operators troubleshooting "why isn't port 853 responding" need to see "TLS: listening on :853" at Debug level.

**Verdict: Add Debug logs for listener start in every protocol. The error logging on I/O failures is already thorough. This is a consistent gap across all 4 protocol packages.**

---

### 6. `server/defense/` -- Anti-Pollution

**Debug Coverage: GOOD** (but small surface area)

**What's logged (good):**
- `poisonguard.go:88` -- "SECURITY: poison detected from %s: %s record for '%s' -> %s"

**What's missing (gaps):**
- `poisonguard.go:74-93` -- The `Validate` function returns `VerdictClean` for nil response and clean responses, neither of which is logged (correct -- would be spam).
- `poisonguard.go:101-116` -- `IsPoisonedByTLD` returns silently. The caller (`recursive.go:261`) logs the result ("RECURSION: poison probe detected A/AAAA...").
- `poisonguard.go:119-131` -- `classify` returns `VerdictUncertain` for authoritative-level (can't distinguish) with no log. This is the GFW blind spot and documenting it at Debug would help operators understand why certain queries were not flagged.

**Verdict: No major gaps. The Detector's `classify` function could log at Debug when returning VerdictUncertain (authoritative-level blind spot), but this is a minor diagnostic aid rather than a gap.**

---

### 7. `server/bridge.go` + `server/server.go` -- Lifecycle

**Debug Coverage: ADEQUATE**

**What's logged (good):**
- `bridge.go:64,70` -- TCP SERVFAIL pack/write errors
- `bridge.go:95,108,113` -- TCP pack error, write lock timeout, write error
- `bridge.go:126,137,144` -- UDP pack error, truncate pack error, write error
- `tasks.go:52` -- "EDNS: rotated DNS cookie secret"
- `tasks.go:131` -- "CACHE: cleaned up N stale rows"

**What's missing (gaps):**
- **`bridge.go:121-147` -- UDP handler path** logs pack/write errors but not the case where `response` is nil (client drop). `handleDNSRequest` returns silently after `handler.ServeDNS` returns nil (line 123's empty `if` block).
- **`server.go:67-121` -- `New()` has zero Debug logs.** The entire dependency wiring (database open, cache init, zone eval, EDNS, resolver, handler, protocol listeners, background tasks) runs silently. If a component fails, only the error is logged. Debug-level tracing through initialization would help diagnose startup failures.
- **`tasks.go:96-99` -- Prefetch cooldown cleanup runs silently.** At minimum a Debug log on the first cleanup cycle would confirm the background goroutine is alive.
- **`tasks.go:102-114` -- TCP write-mu sweep runs silently.** Same issue -- no confirmation that the background goroutine is alive.
- **`tasks.go:56-71` -- ECS refresh silent when unchanged.** `refreshECSOnce` returns with no log when the refresh detected no change.
- **`server.go:157-276` -- `shutdownServer` is logged at Info level only.** For production debugging of slow shutdowns, Debug logs at each phase (signal received, protocol shutdown started, background tasks waiting, cache closing) would help identify what's blocking.

**Verdict: Add Debug logs to `New()` wiring steps and background goroutine lifecycle (first tick) to confirm they are alive.**

---

### 8. `config/` -- Config Loading

**Debug Coverage: SPARSE**

**What's logged (good):**
- `load.go:55` -- "CONFIG: Configuration loaded successfully" (Info, not Debug)
- `load.go:31` -- Insecure permissions warning (Warn)
- `load.go:186-190` -- DDR unsafe characters/empty domain warnings (Warn)

**What's missing (gaps):**
- **`load.go:18-57` -- No Debug logs for any parsing step.** No log for: number of upstream servers loaded, number of fallback servers, features enabled/disabled (ECS, DNSSEC enforce, DDR, cache settings, etc.), protocol ports configured.
- **`load.go:84-99` -- `normalizeStamps` runs silently.** No log for which servers had stamps decoded.
- **`validate.go` -- Validation results are not logged at Debug.** If a config value is clamped to its valid range, there's no indication.
- **No Debug log for the final effective config.** Operators troubleshooting "why is my upstream not working" need to see what was actually configured.

**Verdict: Add Debug logs for each major config section parsed (upstream count, features enabled, ports). This is the most actionable gap for operators.**

---

### 9. `cache/` -- Cache Operations

**Debug Coverage: SPARSE** (compared to complexity)

**What's logged (good):**
- `store.go:534` -- "CACHE: stale cleanup failed (non-fatal): %v"
- `store.go:570,579` -- Eviction statistics
- `store.go:143` -- Warn: SQL Get error
- `store.go:164,177` -- Warn: decompress/unpack errors
- `store.go:144` -- Info: flushDB row count

**What's missing (gaps):**
- **`store.go:139-141` -- Cache miss (`sql.ErrNoRows`) is silent.** This is the most common non-error path and silently returns `nil, false, false`. Adding a Debug log would help distinguish miss from hit in performance traces.
- **`store.go:375-433` -- `Set()` has zero Debug logs on success.** Cache entry creation is a key state transition. Currently only failures are logged (Warn).
- **`store.go:438-471` -- `evictIfNeeded()` has zero Debug logs for the resync or eviction-thresholds path.** Only the actual eviction (`evictOldest`) logs. The decision path (count check, resync, skip) is silent.
- **`async_writer.go` -- No Debug logs for channel drops.** When the async writer's channel is full and a record is silently dropped, there's no indication. This is currently a silent data-loss path.
- **`stats.go:27-54` -- `RecordRequest` runs silently.** The caller in `cache_store.go` logs the resolution result, but the actual asynchronous write submission is not logged.

**Verdict: Add Debug log for cache miss in `Get()`, for successful insert in `Set()`, and for the eviction decision path. The async writer drop should at minimum have a Debug log.**

---

### Cross-Cutting Findings

#### Gap 1: No Standard "Entry/Exit" Tracing Pattern
Most functions do not log on entry. The only consistent entry log is `client.go:127` ("UPSTREAM: querying...") and `resolution.go:65` ("RESOLVER: resolving..."). This makes it hard to trace a query's flow through the system without reading the code. Consider adding entry/exit Debug logs to major functions (governed by a single `log.IsDebug()` check at the top).

#### Gap 2: Background Goroutines Are Not Logged at Start
The background goroutines in `tasks.go` (cookie rotation, ECS refresh, prefetch cooldown cleanup, TCP write-mu sweep, query journal cleanup) have no "started" log. Only the signal handler logs at Info. Operators have no Debug-level confirmation that background tasks are alive.

#### Gap 3: Context Cancellation Is Silent in Recursive Loop
In `recursive.go:116-118`, when the recursive loop exits because the parent context was cancelled, there is no Debug log. This makes it hard to distinguish "timed out during delegation step X" from "parent cancelled because primary upstream succeeded".

#### Gap 4: Config Loading Is Essentially Undocumented at Debug Level
A new operator cannot verify their config was parsed correctly without running the server and checking for Info/Warn/Error messages. Adding Debug logs for the effective configuration would dramatically improve troubleshooting.

#### Gap 5: Protocol Listener Start Is Silent
No protocol listener logs its bind address at Debug level. When troubleshooting "why isn't port 853 listening", there is no trace unless startup fails entirely.

---

## Summary Table

| Package | Debug Log Count | Coverage | Priority for Improvement |
|---------|-----------------|----------|--------------------------|
| `server/handler/middleware/` | ~30 | ADEQUATE | HIGH -- validation.go has zero logs |
| `server/handler/` | ~5 | GOOD | LOW -- minor edge cases |
| `server/upstream/` + sub | ~55 | GOOD | MEDIUM -- DTLS/TLCP/SOCKS5 sparse |
| `server/resolver/` + dnssec | ~70 | EXCELLENT | LOW -- strongest in codebase |
| `server/protocol/` | ~45 | ADEQUATE | MEDIUM -- listener start silent |
| `server/defense/` | ~1 | GOOD | LOW -- small surface area |
| `server/bridge.go` + server.go | ~15 | ADEQUATE | MEDIUM -- New() wiring silent |
| `server/tasks.go` | ~3 | SPARSE | MEDIUM -- background goroutine starts silent |
| `config/` | ~0 | SPARSE | HIGH -- most actionable operator gap |
| `cache/` | ~5 | SPARSE | MEDIUM -- Get miss/Set success silent |
| `edns/` | ~1 | GOOD | LOW |
| `internal/` (dnsutil, latency) | ~3 | ADEQUATE | LOW |

---

## Top Recommended Fixes (by impact)

1. **`server/handler/middleware/validation.go`** -- Add Debug logs for each rejection reason (domain-too-long, invalid label, ANY, AXFR, IXFR). Currently zero logs for an actively rejecting path.

2. **`config/load.go`** -- Add Debug logs for: number of upstream/fallback servers, feature flags (ECS, DNSSEC enforce, DDR, cache settings), protocol ports. This is the highest-impact gap for operators.

3. **`server/tasks.go`** -- Add a single Debug log per background goroutine on first tick (cookie rotation, ECS refresh, cleanup tasks) to confirm they are alive.

4. **`cache/store.go`** -- Add Debug log for cache miss in `Get()` and successful entry insert in `Set()`. These are key state transitions currently silent.

5. **All protocol `Start()` methods** (`plain/server.go`, `tls/server.go`, `tlcp/server.go`, `dnscrypt/server.go`) -- Add "listening on :PORT" Debug log.

6. **`server/upstream/client.go:executeSecureQuery`** -- Log which secure protocol was selected for the upstream query.

7. **`server/upstream/socks5/`** -- Add Debug logs for relay-level failures (authentication, UDP association).

8. **`server/upstream/tls/dtls.go`** -- Add Debug logs for connection setup failures (currently only success is logged).
