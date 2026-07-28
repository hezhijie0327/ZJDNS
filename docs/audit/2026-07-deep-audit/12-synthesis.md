# Synthesis Report — 2026-07 Deep Audit (Final)

## Coverage: 135 of 135 files (100%)

| Scope | Files | Source |
|-------|-------|--------|
| Foundation: `internal/*` | 22 | Main |
| Domain: `config`, `database`, `cache` | 15 | Main |
| DNSCrypt protocol + upstream | 9 | Main |
| Plain protocol | 3 | Main |
| Defense | 2 | Main + Agent |
| Upstream + server core + cmd + remaining | 41 | Agent #1 |
| Handler + middleware | 16 | Agent #2 |
| Protocol TLS/TLCP | 11 | Agent #3 |
| Resolver + dnssec + probe | 18 | Agent #4 |
| **Total** | **~135** | |

## Final Finding Summary

| Severity | Count |
|----------|-------|
| **CRITICAL** | **15** |
| **HIGH** | **17** |
| MEDIUM | 3 |
| LOW | 16 |
| **Total** | **51** |

---

## CRITICAL Findings (15)

| ID | File:Line | Category | Description |
|----|-----------|----------|-------------|
| C1 | `server/protocol/dnscrypt/crypto.go:176` | data-corruption | Shared-key cache uses zero cpk — all classical DNSCrypt queries fail after first |
| C2 | `server/upstream/pool/tcp.go:241` | pool-use-after-free | `resp.Data` aliases pooled buffer on Unpack error |
| C3 | `server/upstream/tls/quic.go:185` | pool-use-after-free | Same as C2 — QUIC Unpack error |
| C4 | `server/upstream/tls/dtls.go:93` | pool-use-after-free | Same as C2 — DTLS Unpack error |
| C5 | `server/upstream/tlcp/dtlcp.go:93` | pool-use-after-free | Same as C2 — DTLCP Unpack error |
| C6 | `server/upstream/client.go:205` | pool-leak | Plain UDP→TCP fallback overwrites pooled response |
| C7 | `server/upstream/warmup.go:30` + `client.go:114` | nil-deref-panic | Nil `*socks5.Dialer` evicted → `d.Close()` panics |
| C8 | `server/handler/middleware/resolution.go:69` | nil-deref-panic | `qr.Err` without nil check in direct path |
| C9 | `server/handler/middleware/dns64.go:61` | nil-deref-panic | `aqr.Err` without nil check |
| C10 | `server/handler/middleware/cache_lookup.go:70,92,133,190` | nil-deref-panic | `refreshGroup.Go()` on nil errgroup |
| C11 | `server/handler/middleware/cache_lookup.go:67,89,109` | nil-deref-panic | `closed()` on nil func pointer |
| C12 | `server/handler/middleware/cache_lookup.go:143` | nil-deref-panic | `context.WithTimeout(nil, ...)` |
| C13 | `resolver.go:159` + `recursive.go:112,168` + `forward.go:269,291` | nil-deref-panic | nil EDNS handler → panic on first query |
| C14 | `resolver.go:162` + `forward.go:89` + `nameserver.go:43` | nil-deref-panic | nil BuildMsg → panic on first query |
| C15 | `resolver.go:165` + `nameserver.go:77` + `forward.go:90` | nil-deref-panic | nil QueryClient → panic on first query |

## HIGH Findings (17)

| ID | File:Line | Category | Description |
|----|-----------|----------|-------------|
| H1 | `server/upstream/client.go:163` | pool-leak | DNSCrypt fallback leaks |
| H2 | `server/upstream/tls/tls.go:87` | memory-safety | Data not cleared exchangeOverTLS |
| H3 | `server/upstream/plain/tcp.go:93` | memory-safety | Data not cleared exchangeViaProxy |
| H4 | `server/upstream/client.go:277` | goroutine-leak | tcpPool never shut down |
| H5 | `server/upstream/pool/tcp.go:270` | memory-safety | Unmatched-ID dangling Data |
| H6 | `server/upstream/socks5/udp.go:151` | context | Background() bypasses cancellation |
| H7 | `server/handler/middleware/chain.go:67` | param-validation | nil deps unchecked |
| H8 | `server/handler/response.go:15` | RFC-consistency | QR=0 for nil req response |
| H9 | `server/protocol/tlcp/tlcp.go:85` | goroutine-leak | No read deadline blocks Shutdown |
| H10 | `tls/{https,dtls,quic}` + `tlcp/{tlcp,dtlcp}` | pool-leak | 5 handlers non-deferred Put |
| H11 | `server/protocol/tlcp/tlcp.go:100` | inconsistency | Nil resp kills TLCP DoT connection |
| H12 | `server/protocol/tls/quic.go:171` | goroutine-leak | No ctx check in handleDOQStream |
| H13 | `server/resolver/forward.go:30,130,155,172` | data-race | Cross-query EDE code corruption |
| H14 | `server/resolver/nameserver.go:152,360` | dead-code | retryWithoutEDNS dead cancel param |
| H15 | `server/resolver/recursive_helpers.go:169-178` | maintenance | Pool zeroing dependency undocumented |
| H16 | `server/resolver/nameserver.go:43,71` | performance | Copy→Put feeds non-pool into pool |
| H17 | `server/resolver/qname_minimise.go:27,41,56` | panic | Prev errors discarded — slice panic risk |

## MEDIUM (3) + LOW (16)

See individual reports: `01-foundation.md`, `02-domain.md`, `03-protocol.md`

---

## Root Cause Analysis (51 findings → 7 root patterns)

| # | Root Pattern | Count | Severity | Prevention |
|---|-------------|-------|----------|------------|
| 1 | **Pool use-after-free**: `Data=nil` missed on error paths | 5 | C2-C5, H5 | CI: check `Data=nil` before every `pool.Put` |
| 2 | **Nil deref on optional deps**: documented optional but used unconditionally | 8 | C8-C15 | Constructor: return error, don't warn-and-continue |
| 3 | **Non-deferred pool.Put**: explicit Put instead of defer | 5 | H10 | CI: enforce `defer pool.Put` pattern |
| 4 | **Missing read deadline/ctx**: goroutines block on I/O without cancellation | 3 | H4, H9, H12 | Always SetReadDeadline + ctx.Done check |
| 5 | **Pool leak on fallback**: response overwritten without Put | 2 | C6, H1 | Check + Put before reassignment |
| 6 | **Missing nil guards**: nil stored in data structure, consumed without check | 2 | C7, H17 | Nil check at consumption site |
| 7 | **Shared mutable state across queries**: resolver-level atomic shared between concurrent queries | 1 | H13 | Per-query state, not per-resolver |
| 8 | Other (documentation, naming, etc.) | 25 | M1-M3, L1-L16, H2-H3, H6-H8, H11, H14-H16 | Various |

---

## Remediation Plan

### Sprint 1 — CRITICAL (15 fixes)

**Pool use-after-free** (4): C2-C5 — add `resp.Data = nil` on error in 4 handlers
**Nil deref on optional deps** (8): C8-C15 — add nil guards (5 middleware) + return error from New (3 resolver)
**Pool leak on fallback** (1): C6 — Put before reassign
**Nil in LRU eviction** (1): C7 — nil check in OnEvict
**Shared-key cache** (1): C1 — move cpk after Decrypt

### Sprint 2 — HIGH (17 fixes)

**Pool Put defer** (5 handlers): H10
**Missing deadline/ctx** (3): H4, H9, H12
**Data=nil** (2): H2, H3
**Pool leak** (1): H1
**Other** (6): H5-H8, H11, H13-H17

### Sprint 3 — MEDIUM + LOW (19 fixes)
See per-package reports.

---

## Assessment

The codebase is well-structured with clear architecture. The 51 findings distribute as:
- **5** systemic pool use-after-free (same bug in 4 files)
- **8** nil deref on optional deps (constructor pattern issue)
- **5** non-deferred pool.Put (most handlers independently deviate from the reference)
- **33** other scattered issues

The highest-impact fixes (12 of 15 CRITICAL) follow just 3 patterns. Fixing the patterns
will resolve the bulk of the severity. The remaining 3 CRITICAL are configuration-time
hazards (constructor warn-and-continue pattern).

**Notable clean areas**: Defense (hopguard/poisonguard), DNSSEC validation (all 5 files),
foundation packages (22 files), domain packages (15 files), and plain protocol (3 files).
