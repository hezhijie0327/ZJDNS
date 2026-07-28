# Resolver + Defense Audit — Agent Findings

## Scope

18 files: `server/resolver/*`, `server/resolver/dnssec/*`, `server/resolver/probe/*`, `server/defense/*`

## Assessment Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 3 |
| HIGH | 5 |

Files with NO findings: `dnssec/validate.go`, `dnssec/trust_anchor.go`, `dnssec/crypto.go`,
`dnssec/extract.go`, `dnssec/nsec.go`, `probe/probe.go`, `defense/hopguard.go`, `defense/poisonguard.go`

---

## CRITICAL Findings

### C13: nil EDNS handler → guaranteed panic on first query

**Files**: `resolver.go:159-160`, `recursive.go:112,168`, `forward.go:269,291`
**Category**: `parameter-validation`, `panic`

`Config.EDNS` is `*edns.Handler`. When nil, `New()` logs a WARN but returns a functioning
`*Resolver`. Every query calls `edns.ParseFromDNS(response)` on the nil pointer — guaranteed
panic on first query.

**Root cause**: warn-and-continue pattern for required dependency. Should return `error`.

### C14: nil BuildMsg → guaranteed panic on first query

**Files**: `resolver.go:162-163`, `forward.go:89`, `nameserver.go:43`
**Category**: `parameter-validation`, `panic`

Same pattern as C13. `Config.BuildMsg` is `BuildQueryFunc` — when nil, every query
calls nil function pointer → panic.

### C15: nil QueryClient → guaranteed panic on first query

**Files**: `resolver.go:165-166`, `nameserver.go:77`, `forward.go:90`
**Category**: `parameter-validation`, `panic`

Same pattern. `Config.QueryClient` is `UpstreamClient` interface — when nil, every query
calls nil interface → panic.

---

## HIGH Findings

### H13: Cross-query EDE code race

**File**: `server/resolver/forward.go:30,130,155,172`
**Category**: `data-race`, `correctness`

`lastUpstreamEDE` is `atomic.Pointer[dns.EDE]` on `*Resolver` shared across all concurrent
queries. Two concurrent queries can:
- Clear each other's EDE (Store(nil)), losing diagnostic info
- Read each other's EDE, attributing wrong diagnostic to wrong query

**Risk**: EDE passthrough (RFC 8914) silently corrupted under concurrency.

### H14: retryWithoutEDNS dead cancel param

**File**: `server/resolver/nameserver.go:152,360`
**Category**: `dead-code`, `goroutine-lifecycle`

`cancel context.CancelFunc` parameter accepted but never called. On FORMERR retry success,
other errgroup goroutines continue running until timeout — waste of connections and CPU.

### H15: Pool zeroing dependency undocumented

**File**: `server/resolver/recursive_helpers.go:169-178,196-205`
**Category**: `pool-management`, `maintenance-hazard`

`processAnswerWithDNSEC` captures response slices, Puts response, then returns slices in
QueryResult. Safe only because pool.Put zeroes `*dns.Msg`. If pool zeroing is ever removed,
6+ call sites become use-after-free bugs. Not documented.

**Risk**: HIGH maintenance hazard; LOW in current codebase.

### H16: baseMsg.Copy() feeds non-pool allocation into pool

**File**: `server/resolver/nameserver.go:43-45,71-72`
**Category**: `pool-management`, `performance`

`baseMsg.Copy()` creates a `new(dns.Msg)` allocation (not from pool), then
`defer pool.Put(msg)` feeds it into the pool. Accumulates heterogeneous objects,
defeating pool reuse efficiency.

### H17: dnsutil.Prev errors discarded

**File**: `server/resolver/qname_minimise.go:27,41,56`
**Category**: `error-handling`, `panic`

`dnsutil.Prev` errors discarded with `_` at 3 call sites. Invalid offset from malformed
FQDN would cause slice-bounds panic instead of graceful error.
