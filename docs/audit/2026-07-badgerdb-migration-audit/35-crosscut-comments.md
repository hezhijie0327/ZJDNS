# 35 · 交叉分析：注释准确性

> 审计 Agent：Phase 2b · Comments
> 范围：全项目注释引用符号存在性、TODO/FIXME 有效性、过时引用


## Comment Accuracy Audit Report

### Scope

Audited 209 `.go` files across all packages. Searched for:
- Stale function/type/field name references in comments (cross-referenced with go doc / grep)
- TODO/FIXME/HACK/临时 markers
- References to moved/deleted code
- Behavioral claims that mismatch current code
- Stale package path references
- Deprecated notices and historical notes

---

### Findings

#### Finding 1 (Medium) — `server/server.go:377` — Stale package path for DNSHandler interface

**File:** `/Users/hezhijie/Downloads/ZJDNS/server/server.go`  
**Line:** 377  
**Current comment:**
```go
// ServeDNS delegates to the query handler. Required by server/tls.DNSHandler
```
**Problem:** References `server/tls.DNSHandler` but:
- The package is `server/protocol/tls` (not `server/tls` — the `server/tls` package does not exist)
- The interface is `edns.DNSHandler`, defined in `zjdns/edns/edns.go` (line 23), not `server/tls.DNSHandler`

The TLS server's `New()` function accepts `edns.DNSHandler`:
```go
// server/protocol/tls/server.go:98
func New(dnsHandler edns.DNSHandler, cfg *Config) (*Server, error) {
```

**Risk:** Misleading. Anyone searching for "server/tls.DNSHandler" will find nothing. New contributors may be confused about which interface `ServeDNS` implements.

**Fix:** Change to:
```go
// ServeDNS delegates to the query handler. Required by the edns.DNSHandler interface.
```

---

#### Finding 2 (Low) — `cmd/zjdns/cli/generate.go:107` — Old package path in comment

**File:** `/Users/hezhijie/Downloads/ZJDNS/cmd/zjdns/cli/generate.go`  
**Line:** 107  
**Current comment:**
```go
// generateDNSCryptConfig wraps the server/dnscrypt config generator for CLI use.
```
**Problem:** Uses old package path `server/dnscrypt`. The actual package is `server/protocol/dnscrypt` (imported as `serverdnscrypt "zjdns/server/protocol/dnscrypt"` at line 15).

**Risk:** Minor — the comment doesn't match the import path. Could confuse readers searching for the package location.

**Fix:** Change to:
```go
// generateDNSCryptConfig wraps the server/protocol/dnscrypt config generator for CLI use.
```

---

### No Issues Found In These Categories

| Search Target | Result |
|---|---|
| **TODO/FIXME/HACK/XXX** | **Zero found** across all 209 Go files. The codebase has no such markers. |
| **Deprecated / Obsolete notices** | **Zero found** — no `// Deprecated` annotations anywhere. |
| **SQLite / bolt / old storage references** | **Zero found** after recent BadgerDB migration (commit 58d012b). |
| **Backtick-quoted symbol references** | All verified function/type names exist. |
| **Behavioral claims in comments** | All claims checked (terminal stub unreachability, CD bit usage, DNSSEC chain of trust, ECSOption type alias, Execution order in `chain.go`, `sortAnswerByLatency` timing, `VerdictUncertain` unreferenced status, `allowFallback` always-false invariant, pool ownership semantics) match current code. |
| **RFC references** | All 150+ RFC citations verified against context — correct numbers, correct section references. |
| **`sortAnswerByLatency` cross-package references** | `server/resolver/recursive.go:26` and `server/resolver/ns_addresses.go:20` both correctly describe the mechanism — function is in `cache/store.go:142`, called from `cache/store.go:134` at Get() time. |
| **Duplicated constants between internal/ and config/** | All verified matching: `defaultTCPKeepAlivePeriod`, `ipDetectDialTimeout`, `ipDetectTimeout`, `stamp DefaultHTTPSPort/DefaultTLSPort/DefaultDNSPort` (stamp uses int, config uses string — different types, same numeric value, justified by binary encoding vs config parsing). |

---

### Summary

| Severity | Count | Files |
|---|---|---|
| **Medium** (wrong package path, misleading) | 1 | `server/server.go:377` |
| **Low** (minor path inconsistency) | 1 | `cmd/zjdns/cli/generate.go:107` |
| **Informational / Verified Accurate** | 30+ comments checked | Across all packages |

The codebase is exceptionally clean for comment accuracy. No TODO/FIXME/HACK markers exist. All stale path references are from an earlier directory layout before the `server/protocol/` hierarchy was introduced.