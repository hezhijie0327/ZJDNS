# 14 · Domain 包深度审计（config + edns）

> 审计 Agent：Phase 1 · Domain
> 覆盖：config/ (7 文件) + edns/ (4 文件)


## Audit Report: config/ (7 files) + edns/ (4 files)

11 non-test files examined across 18 dimensions. 0 CRITICAL, 0 HIGH, 6 MEDIUM, 7 LOW findings.

---

### MEDIUM

**M1 — config/validate.go:351 — DTLS excluded from TLS cert validation**

`validateTLSCertificateConfig` checks `tlsEnabled` against `TLS`, `QUIC`, `HTTPS`, `HTTP3` only — DTLS is absent. If only DTLS (RFC 8094) is enabled without any other TLS protocol, the function short-circuits at the `tlsCert.IsEnabled()` guard, skipping all cert file validation. Users would get a runtime error instead of a clear config validation failure at startup.

```go
tlsEnabled := proto.TLS != "" || proto.QUIC != "" || proto.HTTPS.Port != "" || proto.HTTP3.Port != ""
//                                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//                                    DTLS is missing here
```

- **Risk**: Silent config acceptance → runtime failure when DTLS listener tries to load a missing cert.
- **Fix**: Add `proto.DTLS != ""` to the `tlsEnabled` expression.

---

**M2 — config/validate.go:437 — DTLCP excluded from TLCP cert validation**

`validateTLCPCertificateConfig` checks `tlcpEnabled` against `TLCP` and `HTTPTLCP` only — `DTLCP` is absent. If only DTLCP (GM/T 0128-2023) is enabled, TLCP/SM2 certificate validation is skipped.

```go
tlcpEnabled := proto.TLCP != "" || proto.HTTPTLCP.Port != ""
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
// DTLCP is missing here
```

- **Risk**: Silent config acceptance → runtime failure when DTLCP listener tries to load SM2 certs.
- **Fix**: Add `proto.DTLCP != ""` to the `tlcpEnabled` expression.

---

**M3 — config/ddr.go:167-172 — DDR SVCB dohpath not validated for safe characters**

The `normalizeEndpoint` closure only prepends `/` if missing. Neither `config.validate.go` nor `ddr.go` validates that the HTTP endpoint path contains only SVCB-safe characters (spaces, quotes, semicolons, etc. would break SVCB syntax). The domain/IP safety check at line 64 guards domain/IP but not the endpoint.

```go
// ddr.go:73-81 — no sanitization beyond "/" prefix
normalizeEndpoint := func(ep string) string {
    if ep == "" { ep = DefaultQueryPath }
    if !strings.HasPrefix(ep, "/") { ep = "/" + ep }
    return ep
}
// ddr.go:168 — raw interpolation into SVCB value
content = fmt.Sprintf("%d . alpn=%s port=%s dohpath=\"%s{?dns}\"", ...)
```

- **Risk**: A user-configured endpoint with unsafe characters produces syntactically malformed SVCB records, breaking DDR discovery.
- **Fix**: Validate the endpoint path in `validateConfig` to only contain RFC 9462-safe characters (e.g., `[a-zA-Z0-9/._~-]`).

---

**M4 — config/load.go:42-44 — Stamp-resolved addresses not re-validated after normalization**

`normalizeStamps` runs *after* `validateConfig`. During validation, sdns:// addresses are skipped (validate.go:176: `if !strings.HasPrefix(server.Address, "sdns://")`). After stamp resolution, the resolved concrete address (`s.Address` or `s.BuildDoHURL()`) is never re-validated. A stamp with a malformed embedded address passes stamp parsing but produces an unusable upstream config.

```
Timeline: parse → validateConfig (skips sdns://) → normalizeStamps (replaces address) → [NO RE-VALIDATION] → use
```

- **Risk**: Malformed stamp addresses produce runtime connection failures rather than clear startup errors.
- **Fix**: Run a lightweight address sanity check on resolved addresses after `normalizeStamps` (e.g., non-empty, valid host:port format, valid URL for DoH).

---

**M5 — edns/padding.go:40 — msg.Pack() error discarded**

`msg.Pack()` is called to compute the compressed wire size for padding. The error return is silently discarded (`_ = msg.Pack()`). If packing fails (e.g., message too large, corrupt state), `msg.Data` is stale or empty. The subsequent `currentSize := len(msg.Data)` produces incorrect padding.

```go
_ = msg.Pack()  // error discarded
currentSize := len(msg.Data)
```

- **Risk**: Incorrect padding length calculation on corrupt/unpackable messages; downstream may see malformed EDNS padding.
- **Fix**: Check the error and skip padding (`return 0`) if `Pack()` fails.

---

**M6 — config/ecs.go:136-148 — ECSConfig MarshalJSON round-trip bug for PreferIPv4=false**

`MarshalJSON` uses `omitzero` on `PreferIPv4 bool`, which omits the field when `false`. But `UnmarshalJSON` defaults absent `prefer_ipv4` to `true` (ecs.go:127-128). So `PreferIPv4=false` round-trips as `true`.

```
Marshal(ECSConfig{PreferIPv4: false}) → {"ipv4":"auto"}  // field omitted
Unmarshal({"ipv4":"auto"}) → ECSConfig{PreferIPv4: true}  // defaults to true!
```

- **Risk**: Programmatic config serialization followed by deserialization silently flips `PreferIPv4` to `true`. Only matters when a caller explicitly needs `false`.
- **Fix**: Either remove `omitzero` from `PreferIPv4` in `MarshalJSON`, or use a pointer `*bool` to distinguish absent from false.

---

### LOW

**L1 — config/ddr.go:92 — DDR hint A/AAAA records have TTL=0**

`ZoneRecord{Type: dns.TypeA, Content: ddr.IPv4}` — no TTL set, defaults to 0 (do-not-cache). DDR hint records (RFC 9462) should have a reasonable positive TTL.

```go
cfg.Zone = append(cfg.Zone, ZoneRule{Name: domain, Answer: zoneDirectRecords})
// zoneDirectRecords has TTL=0
```

- **Risk**: Excessive client re-queries for resolver address hints.
- **Fix**: Set TTL (e.g., `DefaultTTL`) on the direct A/AAAA ZoneRecord entries.

**L2 — config/defaults.go:199 — FallbackClientIP "0.0.0.0" used when client IP is nil**

When client IP is nil (internal/background queries), `"0.0.0.0"` is used as the fallback for ECS and cookie generation. This zero-value IP is a real address that could match unexpected CIDR rules or produce degenerate ECS cache keys.

- **Risk**: Low — documented and intentional, but 0.0.0.0 has special semantics that could cause subtle issues with certain ACLs or rules.
- **Fix**: Consider using a loopback address (`127.0.0.1`) or a dedicated sentinel IP instead.

**L3 — edns/cookie.go:178-179, 213 — Reserved bytes extracted but never used in MAC**

`IsServerCookieValid` extracts reserved bytes from the received cookie (lines 178-179) and passes them to `rfc9018MAC`. But `rfc9018MAC` receives `reserved [3]byte` as a parameter and never writes it into the hash buffer — the MAC always uses zero reserved bytes. The parameter is dead code; the extraction is dead code.

```go
var reserved [3]byte
copy(reserved[:], serverCookie[1:4])  // extracted but never used
// ...
expect := rfc9018MAC(&key, clientCookie, reserved, ts, clientIP)
// rfc9018MAC ignores the reserved parameter — always uses zero
```

- **Risk**: None for correctness (MACs match because both sides use zero). But the dead code misleads readers about RFC 9018 compliance.
- **Fix**: Remove the `reserved` parameter from `rfc9018MAC` and remove the extraction.

**L4 — edns/edns.go:91 — ApplyToMessage has 9 parameters, exceeding project guideline**

The method signature has 9 parameters (msg, ecs, isSecureConnection, cookieStr, ede, isRequest, clientWantsPadding, tcpKeepaliveTimeout), violating the project's own guideline: "Group >5 params into config structs."

- **Risk**: Readability, maintainability.
- **Fix**: Extract parameter struct for EDNS options.

**L5 — edns/edns.go:91 — ApplyToMessage is a method on *Handler but never uses the receiver**

All data is passed as parameters; the method never accesses `h` or any field of `Handler`. This is misleading — it looks like it depends on handler state but doesn't.

- **Risk**: Low — no functional impact, but violates "methods use receiver state" convention.
- **Fix**: Convert to a standalone package-level function: `func ApplyEDNS(...)`.

**L6 — edns/ecs.go:26 — ParseFromDNS is a method on *Handler but doesn't use receiver state**

Same pattern as L5 — the only use of `h` is the nil check, after which it statelessly parses the ECS from `msg.Pseudo`.

- **Risk**: Low — cosmetic.
- **Fix**: Convert to standalone function: `func ParseECSFromDNS(msg *dns.Msg) *ECSOption`.

**L7 — edns/cookie.go:272 — ParseCookie is a method on *Handler but doesn't use receiver state**

Same pattern as L5/L6 — uses receiver only for nil check. Stateless parsing of COOKIE option.

- **Risk**: Low — cosmetic.
- **Fix**: Convert to standalone function: `func ParseCookieOption(msg *dns.Msg) *CookieOption`.

**L8 — edns/ecs.go:185 — detectVia allowFallback parameter always false, associated logic dead**

The parameter is documented as "reserved for future IPv4 → IPv6 fallback support and is currently always false." The fallback body (line 192-194) is dead code until the feature is implemented.

- **Risk**: Low — dead code, no functional impact.
- **Fix**: Remove the `allowFallback` parameter and the dead fallback path until needed.

---

### Summary

| Package | File | Line | Severity | Category | Label |
|---------|------|------|----------|----------|-------|
| config | validate.go | 351 | MEDIUM | correctness | DTLS cert validation gap |
| config | validate.go | 437 | MEDIUM | correctness | DTLCP cert validation gap |
| config | ddr.go | 167-172 | MEDIUM | rfc-consistency | DDR dohpath not sanitized |
| config | load.go | 42-44 | MEDIUM | correctness | Stamp addresses not re-validated |
| edns | padding.go | 40 | MEDIUM | error-handling | Pack() error discarded |
| config | ecs.go | 136-148 | MEDIUM | correctness | ECSConfig MarshalJSON round-trip |
| config | ddr.go | 92 | LOW | code-quality | DDR hint A/AAAA TTL=0 |
| config | defaults.go | 199 | LOW | code-quality | FallbackClientIP 0.0.0.0 |
| edns | cookie.go | 178-179,213 | LOW | code-quality | Unused reserved bytes in MAC |
| edns | edns.go | 91 | LOW | architecture | 9 params in ApplyToMessage |
| edns | edns.go | 91 | LOW | code-quality | Unused receiver ApplyToMessage |
| edns | ecs.go | 26 | LOW | code-quality | Unused receiver ParseFromDNS |
| edns | cookie.go | 272 | LOW | code-quality | Unused receiver ParseCookie |
| edns | ecs.go | 185 | LOW | code-quality | Dead allowFallback code |

No import-layer violations found. No data races or unbounded growth issues. No goroutine lifecycle problems. BadgerDB-related config constants are sensible. File declaration order (`type → const → var → func`) is consistently followed. Error wrapping uses `%w` consistently. Context propagation is not needed (synchronous packages). Parameter validation is thorough except for the noted stamp-revalidation gap.