# 08 — Logging Quality (日志质量)

Audit date: 2026-07-25
Scope: Every `log.Info`, `log.Warn`, `log.Error`, `log.Debug` call in non-test `.go` files.
Dimension owner: Log Quality (日志质量)

---

## Summary

Found **14 findings** across 5 categories. The codebase has generally good logging hygiene: the vast majority of hot-path logs are correctly at `Debug` level, context is included in most messages, and prefixes follow consistent `PREFIX:` format (no `[PREFIX]` or `PREFIX ` variants). The main issues are:

1. **4 Info/Warn logs that fire on every query** on per-request hot paths — these should either be startup-only or be downgraded to Debug.
2. **1 Error log on an accept loop** that retries internally — should be Warn to match sibling accept loops.
3. **3 context-incomplete logs** that omit qname/qtype in cache read failure paths.
4. **2 format issues**: a missing log prefix in one Debug call, and a non-canonical `"FALLBACK:"` prefix in startup logs.
5. **4 quiet error-return paths** that silently drop errors without logging.

---

## Category: log-spam (Info/Warn on hot paths)

### L-SPAM-1: resolver-not-set Warn on every query

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `server/handler/middleware/resolution.go:28` |
| **Prefix** | `RESOLVER:` (non-canonical — see L-FMT-1) |
| **Message** | `log.Warnf("RESOLVER: resolver not set — returning SERVFAIL")` |
| **Problem** | Fires on **every** query when `m.resolver` is nil. In production this only happens through a wiring bug (config validation ensures resolver is set), but should the check ever fire, it would spam Warn on every request. |
| **Fix** | Either guard this as a startup-time assertion, or downgrade to `log.Debugf` — the SERVFAIL response is visible to clients via the response code regardless. |

### L-SPAM-2: terminal-handler Warn on every query

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/handler/middleware/chain.go:64` |
| **Prefix** | `CHAIN:` (non-canonical — see L-FMT-1) |
| **Message** | `log.Warnf("CHAIN: terminal handler reached — no resolution middleware configured")` |
| **Problem** | Same pattern as L-SPAM-1. The terminal handler stub is only reached if `Resolution` middleware somehow passes-through (which it never does by design). Firing Warn on every query is excessive. |
| **Fix** | Remove the log entirely, or downgrade to Debug. The SERVFAIL response already signals the condition to clients. |

### L-SPAM-3: TLS SkipTLSVerify Warn on every query

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `server/upstream/client.go:212` |
| **Prefix** | `UPSTREAM:` |
| **Message** | `log.Warnf("UPSTREAM: TLS verification disabled for %s — connection is vulnerable to MITM attacks!", server.ServerName)` |
| **Problem** | Fires on **every** query to a TLS upstream with `SkipTLSVerify=true`. The security warning is valuable but should be logged once at startup (in `WarmUpConnections` or config validation), not on every query. For servers with many upstream queries, this creates substantial log volume for no additional signal. |
| **Fix** | Move the warning to `client.go:WarmUpConnections()` or to config validation. Alternatively, gate it behind a `sync.Once` so it fires only once per server. |

### L-SPAM-4: pending-request follower timeout Warn

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **File** | `server/handler/pending.go:121` |
| **Prefix** | `CACHE:` |
| **Message** | `log.Warnf("CACHE: pending-request follower timeout for %s", qname)` |
| **Problem** | Fires for every dedup follower that times out waiting for the leader (60s timeout). Under sustained load with a slow upstream, this could fire many times. It's a recoverable condition (the follower returns SERVFAIL) — Warn is excessive for a per-query event. |
| **Fix** | Downgrade to Debug. The timeout indicates operational concern, but a single occurrence per batch of followers is enough — Warn on every follower amplifies noise unnecessarily. |

---

## Category: log-level (incorrect severity)

### L-LVL-1: DoQ Accept error at Error level

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/protocol/tls/quic.go:91` |
| **Prefix** | `TLS:` |
| **Message** | `log.Errorf("TLS: DoQ Accept error: %v", err)` |
| **Problem** | The accept loop retries after logging (`time.Sleep(DefaultAcceptRetryDelay)`). The DoT accept loop at `tls.go:67` correctly uses `Warnf` for the same pattern. DoQ is inconsistent. |
| **Fix** | Change to `log.Warnf` to match DoT accept pattern. |

---

## Category: log-context (missing qname/qtype/address/error)

### L-CTX-1: cache Get query failed — missing qname/qtype

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `cache/store.go:142-143` |
| **Prefix** | `CACHE:` |
| **Message** | `log.Warnf("CACHE: get query failed: %v", err)` |
| **Problem** | The surrounding function has `qname`, `qtype` available as local variables but they are not included in the log message. Compare to lines 164 and 177 in the same file which include `id, name, type`. Operators cannot determine which query triggered the failure. |
| **Fix** | Include qname and qtype: `log.Warnf("CACHE: get query failed for %s (type=%d): %v", qname, qtype, err)` |

### L-CTX-2: pending-request timeout — missing qtype

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/handler/pending.go:121` |
| **Prefix** | `CACHE:` |
| **Message** | `log.Warnf("CACHE: pending-request follower timeout for %s", qname)` |
| **Problem** | Includes qname but not qtype. The Debug log at line 111 includes both qname and qtype. For Warn logs (which survive higher log levels), missing qtype makes it harder to identify the query class. |
| **Fix** | Add qtype to the Warn message. |

### L-CTX-3: upstream cert fetch error — missing server address

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/upstream/dnscrypt/cert.go:29` |
| **Prefix** | `UPSTREAM:` |
| **Message** | `log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed: %v", tcpErr)` |
| **Problem** | The `addr` parameter is available but not included in the message. When multiple upstreams are configured, it's unclear which server failed. |
| **Fix** | Include addr: `log.Debugf("UPSTREAM: DNSCrypt cert TCP retry failed for %s: %v", addr, tcpErr)` |

---

## Category: log-format (prefix consistency)

### L-FMT-1: Non-canonical log prefixes

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Files** | `server/handler/middleware/chain.go:64`, `server/handler/middleware/resolution.go:28`, `server/handler/middleware/resolution.go:65` |
| **Prefixes** | `CHAIN:`, `RESOLVER:` |
| **Message** | `log.Warnf("CHAIN: ...")`, `log.Warnf("RESOLVER: ...")` |
| **Problem** | `CHAIN:` and `RESOLVER:` are not in the canonical 23-prefix list. Both are used only once and don't align with a canonical component. |
| **Fix** | Replace `CHAIN:` with `RESOLVER:` (it's in the resolver middleware). Replace `RESOLVER:` with `RECURSION:` or `SERVER:` to match existing conventions. Alternatively, add them to the canonical list if they represent distinct logical components. |

### L-FMT-2: "FALLBACK:" prefix not in canonical list

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/server.go:497` (via `logServer("FALLBACK", ...)`) |
| **Prefix** | `FALLBACK:` |
| **Message** | `log.Infof("%s: %s", role, info)` where `role="FALLBACK"` |
| **Problem** | `FALLBACK:` is not in the canonical 23 prefixes. This is a startup-only log (cold path), but consistency matters for log-filtering tools. |
| **Fix** | Change to use the canonical `UPSTREAM:` prefix with a hint in the info string, e.g., `"UPSTREAM: [fallback] %s"`, or add `FALLBACK` to the canonical list. |

### L-FMT-3: Debug log missing prefix entirely

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `internal/dnsutil/dnsutil.go:197` |
| **Prefix** | (none) |
| **Message** | `log.Debugf("%s", buf.String())` |
| **Problem** | No prefix at all. The buffer contains TLS handshake info text but doesn't start with a component prefix. This breaks log filtering by component. |
| **Fix** | Prepend a prefix: `log.Debugf("TLS: %s", buf.String())` — this is called from `server/protocol/tls/server.go` as part of TLS connection info display. |

---

## Category: log-missing (silent error-return paths)

### L-MISS-1: cache refresh failure silently dropped

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/handler/middleware/cache_lookup.go:214-224` |
| **Prefix** | — |
| **Function** | `refreshCacheEntry` |
| **Problem** | `refreshCacheEntry` is called from serve-stale and prefetch paths. When `m.resolver.Query()` returns an error, the function returns without logging. The caller (`tryStartRefresh`/background refresh goroutine) does not log either. Background refresh failures are invisible in logs unless Debug level is enabled (and the upstream debug logs only fire for the leader query path). |
| **Fix** | Add a Debug log when refresh fails: `log.Debugf("CACHE: refresh failed for %s (type=%d): %v", qname, qtype, qr.Err)` |

### L-MISS-2: upstream DNSCrypt WarmUp failure silently ignored

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/upstream/dnscrypt/client.go:167-172` |
| **Prefix** | — |
| **Function** | `WarmUp` |
| **Problem** | When `resolveStamp` fails (e.g., bad stamp URL), the error is silently returned and discarded. The upstream is then used without a pre-warmed certificate, adding latency to the first query. |
| **Fix** | Add a Debug log: `log.Debugf("UPSTREAM: DNSCrypt WarmUp failed for %s: %v", server.Address, err)` |

### L-MISS-3: upstream warmup failures silently ignored in SOCKS5 proxy dialer cache eviction

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/upstream/warmup.go:30-37` |
| **Prefix** | — |
| **Function** | `proxyDialer` (cache eviction path) |
| **Problem** | When the proxy dialer cache is full, stale entries are evicted with `d.Close()` and errors from `Close()` are silently discarded. While this is a cache management detail, when Close fails (e.g., lingering connection), the error is invisible. |
| **Fix** | Use `zdnsutil.CloseWithLog(d, server.Proxy, "UPSTREAM")` instead of `d.Close()` to surface close errors. |

### L-MISS-4: upstream pool QUIC dial failure during warmup silently dropped

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **File** | `server/upstream/pool/quic.go:130-134` |
| **Prefix** | — |
| **Message** | `return nil, fmt.Errorf(...)` — error returned but caller logs at Debug. |
| **Problem** | When `Acquire` dials a new QUIC connection and the pool fills up during dial, the new connection is closed and an error is returned. The caller (`doQUICQuery` in `tls/quic.go`) checks for errors but only logs at Debug level. This is acceptable for Debug but the QUIC warmup path (`WarmUpQUIC` in `tls/client.go`) already logs at Debug. So this is more a consistency observation. No change needed, but noting for completeness. |
| **Status** | No action required — already logged at Debug upstream. |

---

## Summary Table

| ID | Category | Severity | File | Line |
|----|----------|----------|------|------|
| L-SPAM-1 | log-spam | MEDIUM | `server/handler/middleware/resolution.go` | 28 |
| L-SPAM-2 | log-spam | LOW | `server/handler/middleware/chain.go` | 64 |
| L-SPAM-3 | log-spam | MEDIUM | `server/upstream/client.go` | 212 |
| L-SPAM-4 | log-spam | MEDIUM | `server/handler/pending.go` | 121 |
| L-LVL-1 | log-level | LOW | `server/protocol/tls/quic.go` | 91 |
| L-CTX-1 | log-context | LOW | `cache/store.go` | 143 |
| L-CTX-2 | log-context | LOW | `server/handler/pending.go` | 121 |
| L-CTX-3 | log-context | LOW | `server/upstream/dnscrypt/cert.go` | 29 |
| L-FMT-1 | log-format | LOW | `server/handler/middleware/chain.go`, `resolution.go` | 64, 28, 65 |
| L-FMT-2 | log-format | LOW | `server/server.go` | 497 |
| L-FMT-3 | log-format | LOW | `internal/dnsutil/dnsutil.go` | 197 |
| L-MISS-1 | log-missing | LOW | `server/handler/middleware/cache_lookup.go` | 214-224 |
| L-MISS-2 | log-missing | LOW | `server/upstream/dnscrypt/client.go` | 167-172 |
| L-MISS-3 | log-missing | LOW | `server/upstream/warmup.go` | 30-37 |

**3 MEDIUM, 11 LOW**

---

## Positive Observations

1. **Hot-path Debug discipline is excellent.** The query pipeline (`handler.go`, all 10 middleware `Wrap` methods), upstream exchange (`client.go`, `plain/udp.go`, `plain/tcp.go`), and recursive resolution (`recursive.go`, `nameserver.go`, `forward.go`) correctly use `Debugf` for per-request logging. Zero Info/Warn fires on the common happy path.

2. **Context completeness is strong overall.** Most Warn/Error logs include qname, server address, error details. The three context misses (L-CTX-1, L-CTX-2, L-CTX-3) are minor.

3. **Prefix formatting is remarkably consistent.** Every log message uses `PREFIX: message` format (no `[PREFIX]`, no lowercase `prefix:`). The `CloseWithLog` pattern uses dynamic prefix injection, and all callers pass correct canonical prefixes.

4. **Error logs are reserved for genuine unrecoverable conditions.** Database close failures, cert parse failures, accept-loop terminal errors — all correctly use `Errorf`. Recoverable conditions (query failures, timeouts, temp errors) are correctly `Debugf`.

5. **No log.Fatal calls hot paths.** All Fatal logs are in `main.go` startup only.
