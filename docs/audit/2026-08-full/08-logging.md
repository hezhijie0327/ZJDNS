# logging — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: CrossCut Logging
> 发现数量: 4 ({"MEDIUM":1,"LOW":3})

### F1 [MEDIUM] log-level — TLCP DoH http.Serve failure logged at Error while identical TLS DoH event is Warn
- **文件**: server/protocol/tlcp/http_tlcp.go:50
- **问题**: In the DoH server goroutine, `log.Errorf("TLCP: DoH serve error: %v", err)` fires when `dohSrv.Serve(tlcpListener)` fails (line 49-51). The exact same event — an http.Serve listener failure — is logged at Warn in the TLS DoH server: server/protocol/tls/https.go:78 `log.Warnf("TLS: DoH Serve error: %v", err)`. The goroutine swallows the error and returns nil in both cases, so the server keeps running; this is a recoverable listener failure, not an unrecoverable one. Error is otherwise reserved in this codebase for panics, cert-load failures, and startup/shutdown aborts, so monitoring that treats Error as fatal will misread the TLCP event. https.go additionally suppresses noise during shutdown via `s.ctx.Err()` check (https.go:75-77); http_tlcp.go has no such guard (only excludes http.ErrServerClosed).
- **风险**: Recoverable listener failure in TLCP DoH surfaces at Error level, inconsistent with the TLS DoH twin at Warn; operators/alerting that key on Error may treat a non-fatal, self-recovered event as a crash.
- **修复建议**: Align with https.go:78: downgrade to `log.Warnf` and skip logging when the server context is canceled during shutdown.

### F2 [LOW] log-level — Shutdown-time goroutine-group error logged at Error in TLS, at Warn in server core
- **文件**: server/protocol/tls/server.go:397
- **问题**: In TLS Shutdown: `log.Errorf("TLS: Server goroutines finished with error: %v", err)` on `s.serverGroup.Wait()` failure (line 396-398). The identical aggregate event during shutdown is logged at Warn in server core: server/tasks.go:256 `log.Warnf("SERVER: Background goroutines finished with error: %v", err)` (and tasks.go:274 for cache refresh). During shutdown, listener-goroutine errors are expected (listeners are closed underneath them); the TLS package itself already treats individual listener Serve errors as Warn (https.go:78). Same event class, two levels, in the same shutdown flow.
- **风险**: Inconsistent severity for the same 'background group exited with error during shutdown' event; Error inflation on an expected shutdown condition.
- **修复建议**: Use Warnf to match server/tasks.go:256 and the TLS package's own convention for listener errors.

### F3 [LOW] hot-path-logging — Warn logs on per-query cache hot paths (Get/Set/ReverseLookup) violate 'hot-path logs are Debug only' rule
- **文件**: cache/store.go:115
- **问题**: CLAUDE.md states hot-path logs are Debug only, but the per-query cache paths emit Warnf: cache/store.go:115 (Get query failed), :141 (decompress wire), :155 (unpack wire), :359 (commit tx failed), :364 (insert entry failed); cache/stats.go:91 (ReverseLookup, per PTR query); cache/ptr.go:59 (insert ptr_map, inside Set). `_busy_timeout=10000` (database/db.go:63) absorbs transient lock contention, so these only fire on genuine DB trouble — but exactly then (disk full, corruption, WAL issues) every affected query produces a Warn line on the hottest path, flooding the log during the incident. Additionally, the Set-path failures at store.go:359/364 omit qname/qtype even though both are in scope, while the Get-path logs at 115/141/155 include them.
- **风险**: Log flood at Warn on per-query paths during a DB incident, obscuring the incident and slowing query handling; inconsistent context (qname) between Get and Set failure logs.
- **修复建议**: Downgrade DB-failure logs on Get/Set/ReverseLookup to Debug, or keep Warn behind a rate limiter (e.g. once per N seconds), and add qname/qtype to the Set-path commit/insert failure logs for parity with the Get path.

### F4 [LOW] duplicate-logging — ptr_map insert error logged twice for the same event
- **文件**: cache/ptr.go:59
- **问题**: insertPtrMap logs `log.Warnf("CACHE: insert ptr_map failed: %v", err)` at cache/ptr.go:59, then its only caller logs the same error again at cache/store.go:353 `log.Warnf("CACHE: insert ptr_map failed (non-fatal): %v", err)` before returning. One failed INSERT OR REPLACE into ptr_map produces two near-identical Warn lines per cache Set.
- **风险**: Duplicate log lines per event; noisier logs and ambiguous deduplication when grepping for ptr_map failures.
- **修复建议**: Drop the log inside insertPtrMap and keep only the caller-side log at store.go:353 (or vice versa), since the error is always surfaced by the caller.
