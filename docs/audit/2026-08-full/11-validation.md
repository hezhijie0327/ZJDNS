# validation — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: CrossCut Panic + CrossCut Validation; Error+Context cross-cut
> 发现数量: 6 ({"MEDIUM":2,"LOW":4})

### F1 [MEDIUM] race — Data race on s.wg between DNSCrypt Shutdown swap and accept-loop read
- **文件**: server/protocol/dnscrypt/tcp.go:99
- **问题**: Shutdown() writes `s.wg = &sync.WaitGroup{}` under s.mu (server/protocol/dnscrypt/server.go:385), but the TCP accept loop reads the field at `s.wg.Go(...)` (tcp.go:99) and the UDP read loop at udp.go:108 WITHOUT holding s.mu. The connection-tracking lock (tcp.go:83-87, `s.mu.Lock()/Unlock()` around tcpConns) is released before the wg read, so the read is unsynchronized with Shutdown's swap. Also, serveUDP/serveTCP loops are launched as plain `go s.serveUDP(...)` goroutines (server.go:293/326), not tracked in s.wg — so when Shutdown calls `prevWg.Wait()` (server.go:391) with a zero counter, a concurrent `s.wg.Go` on the old wg violates the WaitGroup Add/Wait rule (sync.WaitGroup: positive-delta Add while Wait is running with counter 0), and Wait may return without that goroutine.
- **风险**: Formal data race (go test -race flags it under concurrent shutdown + traffic). A handler goroutine spawned in the shutdown window either joins the already-returned prevWg or the never-waited fresh wg, escaping shutdown tracking — it finishes as an orphaned goroutine. Impact is bounded in practice (conn read deadlines set to time.Unix(1,0) at server.go:377 force quick exit; no corruption), but the race is confirmed and the WaitGroup misuse can make Shutdown return early.
- **修复建议**: Hold s.mu across the s.wg.Go call (move it inside the existing locked region in tcp.go:83-91 and udp.go:97-108), or read s.wg into a local under s.mu before spawning; alternatively track the accept loops themselves in s.wg so the counter is never zero during Wait.

### F2 [MEDIUM] panic — Unguarded m.refreshCtx.Done() in serveExpiredWithRefresh while the same function nil-guards refreshCtx elsewhere
- **文件**: server/handler/middleware/cache_lookup.go:214
- **问题**: In serveExpiredWithRefresh, the background-update goroutine selected when the client timeout fires calls `case <-m.refreshCtx.Done():` (line 214) with no nil check, while the same function explicitly guards `rc := m.refreshCtx; if rc == nil { rc = context.Background() }` at lines 148-151. The Dependencies struct documents RefreshCtx as an optional field ("Optional fields (nil-checked before use)", chain.go:26-27). A nil context.Context interface calls .Done() → nil-pointer panic.
- **风险**: Latent panic: today server.New() always wires RefreshCtx (server/server.go:75/282), so it is unreachable in current wiring — but any future assembly that omits the documented-optional dependency panics the whole process on the stale-serve timer path instead of degrading. The inconsistent nil-handling (guarded at 148-151, unguarded at 214) is the exact trap the adjacent guard was written to avoid.
- **修复建议**: Use the same local guard: select on `case <-rc.Done():` with the rc fallback already computed above, or add `if m.refreshCtx != nil` around the timer-path goroutine's select.

### F3 [LOW] validation — Aggregate stats query error discarded without comment — DB failure renders silently all-zero stats
- **文件**: cache/stats.go:198
- **问题**: `_ = s.db.SQ.QueryRow(...).Scan(...)` (line 198) discards the error of the 30-column query_stats aggregate without any type/reason comment; the synchronous fallback Exec discards at lines 54 and 57 are likewise uncommented. The identical statements in cache/async_writer.go:168/177 carry the required `// _, _ = result, error: background stats write, non-critical` comments, so this is an inconsistency with the repo's own discard-comment rule, not an intentional-annotation omission. On any DB error (locked, schema drift, I/O) the entire stats display silently reports zeros.
- **风险**: Operator-facing diagnostics silently lie: a broken cache DB produces all-zero stats with no warning line, indistinguishable from a genuinely idle server — exactly the failure mode the commented discards elsewhere are designed to make visible. No crash, no data loss.
- **修复建议**: Add a comment per the repo convention (type + reason), or log a warning once when the scan fails (e.g. `if err := ...Scan(...); err != nil { log.Warnf("DB: stats query failed: %v", err) }`) instead of discarding with `_`.

### F4 [LOW] error-contract/dead-code — ErrDrop sentinel and qctx.Dropped have no producers — the documented drop mechanism is dead
- **文件**: server/handler/middleware.go:66
- **问题**: ErrDrop is defined at middleware.go:66 with an explicit contract ('Returning ErrDrop discards the query silently', middleware.go:22; QueryContext.Dropped field at server/handler/context.go:58) and is checked on every query at server/handler/handler.go:142 via `errors.Is(err, ErrDrop) || qctx.Dropped`. A repo-wide grep (production and test) confirms nothing ever returns ErrDrop or sets Dropped=true — all middleware layers rely on the implicit nil-Res + nil-err path instead. The per-query sentinel check is dead code and the documented API contract is misleading.
- **风险**: Future middleware authors reading the QueryHandler doc comment may implement the drop path via ErrDrop/Dropped and unknowingly exercise an unvalidated mechanism; the redundant errors.Is check runs on every query for no benefit.
- **修复建议**: Either remove ErrDrop and the Dropped field and update the QueryHandler doc comment to state the nil-Res drop contract, or wire at least one real producer (e.g. a drop decision in EDNS/Validation middleware) and add a unit test that exercises handler.go:142.

### F5 [LOW] maintainability — Inconsistent adoption of Go 1.26 errors.AsType[T]: 8 sites still use errors.As(err, &t)
- **文件**: server/handler/middleware/cache_store.go:191
- **问题**: Go 1.26's errors.AsType[T] is already used at internal/dnsutil/dnsutil.go:225, server/upstream/plain/udp.go:190 and cmd/zjdns/cli/probe.go:159, but the older form errors.As(err, &x) remains at server/handler/middleware/cache_store.go:191, server/protocol/tlcp/dtlcp.go:325, server/protocol/tls/dtls.go:144, server/upstream/tls/http3.go:227/235/240/245, server/upstream/tls/https.go:114 and cmd/zjdns/cli/probe.go:313. Functionally identical; purely an idiom inconsistency within the same codebase.
- **风险**: None functional; two competing error-type-assertion idioms make the codebase harder to scan and enforce uniformly.
- **修复建议**: Mechanically convert the remaining errors.As(err, &t) sites to errors.AsType[T] (t is a pointer type in all cases) when touching those files, e.g. `dnsErr, ok := errors.AsType[*resolver.DNSSECError](queryErr)`.

### F6 [LOW] error-handling — isTimeoutOrEOF classifies EPIPE via error-string substring instead of errors.Is
- **文件**: cmd/zjdns/cli/probe.go:163
- **问题**: `return errors.Is(err, io.EOF) || strings.Contains(err.Error(), "broken pipe")` — the 'broken pipe' (EPIPE) condition is detected by substring matching, i.e. the EPIPE sentinel is NOT detectable through the wrap chain with errors.Is, so the code falls back to string matching. If the wrap chain or OS error text changes (different layer wrapping, localization, non-Windows syscall mapping), a pipelining probe misclassifies a gracefully-closed connection as a hard failure (or vice versa) and the RFC 7766 probe result becomes wrong.
- **风险**: Fragile, platform/version-dependent error classification in the --probe --pipeline diagnostic; silently wrong probe verdicts on future platform/error changes.
- **修复建议**: Match the underlying syscall directly, e.g. `errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET)`, keeping the substring check only as a documented last-resort fallback for non-POSIX platforms.
