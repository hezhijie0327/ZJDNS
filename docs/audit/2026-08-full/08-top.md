# 08-top.md — server wiring + cmd/zjdns

Phase 1 package audit — server lifecycle (`server/`), CLI (`cmd/zjdns/`), load-test client (`docs/benchmark/loadtest/`).
Method: AUDIT-METHODOLOGY.md §1.1 (18 dimensions), §1.3, §4.1, §6.1/6.2. Every file read in full; every cross-package reference verified by grep; findings re-verified against exact code. No code modified.

## Inventory

| File | Lines | Role |
|------|-------|------|
| `server/server.go` | 562 | Server struct, New/Start lifecycle, protocol listener wiring, pprof |
| `server/init.go` | 111 | initResolver, dynamic zone content wiring (stats/whoami/*.clear) |
| `server/tasks.go` | 306 | Background tickers, ECS refresh, signal handling, shutdownServer |
| `server/bridge.go` | 365 | UDP/TCP protocol bridge, TCP write serialization, wire truncation |
| `cmd/zjdns/main.go` | 71 | Entry, errLogged sentinel, config load, exit codes |
| `cmd/zjdns/banner.go` | 24 | Banner (strings.ReplaceAll, no fmt verbs) |
| `cmd/zjdns/version.go` | 36 | Version/CommitHash/BuildTime |
| `cmd/zjdns/cli/parse.go` | 273 | Flag parsing, mode exclusivity, dispatch, exit codes |
| `cmd/zjdns/cli/dnsstamp.go` | 162 | sdns:// decode/encode |
| `cmd/zjdns/cli/generate.go` | 110 | Example config / DNSCrypt config generation |
| `cmd/zjdns/cli/probe.go` | 334 | RFC 7766 pipeline / RFC 1035 reuse / idle-timeout probes |
| `cmd/zjdns/cli/sql.go` | 142 | Read-only SQL + RW SQL with confirmation |
| `docs/benchmark/loadtest/main.go` | 135 | Multi-protocol load generator |

Cross-refs verified: `Server` satisfies `edns.DNSHandler` (edns/edns.go:21, passed as `s` to dnscrypt/tlcp Start); `plain.Start(g Group, ctx, handler)` / `plain.Shutdown(ctx)` (plain/server.go:34,43); `tls.New(dnsHandler, cfg)` (tls/server.go:101) / `tls.Shutdown() error` (tls/server.go:333); `dnscrypt.New` / `Shutdown(ctx)` returns `ErrServerNotStarted` when not started; `tlcp.New` / `Shutdown()`; `upstream.Client.WarmUpConnections/ExecuteQuery/SetKTLS/Close`; `resolver.New/ConfigureServers/UpstreamServers/LoadRootHints`; `handler.NewHandler` (handler.go:64) with matching `middleware.Dependencies` fields; all config constants referenced from `config/defaults.go` exist and are positive (ticker intervals safe for `time.NewTicker`); `log.TimeCache.Stop()` is `closeOnce`-guarded (idempotent). `go vet` + `go build ./...` clean.

## Findings

### HIGH

- [HIGH/cache-corruption] server/bridge.go:276 + cache/store.go:729-748 + cache/async_cache.go:104-108 — `truncateWire` mutates `response.Data` in place (TC bit, ANCOUNT/NSCOUNT zeroed, ARCOUNT rewritten), but for entries served from the pending read-through layer `response.Data` IS the shared `msgWire` slice still queued in `cacheWriteItem`; the mutated bytes are flushed to SQLite as the canonical cache row. | risk: oversized (>1400 B or > client EDNS size) UDP cache-hit responses persist a permanently truncated TC=1 answer-less wire for the full TTL — every subsequent UDP **and** TCP hit serves the corrupted truncation; with OPT present the persisted row has ARCOUNT=0 while an OPT record is present (malformed). Deterministic, not racy. Same aliasing class also persists the last requester's message ID/RD via the ID patch (handler/middleware/response.go:60-67). | fix: truncate into a fresh buffer (e.g. `response.Data = truncateWire(slices.Clone(response.Data))`, or `truncateWire` allocates its own output) — the truncation path is rare, so the copy is free; optionally have `cache.Get` copy for the pending path.

### MEDIUM

- [MEDIUM/validation] cmd/zjdns/cli/parse.go:126-131 — `runSQL` is omitted from the mode-exclusivity check (`showVersion, generateConfig, runDNSStamp, runProbeFlag`), contradicting the file's own design comment (parse.go:122-125); `--sql` combined with `--probe`/`--version`/`--dnsstamp`/`--generate-config` silently runs the other mode and discards the SQL request. | risk: silent flag swallowing; user believes the query ran. | fix: add `runSQL` to the `modes` loop.
- [MEDIUM/availability] server/server.go:465-478 — a pprof `ListenAndServe` bind failure (port already in use) is returned from the errgroup and fails `Start()`, taking the entire DNS server down for an optional diagnostics listener; inconsistent with `initPprof`'s own skip-on-error behavior at server.go:378-381 (resolve failure → warn + continue). | risk: DNS outage caused by an auxiliary endpoint's port conflict. | fix: log warn and continue (like the ResolveBindAddrs path), or pre-bind pprof listeners in `initPprof` where errors are already tolerated.
- [MEDIUM/docs] server/server.go:324-326 — comment "Errors are non-fatal — the server starts with the protocols that initialised successfully" contradicts `initProtocolListeners`, which returns the first error (lines 347, 356, 364) and fails `New()`. | risk: misleading maintenance guidance; a TLS/DNSCrypt/TLCP init error aborts all protocols. | fix: correct the comment to describe fail-fast semantics.
- [MEDIUM/close-idempotency] server/tasks.go:299-301 — `shutdownServer` has no idempotency guard; a second invocation panics on `close(s.shutdown)` (double close). Currently only one call site exists (signal handler, tasks.go:176-181), but the function is unguarded and `log.DefaultTimeCache.Stop()` (tasks.go:305) also makes a subsequent `Start()` run with a frozen time cache. | risk: future call site (SIGHUP reload, tests, restart support) crashes the process. | fix: guard with `sync.Once` or `atomic.CompareAndSwapInt32` around the whole shutdown body.
- [MEDIUM/read-only-contract] cmd/zjdns/cli/sql.go:22 + database/db.go:84-88,105-126 — the "read-only" `--sql` tool actually opens a read-write WAL connection: `buildDSN` forces `_journal_mode=WAL&_synchronous=NORMAL&_txlock=immediate`, `database.Open` runs `migrate()` (DDL writes on older DBs) before `PRAGMA query_only=ON` is applied (sql.go:29), and `Close()` runs `PRAGMA optimize` (a write). | risk: unrequested schema migration and -wal/-shm file creation on a DB the user asked to only inspect, possibly a live server DB. | fix: support a read-only open mode (`mode=ro` DSN, skip migrate/optimize) in `database.Open` and use it from `RunSQL`.
- [MEDIUM/measurement] docs/benchmark/loadtest/main.go:87,130 — `elapsed` is derived from deadline math (`time.Since(time.Now().Add(-seconds))`), not the actual query window: on Ctrl-C early exit QPS is divided by the full configured duration (badly understated); `-workers 0` / `-seconds 0` are unvalidated (NaN/Inf output; `latMin` sentinel `1<<62` printed as ~146 years when nothing succeeds). | risk: misleading benchmark numbers. | fix: capture `start := time.Now()` immediately before spawning workers and compute `elapsed` from it; validate workers/seconds ≥ 1.
- [MEDIUM/goroutine-ownership] docs/benchmark/loadtest/main.go:63,70,90 — pprof server goroutine, signal goroutine and worker goroutines lack `defer HandlePanic`; the pprof `_ = http.ListenAndServe(...)` discard is uncommented. | risk: a panic in a worker (or any load-path panic) aborts the whole benchmark run without stats. | fix: wrap worker body with HandlePanic; comment the discard.
- [MEDIUM/constants] cmd/zjdns/cli/probe.go:30-31 — `defaultProbePort = 53` / `defaultProbeTLSPort = 853` duplicate `config.DefaultUDPPort`/`config.DefaultTLSPort` (comment admits "matches"). | risk: cross-package drift if defaults change. | fix: reference `config.DefaultUDPPort`/`config.DefaultTLSPort` directly.

### LOW

- [LOW/constants] server/bridge.go:49 — magic `512` initial capacity for `tcpFramePool`; FNV-1a constants inline (lines 54,57, standard algorithm values, acceptable). | fix: named const.
- [LOW/constants] docs/benchmark/loadtest/main.go:97,46 — magic `1232` (UDPSize; no config constant exists) and `1 << 62` latMin sentinel. | fix: named consts.
- [LOW/validation] server/bridge.go:187,246 — `net.ParseIP(dnsutil.RemoteIP(w))` result never nil-checked; for UDP/TCP `RemoteIP` always returns a valid IP, but a future transport reaching this bridge with an odd `RemoteAddr` type would flow `nil` clientIP into the middleware chain. | fix: guard `if clientIP == nil { return }` or use a fallback.
- [LOW/error-reporting] server/server.go:481-496 — if a protocol goroutine returns an error after shutdown began (listener died during drain), `Start` returns it and main logs "Server startup failed" + exit 1 despite a completed graceful shutdown. | fix: distinguish shutdown-phase errors (log warn, exit 0).
- [LOW/error-reporting] server/tasks.go:218-225 — `dnscryptServer.Shutdown` returns `ErrServerNotStarted` when a signal arrives between `New()` and listener start; logged as `Error` "DNSCRYPT: shutdown failed". | fix: treat `ErrServerNotStarted` as informational.
- [LOW/validation] cmd/zjdns/cli/parse.go:253-256,257 — `--sql` accepts extra positional args silently; `--rw` after positionals is silently ignored (documented in usage at parse.go:100; write attempts then fail with query_only, so the failure surfaces). | fix: reject `len(args) > 2` and warn when `--rw` appears post-positional.
- [LOW/error-discard] cmd/zjdns/cli/probe.go:87,91,96,182,267,296 — `_ =` Close/deadline discards without the methodology-required comment (deadline discards at 199,218,272,298,312 are commented). | fix: add `// _ = error: best-effort close` comments.
- [LOW/security-hygiene] cmd/zjdns/cli/generate.go:33-36 — example config embeds a fixed, valid DNSCrypt private key; users copying the example verbatim publish a known private key. | fix: document prominently or generate a random pair at output time.
- [LOW/goroutine-ownership] server/tasks.go:182-185 — signal-handler goroutine is deliberately untracked (documented NOTE); fine today, fragile if shutdown gains Wait dependencies. | fix: none required; keep NOTE current.

## Package observations

**Lifecycle** — `New()` (build + wire + `startBackgroundTasks()` + arm signal handler) → `Start()` (listeners via errgroup `g`; coordinator goroutine `g.Wait()` → `errChan`; blocks on `for err := range errChan` until the group drains, then `<-s.shutdown`) → `shutdownServer()` (MarkClosed → `s.cancel` → plain/tls/dnscrypt/tlcp/pprof shutdown → wait backgroundGroup (30 s) → wait cacheRefreshGroup (30 s) → close prober → close queryClient → close cache store → `close(s.shutdown)` → stop time cache). The `errChan`/`s.shutdown` coupling is sound: `s.cancel` (called first in shutdown) cancels `serverCtx` (derived from `s.ctx`), draining the errgroup so `errChan` closes, which is what lets `Start` reach `<-s.shutdown`. Background and refresh groups both derive from `s.ctx`, so one cancel drains everything. All `Shutdown()` implementations are nil/start-guarded (dnscrypt returns `ErrServerNotStarted`; TLS/TLCP snapshot under `listenerMu`). `TimeCache.Stop()` idempotent.

**Background tasks** — 6 tasks (cookie rotation, ECS refresh, prefetch cooldown cleanup, tcpWriteMu sweep, query journal cleanup, signal handler), all with `ctx.Done` select + `HandlePanic`; panics in tickers are recovered in-goroutine so the ticker survives; fixed task count (no goroutine-per-tick growth); `cacheRefreshGroup` SetLimit(64); protocol goroutines bounded by `tcpSem` (1024). No restart/backoff logic needed (tickers self-sustain).

**TCP bridge** — write-serialization registry is well-engineered: lookup-or-create + in-flight ref under shard lock closes the sweep TOCTOU; `capacityOnce.Do` lazy init is safe because every reader passes through the Once; pool Get/Put balanced on all three paths (SERVFAIL sync, TCP goroutine, UDP). RFC 2181 §9 truncation is done wire-level with zero allocations (good), but see H1 for the aliasing flaw.

**Signals** — SIGINT/SIGTERM only; no SIGHUP/config-reload (feature gap, documented behavior). Signal handler armed during `New()` (before `Start`); a signal in that window runs shutdownServer against a not-yet-started server — handled gracefully (no-ops + one noisy Error log), and `Start()` then fails fast with "server is closed".

**CLI** — exit codes consistent and documented (0 help/version/success, 1 command failure, 2 flag-parse); `errLogged` sentinel prevents double logging; `%w` chains everywhere in scope; `_` discards in scope mostly commented per methodology §6.1.11; flag-level validation is thorough (mode exclusivity, probe sub-mode pairing, stamp field checks, 32-byte key check).

**Loadtest client** — clean worker lifecycle (`WaitGroup.Go` — Go 1.25+), ctx-cancellable, `defer client.Close()`, atomic counters; per-query `msg := new(dns.Msg)` allocation on the hot loop is fine for a load generator; no rcode-level correctness assertion (throughput tool by design); measurement window inaccuracy noted (M7).

**Go version** — Go 1.26.4 confirmed (go.mod); `errors.AsType[net.Error]` (probe.go:162), `WaitGroup.Go` (loadtest:90), range-over-int, `min/max` all idiomatic. No `go fix` gaps found.
