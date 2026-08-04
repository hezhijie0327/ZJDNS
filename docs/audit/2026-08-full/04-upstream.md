# upstream — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: server/upstream; Goroutine+Resource
> 发现数量: 14 ({"MEDIUM":2,"LOW":10,"HIGH":2})

### F1 [MEDIUM] lock — Exchange returns while holding c.mu — permanent conn deadlock in defensive branch
- **文件**: server/upstream/pool/tcp.go:158
- **问题**: In Conn.Exchange, c.mu is locked at line 140. The trackingID-collision patch block (lines 149-161) has an early return at line 157-158: `if len(writeBuf) < zdnsutil.DNSFramePrefixLen+2 { return nil, fmt.Errorf(...) }` — it returns WITHOUT c.mu.Unlock() (the sibling closed-check at line 141-143 correctly unlocks first). The mutex stays locked forever: every subsequent Exchange, readLoop's delivery RLock (line 277/294) and close() (line 319) block indefinitely. The conn is never marked dead, so ConnPool.Acquire keeps handing it out and every future query on it hangs until ctx timeout; c.close() can never run, leaking the fd and the readLoop goroutine. The branch is commented as unreachable (a Packed message is always >= 12 bytes, so len(writeBuf)=2+len(msgData) >= 14), but a lock leak inside a defensive branch is a latent permanent-deadlock defect if the invariant ever breaks (e.g. a future Pack change).
- **风险**: If the guard ever fires, the pooled connection deadlocks permanently and poisons the pool slot for that upstream key (fd + goroutine leak, all subsequent queries on that conn fail); even without firing, a return-inside-lock is a defect waiting to trip.
- **修复建议**: Unlock c.mu before the return (or restructure so the writeBuf patch happens after c.mu.Unlock, since the buffer is no longer shared at that point).

### F2 [LOW] comment — Stale comment "Close() nils the map" — maps are never nil'd; contradicts Close() comments
- **文件**: server/upstream/tls/https.go:44
- **问题**: Three call sites claim Close() nils the LRU map to justify their nil guard: tls/https.go:44 and tls/http3.go:85 (`if c.dohTransports != nil { // Close() nils the map — a racing query must not panic`) and tlcp/http_tlcp.go:56 (same for c.httpClient). Verified via grep: no `dohTransports = nil` / `doh3Transports = nil` / `httpClient = nil` exists anywhere. tls/client.go:106-108 and tlcp/client.go:43-44 explicitly state the maps are "intentionally NOT nil'd here — in-flight queries read them (guarded by nil checks at the call sites)". So the nil guards are dead defensive code and the comments describe behavior that does not exist.
- **风险**: Misleading comments; future maintainers may believe Close() clears the maps and rely on the guards instead of on lifecycle ordering.
- **修复建议**: Fix the three call-site comments to match reality (guards are defensive-only; maps die with the Client), or actually nil the maps under the LRU lock and keep the guards.

### F3 [LOW] resource — Cached DoH-over-TLCP client stored with plain Set — concurrent first-use race leaks the losing client
- **文件**: server/upstream/tlcp/http_tlcp.go:89
- **问题**: ExecuteHTTPTLCP builds a new *http.Client (with a fresh http.Transport) on a cache miss and stores it with `c.httpClient.Set(key, httpClient)` (line 88-90). Two concurrent first queries for the same server both miss, both build clients, and the second Set replaces the first — the losing client (and its transport) is never closed. lrumap.Set on an existing key replaces e.val in place without invoking OnEvict (lru.go:84-88). The tls package handles this exact race with LoadOrStore + explicit close of the loser (tls/https.go createDOHClient lines 164-170; tls/http3.go lines 205-211); tlcp does not. The losing transport's TLCP idle connection stays open until IdleConnTimeout (config.DefaultHTTPIdleConnTimeout) or GC.
- **风险**: Under concurrent first-use of a TLCP upstream, one orphaned client leaks its connection for up to the idle timeout; pattern inconsistency with the tls package.
- **修复建议**: Use LoadOrStore and CloseIdleConnections() on the losing client, matching tls/createDOHClient.

### F4 [LOW] inefficiency — Per-query 4096-byte heap allocation for DNSCrypt UDP response buffer
- **文件**: server/upstream/dnscrypt/client.go:150
- **问题**: executeOnce allocates `respBuf := make([]byte, config.DefaultDNSCryptUDPSize)` (4096) on every DNSCrypt UDP query (line 150). Every other UDP read path in the codebase reuses a sync.Pool: spoofguardBufPool in plain/udp.go is the exact same 4096 size (RFC 6891 §6.2.5 bound), and socks5.ReadPool/socks5ReadBufPool cover the proxy paths. A 4KB alloc per query is a measurable hot-path allocation for a recursive server.
- **风险**: Unnecessary per-query heap allocation on the DNSCrypt path; inconsistent with the pooling discipline used everywhere else.
- **修复建议**: Add a package-level sync.Pool of 4096-byte buffers (mirroring spoofguardBufPool) and clear() before Put, or reuse the existing pattern.

### F5 [LOW] logic — deleteState on plain read timeout invalidates the 1-hour cert cache on any packet loss
- **文件**: server/upstream/dnscrypt/client.go:153
- **问题**: executeOnce calls c.deleteState(stampAddr, providerName) on ANY UDP read error (line 152-155), decrypt error (163-166) and unpack error (202-205). A read timeout — the most common error under packet loss — triggers cert-cache invalidation even though the server may not have rotated its certificate. The next query then pays a full plain-DNS cert TXT fetch (state.go state() cache miss) before it can send the real encrypted query. Under lossy networks each timeout cascades into extra refetches; the DefaultDNSCryptCertificateCacheTTL (1h) cache becomes ineffective exactly when the network is bad. Decrypt failure is the legitimate invalidation case (key rotation); read timeout is not.
- **风险**: Wasted cert re-fetches (extra RTTs) per lost packet on the DNSCrypt path; degraded performance precisely under packet loss.
- **修复建议**: Only invalidate state on decrypt/unpack failures (evidence of cert rotation); for read errors/timeouts return the error without deleteState.

### F6 [LOW] context — context.Background() used for relay-host DNS lookup in readAddress
- **文件**: server/upstream/socks5/socks5.go:480
- **问题**: In readAddress, the ATYPDomain branch resolves the SOCKS5 relay hostname with `lookupCtx := context.Background()` (line 480), bounded only by a deadline derived from the connection's deadline via context.WithDeadline (lines 481-487). If a caller ever reaches readAddress without having set a deadline on the conn (establishUDPRelay only sets one when ctx has a deadline or d.timeout > 0), the lookup is unbounded — blocking the handshake goroutine and fd indefinitely. This is the flagged production context.Background() pattern; every other I/O path in the package carries ctx.
- **风险**: Unbounded DNS lookup blocks the SOCKS5 negotiation goroutine if no deadline was set; violates the codebase's ctx-first convention.
- **修复建议**: Thread ctx into readAddress (it is always available at both call sites: connect and establishUDPRelay) and use ctx directly instead of deriving from conn.Deadline().

### F7 [LOW] race — Close() nils c.proxyDialers unsynchronized — check-then-use race window with concurrent proxyDialer()
- **文件**: server/upstream/client.go:306
- **问题**: Client.Close() sets `c.proxyDialers = nil` (line 306) after Range-closing the dialers. warmup.go proxyDialer() concurrently does `if c.proxyDialers == nil { return nil }` then `c.proxyDialers.Get(...)` / `c.proxyDialers.Set(...)` without any synchronization. A nil map read is safe, but the nil-check-then-Set window means a query racing with Close can hit `c.proxyDialers.Set` on a nil map (lrumap.Map.Set → m.m[key]=e on nil m.m) and panic. The same shutdown concern is explicitly handled differently in tls/client.go Close() (lines 106-108: maps "intentionally NOT nil'd here — a nil write would race those reads"). The nil write here is the pattern the sibling code deliberately avoids.
- **风险**: Shutdown-time panic (Set on nil map) or silent proxy drop (query returns nil dialer) if Close races an in-flight query's first proxy use; inconsistent with the documented tls.Close convention.
- **修复建议**: Don't nil c.proxyDialers in Close (leave it to GC, matching tls.Client.Close), or guard with an atomic flag checked under the same lock as the map operations.

### F8 [LOW] comment — Stale doc comment on NewConnPool references "NewPool" and type "Pool"
- **文件**: server/upstream/pool/tcp.go:342
- **问题**: Line 342-343: `// NewPool creates a Pool with the specified connection and in-flight limits.` precedes `func NewConnPool(maxConns, maxPipe int) *ConnPool`. The comment names a function (NewPool) and a type (Pool) that do not exist — the actual symbols are NewConnPool/ConnPool. The doc would render as stale godoc for an exported function.
- **风险**: Misleading exported godoc; a reader grepping for "Pool" constructor semantics sees a non-existent name.
- **修复建议**: Update the comment to "NewConnPool creates a ConnPool with the specified connection and in-flight limits."

### F9 [LOW] logic — DoH transport evicted on any error incl. caller-side timeout — contradicts http3.go's deliberate non-eviction policy
- **文件**: server/upstream/tls/https.go:74
- **问题**: ExecuteHTTPS ends with `if err != nil && c.dohTransports != nil && c.dohTransports.CompareAndDelete(key, client) { ... CloseIdleConnections() }` (lines 74-78) — the cached transport is evicted on ANY error, including context.DeadlineExceeded from caller-side cancellation and HTTP-level errors. The DoH3 counterpart explicitly documents the opposite policy (tls/http3.go lines 126-133: "Caller-side cancellation, deadline expiry, and HTTP-level errors do not mean the transport is broken — tearing it down would hurt concurrent requests"). A single timed-out query tears down the shared H2 transport (pooled conns closed), forcing a fresh TLS handshake and cache rebuild for all subsequent queries to that upstream.
- **风险**: Transport churn under load/timeouts: one caller's deadline expiry drops the shared pooled DoH connections and adds handshake latency for concurrent and future queries.
- **修复建议**: Gate the final eviction on a transport-level failure (e.g. reuse shouldRetryHTTP or a connection-reset check) instead of evicting on every error, matching the http3.go policy.

### F10 [LOW] validation — Invalid proxy URL silently downgrades cached DoH transport to direct dial
- **文件**: server/upstream/tls/https.go:143
- **问题**: In createDOHClient, when proxyURL != "" but c.getProxy returns nil (URL failed to parse — socks5.New error), the `transport.DialContext = proxyDialer.DialContext` assignment (line 144) is skipped and the transport keeps its default dialer: queries go DIRECT to the DoH server, bypassing the configured proxy. The resulting client is then cached under the proxy-bearing key (LoadOrStore, line 164), so the direct-dial downgrade persists for the cache entry's lifetime even after the proxy URL is fixed (until LRU eviction at DefaultTransportMax*2 entries). The one-shot warning (warmup.go logProxyError) does not signal that the downgrade is now cached.
- **风险**: User-configured proxying is silently bypassed (source-IP exposure through the direct connection) and the downgrade persists after the proxy config is corrected.
- **修复建议**: When the proxy URL is invalid for a proxied upstream, fail the query (or skip caching the client) instead of falling back to a direct-dialing transport that then gets cached.

### F11 [HIGH] resource-leak — tcpWriteMu sweep is dead code — per-client entries leak forever
- **文件**: server/bridge.go:56
- **问题**: Every tcpWriteEntry permanently holds refs==1. bridge.go:56 increments refs before publishing (`newEntry.refs.Add(1)`, repeated for the loaded entry at line 65) as the map-ownership ref, then line 76 adds the in-flight ref (+1) which is the only one ever released (bridge.go:81 and bridge.go:121). Net refcount after any request completes is 1 — it can never reach 0. The sweep in server/tasks.go:132 (`if entry.refs.Load() != 0 { return true }`) therefore never deletes anything; the `lastAccess` cutoff at tasks.go:135 is unreachable. The comment at bridge.go:49-54 documents the intent ('the writeMu sweep deletes entries with refs == 0') — the pre-increment race fix made 0 unreachable, so the periodic 5-minute sweep is a no-op.
- **风险**: tcpWriteMu (a sync.Map) grows by one entry per distinct client TCP address for the server's entire lifetime — unbounded memory growth on any public-facing deployment with client-IP churn (each entry holds two channels plus atomics). The stale-entry eviction the sweep was designed to provide never happens.
- **修复建议**: Delete entries whose refs == 1 (map ownership only, no in-flight request): change tasks.go:132 to `if entry.refs.Load() > 1 { return true }` so a fully-released entry (refs==1, lastAccess stale) is deleted; optionally release the map-ownership ref on delete.

### F12 [HIGH] goroutine-leak — Per-query fire-and-forget NS probe goroutines with no lifecycle owner and no global bound
- **文件**: server/resolver/nameserver.go:372
- **问题**: On the recursive hot path, up to ~13 goroutines per query are spawned `go func() { defer zdnsutil.HandlePanic("NS addr probe"); probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()` — nameserver.go:372 (per NS name in resolveNSAddressesConcurrent), recursive_ns.go:142 (per glue NS name in cacheGlueRecords), ns_addresses.go:95 and ns_addresses.go:204 (cache refresh path). Each call creates a fresh latency.Prober (probe.go:226, ctx=context.Background, sem cap=DefaultMaxProbes=16) and spawns min(len(ips),16) worker goroutines bounded only by DefaultNSProbeTimeout=5s. Dedup is per sorted-IP-set singleflight (nsPending) while in flight plus a 60s per-IP throttle (DefaultLatencyProbeMinInterval) — an attacker in recursive mode controls referral NS names and in-bailiwick glue IPs, so unique IP sets per query bypass both. None of these goroutines are in an errgroup/WaitGroup; shutdown does not wait for them (only the cache's IsClosed guard prevents use-after-close).
- **风险**: Unbounded goroutine/memory amplification in recursive mode: ~QPS × 13 probe goroutines × up to 16 workers each, each living up to 5s (e.g. ~650k concurrent probe goroutines at 10k QPS with attacker-controlled TTL=0 referrals), exhausting goroutines and heap.
- **修复建议**: Run probes through a shared bounded executor (e.g. a single global semaphore of DefaultMaxProbes, or reuse the existing backgroundGroup with SetLimit) and track their lifetime so shutdown can wait for them instead of fire-and-forget per query.

### F13 [MEDIUM] resource-lifecycle — TLS/TLCP Shutdown can stall up to 60s — active connection read deadlines never shortened
- **文件**: server/protocol/tls/server.go:396
- **问题**: tls.Shutdown() (server.go:396, no context) calls s.serverGroup.Wait() while per-connection handlers (tls.go:165-189) may be blocked in io.ReadFull with a per-message read deadline of config.DefaultTCPPoolIdleTimeout (60s), refreshed on every message; cancellation of s.ctx does not unblock a pending read. The same pattern exists in server/protocol/tlcp/server.go:223 (serverGroup.Wait with handlers bounded by 60s deadlines, tlcp.go:93). This exceeds the intended DefaultShutdownTimeout=15s graceful budget — shutdownServer (server/tasks.go:210-214) calls tls.Shutdown() without its own timeout, so a busy server can take up to 60s to drain idle connections. DNSCrypt does this correctly: server/protocol/dnscrypt/server.go:377 sets `SetReadDeadline(time.Unix(1,0))` on tracked connections before waiting.
- **风险**: Graceful shutdown takes up to 60s instead of the configured 15s; repeated reload/restart cycles accumulate downtime, and the signal handler blocks on shutdownServer for that long.
- **修复建议**: Track accepted connections (like DNSCrypt's tcpConns map) and force SetReadDeadline(time.Now()) on all of them before serverGroup.Wait() in both TLS and TLCP Shutdown.

### F14 [LOW] resource-lifecycle — lrumap OnEvict runs blocking Close under the map mutex
- **文件**: server/upstream/client.go:115
- **问题**: internal/lrumap/lru.go:226 invokes OnEvict with m.mu held (documented contract: 'must not block', lru.go:35). upstream/client.go:115-118 registers proxyDialers.OnEvict = socks5.Dialer.Close, which acquires d.mu and performs socket Close syscalls (socks5/socks5.go:194-199 → cleanupLocked closes ctrlConn + udpConn) while every concurrent proxy dialer lookup blocks on the LRU mutex. Same pattern in internal/latency/httppool.go:89-98, which holds p.mu while calling http3.Transport.Close() (can block on QUIC connection teardown). No lock inversion was found, but a slow close stalls the upstream hot path's proxy lookup for all queries.
- **风险**: Under a slow/stalled socket close, proxy dialer lookups on the per-query upstream path block on the LRU mutex, adding latency or stalling queries.
- **修复建议**: Collect evicted values during eviction and call Close outside the map mutex (the lock is held in evictLocked/Clear), or perform eviction callbacks asynchronously.
