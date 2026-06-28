# ZJDNS Comprehensive Audit Plan

## Audit Date: 2026-06-28
## Scope: Entire codebase — memory, security, performance, dead code, const/var, docs

---

## 1. MEMORY LEAKS & RESOURCE LEAKS

### 1.1 [HIGH] Rate limiter map unbounded growth between sweeps
- **File**: `server/server.go:101` — `rateLimiter.allow()`
- **Issue**: Under DDoS with spoofed IPs, `rl.entries` map can grow to `maxEntries` (10000) quickly, but all entries stay in the map for 5 minutes until the sweeper runs. A 10k×5min window is worse than it needs to be.
- **Fix**: Reduce sweep interval from `DefaultSweepInterval` (5 min) to 30s for rate limiter specifically, or implement per-entry TTL tracking.

### 1.2 [MEDIUM] TCP write mutex map never shrinks under normal operation
- **File**: `server/server.go:412-423` — `startTCPWriteMuSweep()`
- **Issue**: `tcpWriteMu` entries are deleted after `DefaultTCPWriteMuStaleCutoff` (10 min). Under moderate churn, entries can accumulate. Each entry holds a `capacity` channel (size `DefaultMaxPipe`=16) and `writeMu` channel — that's ~200 bytes per entry.
- **Fix**: Reduce cutoff to 2 minutes; connections don't live that long.

### 1.3 [LOW] PTR sweeper goroutine has no explicit stop
- **File**: `cache/memory.go:211-237` — `startPTRSweeper()`
- **Issue**: The sweeper goroutine uses a `time.Ticker` but only checks `mc.closed` on each tick, and it's never stopped via a channel. It will eventually exit when the process terminates, but during normal shutdown it leaks until GC.
- **Fix**: Add a `persistStop`-style stop channel and close it in `Close()`.

### 1.4 [LOW] Socks5Dialer control-connection monitor goroutine
- **File**: `server/client/socks5.go:368-376`
- **Issue**: The goroutine reading from `ctrlConn` blocks until the connection dies. If the proxy never closes the connection, this goroutine lives forever.
- **Fix**: Add a context or done channel to allow explicit cleanup.

---

## 2. PERFORMANCE ISSUES

### 2.1 [HIGH] Type assertion on hot PTR lookup path
- **File**: `server/handler.go:297-299`
- **Issue**: `s.cacheMgr.(interface { ReverseLookup(net.IP) []cache.LookupResult })` type assertion on every PTR query. Type assertions have non-trivial cost.
- **Fix**: Cache the result of this type assertion once during server creation, store as a concrete interface.

### 2.2 [HIGH] Inner WaitGroup blocks errgroup concurrency slots
- **File**: `server/resolver/nameserver.go:258-304`
- **Issue**: `wg.Add(2)` / `wg.Wait()` inside errgroup goroutines. Each NS resolution takes 2 errgroup slots (one for A, one for AAAA) PLUS the outer errgroup slot is held waiting. With 3 NS records and limit=3, all 3 slots can be blocked in Wait(), stalling AAAA resolution.
- **Fix**: Replace inner WaitGroup with a sub-errgroup or use a channel-based fan-out.

### 2.3 [MEDIUM] `BuildCacheKey` allocates intermediate strings
- **File**: `cache/cache.go:138-162`
- **Issue**: `strconv.FormatUint(uint64(qtype), 10)` returns a string that is immediately written to the builder. This creates an allocation that could be avoided with `strconv.AppendUint` or writing directly.
- **Fix**: Use `strconv.AppendUint` with a small buffer, or `fmt.Fprintf` directly.

### 2.4 [MEDIUM] EDNS re-parsing in `addEDNS`
- **File**: `server/message.go:14-32` — `addEDNS()`
- **Issue**: `addEDNS` re-parses `req.IsEdns0()` even though `processDNSQuery` already parsed it. On the cache-hit path, `processCacheHit` already has `clientRequestedDNSSEC` and `ecsOpt`.
- **Fix**: Refactor to accept pre-parsed values; eliminate the `addEDNS` wrapper or make it accept parsed options.

### 2.5 [LOW] `detectRequestProtocol` uses strings.ToLower + HasPrefix
- **File**: `server/handler.go:539-554`
- **Issue**: `strings.HasPrefix(strings.ToLower(network), "tcp")` allocates a new lowercase string on every call. Could be done more efficiently.
- **Fix**: Use case-insensitive comparison on first byte only ('t' vs 'T', 'u' vs 'U').

### 2.6 [LOW] `compact()` in cache uses linear duplicate scan
- **File**: `cache/memory.go:495-521`
- **Issue**: `seen []string` with linear `for _, s := range seen` comparison is O(n²) in the number of records. For responses with many records (large DNSKEY RRsets), this is wasteful.
- **Fix**: Use `map[string]struct{}` for dedup.

### 2.7 [LOW] `sanitizeLogMessage` always allocates
- **File**: `internal/log/log.go:167-181`
- **Issue**: `sanitizeLogMessage` always allocates `make([]byte, 0, len(msg))` even when the message has no special characters. This is called on every log line on the hot path.
- **Fix**: Fast-path scan first; only allocate when replacement is needed.

---

## 3. DEAD CODE / UNUSED

### 3.1 `ErrAllUpstreamFailed` — defined, never used
- **File**: `server/resolver/upstream.go:29-31`
- **Fix**: Remove.

### 3.2 `StatsPersistInterval()` — defined, never called
- **File**: `config/config.go:188-193`
- **Fix**: Remove.

### 3.3 `clonePTRs()` — defined, never called
- **File**: `cache/memory.go:486-493`
- **Fix**: Remove.

### 3.4 `DefaultPprofPort` — defined, never used
- **File**: `config/defaults.go:11`
- **Fix**: Remove (pprof port comes from config JSON, no default needed).

### 3.5 `DefaultMaxConcurrentStreams` — defined, never used
- **File**: `config/defaults.go:88`
- **Fix**: Remove.

### 3.6 `DefaultServerGoroutineLimit` — defined, never used
- **File**: `config/defaults.go:90`
- **Fix**: Remove.

### 3.7 `DefaultDoTWriteChannelSize` — defined, never used
- **File**: `config/defaults.go:106`
- **Fix**: Remove.

### 3.8 `DefaultDedupSweepThreshold` — defined, never used
- **File**: `config/defaults.go:110`
- **Fix**: Remove.

### 3.9 `BytesPerMB` — defined, never used
- **File**: `config/defaults.go:119`
- **Fix**: Remove (the cache code uses `1024*1024` inline).

### 3.10 `DefaultProbeUDPReadBufSize`, `DefaultProbeICMPDataSize`, `DefaultProbeICMPReadBufSize` — NEVER USED
- **File**: `config/defaults.go:144-146`
- **Fix**: Remove (if not used in latency package, check first).

### 3.11 `hmacContextClient` — unused field/constant
- **File**: `edns/cookie.go:23`
- **Issue**: `const hmacContextClient = "client"` — used in `GenerateClientCookie` but that function is never called from anywhere in the codebase.
- **Fix**: Keep `GenerateClientCookie` (it's part of the public API), but verify it's truly unused. If unused, remove both the function and the constant.

### 3.12 `rootServersDomain` — questionable scope
- **File**: `server/security/hijack.go:13`
- **Issue**: `const rootServersDomain = "root-servers.net"` — used only in `isRootServerGlue`. Fine as-is, but verify this is actually still accurate for all root servers (some use `root-servers.org`).

---

## 4. CONST/VAR VIOLATIONS (Hardcoded literals not using named constants)

### 4.1 Server package
- `server/server.go:38`: `const nanosPerSecond int64 = 1e9` → use `time.Second.Nanoseconds()` inline, or define in defaults as `NanosPerSecond`
- `server/message.go:53`: `"0.0.0.0"` → use `config.FallbackClientIP`
- `server/handler.go:542,550,552`: `"UDP"` / `"TCP"` → use `config.ProtoUDP` / `config.ProtoTCP`
- `server/handler.go:82`: `config.DefaultDNSQueryTimeout` for write timer, ok

### 4.2 EDNS package
- `edns/cookie.go:23`: `cookieSecretSize = 32` → use `config.DefaultCookieSecretSize` (already has the same value)
- `edns/cookie.go:88,113`: `"0.0.0.0"` → use `config.FallbackClientIP`
- `edns/cookie.go:23`: `hmacContextClient = "client"` → keep local (it's a crypto context string, not a config default)

### 4.3 Cache package
- `cache/cache.go:166-169`: `createCompactRecord` uses zero-value checks — OK
- `cache/memory.go:71`: `1024*1024` → use `config.BytesPerMB` (but we're removing that — define locally or keep inline)

### 4.4 Resolver package
- `server/resolver/nameserver.go:391`: `const unknownRank = math.MaxInt32` → local const OK
- `server/resolver/recursive.go:40-43`: `nsAddrKeyPrefix`/`nsAddrKeySuffix` → these are cache key format strings, local consts OK

### 4.5 Security package
- `server/security/hijack.go:13`: `rootServersDomain` → local const OK

### 4.6 TLS package
- `server/tls/doh.go:149,164`: `DoHMaxRequestSize` — should this be `config.DefaultDoHMaxRequestSize`?
- **Missing constant**: `DoHMaxRequestSize` is referenced but where is it defined? Search needed.

---

## 5. SECURITY ISSUES

### 5.1 [MEDIUM] DoHMaxRequestSize undefined/unsourced
- **File**: `server/tls/doh.go:149,164`
- **Issue**: `DoHMaxRequestSize` is used on lines 149 and 164 but I need to verify it's defined. If it's a local const in the tls package that's fine. If it's undefined, this is a compiler error.
- **Action**: Verify definition; add to `config/defaults.go` if appropriate.

### 5.2 [LOW] SOCKS5 domain name resolution leaks proxy topology
- **File**: `server/client/socks5.go:636-640`
- **Issue**: When `readAddress` encounters a domain name ATYP in the SOCKS5 response, it resolves the domain via the system resolver. This could leak proxy topology information.
- **Fix**: Use only IP literals; reject domain names in SOCKS5 responses.

### 5.3 [LOW] `sanitizeLogMessage` allows NUL bytes
- **File**: `internal/log/log.go:167-181`
- **Issue**: The sanitization allows `\x00` (NUL) bytes through. Some log processors (journald, syslog) may truncate at NUL.
- **Fix**: Replace NUL bytes with spaces.

### 5.4 [INFO] Config validation gap: TLS port = DNS port
- **File**: `config/config.go:419-438`
- **Issue**: No check if TLS/HTTPS ports conflict with the main DNS port. Running DoH on port 53 would conflict.
- **Fix**: Add conflict detection.

---

## 6. CODE REDUNDANCY / NON-IDIOMATIC PATTERNS

### 6.1 Duplicate ECS refresh logic
- **File**: `server/server.go:325-361` — `startECSRefresh()`
- **Issue**: The initial refresh and ticker refresh have the same 5-line logic copy-pasted. If changed in one place, the other would diverge.
- **Fix**: Extract a helper method.

### 6.2 `displayInfo` has verbose string building
- **File**: `server/server.go:719-785`
- **Issue**: Uses `fmt.Sprintf` in a loop for displayInfo; could use `strings.Builder`.
- **Fix**: Minor — this is startup-only, not hot path.

### 6.3 `close(chan)` ordering in `shutdownServer`
- **File**: `server/server.go:467-583`
- **Issue**: `close(s.shutdown)` is at the end, but `shutdownServer` already called `cancel()`. If `shutdownServer` is called from `setupSignalHandling`, `Start()` will see `<-s.shutdown`. Order is correct but fragile.
- **Fix**: Document the ordering.

### 6.4 `BenchmarkShuffleSlice` calls ShuffleSlice with nil
- **File**: `bench_test.go:145`
- **Issue**: `resolver.ShuffleSlice[[]string](nil)` — meaningless benchmark call. The generic type parameter is also wrong (should be `[]string` not `[][]string`).
- **Fix**: Remove the nil call or fix the type parameter.

---

## 7. DOCUMENTATION ISSUES (CLAUDE.md & README.md)

### 7.1 README.md stale max age
- **Line 52**: "过期缓存服务 (RFC 8767)：上游不可用时返回过期缓存（最大 45 天）"
- **Code**: `config/defaults.go:23` — `DefaultStaleMaxAge = 30 * 86400` (30 days)
- **Fix**: Update README to say 30 days.

### 7.2 README.md missing DNSCrypt feature
- DNSCrypt v2 server + client was added as standalone feature (commit `8223da3`), but README doesn't document it in the features or transport table.
- **Fix**: Add DNSCrypt row to transport table and features section.

### 7.3 README.md cache persistence interval
- **Line 50**: says "磁盘持久化：gob 快照，启动恢复，定时落盘，原子写入"
- Should mention the default interval (30s) and that it's configurable.

### 7.4 CLAUDE.md package structure
- The package structure in CLAUDE.md §Package Structure shows `server/client/` with 11 files but doesn't list the `dnscrypt.go` file that was added.
- **Fix**: Add `dnscrypt.go` to client listing.

### 7.5 CLAUDE.md DefaultStaleMaxAge
- **Line**: `DefaultStaleMaxAge`: 30 days (correct in CLAUDE.md, incorrect in README)

### 7.6 CLAUDE.md Go version
- CLAUDE.md says "Go 1.26" — go.mod says `go 1.26.0`. Correct.

### 7.7 CLAUDE.md constraint table completeness
- Missing entries: `DefaultDNSCryptTCPReadTimeout`, `DefaultDNSCryptTCPIdleTimeout`, `DefaultProbeUDPReadBufSize` (if used), `DefaultInfraProbeTimeout`

---

## 8. REFACTORING OPPORTUNITIES

### 8.1 Unify `queryResult` and `result` structs
- `server/server.go:157-165` — `queryResult` (server package)
- `server/resolver/upstream.go:20-28` — `result` (resolver package)
- These are nearly identical (answer/authority/additional/validated/ecs).
- **Fix**: Use `resolver.QueryResult` everywhere; eliminate `queryResult`.

### 8.2 Server field ordering for cache line optimization
- `server/server.go:41-69` — Server struct fields
- `closed int32` is far from the hot-path fields. Better to group hot-path atomics together.
- **Fix**: Reorder for better cache line packing.

### 8.3 `generateCookieResponse` logic duplication
- `server/message.go:47-78` — `generateCookieResponse`
- Three code paths generate `serverCookie` with nearly identical logic.
- **Fix**: Simplify to one path.

---

## Summary of Fixes by Priority

| Priority | Category | Count |
|----------|----------|-------|
| HIGH | Memory leaks | 1 |
| HIGH | Performance | 2 |
| MEDIUM | Memory leaks | 1 |
| MEDIUM | Performance | 2 |
| MEDIUM | Security | 1 |
| LOW | Memory leaks | 2 |
| LOW | Performance | 2 |
| LOW | Security | 2 |
| INFO | Dead code | 12 |
| INFO | const/var violations | 8 |
| INFO | Documentation | 6 |
| INFO | Refactoring | 3 |

**Total issues found: ~42**
