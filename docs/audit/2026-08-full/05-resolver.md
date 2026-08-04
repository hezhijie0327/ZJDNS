# resolver — 包级审计报告

> 审计日期: 2026-08-04 | 审计范围: server/resolver (+ dnssec, probe); CrossCut Perf + CrossCut Constants
> 发现数量: 14 ({"MEDIUM":4,"LOW":10})

### F1 [MEDIUM] logic — apexCut failure path makes no state progress — repeats minimised queries until steps exhausted
- **文件**: server/resolver/recursive.go:233
- **问题**: In resolve(), when isApexSOANODATA detects a zone cut (apexCut=true, lines 215-216) but advanceApexZoneCut returns ok=false (lines 222-234), the loop executes `continue` with nameservers, currentDomain, and the chain completely unchanged. Next iteration re-queries the same parent servers for the same minimised name; since the minimised name != qname, applyQnameMinimisation keeps incrementing minimiseSteps (recursive_helpers.go:75), so the loop re-issues the identical query/fan-out plus a fresh advanceApexZoneCut NS query ~10 times (until steps >= config.DefaultQnameMinimiseCount forces the full QNAME and the apexCut condition fails). Every cycle also re-runs the full queryNameserversConcurrent fan-out to every parent nameserver. The only escape is steps exhaustion; there is no early bail when the cut cannot be established.
- **风险**: For a parent server that hosts a child-zone copy whose NS names have no glue and unresolvable addresses (the exact topology apexCut targets, e.g. the cn/com.cn platform), each client query triggers up to ~10 redundant resolution cycles against the same servers — extra upstream load and up to ~10x added latency — instead of failing over to the full-QNAME walk immediately.
- **修复建议**: After a failed advanceApexZoneCut, advance the walk state deterministically (e.g. set minimiseSteps = config.DefaultQnameMinimiseCount so the next iteration exposes the full QNAME, or add a one-shot 'apex cut failed' flag that skips the apexCut branch on the retry).

### F2 [LOW] dead-code — tagKey.negate field in filterRecordsByCIDR is stored but never read
- **文件**: server/resolver/forward.go:203
- **问题**: filterRecordsByCIDR builds ipTags from []tagKey{raw, name, negate} (lines 190-205): `negate` is computed and stored, but the match loop (lines 225-234) only ever uses t.raw — `negate` (and `name` beyond the pre-filter) is never read. ruleset.Engine.MatchIP (ruleset/ruleset.go:168-176) already parses and applies the '!' prefix itself and returns the negated result, so the local negation bookkeeping is redundant. The in-code comment at line 222 even states 'the negate field was never used' — it is still unused after the rewrite.
- **风险**: Dead state that invites future maintainers to implement negation locally and get double-negation or bypass semantics wrong; no current functional defect.
- **修复建议**: Drop the negate (and if desired name) fields from tagKey — keep only the raw tag string passed through to MatchIP.

### F3 [LOW] comment — Comments claim pooled-message backing arrays are 'reused by the next Get' and alias corruption — contradicted by pool.Put semantics
- **文件**: server/resolver/recursive_helpers.go:161
- **问题**: checkLameDelegation (lines 161-166) and collectBestNSMatch (line 45) justify their defensive deep-copies with 'the pooled message's backing arrays are reused by the next Get, so aliased slices would be corrupted asynchronously'. This is factually wrong: internal/pool/pool.go:70-79 Put() zeroes only the dns.Msg struct (`*msg = dns.Msg{}`), never the backing arrays, and its own doc comment states captured slices 'retain valid references'. After Put the next Get returns a fully zeroed Msg, so new parses allocate fresh arrays; the old arrays are only reachable via the caller's aliased slices and are never written again. The codebase is internally inconsistent: recursive.go:125-127, recursive.go:262-265, CNAME.resolve (recursive.go:391-392) and forward.go:277 alias pooled slices without deep-copy, relying on the pool semantics that the helper comments deny.
- **风险**: Misleading security-flavoured rationale for unnecessary per-query allocations on terminal/NODATA paths; a future pool change made against these comments could break the aliasing paths that do not copy.
- **修复建议**: Align the comments with pool.Put's documented header-only zeroing (or, if aliasing is meant to be forbidden, make the deep-copy the rule everywhere and add a pool invariant — either way the two claims cannot both stand).

### F4 [LOW] dead-code — resolveNSAddrType's second return value (addrs) is always discarded by both callers — dead return surface plus wasted allocations
- **文件**: server/resolver/nameserver.go:476
- **问题**: resolveNSAddrType has named returns (answer []dns.RR, addrs []string) and builds `addrs` by appending a.A.String()/a.AAAA.String() copies (lines 456-466) — a full duplicate of the strings already appended to the *nsAddrs pointer accumulator. Both callers discard it: `ansARecords, _ = r.resolveNSAddrType(...)` (lines 308, 317). No other caller exists (verified by grep).
- **风险**: Dead API surface; per NS address resolution it allocates and fills a duplicate string slice that is immediately garbage — small per-query waste on the recursive walk path.
- **修复建议**: Remove the second return value and return only the answer records needed for cache.Set, or reuse the returned slice for the *nsAddrs append.

### F5 [LOW] error-wrap — errgroup wait errors discarded with `_ = g.Wait()` without the required comment
- **文件**: server/resolver/forward.go:126
- **问题**: queryUpstream (forward.go:126) and resolveNSAddressesConcurrent (nameserver.go:359) discard the errgroup result via `_ = g.Wait()` with no comment. The audit standard (dimension 8) requires `_`-discarded errors to carry a comment explaining type+reason (the per-goroutine errors here are already logged inside the workers — e.g. nameserver.go:186-188 logs the same value on the parallel wait path — so the discard is defensible, but it is unannotated).
- **风险**: Guideline violation only: no functional impact; the errgroup error is informational here since each worker logs its own failure.
- **修复建议**: Either log it like the nameserver.go:186 pattern, or annotate the discard: `_ = g.Wait() // errors already logged per-goroutine`.

### F6 [MEDIUM] perf — getRootServers() re-reads the entire root NS address set from SQLite on every recursive query
- **文件**: server/resolver/ns_addresses.go:83
- **问题**: recursive.go:72 calls r.getRootServers() inside resolve() — i.e. once per recursive query (and per CNAME hop). getRootServers() (ns_addresses.go:83-124) loops over all 13 root names calling lookupNSAddrsFromCache → lookupCachedRRs, which issues store.Get() for TypeA AND TypeAAAA per name = 26 SQLite SELECTs (each with zstd decompress + msg Unpack + per-entry sortAnswerByLatency map allocation), then sortAddrsByLatency adds ~13-26 more LatencyLastProbe prepared-statement queries. There is no in-memory memoization: the root set is fully re-materialized from SQLite per query even though root hints change roughly never.
- **风险**: ~40-50 SQLite round trips plus per-Get allocations on every recursive query's first hop — measurable latency and GC pressure for a deployment whose hot path is recursive resolution; the cost scales the QPS of the server.
- **修复建议**: Memoize the resolved+latency-sorted root address list in memory (e.g. rebuilt on a background timer aligned with DefaultSweepInterval, or invalidated when root hints are re-downloaded) and serve it from memory in getRootServers().

### F7 [MEDIUM] perf — DNS64 secondary A lookup bypasses the response cache — full upstream query per AAAA miss
- **文件**: server/handler/middleware/dns64.go:50
- **问题**: On every AAAA cache miss (the exact case DNS64 exists for, e.g. IPv6-only clients), dns64.go:50-59 performs m.resolver.Query(A) — resolver.Query (resolver.go:226-239) goes straight to upstream/recursive without consulting cache.Store, and the A result is never Set() back. Even when the A record is already cached (a very common case: other clients query A), the DNS64 path re-queries upstream for it, adding one full upstream round trip to every AAAA miss. CacheLookup middleware (which sits outside DNS64) does not help — it only covers the original AAAA query.
- **风险**: For DNS64-enabled deployments (its raison d'être is IPv6-only clients, where AAAA dominates traffic), every AAAA cache miss costs an extra uncached upstream/recursive A round trip, doubling upstream load for those queries and adding per-query latency.
- **修复建议**: In DNS64.Wrap, first consult the cache Store (Get for the A question; reuse the cache.Store already injected elsewhere) and only fall back to resolver.Query on cache miss; optionally Set() the A result after resolution so subsequent queries hit.

### F8 [MEDIUM] perf — Cache write path (Set + insertPtrMap) uses inline SQL instead of the database package's prepared statements
- **文件**: cache/store.go:335
- **问题**: The database package exposes 10 prepared statements (database/stmts.go) for the query path, but the hottest write path bypasses them: Set() executes the entries INSERT via tx.QueryRow with an inline SQL string (store.go:335-343), and insertPtrMap (ptr.go:50-58) builds a fresh SQL string per call via make([]string, len(unique)) + strings.Join(placeholders, ",") + an args slice — the placeholder count varies with answer size, so each distinct N produces distinct SQL text that must be recompiled. The prepared StmtEntry is SELECT-only; there is no prepared statement for the INSERT/ptr_map writes.
- **风险**: Per-cache-write allocations (SQL string, placeholders, args) and repeated SQLite statement compilation on the per-query hot write path, partially defeating the prepared-statement discipline the database package was built around; ptr_map SQL with N-varying placeholders cannot reuse any internal statement cache.
- **修复建议**: Add a prepared StmtEntryInsert (INSERT OR REPLACE INTO entries ... RETURNING id) in database/stmts.go and use it inside the Set transaction; for insertPtrMap, either use a prepared statement with a fixed placeholder cap (padding unused slots) or reuse a pooled placeholder slice.

### F9 [LOW] perf — cache.Get() allocates per-lookup ECS candidates and runs up to 5 sequential SQL queries on ECS fallback
- **文件**: cache/store.go:106
- **问题**: Every cache Get() calls ecsFallbackCandidates (store.go:578-598), which allocates a fresh []ecsCandidate slice on every call — even for the common nil-ECS case (returns a new 1-element slice each time) — and for ECS requests additionally allocates up to 4 masked net.IP copies (maskIP, store.go:560-573) with String() conversions. The fallback loop (store.go:106-118) then executes up to 5 sequential prepared SELECTs per lookup on an ECS miss (exact, /24, /16, /8, /0).
- **风险**: Per-query heap allocations on the cache-lookup hot path (every query, every deployment) and up to 5 serialized SQLite queries per miss under ECS-heavy load.
- **修复建议**: For the nil-ECS case return a preallocated package-level [1]ecsCandidate (slice it; callers only read it); for ECS misses, batch the fallback candidates into a single IN/OR query (bounded by the existing maxLatencyLookupIPs-style cap) instead of 5 sequential queries.

### F10 [LOW] perf — sortAddrsByLatency calls net.SplitHostPort inside the sort comparator
- **文件**: server/resolver/ns_addresses.go:146
- **问题**: The SortStableFunc comparator (ns_addresses.go:146-154) runs net.SplitHostPort(a) and net.SplitHostPort(b) on every comparison — O(n log n) calls, each allocating (string + error). The host could be extracted once per address before sorting.
- **风险**: Redundant allocations per recursive query whenever the root/NS address list is latency-sorted (getRootServers calls this per query, see X1).
- **修复建议**: Pre-split host:port into a parallel []string (or sort a precomputed []host) before the comparator, mirroring the pattern already used in sortAnswerByLatency (pre-computed rrToIP map).

### F11 [LOW] perf — DNSCrypt upstream UDP response buffer allocated per query (4096 bytes, unpolled)
- **文件**: server/upstream/dnscrypt/client.go:150
- **问题**: executeOnce allocates respBuf := make([]byte, config.DefaultDNSCryptUDPSize) (4096 B) on every DNSCrypt UDP query (client.go:150), and the non-proxy path also constructs a fresh &net.Dialer{} per query (client.go:122). The codebase pools buffers everywhere else (spoofguardBufPool in plain/udp.go, pool.DefaultBuffer), but this path does not.
- **风险**: One 4 KB heap allocation per DNSCrypt UDP query — GC pressure on the DNSCrypt hot path.
- **修复建议**: Use a sync.Pool of 4096-byte read buffers (like spoofguardBufPool) or pool.DefaultBuffer, returning the buffer after response decrypt/unpack; hoist the zero-config net.Dialer into the Client struct.

### F12 [LOW] perf — Per-query RequestRecord heap allocation on the cache-hit hot path
- **文件**: server/handler/middleware/cache_lookup.go:59
- **问题**: Each request outcome allocates a &cache.RequestRecord{...} struct literal (cache_lookup.go:59, 103, 115, 178, 185, 194; cache_store.go:120, 166, 198, 224) that is then copied by value into the async writer channel (async_writer.go:58). The struct is ~100 bytes and its lifetime ends at the channel send — a textbook sync.Pool candidate, matching the pool discipline used for messages/buffers.
- **风险**: One small heap allocation per query (including every cache hit) on the server hot path.
- **修复建议**: Add a RequestRecord sync.Pool (zero it before reuse) and acquire/release in RecordRequest, or refactor the channel to carry values that are constructed inside the middleware from a pooled object.

### F13 [LOW] constants — DNSCrypt 4096-byte limit duplicated as two independent constants
- **文件**: config/defaults.go:287
- **问题**: config.DefaultDNSCryptUDPSize = 4096 (config/defaults.go:287, used as the client read buffer in upstream/dnscrypt/client.go:150) and dnscryptcrypto.MaxDNSUDPPacketSize = 4096 (internal/dnscryptcrypto/proto.go:24, the protocol cap enforced in encryption/padding code) encode the same wire limit in two packages with no derivation between them. They must stay equal: a read buffer smaller than the protocol max would truncate legal responses. (pool.RecursiveUDPBufferSize = 4096, cache.decompressBufCap = 4096, TLSConnBufferSize = 4096 are unrelated 4096s — not part of this finding.)
- **风险**: A future change to one constant silently breaks the invariant (truncated DNSCrypt reads or a too-large advertised max) — a maintainability trap on a protocol-bounded value.
- **修复建议**: Derive config.DefaultDNSCryptUDPSize from dnscryptcrypto.MaxDNSUDPPacketSize (config may import internal/dnscryptcrypto per the import-layer rules), or add a comment cross-referencing the two and a unit test asserting equality.

### F14 [LOW] constants — DNSCrypt TCP padding budget uses inline magic numbers 256 + 64
- **文件**: server/protocol/dnscrypt/crypto.go:49
- **问题**: In encrypt(), the worst-case TCP padding reserve is hard-coded as paddingBudget = 256 + 64 (crypto.go:47-49) with an RFC §5.4.7 comment. The value derives from PadResponse (max 256 bytes) plus 64-byte alignment; the crypto package already names similar quantities (PQMinPaddingResumed = 256 in dnscryptcrypto/certificate.go:148, 63-byte alignment masking in encryption.go:122/126), but this 320-byte budget is unnamed and cannot be found by searching for a constant.
- **风险**: If the DNSCrypt padding policy changes (or the 64-byte alignment in dnscryptcrypto is adjusted), this budget silently drifts from the actual worst case, risking an over-budget encrypted TCP response (violating §5.4.7's 4096 cap).
- **修复建议**: Name the constant (e.g. maxTCPPaddingBudget = 256 + 64) with a comment linking it to PadResponse/alignment, or export the padding maximum from internal/dnscryptcrypto and derive the budget from it.
