# Domain Audit: config / database / cache / edns / zone / ruleset

## Summary

- Files audited: 24 (config/*.go x7, database/*.go x5, cache/*.go x5, edns/*.go x4, zone/*.go x3, ruleset/*.go x2)
- CRITICAL: 0, HIGH: 5, MEDIUM: 11, LOW: 16
- Total findings: 32

---

## Findings

### — config/config.go —

#### [LOW] [代码质量] config/config.go:196 — IsEnabled comments contradict auto-generation claim
- **Problem**: The comment for `DNSCryptCertificate.IsEnabled()` says "Keys are auto-generated when empty, so this is always true when the dnscrypt cert block is present in config." But the function body checks `d.PublicKey != "" && d.PrivateKey != ""` — before auto-generation runs, keys are empty, so it returns false. The auto-generation hasn't happened yet when this method is called during validation.
- **Risk**: Minor documentation inaccuracy; no runtime effect since the config parse and auto-generation sequence happens before the check.
- **Fix**: Update comment to reflect actual behavior: "Returns true when keys are explicitly configured; auto-generated keys are set during LoadConfig after IsEnabled is checked."

#### [LOW] [一致性] config/config.go:202,218 — Inconsistent nil receiver checks
- **Problem**: `UpstreamServer.IsRecursive()` (line 218) has a nil receiver guard, but `DNSCryptCertificate.ProviderName()` (line 202) and other methods do not.
- **Risk**: Inconsistent defensive pattern. Not a runtime risk because these are called on value-typed fields, never on nil pointers from production code.
- **Fix**: Either add nil guards to all methods or remove from `IsRecursive()`.

---

### — config/defaults.go —

#### [LOW] [文档质量] config/defaults.go:49 — StaleMaxAge constant comment omits units
- **Problem**: `DefaultStaleMaxAge = 3 * 86400` is clearly seconds, but the comment doesn't state the unit. Nearby `DefaultPruneInterval` correctly documents `time.Hour`.
- **Risk**: Minor readability concern for maintainers.
- **Fix**: Add `(seconds)` suffix or change to `3 * 24 * time.Hour` and adjust the int64-consuming call sites.

#### [LOW] [常量提取] config/defaults.go:231 — DefaultRootCacheTTL TTL in seconds not a time.Duration
- **Problem**: `DefaultRootCacheTTL = 3600` is in seconds while sibling constants like `DefaultDNSKeyCacheTTL = 86400` are also in seconds, but `DefaultLatencyProbeTimeout = 100 * time.Millisecond` is a proper Duration. No type safety — callers must know the unit.
- **Risk**: Silent wrong-TTL errors if a caller treats it as time.Duration.
- **Fix**: Keep as-is (existing convention), but add `// seconds` suffix to all TTL-in-seconds constants.

---

### — config/load.go —

#### [LOW] [参数校验] config/load.go:15 — LoadConfig accepts empty string (returns default)
- **Problem**: `LoadConfig("")` returns a default config with no error. This is intentional but undocumented behavior. A caller accidentally passing an empty string would silently get a non-nil config with hardcoded example values (`dns.example.com`, `127.0.0.1`).
- **Risk**: Silent misconfiguration if the CLI does not guard against empty config path.
- **Fix**: Document the empty-string default behavior, or keep as-is since it matches project needs.

#### [LOW] [参数校验] config/load.go:100 — resolveStamp doesn't validate non-stamp empty address
- **Problem**: If `server.Address` is empty and not an sdns:// stamp, the function returns nil immediately. The address validation only happens later in `validateUpstreamServers`. This is correct but means a `normalizeStamps` error at line 42 can never occur for empty addresses — validators are split across two phases.
- **Risk**: Traceability — an empty address error surfaces at a different call site.
- **Fix**: Add early validation for empty non-recursive address, or add a comment documenting the two-phase split.

---

### — config/validate.go —

#### [MEDIUM] [日志质量] config/validate.go:85-109 — validateLogLevel silently fixes invalid levels
- **Problem**: `validateLogLevel` never returns an error. If the log level string is completely invalid (e.g., "banana"), the function silently falls back to `info` with only a warning log. The warning at line 107 is easy to miss during startup script automation.
- **Risk**: Operators deploying with a mistyped config level don't get the level they expect and may not notice the warning among other startup logs.
- **Fix**: Return an error for truly invalid level strings so `validateConfig` can propagate it and fail the startup.

#### [MEDIUM] [代码质量] config/validate.go:376-387 — validateProbePort mutates parameter
- **Problem**: `validateProbePort` modifies `*port` as a side effect (default-fill). Although documented, this violates the principle of separation between validation and normalization. Call traces through `validateLatencyProbeStep → validateProbePort` cause mutation of the caller's `LatencyProbeStep.Port` during validation.
- **Risk**: If validation order changes or new validators are added, mutation could cause subtle initialization bugs.
- **Fix**: Split into two functions: `normalizeLatencyProbeDefaults` and `validateProbePort`. Call normalization before validation.

#### [LOW] [常量提取] config/validate.go:29 — Hardcoded port range [1, 65535] uses MaxPortNumber from defaults.go
- **Problem**: Line 29 checks `p < 1 || p > 65535` but `config.MaxPortNumber = 65535` exists in defaults.go. The constant exists but is not used here.
- **Risk**: If the max port definition ever needs to change (e.g., for SCTP support with larger range), this check would be missed.
- **Fix**: Replace `65535` with `config.MaxPortNumber`.

---

### — config/chaos.go —

#### [MEDIUM] [代码质量] config/chaos.go:39-53 — Hardcoded project-specific db.clear names
- **Problem**: The db.clear zone rules use `DefaultProjectName` as a prefix (e.g., "ZJDNS.stats", "ZJDNS.db.clear"). These are config-generic types but embed the project name into the query names that clients use. If the project name changes, all existing client scripts break.
- **Risk**: Clients depending on these names break on project rename.
- **Fix**: Use a stable prefix like "server." instead of the project name, or make the admin endpoint configurable.

---

### — config/ddr.go —

#### [MEDIUM] [性能] config/ddr.go:146 — Uses deprecated sort.SliceStable
- **Problem**: Line 146 uses `sort.SliceStable` with a closure. CLAUDE.md §Performance specifies "slices.SortStableFunc over sort.SliceStable". This allocates a closure per call.
- **Risk**: Only called once during config load, so no runtime cost. Violates project coding standards.
- **Fix**: Replace with `slices.SortStableFunc(records, func(a, b flatRecord) int { ... })`.

#### [LOW] [参数校验] config/ddr.go:63 — ContainsAny checks missing newline/tab characters
- **Problem**: `strings.ContainsAny(domain, " \"")` checks for space and double-quote but not for newlines, tabs, or control characters that could break DDR zone output.
- **Risk**: Malicious domain in config could inject content into DDR records, though config is trusted.
- **Fix**: Widen the check to `strings.ContainsAny(domain, " \"\n\r\t")` or use a more robust character class check.

---

### — config/ecs.go —

#### [MEDIUM] [代码质量] config/ecs.go:107-138 — Custom UnmarshalJSON double-scans JSON
- **Problem**: `ECSConfig.UnmarshalJSON` unmarshals the same JSON data twice (line 120 and 128) to detect absent `prefer_ipv4`. The comment acknowledges this but calls it "acceptable for the negligible cost of config parsing." A simpler approach exists: use a pointer `*bool` for `PreferIPv4` in the aux struct.
- **Risk**: Unnecessary complexity in an otherwise clean codebase.
- **Fix**: Change aux struct to use `PreferIPv4 *bool` and check for nil after first unmarshal, eliminating the second scan.

#### [LOW] [注释准确性] config/ecs.go:126 — Comment about "hot path" is misleading
- **Problem**: The comment says "Second unmarshal to detect absent prefer_ipv4 (config-load only, not hot path — double scan is acceptable)." This references a "hot path" which is not relevant to config parsing; config is loaded once at startup.
- **Risk**: Misleading future maintainers about performance concerns.
- **Fix**: Simplify comment: "Double unmarshal to detect absent prefer_ipv4 field."

---

### — database/db.go —

#### [MEDIUM] [耦合度] database/db.go:10 — database imports config (layer violation)
- **Problem**: `database` is a Layer 3 domain package but imports `config` at line 10 (`"zjdns/config"`). The ARCHITECTURE.md rules state "Domain packages never import other domain packages" with specific exceptions that do NOT include `database → config`. Only `edns→config`, `cache→database/config`, `zone→database/config`, `ruleset→database/config` are listed.
- **Risk**: Creates a circular dependency path if `config` ever needs database access. Makes the architecture unclear.
- **Fix**: Inject all config defaults (cache sizes, max entries, etc.) as function parameters to `database.Open()` instead of importing config constants. The `Options` struct already exists — expand it to carry all default values.

#### [MEDIUM] [Context传播] database/db.go:154-168 — All SQL methods use context-less variants
- **Problem**: `SQLExec`, `SQLQueryRow`, `SQLQuery`, `BeginTx` all use `db.SQ.Exec`/`Query`/`QueryRow`/`Begin` (context-less versions of database/sql). There is no way for the server's shutdown context to cancel in-flight SQL queries.
- **Risk**: During server shutdown, SQLite queries cannot be interrupted via context cancellation. While SQLite queries are typically fast (<1ms), a busy WAL checkpoint could block, delaying shutdown.
- **Fix**: Add context-accepting alternatives (`ExecContext`, `QueryContext`, etc.) plumbed from the caller or stored in the DB struct as a base context.

#### [LOW] [代码质量] database/db.go:128-152 — Close() doesn't guard against nil *sql.DB
- **Problem**: If `Close()` is called on a partially-constructed `DB` (e.g., in error paths from `Open` where `sqldb.Close()` was already called), the method may operate on nil `db.SQ`. In practice, production code never sees a partially-constructed DB, but defensive coding would help test cleanup.
- **Risk**: NPE in tests that partially construct DB for mock scenarios.
- **Fix**: Add `db.SQ == nil` check at the start of `Close`.

---

### — database/migration.go —

#### [MEDIUM] [代码质量] database/migration.go:29 — Migrations slice ordering vs version ordering
- **Problem**: The `migrations` slice lists entries in application-version order, but two entries have the same or overlapping version ranges (e.g., `3.2.1` comes after `3.2.0`, but `3.2.13` is listed after `3.2.1`). This is correct. However, `migrateV3_4_18` adds a column that `migrateV3_4_19` immediately drops. For a migration from pre-3.4.18 to post-3.4.19, this is wasted work.
- **Risk**: Permutation of these two migrations in the slice would cause data loss. Currently correct but fragile — a maintainer inserting a new migration between them could reorder.
- **Fix**: Add a comment explaining that v3.4.18 and v3.4.19 are cumulative (v3.4.18 adds column, v3.4.19 drops table) and must remain in this relative order.

#### [LOW] [文档质量] database/migration.go:23 — Version variable comment misleading
- **Problem**: The comment says "The variable is set once during startup before any migration runs and is never modified thereafter. Reads are not guarded by a mutex because there are no concurrent writers — the setter always happens-before Open()." But `Version` is an exported `var` — it can be modified by any package at any time.
- **Risk**: If a test modifies `database.Version` concurrently, there's a data race. Production code doesn't, but the comment's guarantee is external, not enforced.
- **Fix**: Change to `atomic.Pointer[string]` with a setter, or document as "must not be modified after Open."

---

### — database/schema.go —

#### [LOW] [代码质量] database/schema.go:13-28 — migrate() Exec string concatenation without error isolation
- **Problem**: The multi-statement PRAGMA string at lines 16-25 is built via `fmt.Sprintf` and executed as a single `db.SQ.Exec` call. If any individual PRAGMA fails, the entire batch fails, and the error message doesn't indicate which PRAGMA failed.
- **Risk**: Debugging SQLite misconfiguration is harder than necessary.
- **Fix**: Execute each PRAGMA separately and log individual failures.

---

### — database/stmts.go —

#### [HIGH] [耦合度] database/stmts.go:56-62 — Prepared statement placeholders coupled to zone.maxWildcardLabels
- **Problem**: `StmtZoneWildcard` has exactly 16 fixed `?` placeholders (line 58-59). The constant `maxWildcardLabels = 16` in `zone/zone.go` (line 84) must match exactly. If one is changed without the other, the SQL query will fail at runtime with `sql: expected 16 arguments, got N`.
- **Risk**: Maintainability bomb. A well-intentioned change to increase wildcard label count would cause a hard-to-diagnose SQL error.
- **Fix**: Define the placeholder count in a shared package (e.g., a new constant in `config` or `internal`), or generate the SQL dynamically from the constant at init time. At minimum, add a cross-reference comment in both files.

#### [HIGH] [耦合度] database/stmts.go:69-73 — Prepared statement placeholders coupled to cache.maxLatencyLookupIPs
- **Problem**: `StmtIPLatency` has exactly 64 fixed `?` placeholders (lines 70-72). The constant `maxLatencyLookupIPs = 64` in `cache/store.go` (line 40) must match exactly. Same decoupling risk as above.
- **Risk**: Same as above. If `maxLatencyLookupIPs` changes without updating the SQL, `sql: expected 64 arguments, got N` at runtime on the cache-hot path.
- **Fix**: Same remedy — use a single source of truth for the count.

#### [LOW] [文档质量] database/stmts.go:56-62 — Missing documentation of coupling to zone.maxWildcardLabels
- **Problem**: No comment on line 56-62 explains that the 16 placeholders must match zone's `maxWildcardLabels`. Similarly for the 64-placeholder statement at line 69-73.
- **Risk**: Maintenance oversight.
- **Fix**: Add `// Must match zone.maxWildcardLabels` and `// Must match cache.maxLatencyLookupIPs` comments.

---

### — cache/cache.go —

#### [LOW] [代码质量] cache/cache.go:111-137 — processRR redundant nil check on rr
- **Problem**: `processRR` checks `rr == nil` at line 112, but the caller `ProcessRecords` already iterates with `for _, rr := range rrs` which never produces a nil for a non-nil slice. The nil check is dead code for the normal path (only triggered if a nil is manually inserted into the slice).
- **Risk**: Dead code, minimal overhead.
- **Fix**: Remove nil check, or change to `for i := range rrs { if rrs[i] == nil { continue } }` in ProcessRecords if nil elements are a concern.

#### [LOW] [文档质量] cache/cache.go:142 — Comment text duplicated
- **Problem**: The comment before `ProcessRecords` appears twice (lines 141-142): "ProcessRecords adjusts TTLs on resource records and optionally filters DNSSEC record types." and "ProcessRecords adjusts TTLs and filters records by DNSSEC status."
- **Risk**: Cosmetic clutter.
- **Fix**: Deduplicate to one comment.

---

### — cache/store.go —

#### [MEDIUM] [性能] cache/store.go:289-375 — Set clones records twice for the same purpose
- **Problem**: In `Set`, line 311-313 clones `answer`, `authority`, and `additional` inputs to prevent downstream mutations. But line 307 already called `cloneRRs(additional)` for `stripOPT`. The other two sections are always cloned. If the caller already owns the data (e.g., from a freshly-parsed response), this is a double allocation on every cache insert.
- **Risk**: Two extra heap allocations per cache Set() call (answer + authority each cloned once). Additional is cloned twice, but line 307 overwrites the variable anyway. On busy servers, this adds GC pressure.
- **Fix**: Move cloning into `stripOPT` (which already clones additional) and clone the other two sections only when the caller doesn't already own unique data. Alternatively, document the contract: "Caller must not mutate slices after Set."

#### [MEDIUM] [代码质量] cache/store.go:558-568 — maskIP returns net.IP from Mask — shares backing array
- **Problem**: `net.IP.Mask()` returns a new IP that may share the backing array with the input. When used in `ecsFallbackCandidates` (line 588), the masked IP's `String()` is called immediately (line 589), so the shared backing is safe. But future refactoring could introduce aliasing bugs.
- **Risk**: Low — immediate String() call is safe. But the function signature is misleading (returns a "new" net.IP that might alias).
- **Fix**: Copy the result: `return append(net.IP{}, ip.Mask(mask)...)`.

#### [LOW] [性能] cache/store.go:243-283 — lookupIPLatencies zeroes all 64 pool entries on return
- **Problem**: The defer at lines 255-260 zeroes all 64 slots of the pool array, regardless of how many IPs were actually queried (could be as few as 2). For small answer sets, this zeroes 60+ unnecessary slots.
- **Risk**: Minor CPU waste on the hot cache path (Get → Latency sorting). Actual cost is negligible since the array is small.
- **Fix**: Zero only up to `len(ips)` or track the active range.

---

### — cache/async_writer.go —

#### [MEDIUM] [性能] cache/async_writer.go:159-185 — flush uses individual Exec per record
- **Problem**: `flush()` iterates `batch` and calls `StmtQueryStats.Exec` and (optionally) `StmtQueryLog.Exec` for each record individually. A batch of 64 records generates 64-128 separate SQLite Exec calls. Each Exec involves a WAL write transaction.
- **Risk**: Unnecessary SQLite overhead for batch stats writes. Could cause WAL file growth on very busy servers.
- **Fix**: Use a transaction for the batch or multi-value INSERT where possible. Comment on line 160 says "Individual writes are used rather than a transaction to keep the background goroutine simple" — this is a tradeoff, but the CPU cost is measurable.

#### [LOW] [文档质量] cache/async_writer.go:110 — Flush() default case comment misleading
- **Problem**: Line 111-112: "Goroutine busy — records in its batch will be written by ticker or next Flush. This path is only reached under extreme load." This is also reached if `Flush` is called after `Close()` (goroutine exited), making the comment incomplete.
- **Risk**: Misleading during debugging.
- **Fix**: Broaden comment: "Goroutine busy or already exited — records will be written by ticker or next Flush."

---

### — cache/ptr.go —

#### [LOW] [代码质量] cache/ptr.go:16-63 — insertPtrMap builds SQL with dynamic placeholder count
- **Problem**: Line 56 builds `INSERT INTO ptr_map ... VALUES (?,?,?,?),...` with dynamically generated placeholders. The G202 suppression comment acknowledges this. The values are parameterized via `args`, so SQL injection is not a risk, but the dynamic SQL bypasses the prepared-statement cache in database/sql.
- **Risk**: Each unique set of PTR mappings triggers a new `sql.Stmt` prepare, adding overhead.
- **Fix**: Not worth fixing — PTR inserts are only on cache Set, which is less frequent than reads. Acceptable tradeoff.

---

### — cache/stats.go —

#### [LOW] [性能] cache/stats.go:173-261 — Stats() uses a single query with 30 CASE expressions
- **Problem**: The `Stats()` SQL query (lines 187-226) scans `query_stats` once but uses 30 `CASE WHEN` expressions in a single query. The comment says query_stats is bounded at ~500 rows, so the performance impact is negligible.
- **Risk**: None at current scale. If query retention increases, the query could become slow.
- **Fix**: Decompose into multiple simpler queries, or keep as-is with a comment noting the bound.

---

### — edns/edns.go —

#### [LOW] [代码质量] edns/edns.go:143-159 — addrToNetip allocates unnecessarily for IPv4
- **Problem**: `addrToNetip` calls `ip.To4()` and then `AddrFromSlice` on the 4-byte result, which allocates. For the common case where the IP is already a 16-byte IPv4-in-IPv6, `ip.To4()` returns a newly-allocated 4-byte slice.
- **Risk**: Allocation on every EDNS message that carries ECS. ~32 bytes per call.
- **Fix**: Use `netip.AddrFromSlice(ip)` directly (Go handles both 4-byte and 16-byte forms) and only call `ip.To4()` for the family check.

---

### — edns/cookie.go —

#### [LOW] [内存安全] edns/cookie.go:66 — timeNow package var is mutable by tests without reset
- **Problem**: `timeNow` is a package-level variable (line 66) for test clock injection. If one test overrides it without deferring the restore, subsequent tests get a broken clock.
- **Risk**: Test pollution. Not a production issue.
- **Fix**: Add `timeNow` backup/restore in tests or use a test helper pattern.

---

### — edns/ecs.go —

#### [LOW] [注释准确性] edns/ecs.go:16 — Type alias comment outdated
- **Problem**: Comment says "ECSOption is an alias for config.ECSOption, kept here for compatibility with packages that already depend on the edns package." This is accurate but the alias introduces a naming collision with the config package's original type.
- **Risk**: New developers may be confused about which ECSOption to use. The alias is intentional per CLAUDE.md ("Type aliases: edns.ECSOption = config.ECSOption").
- **Fix**: Add a note pointing to CLAUDE.md for the type alias convention.

---

### — edns/padding.go —

#### [LOW] [性能] edns/padding.go:40 — msg.Pack() called unconditionally, even when padding disabled
- **Problem**: `msg.Pack()` is called to get the wire size (line 40) before checking whether padding is needed. But `addPadding` is only called from `ApplyToMessage` (edns.go line 136), which calls it unconditionally for every outbound message. The `msg.Pack()` call modifies `msg.Data` and may trigger compression work.
- **Risk**: Unnecessary work for messages where `!isSecureConnection || !clientWantsPadding`. The function returns early at line 32-34 in that case, but `msg.Pack()` was already called.
- **Fix**: Move the early return before the `msg.Pack()` call: check `!isSecureConnection || !clientWantsPadding` first.

---

### — zone/zone.go —

#### [HIGH] [耦合度] zone/zone.go:84 — maxWildcardLabels decoupled from database/stmts.go placeholder count
- **Problem**: `maxWildcardLabels = 16` must match the 16 `?` placeholders in `database/stmts.go`'s `StmtZoneWildcard` (line 58). No enforcement mechanism.
- **Risk**: See finding database/stmts.go HIGH 2 above. Same issue, different consumer.
- **Fix**: Same — share the constant or generate SQL from it.

#### [MEDIUM] [代码质量] zone/zone.go:278-280 — evalDynamic may return Matched=false with stale SQL fallthrough
- **Problem**: When a dynamic entry exists for `qname` but the query `qtype` doesn't match any config answer record, `evalDynamic` returns `Matched: false`. The caller then falls through to `queryExact` which finds the sentinel SQL row (inserted during `loadInline` at line 219 with `qtype=0, qclass=0`). The result is an rcode-only (usually 0) response with no answer, bypassing the dynamic function.
- **Risk**: If a client queries a dynamic-only domain with an unexpected qtype, they get an empty success response instead of the dynamic content or an error. This may be intentional but is surprising.
- **Fix**: Document this behavior in the Evaluate function comment, or make `evalDynamic` return the dynamic content regardless of qtype for rules that have `DynamicContent` (since the function is designed to answer regardless).

#### [LOW] [性能] zone/zone.go:86 — wildcardArgsPool holds stale args between uses
- **Problem**: `wildcardArgsPool` returns `*[]any` without zeroing the pre-existing values. After `queryWildcardBatch` returns, the args slice still holds references to the suffix strings and ints used in the query. These references prevent GC of the strings until the pool entry is reused and overwritten.
- **Risk**: Slight memory pressure if the pool is large and entries are reused infrequently. Not a leak — strings are small and get overwritten on next use.
- **Fix**: Zero the args in a defer before returning to pool, or use `sync.Pool` with a New function that returns a zeroed slice.

#### [LOW] [日志质量] zone/zone.go:475 — matchScore comment references "positive tag" terminology
- **Problem**: Comment says "positive tag matches score 2, satisfied negations score 1, untagged rules score 0." This mixes "positive" (meaning non-negated) with "positive score." The logic actually gives 2 for every non-negated match.
- **Risk**: Minor readability issue.
- **Fix**: Clarify: "explicit (non-negated) tag matches score 2."

---

### — zone/parse.go —

#### [LOW] [参数校验] zone/parse.go:155 — parseRecordLine tokenize lacks escape handling
- **Problem**: `tokenize` (line 195-225) splits by whitespace and handles double-quoted strings. But backslash-escaped quotes inside quoted strings (`\"`) are not handled — the backslash is literal. Standard zone files use this escape.
- **Risk**: Zone records with escaped quotes in content (e.g., SPF TXT records with `\;"`) produce wrong results. The line is skipped as invalid.
- **Fix**: Add backslash escape processing inside quoted strings in `tokenize`.

---

### — zone/wire.go —

#### [LOW] [错误处理] zone/wire.go:66-105 — buildRecord swallows dns.New parse error
- **Problem**: Line 98: `if rr, err := dns.New(sb.String()); err == nil { return rr }`. If `dns.New()` fails, the error is silently discarded and a fallback `RFC3597` record is returned with raw content. The caller never sees the parse error.
- **Risk**: A malformed zone record (e.g., wrong content format for type) is silently served as RFC3597 raw data, which may fail at query time.
- **Fix**: Log the parse error at Warn level before returning the RFC3597 fallback.

#### [LOW] [性能] zone/wire.go:87-97 — buildRecord uses strings.Builder then sb.String() for dns.New
- **Problem**: The builder allocates a string for the entire RR text format, then `dns.New` re-parses it. This is two conversions (builder → string → parsed structure) for every zone record. For large zone files (10,000+ records), this is significant CPU and garbage.
- **Risk**: Zone file loading performance, though it only happens at startup.
- **Fix**: Not necessary — startup cost is acceptable. Could cache type/class name lookups.

---

### — ruleset/ruleset.go —

#### [HIGH] [RFC一致性] ruleset/ruleset.go:243-254 — tldPlusOne breaks for multi-part TLDs (.co.uk, .com.au, etc.)
- **Problem**: `tldPlusOne` extracts the last two dot-separated labels from a domain name (e.g., "sub.example.com" → "example.com"). But for multi-part TLDs like "co.uk", it produces only "co.uk" instead of "example.co.uk". This means domain rules for domains under .co.uk, .com.au, .org.uk, .net.au, etc. **never match** their intended targets.
  - Example: rule for "example.co.uk" → stored as "example.co.uk" by `domainKey`.
  - Query "www.example.co.uk" → `tldPlusOne` returns "co.uk".
  - SQL lookup: `WHERE value='co.uk'` → no match.
- **Risk**: All ruleset domain entries under multi-part country-code TLDs are silently non-functional. Users who configure blocking/forwarding for \*.co.uk, \*.com.au, etc. get no protection.
- **Fix**: The project does not include a Public Suffix List. Options: (a) bundle a minimal PSL-derived list of multi-part TLDs, (b) add a configurable list, or (c) document this limitation. Option (a) is the industry standard approach used by browser vendors and ad-blockers.

#### [MEDIUM] [错误处理] ruleset/ruleset.go:99-118 — loadIPRules silently skips all IP rules on SQL error
- **Problem**: If `e.db.SQLQuery(...)` at line 100 returns an error, `loadIPRules` logs nothing and returns immediately, leaving the IP trie empty. All IP-based tag matching is silently disabled for the entire lifetime of the Engine.
- **Risk**: Silent failure — operators may not realize IP-based rules are not working until they investigate a bypass incident.
- **Fix**: Log the error at Warn level before returning. Consider whether to fail the entire `LoadRules` call instead of silently falling back.

#### [LOW] [性能] ruleset/ruleset.go:121-157 — Match() makes SQL query for every DNS query
- **Problem**: `Match()` issues a SQL query (line 126) for domain matching on every DNS query. Domain rulesets loaded from SQLite are not cached in memory. Even though the query uses a PK prefix seek (type+value), it adds latency to every query.
- **Risk**: ~0.1-0.5ms per query for SQLite round-trip. On busy servers, this adds up.
- **Fix**: Cache domain rules in an in-memory map (similar to how IP rules use the trie). SQLite should be the persistence layer only, not the hot-path query engine.

---

### — ruleset/iptrie.go —

#### [LOW] [代码质量] ruleset/iptrie.go:24-76 — insert() ignores the custom IPv6 prefix of ::ffff:0:0/96
- **Problem**: The IPv4→IPv6 mapping hardcodes 96 bits of ::ffff:0:0 prefix (line 37: `for i := range 96`). This assumes that any IPv4 address in the trie is stored as IPv4-in-IPv6. But `net.IP.To16()` can return a regular 16-byte IPv6 address too — the trie cannot distinguish between an IPv4-in-IPv6 address and a native IPv6 address that happens to start with ::ffff:0:0.
- **Risk**: If a native IPv6 CIDR with prefix ::ffff:0:0/... is inserted, it would collide with the IPv4 mapping. Practically zero risk since ::ffff:0:0 is the IPv4-mapped space and is never used as a real IPv6 allocation.
- **Fix**: Add a comment documenting this assumption and why it's safe.

#### [LOW] [性能] ruleset/iptrie.go:110-136 — matchTag walks full 128-bit path every time
- **Problem**: `matchTag` walks all 128 bit positions for every IP check, even for IPv4 addresses (which only need 32 bits after the 96-bit IPv4-in-IPv6 prefix). The function doesn't know the prefix length, so it walks the entire depth.
- **Risk**: Negligible — 128 iterations of a tight loop is sub-microsecond.
- **Fix**: Not necessary, but could track total bit depth per trie.

---

## Summary Cross-Reference by Audit Dimension

| Dimension | Findings |
|-----------|----------|
| 1. 代码质量 | 7 LOW/MEDIUM — dead comments, duplicated comments, double-clone, mutation in validation |
| 2. 内存安全 | 1 LOW — pool entries not zeroed between uses (zone wildcardArgsPool) |
| 3. 锁正确性 | 0 — no data races found; atomic.Pointer and atomic.Int64 used correctly |
| 4. 耦合度 | 3 MEDIUM/HIGH — database→config import, constant decoupling (x2) |
| 5. 架构设计 | 1 MEDIUM — database→config import violates layer rules |
| 6. 性能 | 4 MEDIUM/LOW — sort.SliceStable, per-record Exec in flush, unnecessary Pack, SQL per query |
| 7. Panic检测 | 0 — no nil deref, bounds, or use-after-Put on hot paths; pool reuse is correctly ordered |
| 8. 错误处理 | 3 MEDIUM/LOW — loadIPRules silent error, buildRecord swallow, validateLogLevel no-error |
| 9. Context传播 | 1 MEDIUM — all SQL methods context-less; no cancellation during shutdown |
| 10. Goroutine生命周期 | 0 — AsyncStatsWriter goroutine lifecycle is correct: closeOnce, done ch, flushSig |
| 11. 资源生命周期 | 0 — Close() idempotent via sync.Once and atomic. DB/Store/Evaluator all proper |
| 12. 日志质量 | 2 MEDIUM/LOW — silent error in loadIPRules, ambiguous comment |
| 13. 文档质量 | 3 LOW — duplicate comment, outdated Version comment, misleading hot-path comment |
| 14. 参数校验 | 2 LOW — parseRecordLine no escape handling, empty config path ambiguity |
| 15. 常量提取 | 2 LOW — MaxPortNumber not reused, units unclear |
| 16. RFC一致性 | 1 HIGH — tldPlusOne ignores multi-part TLDs (Public Suffix List not used) |
| 17. 注释准确性 | 2 LOW — IsEnabled contradiction, sort.SliceStable not noted as deprecated |
| 18. 函数排序 | 0 — all files follow type→const→var→func order correctly |

## Key Hot-Path Risks

1. **SQLite queries per DNS request**: `Match()` queries SQLite for every request's domain matching. ~0.1-0.5ms/query.
2. **Double cloning in Set()**: Every cacheable response is cloned before storage, adding GC pressure.
3. **Per-record stats Exec**: AsyncStatsWriter does 64-128 separate Exec calls per flush batch.

## Conclusion

The domain packages are well-structured with strong defensive patterns (nil checks on hot-path methods, pool reuse, atomic counters). No CRITICAL issues found.

The most impactful finding is the **multi-part TLD bug in ruleset** (HIGH) — domain-based rule matching is silently broken for all country-code second-level domains (.co.uk, .com.au, .co.jp, etc.). This is a latent functional bug that would affect any user deploying domain-based ruleset matching with multi-part TLD domains.

The next most impactful finding is the **coupled placeholder constants** (HIGH) — three pairs of constants across package boundaries that will cause runtime SQL failures if changed independently.

The **database→config import** (MEDIUM) is an architectural layer violation that should be resolved at the next refactoring opportunity, as it blocks future work on the import DAG.
