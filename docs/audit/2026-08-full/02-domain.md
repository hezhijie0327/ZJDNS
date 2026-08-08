# 02-domain.md — config/database/cache/edns/zone/ruleset

Phase 1 package audit (Domain). Scope: every non-test file in `config/`, `database/`, `cache/`, `edns/`, `zone/`, `ruleset/` read in full. All 18 dimensions of §1.1 applied. Cross-package claims verified by grep / execution (no speculative findings).

## Package inventory

| Package | Files | Non-test lines | Notes |
|---------|-------|----------------|-------|
| config | chaos.go, config.go, ddr.go, defaults.go, ecs.go, load.go, resinfo.go, validate.go | ~1,900 | Config types + load + validation + DDR/RESINFO/CHAOS rule injection |
| database | db.go, migration.go, schema.go, sqlutil.go, stmts.go | ~1,160 | SQLite open/migrate/prepared statements |
| cache | async_cache.go, async_writer.go, batch_writer.go, cache.go, ptr.go, stats.go, store.go | ~2,200 | SQLite-backed Store + async write-back engine |
| edns | cookie.go, ecs.go, edns.go, padding.go | ~870 | RFC 9018 cookie, RFC 7871 ECS, RFC 8467 padding |
| zone | parse.go, wire.go, zone.go | ~930 | Zone evaluator + zone-file import |
| ruleset | iptrie.go, ruleset.go | ~430 | CIDR trie + domain tag matching |

## Findings

### CRITICAL
(none)

### HIGH

- [HIGH/race] cache/stats.go:118-159 + cache/store.go:730-749 + server/init.go:88-98 — `FlushDB("cache"/"ptr"/"stats"/"querylog")` deletes rows directly on `db.SQ` while the async batch writers (`cacheWriter`/`statsWriter`) still hold unflushed items and the pending read-through LRU map (`s.pending`, up to 4096 entries) is not cleared — the next batch commit re-INSERTs/re-upserts the just-deleted rows and re-inserts ptr_map rows, and `SetEntryCount(0)` is immediately re-inflated by `flushCacheEntries`' EXISTS=false→+1 path | risk: all six `ZJDNS.*.clear` CHAOS endpoints silently fail to clear recently-cached data under load (clear returns "flushed=N" while entries resurrect within the flush window), plus entryCount drift | fix: in `FlushDB`, flush the owning writer (`cacheWriter.Flush()`/`statsWriter.Flush()`) and clear the pending map before the DELETE (or route the clear through the writer goroutine).

- [HIGH/goroutine] cache/batch_writer.go:58,117 — `go w.run()` is the only goroutine in scope without `defer zdnsutil.HandlePanic(...)` (convention: cache/store.go:226 `optimizeLoop`, internal/latency/prober.go:120, server/tasks.go:30) — a panic inside the caller-supplied `flushFn` (e.g. nil prepared statement after a partial Close, driver panic) escapes the goroutine and kills the whole process, taking down the server | risk: process crash on any unexpected panic in the flush path — the standard recovery exists for every other goroutine | fix: add `defer zdnsutil.HandlePanic("Cache batch writer")` as the first line of `run()`.

### MEDIUM

- [MEDIUM/validation] config/validate.go:252-255 — `validateDDR` accepts an IPv4 string in `server.features.ddr.ipv6`: `net.ParseIP("192.168.1.1")` returns the 16-byte form and `To16() != nil` always passes (empirically verified with a probe test). `addDDRRecords` then emits `ZoneRecord{Type: dns.TypeAAAA, Content: "192.168.1.1"}` + `ipv6hint=192.168.1.1` in SVCB — malformed AAAA/hint that silently breaks IPv6 DDR advertisement | risk: silent malformed zone records; DDR clients cannot parse the hint | fix: reject when `ip.To4() != nil` in the ipv6 field (and vice versa, already correct).

- [MEDIUM/validation] config/validate.go:210-213 + config/defaults.go:282-284 — `privacy_profile` is documented as defaulting to strict ("Strict mode (default) rejects skip_tls_verify"), but the check `PrivacyProfile == PrivacyProfileStrict` only fires when the literal string "strict" is set: `skip_tls_verify: true` with no profile (or with an arbitrary string like "banana") passes validation and `InsecureSkipVerify` is silently set in upstream tls/client.go:146,169 | risk: silent downgrade of TLS certificate verification contrary to the documented default; the profile enum is never validated | fix: validate profile ∈ {strict, opportunistic} and treat empty as strict in the check.

- [MEDIUM/rfc] config/resinfo.go:24 — the RFC 9606 §5 `exterr` advertisement "0,2,3,4,5,6,8,9,10,11,12,13,14,15,19,23" violates the invariant stated in its own comment (R2 fix): it advertises codes the codebase never emits — 2 (UnsupportedDSDigestType), 5 (DNSSECIndeterminate), 9 (DNSKEYMissing), 11 (NoZoneKeyBitSet), 13 (CachedError), 14 (NotReady), 19 (StaleNXDOMAINAnswer) — and omits codes actually emitted: 1 (dnssec_chain.go:510), 7 (dnssec_chain.go:505), 12 (dnssec_chain.go:513), 22 (recursive_helpers.go:160), 30 (validation.go:142) — this is a regression of the previously-fixed R2 finding | risk: resolvers advertising RESINFO mislead DDR clients about EDE handling | fix: derive the list mechanically from the emitted `ExtendedError*` constants (a test comparing the advertised string against a grep-able set).

- [MEDIUM/resource] cache/store.go:206-220 — `SQLiteCache.Close()` closes `s.optimizeDone` with no `sync.Once`/atomic guard while every other Close in the chain is guarded (`closeOnce` in batch_writer.go:81, CAS in database/db.go:163) — a second Close panics with "close of closed channel" | risk: shutdown-path crash on double-close (defer + explicit) | fix: `closeOnce`, or nil the channel and guard with `if s.optimizeDone != nil { close(...); s.optimizeDone = nil }` under a mutex/atomic.

- [MEDIUM/logging] zone/zone.go:322-325, 410-412 — `queryExact` and `queryWildcardBatch` swallow SQL errors silently (`if err != nil { return Result{Rcode: dns.RcodeSuccess} }`) — a persistent SQLite failure (e.g. DB corruption, closed DB mid-reload) disables all zone rules with zero log output while the query path proceeds to recursion | risk: silent zone-rule outage — operators cannot tell why rules stopped matching | fix: `log.Warnf("ZONE: ... failed for %s: %v", qname, err)` on the error path (not hot-path — error only).

### LOW

- [LOW/panic] cache/store.go:158-183 — `WireHasDNSSEC` reads `binary.BigEndian.Uint16(wire[4:6])` before any length check; `buildEntry` only guarantees `len(msgWire) >= 3` (store.go:401), so a corrupt 3-5 byte legacy BLOB (only possible via DB corruption — legacy rows are ≥12 bytes by construction) passes buildEntry and panics the serve path in middleware/response.go:59 | risk: index-out-of-range panic on corrupt data | fix: early-return false when `len(wire) < 12`.

- [LOW/sql] database/db.go:84-88 — `buildDSN` interpolates `db_path` into a `file:` URL without escaping — a path containing `?`, `#`, or spaces silently corrupts the DSN (pragmas land in the path; values ignored) while validation only rejects `..` (validate.go:260-265) | risk: misconfigured PRAGMAs with no error | fix: validate the path for URL-reserved characters or escape it.

- [LOW/sql] database/db.go:139-142 — the `SELECT COUNT(*) FROM entries` seed for `entryCount` is silently skipped on error (`if err == nil`) — the counter starts at 0 and eviction resyncs only every 20 evictions | risk: over-eager eviction right after startup on a large pre-existing DB | fix: log a warning when the seed query fails.

- [LOW/docs] database/migration.go:316-320 — comment claims "ALTER TABLE ADD COLUMN is a no-op if column already exists (SQLite ignores duplicate column names...)" — false: SQLite raises "duplicate column name"; the PRAGMA guard makes it safe, but the comment misstates SQLite behavior | risk: misleading maintenance comment | fix: correct the comment.

- [LOW/docs] database/migrations/3.4.23_fqdn_canonical.sql vs database/migration.go:45 ("3.4.24") — archival SQL file version (3.4.23) disagrees with the Go migration tag (3.4.24) for the same fqdn-canonical-form migration | risk: archival drift — future migration audits mis-match | fix: rename the SQL file to 3.4.24_… or align the slice version.

- [LOW/docs] cache/stats.go:18-21 — `statsMetric`'s doc comment is mangled (starts with leftover `RecordRequest` text mid-sentence), and `RecordRequest` carries a duplicated second doc block (lines 37-38) | risk: godoc confusion | fix: merge into one comment each.

- [LOW/docs] cache/cache.go:21-22 — `RequestRecord.Result` doc lists 'hit','miss','stale','zone','error' but the stats schema (database/schema.go:52) and `Stats()` also handle 'blocked' and 'badcookie' | fix: extend the comment.

- [LOW/validation] config/ecs.go:189-207 — `ECSOption.IsValid` accepts Family=1 with a 16-byte (v4-mapped) address (`len >= expectedLen`); RFC 7871 §6 requires family-1 addresses to be 4 bytes | risk: lenient parse of malformed ECS from clients | fix: require exact expected length per family.

## Package observations

**Strengths (systemic, verified):**
- SQL discipline is strong: all hot-path access via prepared statements; placeholder-count cross-package constants (`ZoneWildcardPlaceholders`/`maxWildcardLabels=16`, `IPLatencyPlaceholders`/`maxLatencyLookupIPs=64`, `DelegationLookupZones`/`DefaultDelegationLookupZones=16`) are each guarded by a dedicated test — an exemplary pattern.
- The async write-back engine (BatchWriter: bounded channel with drop-on-full, single-consumer ordering, per-batch tx with timeout, `onCommit` outside the tx) is well designed; the EXISTS→INSERT→counter path cannot drift because the single flush goroutine serializes the checks.
- Pool discipline verified against implementations: `cache.Set`'s Put-before-copy of `msg.Data` (store.go:699 vs 712) is safe **only because** `pool.Message.Put` zeroes the whole struct (internal/pool/pool.go:77) and miekg's `Pack` reallocates when `Data` is nil — fragile but correct today; `buildEntry`'s decompress-buffer copy-before-return is correct.
- All background SQLite writes use `context.WithTimeout` with `config.DefaultCacheWriteTimeout` (never a hang of the query path); context-less `SQLExec` variants carry an explicit documented rationale (db.go:192-195).
- Migration framework is sound: `pragma_table_info` guards, `INSERT OR REPLACE` version row, refuse-older-than-3.0.0, and the "0.0.0 fresh-DB sentinel skips incremental chain" guard (live-test catch).
- EDNS/cookie: RFC 9018 MAC with constant-time compare, RFC 1982 serial arithmetic, RFC 6975 static option reuse; padding double-pack sizing is exactly block-aligned.
- Import DAG verified clean: no domain↔domain imports beyond the documented exceptions (edns→config, cache→database/config, zone→database/config, ruleset→database/config); `internal/` untouched.
- No `context.TODO()`, no `%v` error wrapping, no `errors.As` staleness, no hand-written reverse loops, no `With*` function pairs, no unbounded in-memory growth (pending LRU capped at 4096).

**Per-package notes:**
- config: validation breadth is good (ports, conflicts by transport, certs, ECS, stamps); `validateLogLevel` mutates the global logger as a side effect (harmless — `LoadConfig` error aborts startup). DDR aggregation + SVCB generation is deterministic (sorted) and RFC 9462/9606-aware.
- database: `journal_size_limit` bound to `mmap` bytes in buildDSN is odd but harmless; `Close()` idempotent via atomic CAS.
- cache: eviction is two-phase with serve-stale cutoff and uses `idx_entries_expires_ts`; `PruneQueryJournal` batches bounded deletes per day (WITHOUT ROWID stats PK) and per rowid-LIMIT batch — good large-DB behavior.
- edns: `Handler.GenerateServerCookie`/`IsServerCookieValid` dereference `h.CookieGenerator` with no nil guard (only reachable in hand-constructed test handlers) — noted, not a finding.
- zone: `loadFile` treats per-line insert failures as non-fatal (warn+continue) while `loadInline` propagates — inconsistent but defensible; `evalDynamic` uses `strconv.Quote` for TXT content while `chaos.go`'s `quoteTXT` deliberately avoids Go-style escapes — safe today only because CHAOS contents are ASCII (IPs/stats lines).
- ruleset: IPv4 CIDRs mapped into `::ffff:0:0/96` — an IPv6 rule whose prefix covers the mapped range (e.g. `::/48`) will also match IPv4 clients; inherent to the shared-trie design, undocumented.
- CLAUDE.md claims docs/rfc "116 total"; actual is 113 `rfcNNNN.txt` + 3 drafts — minor drift, worth a one-line update.

**Suggested follow-ups (not findings):** add a `FlushDB`-with-pending test (would have caught the HIGH); consider a goroutine-inventory lint (every `go ` call must be followed by HandlePanic).
