# Round 3 Audit — 10-docs: Living Documentation Consistency

**Auditor**: Claude Code
**Date**: 2026-07-25
**Scope**: CLAUDE.md, ARCHITECTURE.md, README.md, BENCHMARK.md, DEBUG.md
**Method**: Grep Go source for every type/function/field/table referenced in .md files; verify directory listings, build commands, and benchmark counts against actual code.

---

## CLAUDE.md

### MEDIUM: `Middleware` interface does not exist — actual name is `Wrapper`

- **File**: CLAUDE.md:310
- **Category**: Type reference
- **Problem**: The "Key Types" table lists `Middleware` as the interface in `server/handler` with `Wrap(next QueryHandler) QueryHandler`. The actual type in `server/handler/middleware.go:46` is `Wrapper`, not `Middleware`. The interface definition (`Wrapper`) is correct in the code; the docs have the wrong name.
- **Risk**: Low. A human reader would find the type by grepping for `Middleware` and get no results. The `Wrap` signature in the description is correct, but the name mismatch will confuse anyone navigating the codebase.
- **Fix**: Rename to `Wrapper` in the table, or export a `Middleware` type alias.

### MEDIUM: `CertSettings` does not exist — actual name is `CertificateSettings`

- **File**: CLAUDE.md:299
- **Category**: Type reference
- **Problem**: The description of `ServerConfig` says "owns `ECSConfig`, `ProtocolSettings`, `CertSettings`". The actual type in `config/config.go:50` is `CertificateSettings`. The struct field is `Certificate` of type `CertificateSettings`.
- **Risk**: Low. Similar to above — functional impact is zero, but navigation friction.
- **Fix**: Change `CertSettings` to `CertificateSettings` in the description.

### MEDIUM: `RulesetMiddleware` does not exist as a separate middleware

- **File**: CLAUDE.md:228 (directory tree), CLAUDE.md:270 (chain list #8)
- **Category**: Architecture/ordering
- **Problem**: The project structure says `middleware/ ← 10 composable middleware` and the chain lists `RulesetMiddleware` at position 8. In actual code (`server/handler/middleware/chain.go`), there are **9** middleware in the chain, not 10. The `RulesetMiddleware` was previously a separate middleware but its tag-matching logic has been folded into `ZoneMiddleware`. The chain.go comment confirms 9 middleware.
- **Risk**: Medium. Anyone reading CLAUDE.md to understand the pipeline will look for a non-existent middleware file and be confused about where ruleset processing (CIDR/domain tag matching) occurs.
- **Fix**: Remove `RulesetMiddleware` from the chain list; change "10 composable middleware" to "9 composable middleware"; update the chain count in the project structure tree.

### LOW: `Pool` type does not exist — actual name is `ConnPool`

- **File**: CLAUDE.md:314
- **Category**: Type reference
- **Problem**: "Key Types" says `Conn / Pool | server/upstream/pool`. The actual exported type in `server/upstream/pool/tcp.go:50` is `ConnPool`, not `Pool`.
- **Fix**: Change `Pool` to `ConnPool`.

### LOW: `Stamp` type does not exist — actual type is `*DNSStamp`

- **File**: CLAUDE.md:318
- **Category**: Type reference
- **Problem**: "Key Types" says `Stamp | internal/stamp`. The actual exported type in `internal/stamp/stamp.go:36` is `DNSStamp`. The `Parse()` function returns `*DNSStamp` and all methods are on `*DNSStamp`.
- **Fix**: Change `Stamp` to `DNSStamp`.

### LOW: "12 prepared stmts" is incorrect — actual count is 8

- **File**: CLAUDE.md:302
- **Category**: Stale numeric claim
- **Problem**: The `DB` type description says "Unified SQLite DB; WAL mode, 12 prepared stmts". The code in `database/db.go:39-50` defines only 8 prepared statements: StmtEntry, StmtQueryLog, StmtQueryStats, StmtInsertLatency, StmtLastProbe, StmtZoneExact, StmtZoneWildcard, StmtIPLatency.
- **Risk**: Trivial. Does not affect understanding of the architecture.
- **Fix**: Change "12 prepared stmts" to "8 prepared stmts".

### LOW: Benchmark counts are outdated

- **File**: CLAUDE.md:139
- **Category**: Stale numeric claim
- **Problem**: "98 benchmarks across 14 files" — actual code contains 100 benchmark functions across 19 benchmark files. The baseline file at `docs/benchmark/benchmark-baseline.txt` contains 99 benchmark entries, also outdated.
- **Risk**: Trivial. Does not affect usage, but the number keeps drifting as benchmarks are added.
- **Fix**: Regenerate the baseline file, then update the count in CLAUDE.md.

### INFO: CLI probe examples use addresses without port numbers

- **File**: CLAUDE.md:162-164
- **Category**: Example accuracy
- **Problem**: The `--probe` examples show `tcp://8.8.8.8` and `tls://1.1.1.1` without port numbers. The actual CLI help shows `tcp://host:port` format. These will fail (default DNS port is not assumed by the probe flag).
- **Risk**: Trivial. Users would get an error and add a port themselves.
- **Fix**: Add `:53` or `:853` suffix to examples.

---

## docs/ARCHITECTURE.md

### MEDIUM: Table count is wrong — "ten SQLite tables" should be 8

- **File**: ARCHITECTURE.md:7
- **Category**: Stale numeric claim
- **Problem**: "The unified database (`database/`) contains ten SQLite tables" — but `database/schema.go` defines only 8 tables: version, query_stats, query_log, entries, ptr_map, ip_latency, ruleset_entries, zone_entries.
- **Risk**: Low. A reader counting tables in the SQL DDL below will see only 8 and wonder where the other 2 went.
- **Fix**: Change "ten" to "eight".

### MEDIUM: `hijack` column renamed to `poisoned` in both query_stats and query_log

- **File**: ARCHITECTURE.md:38,54
- **Category**: Schema mismatch
- **Problem**: The schema DDL in ARCHITECTURE.md shows `hijack INTEGER NOT NULL DEFAULT 0` in both `query_stats` and `query_log`. The actual schema (`database/schema.go`) uses `poisoned INTEGER NOT NULL DEFAULT 0` in both tables. The column was renamed in migration `migrateV3_5_0` ("rename-hijack-to-poisoned").
- **Risk**: Medium. Anyone using the ARCHITECTURE.md schema as a reference for SQL queries will use `hijack` and get a SQL error.
- **Fix**: Replace `hijack` with `poisoned` in both `query_stats` and `query_log` DDL in ARCHITECTURE.md.

### MEDIUM: DTLCP TODO comments no longer in code

- **File**: ARCHITECTURE.md:160-161
- **Category**: Stale workaround description
- **Problem**: The DTLCP section says the server and client files contain TODOs to replace workarounds with `dtlcp.Listen` / `dtlcp.Dial` when upstream fixes. These TODO comments no longer exist in the code (`server/protocol/tlcp/dtlcp.go` and `server/upstream/tlcp/dtlcp.go`). The workarounds remain in place but the TODOs were removed.
- **Risk**: Low. The workaround description is still accurate; only the TODO references are stale.
- **Fix**: Remove the two TODO bullet points or rephrase to past tense noting the workarounds remain.

### LOW: PqCertContext description uses wrong field name

- **File**: ARCHITECTURE.md:143
- **Category**: Inaccurate description
- **Problem**: The PqCertContext HKDF is described as including "resolver-pk". For PQ certificates, the signed portion at the `CertPQPkOff` offset contains the 1216-byte `PqPublicKey`, not the 32-byte `ResolverPk` (which is zero-filled for PQ certs). The correct term is "pq-public-key".
- **Risk**: Trivial. The implementation detail is correct; only the field name in the description is slightly misleading.
- **Fix**: Change "resolver-pk" to "pq-public-key" in the PqCertContext description.

### LOW: Missing `idx_ptr_map_entry_id` index from schema listing

- **File**: ARCHITECTURE.md:63-70
- **Category**: Incomplete schema
- **Problem**: The `ptr_map` DDL shows only the PRIMARY KEY declaration. The actual schema also creates `CREATE INDEX IF NOT EXISTS idx_ptr_map_entry_id ON ptr_map(entry_id)`. This index enables efficient cascade cleanup lookups.
- **Risk**: Trivial. The DDL is valid but incomplete. The missing index would only matter if someone recreated the schema from the docs.
- **Fix**: Add the missing index to the `ptr_map` DDL block.

---

## README.md

### LOW: "九表设计" should be "八表设计" (8 tables, not 9)

- **File**: README.md:67
- **Category**: Stale numeric claim
- **Problem**: The Chinese text says "九表设计" (9-table design), but the table below lists exactly 8 tables (version, entries, ptr_map, query_stats, query_log, ip_latency, ruleset_entries, zone_entries). The schema also has only 8 tables. This text has been wrong since the `entry_hit_counters` and `request_log` tables were merged into `query_stats` and `query_log`.
- **Risk**: Trivial. Minor inconsistency in the introductory sentence.
- **Fix**: Change "九表" to "八表".

---

## docs/debug/DEBUG.md

### LOW: Stale `request_log` table reference in SQL example

- **File**: DEBUG.md:383
- **Category**: Stale table name
- **Problem**: The SQL example at the bottom of the Debug Config section queries `FROM request_log`. This table was renamed to `query_log` in migration `v3.2.21`. All other references in the codebase and docs use `query_log`.
- **Risk**: Low. Running this command will produce a SQL error ("no such table: request_log").
- **Fix**: Change `request_log` to `query_log`.

### LOW: Directory listing missing `client-tlcp.json` and `server-hijack.json`

- **File**: DEBUG.md:8-20
- **Category**: Incomplete listing
- **Problem**: The `docs/debug/loopback/` directory contains `client-tlcp.json` (TLCP TLS loopback client) and `server-hijack.json` (server config with hijack detection enabled), but they are not listed in the directory tree. The TLCP/DTLCP test section later mentions loopback tests but doesn't reference `client-tlcp.json`.
- **Risk**: Trivial. These files exist and work; they just won't be discovered from the directory listing.
- **Fix**: Add missing filenames to the `docs/debug/loopback/` directory listing.

---

## docs/benchmark/BENCHMARK.md

No issues found. All config file paths verified, commands match actual CLI flags.

---

## Summary

| Severity | Count | Key Areas |
|----------|-------|-----------|
| MEDIUM   | 6     | Middleware name (`Wrapper`), `CertSettings` name, RulesetMiddleware removal, `hijack`→`poisoned` (2x), table count, stale DTLCP TODOs |
| LOW      | 9     | `Pool`→`ConnPool`, `Stamp`→`DNSStamp`, 12→8 stmts, 98→100 benchmarks, 9→8 tables, `request_log` stale ref, PqCertContext field name, missing index, missing debug files |
| INFO     | 1     | Probe examples without port |

**No issues**: BENCHMARK.md, CLI commands, log prefixes (all 23 verified), import layer rules, project structure directories.
