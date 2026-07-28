# Domain Packages Audit — config, database, cache

## Files Audited

- `config/config.go` — Type definitions
- `config/defaults.go` — All default constants
- `config/validate.go` — Configuration validation
- `config/load.go` — Config loading + stamp normalization
- `config/ecs.go` — ECS configuration
- `database/db.go` — SQLite DB lifecycle
- `database/schema.go` — DDL schema
- `database/stmts.go` — Prepared statements
- `database/migration.go` — Schema migrations
- `database/sqlutil.go` — SQL utilities
- `cache/cache.go` — Store interface
- `cache/store.go` — SQLiteCache implementation
- `cache/async_writer.go` — Async stats writer
- `cache/stats.go` — Cache statistics
- `cache/ptr.go` — PTR reverse lookup

## Findings

### CRITICAL — None

### HIGH — None

### MEDIUM — None

### LOW

| ID | File | Line | Category | Description |
|----|------|------|----------|-------------|
| L11 | `config/config.go` | 202-203 | validation | `ProviderName()` returns "2.dnscrypt-cert." for empty domain — no input validation |
| L12 | `database/stmts.go` | 68-73 | coupling | 64-placeholder `StmtIPLatency` must match `cache.maxLatencyLookupIPs` — fragile cross-package constant coupling |
| L14 | `cache/store.go` | 352,358,363 | error-wrap | Uses `%v` for error logging (not `%w` — logging doesn't need `%w`, but inconsistent with other warn logs) |
| L15 | `config/load.go` | 152 | correctness | `protocolMatchesStamp` maps DoH stamp to `ProtoHTTP` ("http") not `ProtoHTTPS` ("https") — works correctly because `BuildDoHURL()` prepends "https://" but confusing |

## Assessment

Domain packages are very clean. The config validation is thorough. Cache implementation has
exemplary pool discipline with clear lifecycle comments and correct defer ordering.
Database layer has proper idempotent Close via `atomic.CompareAndSwapInt32`.
No CRITICAL or HIGH issues found.
