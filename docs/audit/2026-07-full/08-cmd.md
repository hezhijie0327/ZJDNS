# CMD & CLI Audit: cmd/zjdns/*

## Summary

- **Files audited**: 8 (main.go, banner.go, version.go, cli/parse.go, cli/probe.go, cli/dnsstamp.go, cli/generate.go, cli/sql.go)
- **CRITICAL**: 0
- **HIGH**: 1
- **MEDIUM**: 8
- **LOW**: 10
- **INFO**: 2

## CLI Flag Audit

| Flag | Type | Default | Required | Validation | Status |
|------|------|---------|----------|------------|--------|
| `--config` | string | `""` | No | None (deferred to config.LoadConfig) | PASS |
| `--version` | bool | false | No | N/A | PASS |
| `--generate-config` | bool | false | No | N/A | PASS |
| `--dnscrypt` | bool | false | No | N/A | MEDIUM — no-op when used without `--generate-config` |
| `--provider` | string | `""` | With `--generate-config --dnscrypt` | None | PASS — validated by dnscrypt generator |
| `--addr` | string | `"127.0.0.1:8443"` | No | Has default | PASS |
| `--sql` | bool | false | No | N/A | PASS |
| `--rw` | bool | false | No | N/A | MEDIUM — must appear before positional args |
| `--dnsstamp` | bool | false | No | N/A | PASS |
| `--decode` | bool | false | With `--dnsstamp` | N/A | LOW — can be set with `--encode`, decode wins silently |
| `--encode` | bool | false | With `--dnsstamp` | N/A | LOW — same as above |
| `--proto` | string | `""` | With `--dnsstamp --encode` | Validated against 8 known types | PASS |
| `--stamp-addr` | string | `""` | With `--dnsstamp --encode` (not for ODoHTarget) | None | PASS |
| `--provider-name` | string | `""` | No | None | PASS |
| `--public-key` | string | `""` | With DNSCrypt stamp encode | Validated: 32 bytes / 64 hex chars | PASS |
| `--path` | string | `"/dns-query"` | No | Has default | PASS |
| `--props` | uint64 | `0` | No | None | LOW — no validation against known bitmask values |
| `--probe` | bool | false | No | N/A | PASS |
| `--pipeline` | bool | false | With `--probe` | N/A | LOW — can be set with other probe types, first wins |
| `--conn-reuse` | bool | false | With `--probe` | N/A | LOW — same as above |
| `--idle-timeout` | bool | false | With `--probe` | N/A | LOW — same as above |

## Signal Handling Audit

- **SIGINT handler**: Registered via `os/signal.Notify` in `server/tasks.go:setupSignalHandling()` (line 141), called from `Server.New()` (line 22 of `startBackgroundTasks` at line 123 of server.go). A goroutine listens on `sigChan` and calls `shutdownServer()` on signal.
- **SIGTERM handler**: Same channel, same handler as SIGINT.
- **Shutdown order**: `MarkClosed() -> cancel context -> plain.Shutdown() -> tls.Shutdown() -> dnscrypt.Shutdown() -> pprof.Shutdown() -> tlcp.Shutdown() -> wait backgroundGroup -> wait cacheRefreshGroup -> close prober -> close queryClient -> close cacheStore -> close(shutdown) -> log.Stop()`
- **Grace period**: 15s per protocol listener (`config.DefaultShutdownTimeout`), 30s for background/cache-refresh goroutines (`config.DefaultBackgroundShutdownTimeout`).
- **Gap in main.go**: main.go has no signal handling of its own. It relies entirely on `server/tasks.go`. If `Start()` returns an error (partial startup failure), `os.Exit(1)` is called without explicit cleanup — though `Start()`'s defers cancel the server context before returning, so goroutines eventually exit. This is acceptable because `Start()` only fails before the server is fully operational.

## Findings

### HIGH

#### [H-01] 代码质量+错误处理 — cli/probe.go:223 — OOO pipelining detection has false-negative blind spot

- **Problem**: The out-of-order (OOO) detection in `probePipeline` relies on comparing `resp.ID` against the sequential loop index `i` (0..4). For TCP connections, data arrives in the exact order the server writes it. If the server processes all 5 pipelined queries in FIFO order (the most common behavior for authoritative/recursive servers), responses arrive as IDs 0,1,2,3,4 in sequence, and OOO is never flagged even though pipelining IS supported. The code's own comment (lines 198-202) explicitly acknowledges this limitation: "Out-of-order delivery manifests if readDNSMsg reads a response for a later query while the conn has buffered an earlier one — unlikely in practice."
- **Risk**: The probe reports "No out-of-order responses observed — server may not support pipelining" for servers that correctly support RFC 7766 pipelining but process queries in order. The tool's output is misleading — it suggests lack of pipelining support when the test is simply incapable of proving it. Users may falsely conclude their server doesn't support pipelining.
- **Fix**: Replace sequential ID-to-index comparison with a bitmap-based presence check: record each `resp.ID` as received and, after all responses arrive, verify that every expected ID (0..N-1) is present. This definitively detects successful pipelining (all N responses received) even when OOO is not observed. The OOO message can remain as an additional diagnostic. A more robust approach would also use multiple concurrent connections (one per query) to force parallel processing, but that introduces complexity beyond what a CLI probe warrants. The minimum fix is: detect completion via ID presence (bitmap), not order. Also correct the output message when all responses arrived in order: say "all responses received (in order)" rather than "may not support pipelining".

### MEDIUM

#### [M-01] 架构设计 — cli/parse.go:56-58 — `--dnscrypt` flag is a silent no-op without `--generate-config`

- **Problem**: The `--dnscrypt` boolean flag only has an effect when `--generate-config` is also set (line 127: `if generateConfig { if dnscrypt { ... } }`). If a user passes `--dnscrypt` alone, the flag is set to true in memory but never checked — the program proceeds to server start mode or exits via another path. There is no error message or feedback.
- **Risk**: User confusion. A user running `zjdns --dnscrypt --provider example.com` without `--generate-config` sees nothing related to DNSCrypt and may think the command is still running or that DNSCrypt was applied to server config.
- **Fix**: After flag parsing, validate that `--dnscrypt` is accompanied by `--generate-config`. If not, print an error and exit:
  ```go
  if dnscrypt && !generateConfig {
      fmt.Fprintf(os.Stderr, "--dnscrypt requires --generate-config\n")
      return "", true
  }
  ```

#### [M-02] 参数校验 — cli/parse.go:148-157, 167-183 — Mutually exclusive sub-mode flags not validated

- **Problem**: (a) `--decode` and `--encode` can both be set; decode wins due to switch-case ordering. (b) `--pipeline`, `--conn-reuse`, `--idle-timeout` can all be set simultaneously; the first matching case wins. Neither group validates mutual exclusivity.
- **Risk**: Silent misbehavior if a user accidentally passes both flags (e.g., a script or alias that sets both). The user gets behavior they didn't intend with no warning.
- **Fix**: Validate mutual exclusion explicitly:
  ```go
  if dnsStampDecode && dnsStampEncode {
      fmt.Fprintf(os.Stderr, "--decode and --encode are mutually exclusive\n")
      return "", true
  }
  ```
  Same pattern for probe sub-modes (count set flags, error if > 1).

#### [M-03] 参数校验 — cli/parse.go:62-63 — `--rw` flag ordering dependency is fragile

- **Problem**: The `--rw` flag must appear before the positional `<db> <query>` arguments because Go's `flag` package stops parsing at the first non-flag argument. If `--rw` is placed after the positional args, it is silently ignored, and the query runs in read-only mode even though the user intended read-write. The usage text (line 94) notes this, but mis-ordering produces no warning.
- **Risk**: A user trying `zjdns --sql cache.db "INSERT INTO ..." --rw` gets read-only mode with no error. The INSERT silently fails (PRAGMA query_only blocks it), and the user gets "0 row(s) affected" with no explanation.
- **Fix**: After parsing, check if `--rw` is actually set via `fs.Lookup("rw").Value.String() == "true"`. If it claims to be false but the user intended it, there's no reliable detection. Alternatively, use a custom flag parsing approach or document this more prominently. A better fix: warn if `sqlRW` is false but the query starts with `INSERT`, `UPDATE`, `DELETE`, `DROP`, or `ALTER` (case-insensitive).

#### [M-04] 耦合度 — cli/generate.go:14 — server/protocol/dnscrypt import in CLI creates layer violation

- **Problem**: `generate.go` imports `zjdns/server/protocol/dnscrypt` directly (as `serverdnscrypt`). Per the project's architecture rules (CLAUDE.md), `server/` sub-packages should not be imported by higher-level packages beyond `server/` itself. The CLI tool is at the top layer alongside `cmd/zjdns`, and pulling in a `server/protocol` package creates an unnecessary dependency chain. The comment (DC-05) acknowledges this but justifies it because "key generation was extracted to internal/dnscryptcrypto, but GenerateDNSCryptConfig still lives in server/protocol/dnscrypt."
- **Risk**: This coupling means changes to `server/protocol/dnscrypt` (e.g., config structure changes) can break the CLI tool. It also means importing the CLI package pulls in all of server/protocol/dnscrypt's dependencies (including TLS, QUIC, etc.) into the binary even when only key generation is needed.
- **Fix**: Extract `GenerateDNSCryptConfig` into `internal/dnscryptcrypto` (which already exists) or a new `internal/generate` package. The `server/protocol/dnscrypt` package can call the same internal function for its own config generation. This breaks the dependency cycle cleanly.

#### [M-05] Panic检测 — cli/probe.go:177-178 — crypto/rand.Read error silently discarded

- **Problem**: `crypto/rand.Read(b[:])` error is assigned to `_` and ignored. If the system entropy source fails, `b` remains zero, producing domains like `www.00000000.com.` — all 5 queries target the same name. This is a degenerate test case: a single cached response could serve all queries, defeating the purpose of generating unique queries to exercise different resolution paths.
- **Risk**: In the unlikely event of entropy exhaustion (container startup, low-entropy VMs), the pipelining probe tests are meaningless because all 5 queries are identical.
- **Fix**: Check the error:
  ```go
  if _, err := rand.Read(b[:]); err != nil {
      return fmt.Errorf("generate random domain: %w", err)
  }
  ```
  Or use `math/rand/v2` for this non-cryptographic use case, avoiding the entropy dependency entirely.

#### [M-06] 参数校验 — cli/dnsstamp.go:86-88 — ODoHTarget protocol not validated for required fields

- **Problem**: `RunDNSStampEncode` checks that `addr` is required for all protocols except `ProtoODoHTarget`. However, it doesn't validate that `providerName` is set for ODoHTarget (which requires a provider name by definition, since it has no direct address). If a user encodes an ODoHTarget stamp without `--provider-name`, the resulting stamp has an empty `ProviderName`.
- **Risk**: An encoded but semantically invalid DNS stamp is produced without warning.
- **Fix**: Add validation:
  ```go
  if proto == zstamp.ProtoODoHTarget && providerName == "" {
      return fmt.Errorf("--provider-name is required for odoh-target protocol")
  }
  ```

#### [M-07] 错误处理 — cli/generate.go:100-103 — generateExampleConfig returns empty string on error

- **Problem**: If `json.MarshalIndent` fails (theoretically impossible for a struct, but could happen with recursive or cyclic data), `generateExampleConfig` returns `""`. The caller (`parse.go:135`) prints this silently: `fmt.Println(generateExampleConfig())`. The user sees an empty line and no error feedback.
- **Risk**: User confusion if this extremely rare error occurs.
- **Fix**: Return the error to the caller instead of logging and returning empty string. Change the signature to `func generateExampleConfig() (string, error)` and let `parse.go` handle the error display.

#### [M-08] 代码质量 — cli/probe.go:151-160 — isTimeoutOrEOF uses fragile string matching for EOF

- **Problem**: `isTimeoutOrEOF` checks for EOF using `strings.Contains(err.Error(), "EOF")` instead of the idiomatic `errors.Is(err, io.EOF)`. The string match also catches "EOF" in non-EOF error messages (e.g., "unexpected EOF in header"), which may be overly broad.
- **Risk**: False positives from error messages that accidentally contain "EOF". Also, wrapping an `io.EOF` error with `fmt.Errorf("...%w", io.EOF)` would still contain "EOF" so it works, but it's fragile. For "broken pipe", string matching is acceptable since there's no standard sentinel.
- **Fix**: Add `errors.Is(err, io.EOF)` as the primary check, fall through to string matching for "broken pipe":
  ```go
  if errors.Is(err, io.EOF) || errors.Is(err, syscall.EPIPE) {
      return true
  }
  ```

### LOW

#### [L-01] 注释准确性 — main.go:15-48 — Redundant os.Exit NOTE comments repeated 3 times

- **Problem**: The comment "NOTE: os.Exit skips deferred functions in main(). This package has no defers; safe." (or similar) is repeated on lines 15-16, 32, 42, and 47. Each instance is slightly different wording but conveys the same information. This is unnecessary repetition.
- **Fix**: Consolidate to a single comment at the top of `main()` or remove the per-call instance comments. The code is simple enough that a single note suffices.

#### [L-02] 参数校验 — cli/probe.go:48-98 — dialProbeTarget doesn't validate host after tryAddPort

- **Problem**: `tryAddPort` adds a default port if `net.SplitHostPort` fails. But `net.SplitHostPort` also fails for invalid host formats (e.g., bare IP like "1.2.3.4" without brackets). The function adds a port and returns the combined result, but the original invalid host (e.g., `1.2.3.4:53` vs `[::1]:53` for IPv6) isn't validated for correctness. `net.Dial` will attempt the connection and fail, producing a potentially confusing error message.
- **Risk**: Low-severity usability issue. The user gets an unclear connection error instead of "invalid address format."
- **Fix**: After `tryAddPort`, validate the host with a basic check or rely on `net.Dial` for the definitive error. Considered acceptable for a CLI probe tool.

#### [L-03] 参数校验 — cli/dnsstamp.go:81 — Path not validated for DoH/ODoH HTTPS path format

- **Problem**: `RunDNSStampEncode` accepts `--path` (default `/dns-query`) without validating that it starts with `/` for DoH/ODoH protocols. A user could pass `dns-query` (no leading slash) and produce an invalid stamp.
- **Risk**: Generated stamp is technically malformed for DoH protocol.
- **Fix**: If `proto` is DoH or ODoHTarget and `path` doesn't start with `/`, prepend one or warn:
  ```go
  if !strings.HasPrefix(path, "/") && (proto == zstamp.ProtoDOH || proto == zstamp.ProtoODoHTarget) {
      path = "/" + path
  }
  ```

#### [L-04] 参数校验 — cli/dnsstamp.go:82 — stampProps not validated against known bitmask values

- **Problem**: `--props` accepts any uint64 value. The documented valid values are 1 (DNSSEC), 2 (NoLog), 4 (NoFilter). No validation or warning is given for unknown bits.
- **Risk**: A user could pass `--props 8` and produce a stamp with undefined property bits, which other implementations may reject or misinterpret.
- **Fix**: Warn if any bits outside the known 1+2+4 mask are set, or silently mask them.

#### [L-05] 性能 — cli/probe.go:149 — SetDeadline/SetReadDeadline errors silently discarded

- **Problem**: Multiple calls to `conn.SetDeadline()`, `conn.SetWriteDeadline()`, and `conn.SetReadDeadline()` have their error returns discarded with `_ = ...`. If the connection is already closed or in an error state when a deadline is set, the error is silently lost. The subsequent read/write operation will fail with a potentially confusing error (e.g., "use of closed network connection").
- **Risk**: Debugging difficulty when probing fails — the root cause (deadline on closed conn) is masked by the subsequent I/O error.
- **Fix**: At minimum, log the deadline error at debug level. Since the probe is a CLI tool and these are unlikely to fail on a valid connection, this is low severity.

#### [L-06] 代码质量 — cli/sql.go:107-134 — RunSQLRW opens database before user confirms

- **Problem**: `RunSQLRW` opens the database connection BEFORE prompting for user confirmation (lines 120 vs 108-117). If the database cannot be opened (file not found, corrupt), the error is returned after the user types 'y', creating a confusing UX: user confirms, then gets an error.
- **Fix**: Open the database first, then prompt. If open fails, return immediately without prompting:
  ```go
  db, err := database.Open(dbPath, 0, database.Options{})
  if err != nil {
      return fmt.Errorf("open database: %w", err)
  }
  defer func() { _ = db.Close() }()
  // ... then prompt
  ```

#### [L-07] 文档质量 — cli/parse.go:85-101 — Usage text shows --sql with both --rw before and after args

- **Problem**: Line 94 shows `--sql <db> <query> --rw` (RW flag after positional args) while line 95 shows `--sql <db> <query>` (read-only, no `--rw`). But line 94's `--rw` position is misleading because Go's flag parser stops at the first non-flag arg, so `--rw` after `<db>` and `<query>` is silently ignored.
- **Fix**: Change line 94 to show `--rw --sql <db> <query>` (RW flag before positional args) and add a note that `--rw` must precede the database path.

#### [L-08] 日志质量 — cli/parse.go:159-161 — Probe error messages not distinguished from probe output

- **Problem**: When `runProbe` returns an error, the error is printed with `fmt.Fprintf(os.Stderr, "probe: %v\n", err)`. But the probe functions themselves print status messages to stdout via `fmt.Printf`. If both stdout and stderr are visible (normal terminal), the interleaving is fine. If stdout is redirected, the error goes to stderr but the partial probe output goes to stdout, potentially confusing script consumers.
- **Risk**: Very low — the probe is an interactive CLI tool, not designed for script consumption.
- **Fix**: Not required. Documented for awareness.

#### [L-09] 常量提取 — cli/probe.go:28-29 — Default probe ports duplicate config defaults

- **Problem**: `defaultProbePort = 53` and `defaultProbeTLSPort = 853` are defined locally in `probe.go`. These duplicate `config.DefaultUDPPort` (53) and `config.DefaultTLSPort` (853) defined in `config/defaults.go`. If the config defaults change, the probe defaults become inconsistent.
- **Fix**: Import and use `config.DefaultUDPPort` and `config.DefaultTLSPort` instead of duplicating the constants. Alternatively, accept that probe defaults are intentionally independent (the probe tests raw protocol behavior, not server config).

#### [L-10] 函数排序 — cli/probe.go:19-30 — Constants after imports but before type declarations

- **Problem**: Per project convention, declaration order should be `type → const → var → func`. In `probe.go`, the const block (lines 20-30) is defined directly after the import block, with no preceding types. This is correct (const before func), but there's no type block — the file is all functions. However, the constants include a comment that says "Probe timeout and count constants" — this is a struct comment style applied to a const block. Minor style inconsistency.
- **Fix**: Rename the comment or remove it. The const group is self-explanatory.

### INFO

#### [I-01] SQL injection — cli/sql.go:27,126 — User-controlled SQL queries are passed directly to the database engine

- **Observation**: Both `RunSQL` and `RunSQLRW` accept user-provided SQL strings from CLI arguments and pass them directly to `db.SQ.Query()` / `db.SQ.Exec()`. This is by design — the `--sql` flag is an administrative CLI tool for the user's own local database. There is no privilege boundary to cross: the user already has direct filesystem access to the `.db` file. No mitigation required.

#### [I-02] 架构设计 — main.go:18-18 — database.Version setting propagates build version

- **Observation**: `database.Version = Version` in main.go sets a package-level variable in the `database` package that is embedded into the SQLite schema header. This is a clean pattern for propagating build metadata to persistent storage. No issues. The import of `database` in main.go exists solely for this line, which is a minor coupling but acceptable for a top-level wiring package.

## Detailed File-by-File Notes

### main.go (22 lines)
- **Architecture**: Clean wiring — parse flags, load config, create server, start server. Minimal surface area. No anti-patterns.
- **Signal handling**: Entirely delegated to `server/tasks.go`. If `Start()` returns an error, `os.Exit(1)` is used (documented with NOTE comments).
- **Edge case**: When `s.Start()` returns an unexpected error after partial listener startup, `os.Exit(1)` bypasses any defers in main() — currently safe as there are none, but brittle against future changes.
- **Import check**: Imports `database` only for `database.Version = Version` (line 18). No other dependencies. No layer violations.

### banner.go (21 lines)
- Standard ASCII art banner with version interpolation. Single function.
- Minor: `b[1:]` strips the leading newline from the raw string literal — correct.

### version.go (25 lines)
- Package-level vars with ldflags hooks for CommitHash and BuildTime.
- `getVersion()` handles both ldflags-filled and empty cases gracefully.
- No issues.

### cli/parse.go (208 lines)
- Well-structured flag parsing with comprehensive Usage output.
- Help (`-h`/`--help`) is checked before `fs.Parse()` to avoid error output on intentional help.
- All special commands (`--version`, `--generate-config`, `--probe`, `--dnsstamp`, `--sql`) return `exitAfter=true` to prevent server startup.
- See findings M-01, M-02, M-03, L-07.

### cli/probe.go (296 lines)
- Three probe types implemented: pipeline, conn-reuse, idle-timeout.
- `dialProbeTarget` handles both TCP and TLS connections. TLS uses `InsecureSkipVerify: true` and `CurvePreferences: []eTLS.CurveID{}` — acceptable for a probing tool.
- `writeDNSMsg` / `readDNSMsg` handle TCP DNS framing correctly (2-byte length prefix + data).
- All connections are `defer close`'d.
- See findings H-01, M-05, M-08, L-02, L-05, L-10.

### cli/dnsstamp.go (115 lines)
- `RunDNSStampDecode` correctly maps stamp fields to `config.UpstreamServer` for all protocol types. The comment references `config.normalizeStamps` for cross-reference.
- `RunDNSStampEncode` validates public key length and DNSCrypt requirement. Missing ODoHTarget provider name validation (M-06).
- `parseProto` handles all 8 protocol types with informative error message on unknown input.
- See findings M-06, L-03, L-04.

### cli/generate.go (110 lines)
- `generateExampleConfig` produces a comprehensive, realistic example config spanning all major features (server settings, upstream servers with all protocols, zone rules, CIDR rulesets).
- Uses `config.NewDefaultServerConfig()` as base and overrides specific fields with demo values.
- `generateDNSCryptConfig` wraps `serverdnscrypt.GenerateDNSCryptConfig` — see finding M-04 for coupling concern.
- See findings M-04, M-07.

### cli/sql.go (134 lines)
- `RunSQL`: Opens database read-only, sets `PRAGMA query_only`, executes query, formats results as columnar table with header and row count.
- `RunSQLRW`: Opens database read-write, prompts for confirmation, executes statement, reports affected rows.
- Both functions properly close the database via `defer`.
- `valStr` handles nil, []byte, and arbitrary types gracefully.
- Row count printed to stderr (permits stdout redirection for table data).
- See findings L-06, L-07, I-01.
