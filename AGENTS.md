# Repository Guidelines

ZJDNS is a high-performance, pure-Go recursive DNS server (module `zjdns`, Go 1.26, no CGo). It serves plain UDP/TCP, DoT, DoQ, DoH/DoH3, DNSCrypt, and TLCP/DTLCP, with built-in iterative recursion, DNSSEC validation, and a pure in-memory cache with optional file snapshots.

## Project Structure & Module Organization

- `cmd/zjdns/` — main binary and CLI tools (`--dnsstamp`, `--probe`, `--generate-config`, benchmark client).
- `server/` — protocol listeners (`protocol/`), request middleware chain (`handler/`), recursive/forward resolution (`resolver/`), outbound clients (`upstream/`), defenses (`defense/`).
- `cache/` — in-memory DNS response cache (LRU) with snapshot persistence and stats journal.
- `config/` — config loading/validation; all magic numbers live in `config/defaults.go`.
- `zone/`, `ruleset/`, `edns/` — zone filtering, tag rules, EDNS handling.
- `internal/` — shared libraries (log, pool, pending, dnsutil, latency, etc.).
- `docs/` — architecture, audit methodology, mirrored RFCs (`docs/rfc/`), debug configs, benchmark baselines.

## Build, Test, and Development Commands

```bash
go build -o zjdns ./cmd/zjdns                       # build
go test ./... -short                                # all tests
go test ./server/resolver/... -run TestXxx -v       # single test
go fix ./... && golangci-lint run && golangci-lint fmt  # required before commit (zero warnings)
sh scripts/bump-version.sh patch zjdns              # bump version (default: patch)
```

Run locally: `./zjdns --config config.example.json`.

## Coding Style & Naming Conventions

- `gofumpt` formatting; declaration order `type → const → var → func`; all lint suppressions inline (`//nolint:NAME // reason`).
- PascalCase exported / camelCase unexported; acronyms all-caps (`DNS`, `QUIC`); `Default` prefix for value constants, `ErrXxx` for sentinel errors, `IsXxx`/`HasXxx` for booleans, no `Get` prefix.
- Avoid stutter (`cache.Entry`, not `cache.CacheEntry`); one file per concern (~500 lines); interfaces defined in the consumer package.

## Testing Guidelines

- Standard `go test`; table-driven tests with `t.Run` subtests; name tests `TestXxx`.
- Unit benchmarks in per-package `benchmark_test.go`; integration benchmarks in `cmd/zjdns/benchmark_test.go`.
- Run `go test ./... -short` before committing; update `docs/benchmark/benchmark-baseline.txt` when benchmarks change.

## Commit & Pull Request Guidelines

- Conventional Commits: `fix:`, `perf:`, `feat:`, `chore:`, `refactor:`, `docs:`; descriptive body explaining the why; append `Co-authored-by:` trailers when applicable.
- Commit incrementally — one logical change per commit, after lint and tests pass.
- PRs: link the issue, summarize the change and verification (tests/benchmarks), and include config/log/pprof evidence for bug fixes.

### Co-Author Format

- Always add co-author information. If closing an issue in commit text, verify against `main` first: `gh issue view <issue-id>`.
- Only ONE co-author line is allowed. If multiple agents contributed, aggregate into ONE entry.

Format: `Co-authored-by: <AgentName> <Email>`

Valid examples (choose EXACTLY ONE):

```
Co-authored-by: Codex <codex@openai.com>
Co-authored-by: QoderAI <qoder_ai@qoder.com>
```

## Additional Guidance

- Start at `docs/README.md` — the docs index (navigation, test-doc boundaries, conventions).
- Architecture: `docs/ARCHITECTURE.md`; audit methodology: `docs/AUDIT-METHODOLOGY.md`; flowcharts: `docs/FLOWCHARTS.md`.
- `CLAUDE.md` holds agent behavioral guidelines — read it before large changes. Check `docs/rfc/` before implementing protocol behavior.
