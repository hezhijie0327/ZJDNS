# 10 · 文档一致性审计

**审计日期**：2026-07-29
**审计重点**：ARCHITECTURE.md、CLAUDE.md 与代码一致性、注释准确性

---

## 审计摘要

文档整体质量良好，但发现 1 处已过时的接口引用（已修复）。CLAUDE.md 中的类型引用、中间件列表、架构描述与代码完全一致。

**发现总数**：0 CRITICAL + 0 HIGH + 1 MEDIUM + 0 LOW（全部已修复）

---

## MEDIUM（已修复）

### M-Doc1：`docs/ARCHITECTURE.md:141` — `ZoneStorage` 接口不存在

- **状态**：✅ 已修复——更新为直接使用 `*database.DB` 的描述
- **原内容**：引用已删除的 `ZoneStorage` 接口（`Exec`, `Begin`, `QueryZoneExact`, `QueryZoneWildcard`, `Close`）
- **新内容**：描述 `Evaluator` 持有 `*database.DB` 共享句柄，通过 BadgerDB prefix scan 查询

---

## 文档-代码交叉验证

### ARCHITECTURE.md 类型引用验证

| 文档引用 | 代码存在性 | 状态 |
|----------|-----------|------|
| `DB` struct | `database/db.go` | ✅ |
| `Cache` struct | `cache/cache.go` | ✅ |
| `Store` interface | `cache/cache.go` | ✅ |
| `AsyncStatsWriter` | `cache/async_writer.go` | ✅ |
| `Entry` struct | `cache/cache.go` | ✅ |
| `Evaluator` | `zone/zone.go` | ✅ |
| `Engine` (ruleset) | `ruleset/ruleset.go` | ✅ |
| `Detector` | `server/defense/` | ✅ |
| `Resolver` | `server/resolver/` | ✅ |
| ~~`ZoneStorage` interface~~ | N/A | ❌→✅ 已修复 |
| `HopGuard` | `server/defense/hopguard.go` | ✅ |
| `SpoofGuard` | `server/upstream/plain/udp.go` | ✅ |
| `SplitGuard` | `server/upstream/pool/tcp.go` | ✅ |
| 9 中间件列表 | `server/handler/middleware/` | ✅ |

### CLAUDE.md 类型引用验证

| 文档引用 | 代码存在性 | 状态 |
|----------|-----------|------|
| 全部 26 种 Key Types | 对应包中 | ✅ |
| BadgerDB 5 种 Key Prefix | `database/keys.go` | ✅ |
| 23 种 Log Prefix | `internal/log/` | ✅ |
| 导入层次 DAG | `go mod graph` | ✅ |

---

## 注释准确性扫描

| 文件 | 注释 | 准确性 |
|------|------|--------|
| `zone/parse.go:28` | ~~"inserts entries directly into SQL"~~ | ❌→✅ 已修正 |
| `cmd/zjdns/cli/parse.go:57` | ~~"// SQL"~~ | ❌→✅ 已删除 |
| `cache/store.go:217` | ~~"Wire format is zstd-compressed"~~ | ❌→✅ 已修正 |
| `zone/wire.go:14` | ~~"zstd(dns.Msg.Pack())"~~ | ❌→✅ 已修正 |
| `database/keys.go:42-43` | ~~重复的 godoc~~ | ❌→✅ 已修复 |

---

## 流程图覆盖（FLOWCHARTS.md）

未详细审查——建议下次审计包含完整的 mermaid 流程图验证。
