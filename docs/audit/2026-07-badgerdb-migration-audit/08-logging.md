# 08 · 日志质量审计

**审计日期**：2026-07-29
**审计重点**：热路径日志级别、刷屏检测、错误日志上下文完整性

---

## 审计摘要

日志质量整体良好。热路径（`cache.Get`、`Resolve` 等每查询路径）仅使用 `Debug` 级别。`Info`/`Warn` 仅用于状态变更和可恢复异常。发现 1 个 MEDIUM 问题。

**发现总数**：0 CRITICAL + 0 HIGH + 1 MEDIUM + 0 LOW

---

## MEDIUM（1 项）

### M-Log1：`cache/store.go:118,277,283` — Warn 日志不包含 qname/qtype 上下文

- **文件**：`cache/store.go:118,277,283`
- **类别**：logging
- **问题**：
  - 第 118 行：`log.Warnf("CACHE: unpack wire for entry %d (name=%s type=%d): %v", id, qname, qtype, err)` ✅ 有上下文
  - 第 277 行：`log.Warnf("CACHE: insert ptr_map failed (non-fatal): %v", ptrErr)` ❌ 缺少 entry ID/qname
  - 第 283 行：`log.Warnf("CACHE: insert entry failed: %v", err)` ❌ 缺少 qname/qtype
- **风险**：当 ptr_map 插入失败时，无法从日志定位是哪个域名/条目出的问题。
- **修复**：在第 277 行添加 entry ID，在第 283 行添加 qname/qtype。

---

## 热路径日志审计

每查询执行路径（所有中间件 + Resolver）：

| 文件 | 级别 | 检查 |
|------|------|------|
| `cache/store.go:107` | Debug | ✅ `CACHE: miss` |
| `cache/store.go:231` | Debug | ✅ 仅 `ZONE: bypass` debug |
| `zone/zone.go:231-233` | Debug | ✅ bypass 匹配 debug |
| `handler/middleware/*.go` | Debug | ✅ 中间件决策 debug |

**结论**：热路径无 `Info`/`Warn` 刷屏问题。

---

## 23 规范前缀使用审计

所有日志前缀与 23 个规范前缀列表一致。抽查结果：

| 文件 | 前缀 | 状态 |
|------|------|------|
| `cache/store.go` | `CACHE:` | ✅ |
| `cache/stats.go` | `CACHE:` | ✅ |
| `cache/async_writer.go` | `CACHE:` | ✅ |
| `zone/zone.go` | `ZONE:` | ✅ |
| `ruleset/ruleset.go` | `RULESET:` | ✅ |
| `database/db.go` | `DB:` | ✅ |

---

## 日志级别分布

| 级别 | 数量（估算） | 主要位置 |
|------|-------------|----------|
| Info | ~15 | 启动/关闭/规则加载 |
| Warn | ~12 | 可恢复错误（缓存未命中、解析失败） |
| Error | ~4 | 不可恢复错误（数据库关闭失败等） |
| Debug | ~30+ | 每查询调试信息 |
