# 11 · 参数校验审计

**审计日期**：2026-07-29
**审计重点**：公开函数 nil/空字符串/零值检查、错误丢弃注释、裸类型断言

---

## 审计摘要

公开 API 的参数校验覆盖良好。构造函数（`New`、`Open`）对关键参数有 nil panic（fail-fast 模式）。错误丢弃全部有合理原因说明。

**发现总数**：0 CRITICAL + 0 HIGH + 0 MEDIUM + 1 LOW

---

## LOW（1 项）

### L-V1：`cache/stats.go:362` — `LatencyLastProbe` 未验证 `ip` 参数非空

- **文件**：`cache/stats.go:362`（修复后）
- **类别**：validation
- **问题**：函数未检查 `ip == ""`。虽然调用方 `probe.go` 不会传空 IP，但作为公开方法（`StoreReader` 接口的一部分），应做防御性检查。
- **风险**：LOW——空 IP 会查询 `e:ip:\x00_lat` key，不会 panic，但语义不正确。

---

## 构造函数 nil 检查审计

| 构造函数 | nil 检查 | 策略 |
|----------|---------|------|
| `cache.New(db)` | ✅ `panic("cache: nil database")` | fail-fast |
| `zone.New(db)` | ✅ `panic("zone: nil database")` | fail-fast |
| `ruleset.New(db)` | ✅ `panic("ruleset: nil database")` | fail-fast |
| `database.Open(path)` | N/A | 空路径=内存模式 |
| `server.New(cfg)` | ✅ `return error` | 返回错误 |

---

## `_` 错误丢弃审计

| 文件:行 | 丢弃的值 | 原因 | 状态 |
|----------|---------|------|------|
| `cache/store.go:86` | View error | 只读闭包，失败不影响 | ✅ 可接受 |
| `cache/store.go:200` | View error | 只读闭包 | ✅ 可接受 |
| `cache/stats.go:59` | View error | 只读遍历 | ✅ 可接受 |
| `cache/stats.go:371` | View error | 通过 `found` bool 传递结果 | ✅ 已修复（C1） |
| `cache/async_writer.go:174` | WriteBatch.Set error | 仅 OOM 失败；best-effort stats | ✅ 已加注释 |
| `zone/zone.go:269` | View error | 只读遍历 | ✅ 可接受 |
| `zone/zone.go:335` | View error | 只读遍历 | ✅ 可接受 |

---

## 裸类型断言审计

- **结果**：未发现裸类型断言（全部使用 comma-ok 模式）

---

## `net.ParseIP` / `net.ParseCIDR` nil 检查审计

| 文件 | 检查 | 状态 |
|------|------|------|
| `ruleset/ruleset.go:107` | ✅ `if err != nil` | ✅ |
| `ruleset/ruleset.go:199` | ✅ `if parsedIP == nil` | ✅ |
| `ruleset/ruleset.go:218` | ✅ `if _, _, err := net.ParseCIDR(value)` | ✅ |
