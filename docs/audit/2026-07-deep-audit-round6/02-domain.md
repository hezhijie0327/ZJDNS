# Domain Audit — config / database / cache / edns / zone / ruleset

**日期**: 2026-07-28
**范围**: config, database, cache, edns, zone, ruleset (33 文件)

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| D1 | MEDIUM | dead-code | `ruleset/ruleset.go:32,59,85` | 死字段 `hasDomainRules` — 设为 true 后立即置 false，从未读取 |
| D2 | MEDIUM | code-quality | `cache/store.go:302` | `stripOPT` 修改调用方切片底层数组作为副作用 |
| D3 | MEDIUM | panic | `edns/cookie.go:72,87` | CSPRNG 失败时 panic（两处） |
| D4 | LOW | documentation | `cache/cache.go:141-142` | 导出函数 `ProcessRecords` 的重复 godoc |
| D5 | LOW | code-quality | `zone/zone.go:43` | 拼写错误的非导出字段 `cachable`（应为 `cacheable`） |
| D6 | LOW | validation | `edns/padding.go:40` | `msg.Pack()` 错误静默丢弃，填充被错误跳过 |
| D7 | LOW | code-quality | `config/validate.go:107` | Warn 使用未 trim 的 `cfg.Server.LogLevel` 而非 `levelStr` |
| D8 | LOW | validation | `zone/zone.go:302,389` | zone 查询迭代中缺少 `rows.Err()` 检查 |
| D9 | LOW | performance | `config/validate.go:135` | 静态 `validProtocols` map 每次调用时重建 |
| D10 | LOW | code-quality | `cache/store.go:466` | 淘汰中 `last_probe_time > 0` 过滤器缺少文档注释 |

---

## 关键发现

### D1 — 死字段 `hasDomainRules` (MEDIUM)

`Engine.hasDomainRules` 在 `LoadRules` 循环中设为 `true`，事务提交后立即设为 `false`。该字段在整个代码库中从未被读取。

**修复**: 从 `Engine` 结构体中移除该字段及其两个赋值。

### D2 — `stripOPT` 副作用 (MEDIUM)

`Set()` 调用 `additional = stripOPT(additional)` 在原位修改调用方提供的切片底层数组。调用方获得损坏的数据视图。

**修复**: 在剥离前进行防御性拷贝：`stripOPT(cloneRRs(additional))`。

### D3 — CSPRNG 失败时 panic (MEDIUM)

`NewCookieGenerator` 和 `RotateSecret` 在 `crypto/rand.Read` 失败时调用 `panic`。

**修复**: 改为返回 `error`，让调用方决定是否记录日志、重试或正常失败。

---

## 无问题维度

- 导入分层：所有 domain 包导入遵循已记录的例外情况
- 数据竞争：无锁顺序违规或 goroutine 泄漏
- Pool 误用：`decompressBufPool`、`latencyArgsPool`、`wildcardArgsPool` 模式正确
- RFC 一致性：cookie 实现（RFC 9018 §4.2–§4.4）正确
