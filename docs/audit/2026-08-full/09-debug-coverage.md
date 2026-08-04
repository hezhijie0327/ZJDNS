# 09 — Debug 日志覆盖率审计

> 审计日期: 2026-08-04 | 方法: 对热路径文件（bridge.go、cache_lookup.go、response.go、edns.go、tlcp.go、probe.go、cache/store.go）逐文件核对 Debug 日志覆盖

## 已核验的覆盖情况（通过）

| 路径 | 覆盖点 | 结果 |
|------|--------|------|
| `server/bridge.go` | TCP SERVFAIL pack/write 错误、write-lock 超时、UDP pack/truncate/write 错误 | ✅ 全部 Debugf |
| `middleware/cache_lookup.go` | refresh 失败、refresh 跳过（in-flight 去重） | ✅ Debugf |
| `middleware/response.go` | 无效 client cookie 长度、cookie 状态、EDNS 构造详情 | ✅ Debugf |
| `middleware/edns.go` | unpack 失败、malformed ECS/cookie、BADCOOKIE 各分支 | ✅ Debugf |
| `protocol/tlcp/tlcp.go` | accept 错误、read 错误、write 错误 | ✅ Debugf |
| `resolver/probe/probe.go` | —（无日志，静默成功路径，可接受） | ✅ |
| `cache/store.go` | miss 记录 | ✅ Debugf |

## 发现

### D1. [LOW] `cache/store.go:115` — Get/Set/ReverseLookup 热路径上的 Warn
每查询热路径（Get 失败、Set 失败）使用 Warn 而非 Debug（违反"每查询一条日志原则"，见方法论 §6.1-6）。在 SQLite 瞬时错误（锁竞争、IO 抖动）下高 QPS 会刷屏。应降为 Debug 并采样，或保留 Warn 但限流。
（与 08-logging.md 的 L 项重复，此处归档。）

### D2. [LOW] `cache/ptr.go:59` — ptr_map 插入错误同一事件记两次
同一 SQL 错误先 Warn 一次、return 后上层又 Warn 一次。合并为单次记录。

### D3. [LOW] `middleware/dns64.go` — DNS64 二次 A 查询无结果时无 Debug 日志
A 查询失败/空结果静默降级（返回无合成 AAAA），排障时无法区分"未配置 DNS64"与"A 查询失败"。建议补一条 Debug（qname/qtype/原因）。

### D4. [LOW] `resolver/recursive.go` apexCut 分支（line 223-233）
`advanceApexZoneCut` 失败后静默 `continue`，无 Debug 说明原因。与 M7（无状态推进）相关，修复 M7 时补日志。

## 结论
Debug 日志纪律整体良好：所有协议处理器的错误路径均为 Debugf，无 Error 滥用。遗留问题集中在 cache 层 Warn 级别误用（D1）与少量静默降级路径（D3/D4）。
