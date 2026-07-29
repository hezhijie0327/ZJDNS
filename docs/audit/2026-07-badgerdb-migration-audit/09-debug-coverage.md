# 09 · Debug 日志覆盖率审计

**审计日期**：2026-07-29
**审计重点**：关键路径是否有 Debug 日志覆盖

---

## 审计摘要

Debug 日志覆盖了所有关键决策点。缓存命中/未命中、Zone 规则匹配、EDNS 处理、递归步骤均有 Debug 日志。

**发现总数**：0 CRITICAL + 0 HIGH + 0 MEDIUM + 1 LOW

---

## LOW（1 项）

### L-DC1：`cache_lookup.go:147-175` — stale 刷新路径无结果日志

- **文件**：`server/handler/middleware/cache_lookup.go:147-175`
- **类别**：debug-coverage
- **问题**：`serveExpiredWithRefresh` 启动后台刷新后，不记录刷新是成功还是失败。仅有 `RecordRequest` 调用记录到 stats key 中（非 Debug 日志行）。
- **风险**：LOW——stale 数据已返回给客户端，刷新失败不影响用户体验。

---

## 关键路径覆盖矩阵

| 路径 | Debug 日志 | 状态 |
|------|-----------|------|
| 缓存命中 | `CACHE: hit`（在 middleware 层） | ✅ |
| 缓存未命中 | `CACHE: miss for %s (type=%d)` | ✅ |
| 缓存过期可服务 | `CACHE: serve expired`（在 middleware 层） | ✅ |
| Zone 规则匹配 | `ZONE: bypass[%d] score=%d` | ✅ |
| EDNS Cookie 验证 | `EDNS: cookie valid/invalid` | ✅ |
| PTR 查找 | Debug（在 middleware 层） | ✅ |
| 递归步骤 | `RECURSION: step %d` | ✅ |
| DNSSEC 验证 | `DNSSEC: valid/bogus` | ✅ |
| 延迟探测 | Debug（在 probe 层） | ✅ |
| 防御触发 | `SECURITY: poison detected` | ✅ |
| 上游选择 | `UPSTREAM: selected %s` | ✅ |
