# 06 · Handler 包审计

**包范围**：`server/handler`、`server/handler/middleware`

**审计日期**：2026-07-29
**审计重点**：中间件链执行顺序、QueryContext 安全、prefetch 逻辑

---

## 审计摘要

Handler 层实现了 9 层中间件管道，执行顺序正确。`QueryContext` 设计合理——可变共享状态在各中间件间传递。Prefetch 机制使用 bounded map 防止内存泄漏。

**发现总数**：0 CRITICAL + 0 HIGH + 1 MEDIUM + 0 LOW

---

## MEDIUM（1 项）

### M-H1：`cache_lookup.go:153` — prefetch goroutine 使用 `context.Background()`

- **文件**：`server/handler/middleware/cache_lookup.go:153`
- **类别**：context
- **问题**：`rc = context.Background()` 在 serve-expired 刷新路径中创建独立 context。虽然这是有意为之（后台刷新不应被原始请求的 context 取消影响），但应使用 `context.WithoutCancel(ctx)` 保留 tracing 元数据。
- **风险**：LOW——bg refresh 失败不影响当前请求（已有 stale 响应返回）。

---

## 中间件管道审计

按执行顺序（外层→内层）：

| 序号 | 中间件 | 职责 | 正确性 |
|------|--------|------|--------|
| 1 | `Response` | EDNS/Cookie/EDE finalisation | ✅ |
| 2 | `CacheStore` | 写缓存、请求日志、延迟探测 | ✅ |
| 3 | `Validation` | 域名/标签/ANY-AXFR 拒绝 | ✅ |
| 4 | `Zone` | Zone 规则匹配、合成响应 | ✅ |
| 5 | `EDNS` | ECS 解析、Cookie 验证 | ✅ |
| 6 | `CacheLookup` | fresh→serve, stale→serve+refresh, miss→delegate | ✅ |
| 7 | `PTR` | 反向 PTR 查找 | ✅ |
| 8 | `DNS64` | AAAA 合成 (RFC 6147) | ✅ |
| 9 | `Resolution` | upstream (first-win) 或递归 + singleflight | ✅ |

---

## ✅ 验证通过

| 检查项 | 状态 |
|--------|------|
| 中间件链短路正确 | ✅ `qctx.Res` 设置后停止传播 |
| PrefetchCooldown bounded map | ✅ 容量限制 + 定期清理 |
| QueryContext 字段访问安全 | ✅ 单 goroutine 访问（query per goroutine） |
| RecordRequest 异步发送 | ✅ async writer + 满时丢弃 |
