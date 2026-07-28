# Handler Audit — server/handler/*

**日期**: 2026-07-28
**范围**: server/handler + middleware (15 文件)

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| H1 | **HIGH** | panic | `middleware/dns64.go:66` | `pending.Join` 返回 nil 时 nil 指针解引用 |
| H2 | MEDIUM | memory | `pending.go:71-113` | LRU map 淘汰导致 follower goroutine 成为孤儿（60s 超时） |
| H3 | LOW | logging | `handler.go:154-156` | SERVFAIL 回退路径上 `RecordRequest` 缺少查询身份字段 |
| H4 | LOW | coupling | `middleware/cache_store.go:13` | Middleware 直接导入 `server/resolver/dnssec` |
| H5 | LOW | panic | `middleware/cache_lookup.go:207` | `buildResponse` 未对 `entry` 做 nil 守卫 |
| H6 | LOW | performance | `middleware/cache_lookup.go:130` | Stale-hit 刷新产生无界 goroutine |
| H7 | LOW | performance | `middleware/edns.go:92` | BADCOOKIE 响应中重复 OPT 解析 |
| H8 | LOW | performance | `prefetch.go:57-83` | `Cleanup` 每 ~10s 进行 O(n log n) 排序 |

---

## 关键发现

### H1 — DNS64 nil 解引用 (HIGH)

`dns64.go:66` 将 `shared` 赋值给 `aqr` 并检查 `aqr.Err`，但未做 nil 守卫。若 leader 的 resolver panic 导致 `Done` 被调用并传入 nil，则 follower 收到 nil，此处发生 panic。

**修复**: 添加 nil 检查：
```go
if shared, follower := m.pending.Join(...); follower {
    if shared == nil {
        return err
    }
    aqr = shared
}
```

### H2 — PendingRequests LRU 淘汰导致 follower 孤儿 (MEDIUM)

`PendingRequests` 使用容量为 10000 的 `lrumap.Map`。满容量时 `LoadOrStore` 淘汰最久未使用的条目。若被淘汰的条目有活跃 follower 等待 `call.done`，leader 的 `Done` 调用找不到 key（`p.sets.Get` 返回 false）并提前返回而不关闭 channel。Follower 被阻塞直至 60s 的 `DefaultPendingFollowerTimeout` 触发。

**修复**: 将 `*pendingCall` 引用独立于 LRU map 存储，确保 `Done` 在 map 淘汰后仍能关闭 channel。

### H6 — Stale-hit 刷新 goroutine 无界 (LOW)

`serveExpiredWithRefresh` 通过 `m.refreshGroup.Go` 产生无界 goroutine。刷新 errgroup 无 `SetLimit`，持续的 stale-hit 负载可能导致数十万 goroutine 积累。

**修复**: 对刷新 errgroup 应用 `SetLimit`，或重构 timer-path 代码避免额外的 goroutine。

---

## 无问题维度

- 中间件链：组装顺序正确，与文档一致
- 锁正确性：`pending.Join`/`Done` 同步正确
- Pool 纪律：`resolution.go` 中响应 Put 正确
- 验证：nil req、空 question、nil IP 均正确检查
