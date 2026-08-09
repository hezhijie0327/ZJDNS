# 06 — server/handler + middleware 审计

## L6 [LOW] stale-prefetch 路径在 refreshGroup==nil 时获取 gate 无释放

- **位置**：server/handler/middleware/cache_lookup.go:103-114
- **类别**：other（test-only 布线缺口）
- **问题描述**：preferStale 分支先 `m.tryStartRefresh(...)` 获取 pending-refresh gate（103 行），再检查 `m.refreshGroup != nil`（104 行）决定是否 TryGo。若 refreshGroup 为 nil（测试布线），gate 获取后无人释放 → 该 key 的所有后续 refresh 被永久阻塞。对比：fresh 命中路径（76 行）把 `m.refreshGroup != nil` 放进前置条件，显式注释了这个坑（73-75 行）—— stale 路径遗漏了同样的守卫。生产代码 refreshGroup 恒非 nil，故不可达。
- **风险**：仅测试环境；若未来重构允许 refreshGroup 可选，此路径静默阻塞刷新。
- **修复建议**：103 行条件补 `m.refreshGroup != nil &&`（与 76 行一致），并简化 104 行嵌套。

## QueryContext 与响应缓冲所有权

- **无发现**。已确认：
  - QueryContext 每查询独立分配、随请求生命周期释放，无跨请求滞留；
  - 缓存命中直发路径（pre-packed wire）所有权单一：response middleware 修 ID/RD 后由 bridge 写回，无中间层截留；
  - serve-stale 刷新路径缓冲归还正确（cache_lookup.go:148 归还 TTLOffsets —— 与 M1 形成对照，本包纪律良好）；
  - 中间件链无 per-query goroutine（全部同步链式调用），刷新 goroutine 全部 errgroup 追踪 + HandlePanic；
  - DNS64 合成缓冲无滞留。
