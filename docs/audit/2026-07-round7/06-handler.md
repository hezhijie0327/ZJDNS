# Handler/Middleware 层审计报告 (Phase 1)

审计范围: `server/handler/*` + `server/handler/middleware/*` (16 个源文件)
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 0 | — |
| HIGH | 3 | 后台刷新 goroutine 存活超 shutdown、ProcessRecords 合约违规、刷新 goroutine 无界 |
| MEDIUM | 8 | QueryContext 分配、net.ParseIP 热路径、全量 Unpack、验证缺失、pendingRefreshes 泄漏路径 |
| LOW | 7 | ErrDrop pool 泄漏、超时日志、重复逻辑、审计追踪完整性 |

**共 18 个发现** (0 CRITICAL, 3 HIGH, 8 MEDIUM, 7 LOW)

## HIGH

### H1: 后台刷新 goroutine 可存活超过 server shutdown

- **文件**: `server/handler/middleware/cache_lookup.go:71-77, 137-158`
- **类别**: `goroutine/resource`
- **描述**: cacheRefreshGroup 无 context 取消。server shutdown 时刷新 goroutine 继续运行直到完成。每个调用 m.store.Set()/RecordRequest()；若 SQLite 已关闭则 data race/panic。
- **风险**: Shutdown 时 SQLite store 上的 data race。
- **修复**: 添加 context 取消同步或 MarkClosed() 中等待 refreshGroup。

### H2: restoreDomain 违反复制合约

- **文件**: `server/handler/middleware/response.go:119-138` + `cache/cache.go:139-161`
- **类别**: `memory`
- **描述**: cache.ProcessRecords 快速路径返回原始切片（无复制），restoreDomain 修改了返回记录上的 rr.Header().Name。违反 ProcessRecords 文档合约。
- **风险**: 若未来代码变化共享了结果，缓存损坏。
- **修复**: restoreDomain 调用前克隆记录或 restoreDomain 内克隆。

### H3: 后台刷新 goroutine 数量无界

- **文件**: `server/handler/middleware/cache_lookup.go:71-77`
- **类别**: `goroutine/resource`
- **描述**: cacheRefreshGroup errgroup 无 SetLimit()。病态负载下（大量唯一过期条目并发查询），可能创建数千 goroutine。
- **风险**: 病态负载下 OOM。
- **修复**: 添加 `m.refreshGroup.SetLimit(100)`。

## MEDIUM (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| M1 | `handler/handler.go:131` | 每查询分配 QueryContext — 考虑 sync.Pool |
| M2 | `middleware/response.go:84` | 热路径 net.ParseIP(FallbackClientIP) — 应启动时解析 |
| M3 | `middleware/edns.go:32-39` | 每查询全量 Unpack — 预处理 OPT 检查 |
| M4 | `middleware/validation.go:41-46` | 缺失 QCLASS/Opcode 验证 |
| M5 | `middleware/cache_lookup.go:132` | refreshGroup nil 时 pendingRefreshes 键泄漏 |
| M6 | `handler/handler.go:141` | 中间件链无每查询超时 context |
| M7 | `middleware/cache_lookup.go:67-78` | prefetch cooldown 和 tryStartRefresh 间无锁窗口 |
| M8 | `handler/pending.go:58` | LRU 逐出关闭 done channel 设 nil result — SERVFAIL 退化 |

## LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `handler/handler.go:143-147` | ErrDrop 路径潜在 pool 消息泄漏 |
| L2 | `handler/pending.go:96` | follower 超时错误不含 qname/qtype |
| L3 | `handler/handler.go:110-117` | 重复 FORMERR 构建逻辑 |
| L4 | `middleware/cache_store.go:110-127` | RecordRequest 在 ProcessRecords 前调用 |
| L5 | `middleware/ptr.go:26-27` | 缓存命中后不必要委托解析 |
| L6 | `handler/context.go:18-68` | 缺少 ServedBy 字段追踪响应来源 |
| L7 | `server/bridge.go:98-142` | TCP 查询无界 goroutine（tcpSem 部分解决） |
