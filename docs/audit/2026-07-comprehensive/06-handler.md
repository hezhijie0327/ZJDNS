# Handler + Defense + Server 顶层审计报告

## 审计范围

30 个源文件：`server/handler/`, `server/handler/middleware/`, `server/defense/`, `server/*.go`, `cmd/zjdns/`

## 发现

### HIGH

#### H1. HopGuard 永久拒绝所有状态

- **文件**: `server/defense/hopguard.go:117-126`
- **类别**: correctness, state-machine
- **问题**: 一旦 `st.armed` 变为 `true`，学习代码路径被永久绕过。`rebuildTrusted` 每次将直方图计数衰减 3/4。若所有受信任 TTL 衰减到阈值以下，`st.trusted` 变为空 map，但 `st.armed` 仍为 `true`——无解除武装机制。
- **风险**: 上游永久不可达直到进程重启。
- **修复**: 当 `len(st.trusted) == 0` 时重置为学习模式。

#### H2. Pending-refresh 锁泄漏（stale-prefetch）

- **文件**: `server/handler/middleware/cache_lookup.go:88-98`
- **类别**: resource, goroutine
- **问题**: `TryGo` 失败时 goroutine 不运行，`finishRefresh`（释放锁）永不调用。Pending-refresh 键被永久锁定。
- **修复**: `TryGo` 失败时立即调用 `finishRefresh`。

#### H3. serveExpiredWithRefresh goroutine + 锁泄漏

- **文件**: `server/handler/middleware/cache_lookup.go:119-145`
- **类别**: resource, goroutine
- **问题**: 前台刷新 goroutine 启动失败时，`done` channel 永不关闭，第二个 goroutine 永久阻塞。
- **修复**: `TryGo` 失败时立即关闭 `done`。

### MEDIUM

#### M1. cache.Set 错误被静默丢弃

- **文件**: `server/handler/middleware/cache_lookup.go:191-192,225` / `cache_store.go:108`
- **类别**: logging, error-handling
- **修复**: 记录 Debug 级别错误。

#### M2. Validation 中间件穿透逻辑不直观

- **文件**: `server/handler/middleware/validation.go:62-84`
- **类别**: code-quality
- **修复**: 重构为每个拒绝类别的早期返回。

#### M3. handler→resolver 子包耦合

- **文件**: `server/handler/handler.go:17`
- **类别**: coupling
- **说明**: 有意为之，架构文档认可。

#### M4. QueryContext Req "immutable" 注释不准确

- **文件**: `server/handler/context.go:19-21`
- **类别**: comments
- **修复**: 澄清为 "Pointer is never reassigned"。

### LOW

#### L1. 死代码 `var _ int64`

- **文件**: `server/handler/middleware/cache_store.go:100`
- **修复**: 移除。

#### L2. 关闭超时时孤儿 goroutine

- **文件**: `server/tasks.go:212-232`
- **说明**: 进程即将退出，可接受。

#### L3. HasPaddingOption 被调用两次

- **文件**: `server/handler/middleware/response.go:57-59`
- **修复**: 缓存结果。

### 维度合规

| 维度 | 状态 |
|------|------|
| 代码质量 | ⚠️ M2, L1, L3 |
| 内存安全 | ❌ H2（锁泄漏） |
| Goroutine 生命周期 | ❌ H2, H3 |
| 日志质量 | ⚠️ M1 |
| 注释准确性 | ⚠️ M4 |
| 架构设计 | ⚠️ M3 |
| 其余 | ✅ |
