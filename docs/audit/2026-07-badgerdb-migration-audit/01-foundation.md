# 01 · Foundation 包审计

**包范围**：`internal/log`、`internal/pool`、`internal/ipdetect`、`internal/stamp`、`internal/ttl`、`internal/dnsutil`、`internal/lrumap`、`internal/pending`、`internal/siphash`、`internal/ipttl`、`internal/dns64`、`internal/latency`

**审计日期**：2026-07-29
**审计深度**：全部非测试文件

---

## 审计摘要

Foundation 层代码质量整体良好。未发现 CRITICAL 或 HIGH 问题。`lrumap.Map` 泛型 LRU 缓存实现稳健，正确替代了手写 map+mutex 模式。

**发现总数**：2 MEDIUM + 1 LOW

---

## MEDIUM（2 项）

### M-F1：`internal/latency/prober.go:33` 使用 `context.Background()`

- **文件**：`internal/latency/prober.go:33`
- **类别**：context
- **问题**：`bgCtx = context.Background()` 在 prober 初始化时创建独立的 background context，绕过了调用方的取消链。虽然 latency probe 是后台任务，但应使用 `context.WithoutCancel(parentCtx)` 来保留 parent context 的 values（如 tracing）。
- **风险**：prober 的 context 不继承任何 tracing/logging 元数据。在 shutdown 时，prober goroutine 无法通过 context 取消（依赖 `closeOnce` 和 channel 关闭）。
- **修复**：将 `New` 改为接受 `parentCtx context.Context`，内部用 `context.WithoutCancel(parentCtx)` 派生 background context。

### M-F2：`internal/dnsutil/dnsutil.go:64` — `CloseWithLog` 函数未在热路径外使用

- **文件**：`internal/dnsutil/dnsutil.go:64`
- **类别**：code-quality
- **问题**：`CloseWithLog(c io.Closer, name, prefix string)` 仅在测试文件中使用。生产代码中所有 Close 调用都是内联的（`_ = x.Close()` 或 `defer CloseWithLog`）。函数本身没有错误——只是它的存在暗示应统一 Close 模式，但实际未达成。
- **修复**：考虑在协议处理器中统一使用 `CloseWithLog` 替代裸 `_ = x.Close()`，或删除此函数以保持简洁。

---

## LOW（1 项）

### L-F1：`internal/log/log.go:324` — 日志轮转 goroutine 无 owner 追踪

- **文件**：`internal/log/log.go:324`
- **类别**：goroutine-lifecycle
- **问题**：`go func() { ... }()` 启用了日志文件轮转，但该 goroutine 未被任何 errgroup/WaitGroup 追踪。关闭通过 `closeOnce` + channel 实现，但没有等待 goroutine 退出的机制。
- **风险**：LOW——日志轮转是 fire-and-forget 的设计，通过 ticker 和 done channel 正确停止。

---

## ✅ 验证通过

| 检查项 | 状态 |
|--------|------|
| `lrumap.Map` 实现正确性 | ✅ 泛型、并发安全、LRU 淘汰 |
| `lrumap.New` 所有 12 个调用点 OnEvict 正确 | ✅ 资源型值全部设 OnEvict |
| `sync.Pool` 使用安全 | ✅ Put 前零值化 |
| `internal/pool` 分配器 | ✅ 正确使用 |
| `internal/ttl` TTL 计算 | ✅ 与 DNS 语义一致 |
| `internal/stamp` sdns:// 编解码 | ✅ 8 协议类型覆盖 |
