# 03 · Protocol 包审计

**包范围**：`server/protocol/plain`、`server/protocol/tls`、`server/protocol/tlcp`、`server/protocol/dnscrypt`

**审计日期**：2026-07-29
**审计重点**：并发安全、goroutine 生命周期、资源关闭、池归还纪律

---

## 审计摘要

协议层代码质量良好。TLS DoT handler 的池归还模式正确，被其他处理器作为模板引用。`lrumap.Map` 在 QUIC 地址缓存中的应用正确。

**发现总数**：0 CRITICAL + 0 HIGH + 1 MEDIUM + 1 LOW

---

## MEDIUM（1 项）

### M-P1：TLS server goroutine 使用 `context.Background()` 做 shutdown timeout

- **文件**：`server/protocol/tls/server.go:308,314`
- **类别**：context
- **问题**：`context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)` 在 shutdown 路径中创建独立 context。虽然 shutdown 时 server context 可能已取消，但使用 `context.Background()` 丢失了 tracing 上下文。
- **风险**：LOW——shutdown 路径不影响正常运行，但在调试 shutdown hang 时缺少 tracing 信息。

---

## LOW（1 项）

### L-P1：`server/protocol/tls/quic.go:29` — `addrCache` 包级变量

- **文件**：`server/protocol/tls/quic.go:29`
- **类别**：code-quality
- **问题**：`addrCache` 是包级变量，意味着多个 QUIC server 实例共享同一缓存。当前架构下只有一个 server 实例，但包级变量限制了未来扩展。
- **修复**：将 `addrCache` 移入 Server struct。

---

## ✅ 验证通过

| 检查项 | 状态 |
|--------|------|
| 池归还纪律（TLS DoT 模板） | ✅ 所有协议处理器正确 `defer Put` |
| `response.Data = nil` 在 Put 前 | ✅ 遵循 `tcp.go` 模式 |
| DNSCrypt 密钥轮转 | ✅ 24h 间隔 + 证书重叠期 |
| DTLS/DTLCP gotlcp workaround | ✅ 正确注释，有已知限制 |
| QUIC addr validation token cache | ✅ LRU + bounded |
| HTTP/3 Alt-Svc | ✅ 正确实现 |
| Goroutine 生命周期 | ✅ `errgroup` + `ctx.Done` 管理 |
| `Close()` 幂等性 | ✅ `sync.Once` 守卫 |
