# 04 · Upstream 包审计

**包范围**：`server/upstream`、`server/upstream/plain`、`server/upstream/tls`、`server/upstream/tlcp`、`server/upstream/dnscrypt`、`server/upstream/pool`、`server/upstream/socks5`

**审计日期**：2026-07-29
**审计重点**：连接池管理、lrumap 资源释放、SOCKS5 代理正确性

---

## 审计摘要

Upstream 层代码质量优秀。连接池管理清晰，`lrumap.Map` 用于 HTTP client/QUIC config 缓存且正确设置了 `OnEvict` 回调。SOCKS5 代理实现完整。

**发现总数**：0 CRITICAL + 0 HIGH + 0 MEDIUM + 1 LOW

---

## LOW（1 项）

### L-U1：`server/upstream/socks5/socks5.go:451` — `context.Background()` 做 UDP associate

- **文件**：`server/upstream/socks5/socks5.go:451`
- **类别**：context
- **问题**：`ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)` — UDP associate 创建独立的 context，不继承调用方的取消信号。
- **风险**：LOW——10s timeout 提供了保护，但若调用方 context 提前取消，UDP associate 不会随之取消。

---

## ✅ `lrumap` 审计 — OnEvict 检查

| 位置 | 值类型 | OnEvict | 状态 |
|------|--------|---------|------|
| `upstream/client.go:112` | `*socks5.Dialer` | ✅ `d.Close()` | ✅ |
| `upstream/tls/client.go:75` | `*quic.Config` | N/A（纯配置） | ✅ |
| `upstream/tls/client.go:76` | `*http.Client` | ✅ `CloseIdleConnections()` | ✅ |
| `upstream/tls/client.go:77` | `*http.Client` | ✅ `t.Close()` | ✅ |
| `upstream/tlcp/client.go:34` | `*http.Client` | ✅ `CloseIdleConnections()` | ✅ |
| `upstream/dnscrypt/client.go:32` | `*State` | N/A（纯数据） | ✅ |

---

## ✅ 验证通过

| 检查项 | 状态 |
|--------|------|
| TCP 连接池 RFC 7766 pipelining | ✅ |
| QUIC 连接池 0-RTT | ✅ |
| SplitGuard TCP 分段 | ✅ 随机 [1,4] 字节 + jitter |
| SOCKS5 UDP associate | ✅ RFC 1928 |
| DNSCrypt client key 缓存 | ✅ LRU + bounded |
| WarmUp goroutine 追踪 | ✅ `sync.WaitGroup` |
| 代理拨号器缓存 | ✅ OnEvict 正确关闭 |
| 同一 upstream 连接复用 | ✅ |
