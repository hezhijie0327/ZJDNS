# 26 · 交叉分析：资源生命周期

> 审计 Agent：Phase 2a · Resource
> 范围：全项目 Close() 幂等性、New/Close 对称性


---

## ZJDNS 资源生命周期审计报告

### 审计范围
- 所有的 `func Close()/Shutdown()` 方法 -- 幂等性检查
- Close 中的阻塞 IO（锁内 IO）
- `net.Listener`, `net.Conn`, `io.Closer` -- Close 配对
- `SetReadDeadline` -- 取消阻塞 IO
- goroutine 泄漏风险

---

### F1（中等）`upstream.Client.Close()` 缺少幂等性守卫

**文件**: `server/upstream/client.go:289`

**问题**: 没有 `sync.Once` 或 `atomic` 守卫。第二次调用会：
1. `c.warmWg.Wait()` 再次执行 —— 不 panic，但 WaitGroup 计数可能已经归零
2. 依次调用 `c.plainClient.Close()`、`c.tlsClient.Close()`、`c.dnscryptClient.Close()` —— 其中部分子客户端没有幂等性
3. `c.proxyDialers` 已经在前一次被置为 nil（`Range` 后 `c.proxyDialers = nil`），第二次进入 `proxyDialers != nil` 为 false，跳过 —— 分支出 bug：若 `proxyDialers` 的 `Range` 和第 306 行的 `nil` 赋值之间有 panic，则残留的 map 不会被再次遍历

**风险**: 低。在 `shutdownServer()` 的单次调用路径中不会触发；但如果被多个 goroutine 并发调用，有潜在的 panic 或双重关闭。

**修复建议**: 添加 `sync.Once` 或 `atomic.Bool` 守卫，如同 `cache/async_writer.go:27` 或 `database/db.go:146`。

---

### F2（低）`upstream/tls.Client.Close()` 缺少幂等性守卫

**文件**: `server/upstream/tls/client.go:101`

**问题**: 没有幂等性守卫。`dotPool.Shutdown()` 和 `quicPool.Shutdown()` 本身支持多次调用（pool.Shutdown 的设计是安全的），但 `dohTransports.Range` 在 lrumap 上的行为虽然对 nil 安全（Go 的 range map 安全），但逻辑上可能重复关闭。

**风险**: 低。子池的 Shutdown 是幂等的。

**修复建议**: 添加 `sync.Once` 守卫，与 `Client.Close()`（F1）保持一致。

---

### F3（中）DNSCrypt Server `Shutdown()` — TCP 连接 deadline 遗漏的竞态条件

**文件**: `server/protocol/dnscrypt/server.go:235-253`

**问题**: 存在 TOCTOU 竞态：
1. 第 248-250 行关闭 `tcpListeners`，此时不再接受新连接
2. 第 251-253 行 `range s.tcpConns` 设置 `SetReadDeadline(time.Unix(1, 0))`
3. 在第 1 步和第 2 步之间，如果有一个已经在第 1 步之前 `listener.Accept()` 返回的连接，在第 2 步的 `range` 之后才添加到 `s.tcpConns`（`serveTCP` 第 72-73 行），则该连接不会被设置 deadline

**触发场景**: 并发关闭时，一个 TCP 连接在 `handler goroutine` 中卡在 `ReadPrefixed`（第 107 行）。如果没有 deadline 触发，它可能永远无法退出除非客户端关闭连接。

**风险**: 中。概率低但一旦触发会导致 goroutine 泄漏。

**修复建议**: 在 `listener.Close()` 后，再启动一个"清扫"goroutine（或在循环中重试）：延迟一小段时间后第二次检查 `s.tcpConns`，对遗漏的连接设置 deadline。与 `dtlcpListener.Close()` 的 straggler 模式类似。

---

### F4（低）`socks5 Dialer.cleanupLocked()` — 通道和连接的双重关闭风险

**文件**: `server/upstream/socks5/udp.go:206-211`

**问题**: `cleanupLocked()` 在同一把锁下执行 `close(d.ctrlClosed)`。在并发场景下：
- `Dialer.Close()` 从外部调用的 `cleanupLocked` 和内部监视 goroutine 的 `cleanupLocked` 由 `d.mu` 串行化，`d.ctrlConn != nil` 守卫避免第二次调用
- 但第 194 行的 `_ = ctrlConn.Close()`（"unblock the read goroutine"）是显式给出的额外关闭。Go 标准库的 `net.Conn.Close()` 支持多次调用，但注释（第 191-192 行）指出替代实现可能不支持

**风险**: 低。仅当使用非标准 `net.Conn` 实现时才会出现问题。

**修复建议**: 保留现状，注释已充分说明。清理 goroutine 中的双重关闭逻辑可以用 `closeOnce` 或 `sync.Once` 包装。

---

### F5（低）`http3Transport.Close()` 缺少幂等性守卫

**文件**: `server/upstream/tls/http3.go:48`

**问题**: `Close()` 使用 `h.closed` 布尔值配合 `sync.Mutex`，但没有防止 `baseTransport.Close()` 被多次调用。

**风险**: 低。`http3.Transport.Close()` 可能支持多次调用，但不一定保证。

**修复建议**: 添加 `sync.Once` 守卫，或使用 `atomic.Bool` 记录已关闭状态。

---

### F6（低）`cache/store.go Cache.Close()` 缺少显式的幂等性守卫

**文件**: `cache/store.go:58`

**问题**: 本身无守卫，但委托的 `asyncWriter.Close()`（sync.Once）和 `db.Close()`（atomic.CAS）都是幂等的。如果将来向 `Cache` 添加了其他没有幂等性的资源，`Close()` 的二次调用可能不安全。

**风险**: 极低。当前状态安全。

**修复建议**: 可选添加一个上层 `sync.Once` 守卫作为防御性编程。

---

### F7（低）`upstream/plain.Client.Close()` 缺少幂等性守卫

**文件**: `server/upstream/plain/client.go:39`

**问题**: 无守卫。委托的 `tcpPool.Shutdown()` 本身支持多次调用。

**风险**: 极低。

**修复建议**: 可选添加守卫以保持代码风格一致。

---

### F8（信息性）`socks5 Dialer.Close()` 在持有锁时执行 IO 操作

**文件**: `server/upstream/socks5/socks5.go:196-201`

**问题**: `Dialer.Close()` 在 `d.mu.Lock()` 保护下调用 `cleanupLocked()`，该函数内部调用 `net.Conn.Close()`。`net.Conn.Close()` 通常不会显著阻塞，但严格来说是在锁内做 IO。

**风险**: 低。标准 TCP socket `Close()` 是快速操作；仅在异常实现或特殊网络条件下可能阻塞。

**修复建议**: 可模仿 `pool.ConnPool.Shutdown()` 的模式：在锁内收集资源，在锁外关闭。但当前状态的阻塞风险非常低。

---

### F9（信息性）`SetReadDeadline` 用于取消阻塞 IO — 使用均正确

**检查结果**: 所有 `SetReadDeadline` 的使用场景都是正确的：

| 位置 | 用途 |
|------|------|
| `server/protocol/dnscrypt/server.go:252` | `time.Unix(1, 0)` 设置历史 deadline 以取消 TCP Read |
| `server/upstream/pool/tcp.go:220` | 每个消息读循环的 idle timeout |
| `server/protocol/tls/tls.go:166` | DoT 连接 idle timeout |
| `server/protocol/tls/dtls.go:114` | DTLS 连接 idle timeout |
| `server/protocol/tlcp/dtlcp.go:285` | DTLCP 连接 idle timeout |
| `server/upstream/plain/udp.go:171-177` | Spoofguard 多读循环的轮询间隔 |

**风险**: 无。

---

### F10（信息性）`Net.Listener`/`net.Conn` 的 Close 配对 — 全部完整

**检查结果**: 所有 `net.Listener` 和 `net.Conn` 实例都有对应的 `Close()` 调用路径：

- `database/db.go:150` — `db.Badger.Close()`
- `server/protocol/plain/server.go:43-60` — `dns.Server.Shutdown()` 内部关闭 listener
- `server/protocol/tls/server.go:282-351` — 关闭所有 dot/doq/https/h3/dtls 的 listener 和 conn
- `server/protocol/tlcp/server.go:196-228` — 关闭所有 dot/doh/dtlcp listener
- `server/protocol/dnscrypt/server.go:235-277` — 关闭所有 UDP conn 和 TCP listener  
- `server/tasks.go:146-266` — 顶级 shutdown 序列先关闭协议服务器，再关 client 和 cache

**风险**: 无。

---

### F11（信息性）`Preload -> Resource Pairing` — `New` 创建的资源和 `Close` 的对应

审计了每个 `Close()` 方法和对应的 `New`/构造函数：

| 类型 | New 创建的资源（需关闭的部分） | Close 中释放 |
|------|---|---|
| `database.DB` | BadgerDB 实例 | `db.Badger.Close()` — 是 |
| `cache.Cache` | BadgerDB, AsyncStatsWriter goroutine | `asyncWriter.Close()`, `db.Close()` — 是 |
| `cache.AsyncStatsWriter` | goroutine (`run()`) | `close(ch) + <-done` 等待退出 — 是 |
| `upstream.Client` | plain/tls/dnscrypt sub-clients | 全部关闭 — 是 |
| `internal/log.TimeCache` | goroutine (ticker + update loop) | `Stop()` close channel + ticker.Stop — 是 |
| `internal/latency.Prober` | httpClientPool | Close() 释放 HTTP3/QUIC 连接 — 是 |
| `server/resolver/probe.Prober` | latency.Prober | `p.engine.Close()` — 是 |
| `server/upstream/pool/Conn` | goroutine (`readLoop`) | `close()` 等待 done channel — 是 |
| `server/handler.Handler` | 不创建资源 | MarkClosed() 标识停止；资源由 server 管理 — 是 |

**风险**: 无。所有构造函数创建的 goroutine 都有对应的关闭机制。

---

### 汇总

| 编号 | 文件 | 行号 | 严重程度 | 类别 | 描述 |
|------|------|------|----------|------|------|
| F1 | `server/upstream/client.go` | 289 | 中等 | 幂等性缺失 | `Client.Close()` 没有 sync.Once 守卫 |
| F2 | `server/upstream/tls/client.go` | 101 | 低 | 幂等性缺失 | `tls.Client.Close()` 没有守卫 |
| F3 | `server/protocol/dnscrypt/server.go` | 235 | 中等 | 竞态条件 | Shutdown 中 TCP 连接 deadline 遗漏导致潜在 goroutine 泄漏 |
| F4 | `server/upstream/socks5/udp.go` | 206 | 低 | 双重关闭 | `cleanupLocked` + 监视 goroutine 可能双重关闭 ctrlConn |
| F5 | `server/upstream/tls/http3.go` | 48 | 低 | 幂等性缺失 | `http3Transport.Close()` 可能多次调用 baseTransport.Close() |
| F6 | `cache/store.go` | 58 | 注意 | 防御性编程缺失 | `Cache.Close()` 自身无守卫 |
| F7 | `server/upstream/plain/client.go` | 39 | 注意 | 幂等性缺失 | `plain.Client.Close()` 无守卫 |
| F8 | `server/upstream/socks5/socks5.go` | 196 | 信息 | 锁内 IO | `Close()` 在持有锁时调用 `net.Conn.Close()` |
| F9 | 多个位置 | — | 信息 | 最佳实践 | `SetReadDeadline` 使用正确 |
| F10 | 多个位置 | — | 信息 | 资源完整性 | 所有 Listener/Conn 都有对应 Close |
| F11 | 多个位置 | — | 信息 | 配对完整性 | New 创建的 goroutine 和资源在 Close 中全部释放 |