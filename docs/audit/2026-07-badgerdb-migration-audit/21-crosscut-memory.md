# 21 · 交叉分析：内存安全

> 审计 Agent：Phase 2a · Memory
> 范围：全项目 goroutine 泄漏、无界增长、资源泄漏、池误用


现在我有了全面的了解。以下是完整的审计报告。

---

## 审计报告：ZJDNS 内存安全与资源泄漏

### 方法

审计了所有非测试 `.go` 文件（排除了 `_test.go` 和 `vendor/`），针对以下方面：

1. `make(chan[...` 和 `make(map[...` —— 边界检查
2. `append(` —— 无界增长风险
3. `sync.Pool` —— Put 之前的清理
4. `go func` —— 协程退出路径
5. 通过 `atomic.Pointer` 共享切片底层数组
6. 在 select 中使用 `timer.After`/`time.After`

---

### 总体评估

代码库在这方面维护得很好。除了一个中等严重级别的问题外，所有发现都是低严重性或信息性的。所有通道和 map 都具有固定的容量、信号量通信模式或用于限界的定期清理。大多数 `sync.Pool` Put 操作在返回前清除其缓冲区。所有协程都协调了退出路径。

---

### 发现

#### 等级：中等

**1. `//server/resolver/nameserver.go` 第 270、276 行 —— 无上下文防护的并发 NS 地址解析协程**

- **文件：** `/server/resolver/nameserver.go:270-276`
- **问题：** `resolveNSAddrType` 通过 `r.resolve(...)` 启动并发 A/AAAA 解析，该调用内部会分配 `context.WithTimeout`。这些协程通过 `wg.Wait()` 同步等待，没有外层 `select`/`ctx.Done()` 来短路。如果父上下文被取消（例如，第一个成功响应到达），解析协程仍然允许运行，直到它们各自的超时。
- **风险：** 中等。在正常操作下，协程数量受 NS 数量限制（通常 < 20），每个都有 DNS 查询超时（~5 秒）。但在高负载中断场景中，可处理的累积工作是：`NS_count × 2 × timeout`。如果一个区域有 20 个 NS 且每个查询超时，在最坏情况下这是 40 个解析 goroutine × 5 秒的持续工作。更关键的是，来自 `r.resolve` 的响应（可能来自池）没有为这些协程清理，导致更高的 GC 压力。
- **修复：** 考虑在 `resolveNSAddrType` 的 ctx 包装器中添加 `select { case <-ctx.Done(): return }`，或者为 `wg` 添加一个上下文感知的等待替代方案。此外，在取消时适当地 Put 回响应：
  ```go
  resolveCtx, resolveCancel := context.WithTimeout(queryCtx, timeout)
  defer resolveCancel()
  // 在超时或完成时检查 resolveCtx.Err()
  ```

**2. `//server/resolver/nameserver.go` 第 336 行 —— 服务器关闭时可能积累的 fire-and-forget NS 探测协程**

- **文件：** `/server/resolver/nameserver.go:336`，以及 `/server/resolver/recursive_ns.go:114`，`/server/resolver/ns_addresses.go:94,135`
- **问题：** 使用 `go func() { probe.ProbeNSAddrs(r.ctx, r.cache, addrs) }()` 启动的探测协程不检查 `r.ctx.Done()`。在服务器关闭期间，`backgroundCtx` 被取消，但任何已经在运行或已获取 `nsPending.Start` 令牌的探测协程将继续运行到完全探测超时（每次探测最多 300 毫秒，每个步骤最多 3 个步骤，每个 100 毫秒 = 最多 300 毫秒）。在高流量递归场景中，DNS 缓存未命中可能触发大量此类探测，在关机时产生成百上千个短暂的协程。
- **风险：** 低。每次探测都会获得一个 `nsPending.Start` 令牌（`maxPending=10000`）。每个探测工具都使用 `context.WithTimeout` 创建子上下文。实际风险是最坏情况下 ~10k × 300ms = 关机时额外的 ~3000 协程-秒工作。没有内存泄漏，但关机延迟可能略微延长。
- **修复：** 在探测函数的顶部添加一个快速 `ctx` 退出守卫：
  ```go
  func ProbeNSAddrs(ctx context.Context, cache CacheSetter, addrs []string) {
      if ctx.Err() != nil { return }
      // ...现有代码...
  }
  ```

---

#### 等级：低

**3. `//server/upstream/socks5/udp.go:292,364` —— `socks5WritePool` 在 Put 前没有清除**

- **文件：** `/server/upstream/socks5/udp.go:287-292` (`WriteTo`)，第 359-364 行 (`socks5UDPConn.Write`)
- **池：** `socks5WritePool`（在 `/server/upstream/socks5/socks5.go:110` 中定义，1500 字节缓冲区）
- **问题：** 写入路径上的 SOCKS5 UDP 缓冲区在返回前没有清除。虽然每个缓冲区在被 `writeDatagramHeader` + `copy` 写入到 socket 之前都会被完全覆盖到其 `totalLen`，但底层数组（容量为 1500）中超过新切片的 `totalLen` 且超过之前的总长度的部分可能包含旧的 DNS 查询数据。之前调用的 `totalLen` 与之后调用的 `totalLen` 之间的间隙会在内存中保留旧数据，直到 GC 回收。
- **风险：** 低。DNS 查询载荷不是秘密（查询名称、类型）。数据留在池缓冲区中，只有通过检查同一池的其他调用者的内存才能访问（同一进程，无跨进程泄漏）。写入路径在从 `Get` 返回后总是覆盖缓冲区，因此网络不会暴露旧数据。
- **修复：** 在 `Put` 之前添加 `clear(buf)`：
  ```go
  // WriteTo 第 292 行 — 变为：
  defer func() { clear(*bp); socks5WritePool.Put(bp) }()
  
  // socks5UDPConn.Write 第 364 行 — 类似
  ```

**4. `/server/handler/prefetch.go:20` —— 周期性清理器防止了无界 map 增长**（信息性）

- **文件：** `/server/handler/prefetch.go:57-83`
- **问题：** `PrefetchCooling.data`（`map[string]int64`）在没有 LRU 边界的情况下无限制地增长。然而，每 `DefaultPrefetchThrottleInterval × 10` 运行的 `Cleanup()` 方法通过在超过 `DefaultPrefetchCooldownMaxEntries` 时删除最旧的一半条目来强制执行硬性上限。
- **风险：** 无。边界有效。记录此处作为参考。

---

#### 通道边界（无问题）

检查了所有 `make(chan[` 实例。每个通道要么具有固定容量，要么是一个无缓冲的信号通道，要么是一个带有固定容量的信号量。未发现有界增长：

| 位置 | 容量 | 用途 |
|----------|----------|---------|
| `cache/async_writer.go:35` | `bufferSize` | 请求记录队列 — 满时丢弃 |
| `cache/async_writer.go:36` | 0（无缓冲） | Flush 信号 |
| `internal/latency/prober.go:37` | `DefaultMaxProbes` | 并发探测信号量 |
| `server/tasks.go:127` | 1 | 操作系统信号捕获 |
| `server/tasks.go:207,225` | 1 | 关闭时的 errgroup 等待 |
| `server/server.go:83` | `DefaultServerGoroutineLimit` | TCP 协程边界信号量 |
| `server/bridge.go:53` | `DefaultMaxPipe` | 每客户端 TCP 管道容量 |
| `server/bridge.go:54` | 1 | 每客户端 TCP 写入互斥体 |
| `server/protocol/tls/tls.go:108` | `DefaultDOTWriteChannelSize` | DoT 写入任务队列 |
| `server/protocol/tls/tls.go:153` | `DefaultMaxPipe` | DoT 工人容量 |
| `server/protocol/dnscrypt/server.go:122` | `DefaultMaxConcurrentStreams` | DNSCrypt 工人容量 |
| `server/resolver/forward.go:43` | 1 | 查询结果发送（有界发送者） |
| `server/resolver/nameserver.go:34` | 1 | NS 查询结果 |
| `server/upstream/pool/tcp.go:80` | `maxPipe` | 管道容量 |

---

#### sync.Pool 清理（无问题）

所有 `sync.Pool` 实例在返回前正确清除内存：

| 池 | 位置 | 清理 | 状态 |
|-----|----------|-------|--------|
| `pool.DefaultMessage` | `internal/pool/pool.go:104` | `*msg = dns.Msg{}` | 好 |
| `pool.DefaultBuffer` | `internal/pool/pool.go:151-152` | `clear(buf)` | 好 |
| `spoofguardBufPool` | `server/upstream/plain/udp.go:133` | `clear(buf)` | 好 |
| `socks5ReadBufPool` | `server/upstream/socks5/udp.go:253,333` | `clear(*buf)` | 好 |
| `socks5WritePool` | `server/upstream/socks5/udp.go:292,364` | 未清除（见发现 3） | 次要 |
| `socks5.ReadPool` | `server/upstream/plain/udp.go:116,264` | `clear(*respBuf)` | 好 |

---

#### 协程退出路径（审查）

24 个非测试 `go func()` 实例已审查。所有都有明确的退出路径：

- **基于 ticker 的后台任务**（`tasks.go`，`async_writer.go`，`log.go`）：通过 `<-ctx.Done()` 或通过 `close(done)` 退出
- **连接处理程序**（`tls.go`，`http3.go`，`dtls.go`，`dnscrypt/server.go`）：通过连接错误、`ctx.Done()` 或 `Accept` 返回退出
- **查询工作协程**（`tls.go:230`，`bridge.go:98`）：在单个查询处理后退出，具有基于 defer 的清理
- **errgroup 协调器**（`forward.go:97`，`nameserver.go:173`，`server.go:459`，`tls/server.go:256`）：当组完成时退出，具有有界通道发送
- **SOCKS5 UDP 中继监视器**（`socks5/udp.go:180`）：当 ctrlConn 关闭或 ctrlClosed 信号触发时退出

未发现协程泄漏。

---

#### 原子指针和切片共享（审查）

- **`resolver.go:61`** — `servers atomic.Pointer[[]*config.UpstreamServer]`：`list()` 返回 `*p`（与存储的切片共享底层数组）。存储始终分配一个新切片。调用者只读迭代。**安全。**
- **`forward.go:29`** — `lastUpstreamEDE atomic.Pointer[dns.EDE]`：存储的 EDE 指针指向来自池化消息的 Pseudo 切片的底层数组。Put 不会释放底层数组。**安全。**
- **`forward.go:44`** — `nxdomainResult atomic.Pointer[QueryResult]`：存储一个新分配的 QueryResult，具有来自消息的复制切片标头。消息被 Put 回去，但底层数组保持有效。**安全。**
- **`nameserver.go:40`** — `nxdomainMsg atomic.Pointer[dns.Msg]`：在成功的 `CompareAndSwap` 上存储而不 Put（第 145 行）。当 CAS 失败时 Put。在服务器关闭期间返回之前从未 Put 回去过（第 197 行）。**安全。**
- **`forward.go:266`** — `QueryResult{Answer: queryResult.Response.Answer, ...}`：复制切片标头，然后 Put 消息。底层数组保持有效。**安全。**

---

#### timer.After 在 select 中

代码库一致地使用 `time.NewTimer` 并配合 `defer timer.Stop()` 和超时清理循环。未在 select 中找到 `time.After`。`time.Ticker` 实例在函数退出时通过 `defer ticker.Stop()` 正确停止。

---

### 建议摘要

| 严重 | 文件 | 行 | 类别 | 描述 |
|----------|------|------|----------|-------------|
| 中 | `nameserver.go` | 270, 276 | 当上下文取消时 goroutine 不退出 | A/AAAA 解析协程在取消后仍然运行到超时。修复：添加 ctx.Done() 检查。 |
| 中 | `nameserver.go` | 336 | goroutine 在关闭期间运行 | ProbeNSAddrs 在服务器取消时没有短路。修复：在探测函数中添加 ctx.Err() 检查。 |
| 低 | `socks5/udp.go` | 292, 364 | 在 Put 之前没有 clear() | socks5WritePool 返回时在缓冲区中保留旧的 DNS 数据。修复：在 Put 之前添加 clear(*bp)。 |