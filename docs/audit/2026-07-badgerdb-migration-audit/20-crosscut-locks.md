# 20 · 交叉分析：锁正确性

> 审计 Agent：Phase 2a · Locks
> 范围：全项目 sync.Mutex/RWMutex/Once/atomic/channel/WaitGroup/Pool


现在我已经读取了所有相关文件。让我整理同步原语审计结果。

以下是 ZJDNS 代码库（排除 `_test.go`）中所有同步原语使用的综合审计。

---

# 同步原语安全审计报告

## 审计范围

已审计 30+ 个源文件，包含所有 `sync.Mutex`、`sync.RWMutex`、`sync.Once`、`sync.WaitGroup`、`sync.Pool`、`sync.Map`、`atomic.*` 操作和 `chan` 使用。

---

## 发现

### 1. [严重] DNSCrypt 服务器关闭：`s.wg` 上的数据竞争

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/dnscrypt/server.go:44`（声明），`:117`（赋初值），`:236-261`（关闭）

**问题：** `s.wg` 在 `Shutdown()`（第 236-261 行）中在 `s.mu` 下被写入（交换一个新的 `WaitGroup`），但在 `serveTCP`/`serveUDP`（第 44 行处的字段）中读取 `s.wg` 时未持有 `s.mu`。这是**无锁的共享可变数据**——在没有编译器/CPU 障碍的情况下读取 `s.wg` 指针。

**风险：** 读取协程可能获取旧指针，然后在 Shutdown 执行的 `prevWg.Wait()` 之后调用 `Add(1)`/`Done()`，导致在 WaitGroup 的计数已经达到零并被等待后对其进行操作——这是一个**已使用的 WaitGroup 被后续使用**，属于未定义行为。或者，如果读取协程获取了新指针，它会向一个永远不会被等待的 WaitGroup 添加，从而泄露协程追踪。

**修复建议：** 在 `serveTCP`/`serveUDP` 中，在对 `s.wg` 的任何读取周围添加 `s.mu.RLock()`/`RUnlock()`。或者（更干净的方法），完全不要交换 WaitGroup——使用一个单独的 `sync.WaitGroup` 并仅靠上下文取消来驱动关闭。

---

### 2. [高] OnEvict 回调在持有 lrumap 锁时执行阻塞 I/O

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/client.go:115-119`，回调在 `/Users/hezhijie/Downloads/ZJDNS/internal/lrumap/lru.go:176-187`（`evictLocked`）中被调用

**问题：** `lrumap.Map` 的 `OnEvict` 钩子被记录为“在持有 map 互斥锁的情况下运行，因此不得回调到 map 中或阻塞”。然而，在 `client.go:115-119` 中注册的回调中：

```go
c.proxyDialers.OnEvict = func(_ string, d *socks5.Dialer) {
    if d != nil {
        _ = d.Close()  // 获取 Dialer.mu 并执行网络 I/O
    }
}
```

`socks5.Dialer.Close()`（`socks5/socks5.go:196-199`）获取 `Dialer.mu` 并调用 `cleanupLocked()`，后者执行 `ctrlConn.Close()` 和 `udpConn.Close()` 这两个**阻塞网络 I/O** 操作——所有这些都发生在持有 `lrumap.Map.mu` 期间。这违反了 lrumap 的合约。

**锁顺序：** `lrumap.mu` → `Dialer.mu`

其他代码路径（`upstream/client.go:301-305` 中的 `proxyDialers.Range`）也遵循相同的顺序（在持有 `lrumap.mu` 时调用 `Dialer.Close()`），所以不存在 ABBA 死锁。但阻塞 I/O 在持有 `lrumap.mu` 时仍会阻塞所有对代理拨号器映射的访问。

**修复建议：** 从 OnEvict 回调中移除 I/O。相反，将要关闭的拨号器排入一个专用通道，由专用清理协程处理。或者在解引用并关闭之前，从 lrumap 中删除条目（先释放锁）。

---

### 3. [中] `PrefetchCooldown.ShouldStart()` 中的双重检查锁

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/handler/prefetch.go:30-52`

**模式：** 使用带有读锁/写锁优化的双重检查锁来减少写锁竞争。实现是正确的：

1. 快速路径：`RLock` → 读取 → `RUnlock` → 在 cooldown 内时返回 false
2. 慢速路径：`Lock` → 双重检查 → 存储 → `Unlock`

`Cleanup()`（第 57-84 行）在持有 `Lock` 时执行 `sort.Slice`（分配和 O(n log n) 排序）。在清理期间这会阻塞所有 `ShouldStart` 调用，但清理频率较低（每 ~N 秒），并且冷启动竞争应可忽略不计。**没有问题**，但值得了解其性能特征。

**风险：** 低。在负载下，`Cleanup` 持有写锁的时间可能比预期的长（由于 `sort.Slice`）。考虑在清理期间限制排序或分块处理。

---

### 4. [中] `dnscrypt/client.go`：`cacheMu` + lrumap 嵌套锁

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/dnscrypt/state.go:103-105`，`client.go:24-26`

`cacheMu`（一个 `sync.Mutex`）保护对 `cache *lrumap.Map` 指针的访问，而 lrumap 有它自己的内部 `sync.Mutex`。嵌套顺序为：`cacheMu` → `lrumap.mu`。这种顺序是全局一致的——没有相反的获取路径——所以不存在死锁。

**风险：** 无。设计正确。

---

### 5. [中] `DTLCP dtlcpListener.Close()`：连接的中途竞争

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/dtlcp.go:78-114`

**问题：** `Close()` 拍摄 `active` 连接快照，释放锁，关闭快照，重新获取锁检查剩余连接（在停止后接受的），然后关闭它们。在两个锁释放之间的窗口期，`Accept()`（第 57-76 行）可能添加一个新连接，该连接会被两个快照遗漏。这会导致连接永远不会被关闭。

**风险：** 低。关闭后，`l.closed` 为 true，并且 `readFirstDatagram()`（第 122-149 行）在读取下一个数据包之前检查它——所以窗口期最多只持续一个数据包。首次读取成功的连接可能会存活下来，但 `l.udpConn.Close()`（第 98 行）会关闭共享的 UDP 套接字，导致任何对该套接字的后续读取/写入失败。连接最终会因 I/O 错误而退出。**永远不会被关闭**的泄漏场景是理论上的，在实际中不太可能发生。

**修复建议：** 在退出 `Close()` 之前获取锁，并删除 `l.active` 中剩余的所有内容。

---

### 6. [低] `ConnPool.Acquire()` 中的 TOCTOU 竞争

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/pool/tcp.go:370-398`

`IsFull()` 检查和在返回的连接上发送之间有一个竞争窗口——`readLoop()` 可能已经在此刻关闭了连接。代码正确地记录了这一点（第 375 行注释），并且 `Exchange()` 通过 `closed.Load()` 检查安全地处理了这个问题，调用者会重试。

**风险：** 低。良性，有记录。

---

### 7. [低] `sync.Pool` Get/Put 配对——均已验证

所有 5 个 `sync.Pool` 实例：

| 池 | 文件 | 状态 |
|---|---|---|
| `pool.DefaultMessage` | `internal/pool/pool.go:73` | 正确——Put 时清零 |
| `pool.DefaultBuffer` | `internal/pool/pool.go:118` | 正确——验证 cap，清零 |
| `icmpBufPool` | `internal/latency/probes.go:32` | 正确——类型断言保护 |
| `spoofguardBufPool` | `server/upstream/plain/udp.go:49` | 正确——Put 时清零 |
| `socks5WritePool` / `ReadPool` / `socks5ReadBufPool` | `server/upstream/socks5/{socks5.go,udp.go}` | 正确——类型断言，Put 时清零 |

所有池都有正确的 Get/Put 配对、在 Put 时清除状态以防止信息泄漏，以及在类型断言失败时的优雅回退。**没有问题。**

---

### 8. [低] `atomic.Pointer` 用于不可变快照——均已正确

以下 `atomic.Pointer` 用法都遵循不可变快照模式（存储新分配的 struct，永远不修改已存储的 struct）：

| 位置 | 类型 | 正确性 |
|---|---|---|
| `edns/cookie.go:37` | `secrets atomic.Pointer[secretPair]` | 正确——旋转时分配新的 |
| `edns/edns.go:30-31` | `defaultECSIPv4/6` | 正确 |
| `server/resolver/forward.go:29` | `lastUpstreamEDE` | 正确——每次响应时捕获 |
| `server/resolver/forward.go:44` | `nxdomainResult` | 正确——CAS 保证唯一存储 |
| `server/resolver/resolver.go:61` | `upstreamSet.servers` | 正确——`store` 总是分配新的 slice |

---

### 9. [低] `server/resolver/nameserver.go:39-40`：`atomic.Pointer` + `pool.Put` 交互

```go
var poisonRejected atomic.Bool
var nxdomainMsg atomic.Pointer[dns.Msg]

// CAS 存储：
if !nxdomainMsg.CompareAndSwap(nil, result.Response) {
    pool.DefaultMessage.Put(result.Response)
}

// 消费：
if nx := nxdomainMsg.Load(); nx != nil {
    pool.DefaultMessage.Put(nx)  // 返回 NXDOMAIN
}
return nx, verdict, nil
```

如果 `nxdomainMsg` 被 CAS 存储，响应会从池中取出并由调用者使用，然后最终被放回。如果 NOERROR 后来被消费，NXDOMAIN 会被放回（第 185-186 行）。所有路径都正确地放回了响应。**没有问题。**

---

### 10. [低] `channel` 关闭所有权——均已正确关闭

| 通道 | 所有者 | 关闭保护 |
|---|---|---|
| `async_writer.go:ch` | `Close()` | `sync.Once` |
| `async_writer.go:done` | `run()` | 单个写入者 |
| `async_writer.go:flushSig` | `run()` | 从不关闭 |
| `pending.go:done` | `Done()` + `OnEvict` | `sync.Once` |
| `pending.go:resultCh` (forward.go) | 等待协程 | 单个写入者 |
| `pending.go:resultChan` (nameserver.go) | 等待协程 | 单个写入者 |
| `pool/tcp.go:done` | `close()` | `sync.Once` |
| `pool/tcp.go:resultCh` | `readLoop()` 写入，`Exchange` defer 排空 | 从不关闭（select/default 排空） |
| `log.go:done` | `Stop()` | `sync.Once` |
| `dnscrypt/server.go:rotateCh` | `Shutdown()` | 单个写入者 |

所有通道关闭都由唯一的已知所有者执行，或在 `sync.Once` 下执行。**没有发现双重关闭风险。**

---

### 11. [低] `atomic.Bool` 和 `sync.Mutex` 在 `hopguard.go` 中的混合

**文件：** `/Users/hezhijie/Downloads/ZJDNS/server/defense/hopguard.go:34`

`serverState.mu` 保护所有状态字段。`HopGuard` 本身维护一个 `*lrumap.Map[string, *serverState]`。`Validate()` 和 `Feed()` 获取 `serverState.mu`，但 lrumap 有其自己的内部锁。没有嵌套锁——lrumap 访问在 `serverState.mu` 之前被获取和释放。

**风险：** 无。锁顺序正确。

---

### 12. [低] `internal/lrumap/lru.go`——一般的互斥锁正确性

所有方法都在访问或修改共享 map 之前获取 `m.mu.Lock()`。`Range()` 在整个迭代过程中持有锁——这意味着回调应迅速返回（回调中不能进行 I/O、分配或其他锁获取）。所有当前的 `Range` 使用都是快速的（读取和关闭）。

**风险：** 无，只要 `Range` 调用不使用阻塞操作。

---

## 分类摘要

| # | 严重性 | 位置 | 问题 | 风险 |
|---|---|---|---|---|
| 1 | **严重** | `server/protocol/dnscrypt/server.go:44,236-261` | WaitGroup 交换时的数据竞争——已使用的 WaitGroup 被后续使用 | Shutdown 过程中 panic 或死锁 |
| 2 | **高** | `server/upstream/client.go:115-119` | OnEvict 在持有 lrumap 锁时执行阻塞 I/O | 在高代理关闭负载下长时间阻塞 LRU 访问 |
| 3 | **中** | `server/handler/prefetch.go:30-52` | 双重检查锁正确，但 Cleanup 持有锁进行排序 | 偶尔的高延迟，非关键 |
| 4 | **中** | `server/protocol/tlcp/dtlcp.go:78-114` | 关闭过程中连接被快照遗漏 | 连接句柄泄漏（低概率） |
| 5 | **低** | `server/upstream/pool/tcp.go:370-398` | TOCTOU：IsFull -> Exchange 窗口 | 良性，有记录，调用者重试 |
| 6 | **低** | 所有 `sync.Pool` | 全部正确配对 | 无 |
| 7 | **低** | 所有 `atomic.Pointer` | 全部正确使用不可变快照 | 无 |
| 8 | **低** | 所有 channel 关闭 | 全部由唯一所有者正确关闭 | 无 |
| 9 | **低** | `server/defense/hopguard.go` | 锁顺序正确，无嵌套竞争 | 无 |

---

## 修复优先级

1.  **严重（#1）**：立即修复。在访问 `s.wg` 时添加 `s.mu.RLock()` 以消除数据竞争。最干净的修复是不交换 WaitGroup——仅依靠上下文取消进行生命周期控制。
2.  **高（#2）**：需要优先考虑。从 OnEvict 中移除阻塞 I/O。最简单的修复是排入一个专用通道，由一个专门的清理协程处理。
3.  **中（#3-#4）**：应计划在下次迭代中修复。