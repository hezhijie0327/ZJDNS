# 24 · 交叉分析：Context 传播

> 审计 Agent：Phase 2a · Context
> 范围：全项目 ctx 第一参数、取消传播、Background/TODO 审计


现在我拥有所需的所有数据。以下是 **ZJDNS context.Context 审计** 报告。

---

## ZJDNS context.Context 审计报告

### 1. context.Background() 使用

发现 **18 处** `context.Background()` 调用（排除 `main.go` 和 `_test.go`）。按风险分类：

#### 高风险（2 项）

| # | 文件:行 | 详情 |
|---|---------|------|
| 1 | `server/resolver/probe/probe.go:226` | `latency.New(defaultNSProbeSteps(), context.Background())` — 使用 Background 而非从调用者的 `ctx` 衍生创建 Prober。 `ProbeIPsLatency` 检查 `p.ctx.Done()`（prober.go:88, 97）作为取消信号，但由于 Background 永不取消，导致该检查无效。从 `recursive_ns.go:114`、`nameserver.go:336`、`ns_addresses.go:94,135` 等 fire-and-forget goroutine 调用的 `ProbeNSAddrs`，会将 Prober 内部的 worker goroutine 与服务器生命周期解除绑定。 |
| 2 | `server/upstream/warmup.go:51` | `context.WithTimeout(context.Background(), c.timeout)` — 预热 goroutine 未绑定服务器生命周期。若预热期间服务器关闭（例如 `New()` 之后失败），goroutine 会持续运行至超时。 |

**风险：** 在关闭期间，Prober worker 可能会占用信号量槽位并继续测量，直到函数级超时到期。预热 goroutine 可能会在服务器关闭后存活。

#### 中风险（3 项）

| # | 文件:行 | 详情 |
|---|---------|------|
| 3 | `server/resolver/probe/probe.go:145` | `probeAndReorder` 中的 nil 回退：`if ctx == nil { ctx = context.Background() }` — 掩盖了传递 nil 的调用者。 |
| 4 | `server/resolver/probe/probe.go:182` | `ProbeNSAddrs` 中的 nil 回退：相同模式。 |
| 5 | `server/handler/middleware/cache_lookup.go:153` | `serveExpiredWithRefresh` 中的 nil 回退：`rc = context.Background()` 当 `m.refreshCtx` 为 nil 时。此时 `refreshCacheEntry`（第 248 行）会用 Background 运行，忽略了关闭信号。实践中 `refreshCtx` 始终设置于 `server.New()`，但 nil 分支掩盖了配置错误。 |

**风险：** 掩盖了上游调用者中传递 nil context 的 bug；取消传播会被静默破坏。

#### 低风险（13 项 — 使用正确，但可通过 `WithoutCancel` 改进）

位置：`server/tasks.go:166,177,187`、`server/protocol/tls/server.go:165,308,314`、`server/protocol/tlcp/server.go:116,208`、`server/protocol/tls/quic.go:122`、`server/protocol/dnscrypt/server.go:104`、`server/server.go:71`、`server/upstream/socks5/socks5.go:451`、`internal/latency/prober.go:33`。

- 根 context 创建（`server.go:71`、`tls/server.go:165`、`tlcp/server.go:116`、`dnscrypt/server.go:104`）：正确 — 服务器的派生根节点。
- 关闭超时（`tasks.go:166,177,187`、`tls/server.go:308,314`、`tlcp/server.go:208`）：这些在父 context 已被取消后运行，因此需要新鲜的 Background()。不适合使用 `WithoutCancel`。
- SOCKS5 解析（`socks5.go:451`）：新鲜超时用于 DNS 查询，正确。
- DoQ 延迟关闭（`quic.go:122`）：连接 context 可能已经取消，因此新鲜的 Background() 正确。

**风险：** 无直接风险。这些位置在语义上是 `context.WithoutCancel(parentCtx)` 的理想候选；不会阻止取消。

---

### 2. context.TODO() 使用

**未发现。** 良好规范。

---

### 3. context.WithoutCancel 使用

**未发现。** 8 个位置应使用 `WithoutCancel` 而非 `Background()` 来保留父 context 的值：

| # | 文件:行 | 当前模式 | 建议 |
|---|---------|----------|---------|
| A | `server/tasks.go:166` | `WithTimeout(context.Background(), ...)` | `WithTimeout(context.WithoutCancel(s.ctx), ...)` |
| B | `server/tasks.go:177` | 同上 | 同上 |
| C | `server/tasks.go:187` | 同上 | 同上 |
| D | `server/protocol/tls/server.go:308` | 同上 | `WithTimeout(context.WithoutCancel(s.ctx), ...)` |
| E | `server/protocol/tls/server.go:314` | 同上 | 同上 |
| F | `server/protocol/tlcp/server.go:208` | 同上 | `WithTimeout(context.WithoutCancel(s.ctx), ...)` |
| G | `server/protocol/tls/quic.go:122` | `WithTimeout(context.Background(), ...)` | `WithTimeout(context.WithoutCancel(conn.Context()), ...)` |
| H | `server/upstream/warmup.go:51` | `WithTimeout(context.Background(), ...)` | `WithTimeout(context.WithoutCancel(clientCtx), ...)` 如可用 |

**影响：** 低。当前使用是安全的；`WithoutCancel` 将更准确地表达意图，并保留任何 context 值（跟踪 ID、日志字段）。

---

### 4. 接受 ctx 的函数：参数位置

**已检查 80 多个接受 `context.Context` 的函数签名。** 发现以下违反 Go 约定（ctx 应为第一个参数）的情况：

| # | 文件:行 | 函数 | 问题 |
|---|---------|------|---------|
| 6 | `server/resolver/recursive_helpers.go:109` | `validateNODATAWithNSEC(response *dns.Msg, ctx context.Context, ...)` | ctx 为第二个参数。应改为 `ctx context.Context, response *dns.Msg, ...` |
| 7 | `server/protocol/plain/server.go:34` | `Start(g Group, ctx context.Context, handler dns.Handler)` | ctx 为第二个参数 |
| 8 | `server/protocol/plain/udp.go:14` | `startUDP(g Group, ctx context.Context, ...)` | 同上 — 匹配上游模式 |
| 9 | `server/protocol/plain/tcp.go:14` | `startTCP(g Group, ctx context.Context, ...)` | 同上 |

构造函数（`prober.go:31`、`server.go:240`、`handler.go:57`）有多个必填参数，并将 ctx 放在最后。这不太理想但更可接受。

**风险：** `golangci-lint` 未配置为强制执行 `contextcheck` 规则。`validateNODATAWithNSEC` 的排序异常可能使读者混淆参数顺序。

---

### 5. WithTimeout/WithDeadline：cancel() 调用

已检查所有 30 处 `WithTimeout`/`WithDeadline` 调用。几乎所有都有正确的 `defer cancel()`。

**异常：**

| # | 文件:行 | 问题 |
|---|---------|------|
| 10 | `server/protocol/tls/server.go:314-316` | `cancel()` 在 `srv.Shutdown(ctx)` 之后调用，而非使用 `defer cancel()`。若 `Shutdown` panic，则 context 泄露。 |
| 11 | `server/protocol/tlcp/server.go:208-210` | 相同模式：`cancel()` 在 `srv.Shutdown(ctx)` 之后。 |
| 12 | `server/protocol/tls/server.go:308` vs `:314` | 同一函数中模式不一致：第 308 行使用 `defer cancel()`，第 314 行使用手动 `cancel()`。 |

**风险：** 低。若 `srv.Shutdown` panic（可能性极低），则 context 会泄露直到 GC。

---

### 6. Goroutine context 获取

已审计 30 多处 goroutine 创建处的 context 获取：

#### 正确模式：

- `server/protocol/tls/tls.go:111,230` — goroutine 通过闭包使用 `connCtx`（派生自 `s.ctx`）。安全。
- `server/bridge.go:98` — goroutine 检查 `s.ctx.Done()`。按引用捕获用于读取的 `s.ctx` 是安全的。
- `server/protocol/dnscrypt/server.go:168,201` — goroutine 按值接收 `s.ctx`（作为参数传递给 `serveUDP`/`serveTCP`）。安全。
- `cache/async_writer.go:40` — 运行自己的 context（在 `run()` 方法中）。安全。
- `internal/latency/prober.go:80` — goroutine 按值接收 `ctx` 参数。安全。
- `server/resolver/nameserver.go:270,276` — NS 解析 goroutine。安全。

#### 值得注意的模式：

| # | 文件:行 | 详情 |
|---|---------|------|
| 13 | `server/resolver/recursive_ns.go:114` | 通过闭包按引用传递 `r.ctx`（解析器 context）给 fire-and-forget goroutine。如果解析器在其 goroutine 完成前关闭，监听 `r.ctx.Done()` 的 goroutine 将被取消。**正确。** |
| 14 | `server/resolver/nameserver.go:336` | 与上述相同模式 — 将 `r.ctx` 按引用传递给 `ProbeNSAddrs`。**正确。** |
| 15 | `server/resolver/ns_addresses.go:94,135` | 与上述相同模式。**正确。** |

**风险：** 无。这些是标准的、安全的模式。

---

### 7. Forward 路径 context 深度检查

`server/resolver/forward.go`：

- 第 45-46 行：`queryCtx, cancel := context.WithCancelCause(ctx); defer cancel(...)` — 正确模式。
- 第 75 行：`subCtx, subCancel := context.WithTimeout(queryCtx, ...); defer subCancel()` — 在 goroutine 内部，每次 NS 查询都正确地使用独立超时。
- 第 299 行：`recursiveCtx, recursiveCancel := context.WithTimeout(groupCtx, ...); defer recursiveCancel()` — 正确。
- `processUpstreamResponse`（第 240 行）和 `handleRecursiveQuery`（第 298 行）接受 `cancel` 和 `groupCtx` 作为参数。排序不标准但参数列表较长。

---

### 汇总

| 类别 | 数量 | 高风险 | 中风险 | 低风险 | 信息性 |
|--------|-------|--------|--------|-------|-----------|
| `Background()` | 18 | 2 | 3 | 13 | 0 |
| `TODO()` | 0 | 0 | 0 | 0 | 0 |
| 缺少 `WithoutCancel` | 8 个候选 | 0 | 0 | 8 | 0 |
| Ctx 参数位置 | 4 个异常 | 0 | 1 | 3 | 0 |
| `WithTimeout` 中缺失 `defer cancel` | 2 | 0 | 0 | 2 | 0 |
| Goroutine context 获取 | 15 个已审计 | 0 | 0 | 0 | 15 |

**总评分：** context.Context 规范是良好的。代码库避免 `context.TODO()`，在所有必需位置使用 `WithCancelCause`，通常使用正确的延迟取消模式，并正确地将 context 传播到 goroutine。最大风险领域是 `server/resolver/probe/probe.go` 中用于 NS 延迟探测的 Prober 使用 `context.Background()`，该 Prober 在服务器关闭期间不会取消——虽然函数级超时最终会提供边界，但服务器关闭信号丢失了。次要改进是将关闭路径改用 `context.WithoutCancel`，并修复 `recursive_helpers.go:109` 中的 ctx 参数顺序。