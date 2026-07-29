# 18 · Handler 包深度审计

> 审计 Agent：Phase 1 · Handler
> 覆盖：server/handler/* 全部 19 个非测试文件


现在我已经对所有 19 个文件进行了全面审计。以下是完整的审计报告。

---

# server/handler/ + server/handler/middleware/ 审计报告

审计范围：19 个非测试 .go 文件（`server/handler/` 下的 6 个文件 + `server/handler/middleware/` 下的 12 个文件 + 1 个共享的 handler 前导文件）。涉及的全部 18 个维度。

---

## 发现 #1 — HIGH — errgroup.Go() 在刷新容量饱和时同步阻塞查询处理程序

**文件：**
- `server/handler/middleware/cache_lookup.go` 第 71、95、141、215 行（调用 `m.refreshGroup.Go()` 的四个位置）

**类别：** 性能 / Goroutine 生命周期

**描述：**
`m.refreshGroup` 由 `errgroup.WithContext(ctx)` 创建，并设有限制 `DefaultCacheRefreshConcurrency = 64` (config/defaults.go:152)。`errgroup.Group.Go()` 在超过限制时会阻塞——它等待一个槽位空闲，然后才启动 goroutine。在 `cache_lookup.go` 中，`Go()` 的四个调用点均位于查询处理程序 goroutine 内部（即同步路径上）：
- 第 71 行：预热预取（缓存命中，TTL 较低）
- 第 95 行：过期入口的陈旧预取
- 第 141 行：`serveExpiredWithRefresh` 中的前台刷新
- 第 215 行：超时后的后台更新

如果所有 64 个槽位都被活跃的刷新占满，第 65 个查询会阻塞在 `Go()` 上，从而导致客户端响应延迟。对于第 141 行，阻塞发生在设置计时器之前，因此 600 毫秒的陈旧服务超时实际上直到 `Go()` 返回后才开始计时。

**风险场景：**
在突发陈旧入口刷新期间（例如，10,000 个 TTL 几乎同时过期），64 个刷新 goroutine 填满 errgroup。随后针对其他过期入口的查询会无限期阻塞，直到一个槽位释放。客户端观察到查询超时或延迟显著增加。由于 `DefaultServeExpiredClientTimeout` 是 600 毫秒，如果 `Go()` 阻塞超过 600 毫秒，陈旧响应将返回延迟。

**修复建议：**
将 errgroup 线程数包装到一个非阻塞的分派模式中：
```go
select {
case m.refreshLimiter <- struct{}{}:
    go func() {
        defer func() { <-m.refreshLimiter }()
        // … existing logic …
    }()
default:
    log.Debugf("CACHE: refresh skipped — at capacity")
}
```
或者，使用一个带缓冲通道的专用 goroutine 作为工作池，而不是同步的 `errgroup.Go()`。

---

## 发现 #2 — HIGH — BADCOOKIE 响应上重复的 ApplyToMessage 导致 OPT 选项重复

**文件：**
- `server/handler/middleware/edns.go` 第 91 行（`buildBadCookieResponse` 调用 `ApplyToMessage`）
- `server/handler/middleware/response.go` 第 67 行（`finalizeResponse` 调用 `ApplyToMessage`）

**类别：** RFC 一致性 / 正确性

**描述：**
当一个无效的 DNS Cookie 触发 BADCOOKIE 响应时：
1. `edns.go` 第 84-93 行的 `buildBadCookieResponse` 通过 `m.edns.ApplyToMessage()` 构建消息并应用 EDNS 选项（ECS、COOKIE、PADDING）。
2. 控制权返回到外部中间件（CacheStore、Validation、Response）。
3. `response.go` 第 38-78 行的 `Response.finalizeResponse` 再次调用 `m.edns.ApplyToMessage()`，并传入从 `generateCookieStr` 生成的第二个 cookie 字符串。

`ApplyToMessage` (edns/edns.go:106-123) 使用 `append(msg.Pseudo, ...)` 来添加选项——它不会清除现有选项。结果导致 `msg.Pseudo` 中出现了重复的 `dns.COOKIE`、`dns.SUBNET` 和 `dns.PADDING` 选项。序列化后会产生一个格式错误的 OPT 记录，违反了 RFC 6891。

**风险场景：**
每次无效的 DNS Cookie（短/过期/伪造的服务器 cookie）都会产生一个带有重复 EDNS 选项的 BADCOOKIE 响应。对等端可能会丢弃这些响应，导致查询失败/重试。这也使得服务器 Cookie 生成和验证的审计日志变得混乱。

**修复建议：**
最简单的修复方案：让 `finalizeResponse` 在再次调用 `ApplyToMessage` 之前，检查响应是否已经通过 EDNS 中间件构建（例如，检查一个 `qctx.EDNSApplied` 标志位）。或者，更简洁的方案：让 Response 中间件跳过对由 `qctx.Res` 非 nil 且 `CacheServed` 为 false 且 `ZoneMatched` 为 false 的短期响应调用 `ApplyToMessage`——不过，这需要一个更好的状态机。
或者，将 cookie 生成逻辑统一到 Response 中间件中，并移除 `buildBadCookieResponse` 中的 `ApplyToMessage` 调用。

---

## 发现 #3 — MEDIUM — 待处理请求的 LRU 驱逐导致 SERVFAIL 静默丢失

**文件：** `server/handler/pending.go` 第 58 行（`OnEvict` 回调），第 78 行（`LoadOrStore`）

**类别：** 内存安全 / 正确性

**描述：**
`PendingRequests.sets` 是一个容量为 10,000 的 `lrumap.Map`。当它达到容量上限时，`LoadOrStore`（第 78 行）或 `Store` 会驱逐最旧的条目。驱逐回调（第 58 行）会关闭该条目的 `done` 通道：
```go
p.sets.OnEvict = func(_ PendingKey, call *pendingCall) { call.once.Do(func() { close(call.done) }) }
```
如果被驱逐的条目有一个正在等待的跟随者 goroutine，跟随者会从 `<-actual.done` 唤醒，读取 `actual.result`——该值为 nil，因为 `Done()` 从未执行——然后返回 nil。`Resolution.Wrap` (resolution.go:52-55) 检查 `qr == nil` 并设置 `qctx.ResolutionError = true`，但不设置任何响应。后续的 CacheStore 中间件看到 `ResolutionError`，会返回 SERVFAIL。

**风险场景：**
在超过 10,000 个并发唯一查询（相同 qname+qtype+ECS）的极端情况下，当某个查询仍在进行中（其 `pendingCall` 仍在映射中，`Done` 尚未被调用）时，该条目可能会被驱逐。等待中的跟随者会收到 SERVFAIL。实际上，在 10,000 条限制下，这种情况极为罕见——要求并发 inflight 查询数量超过映射容量，这通常受文件描述符的限制。然而，在遭受字典攻击攻击或发生异常上游延迟时，这是可能的。

**修复建议：**
将 LRU 映射替换为一个普通的 `sync.Map`，并配合基于通道的驱逐机制，或者使用一个自定义的映射，该映射在容量满载时拒绝新条目（从而允许最旧的 inflight 条目保留在映射中），然后优雅地回退。或者，将 `OnEvict` 回调设置为仅当 `result` 已设置（即其 `once.Do` 已在 `Done()` 中执行过）时才关闭 `done`，否则忽略驱逐并让映射泄漏该条目（建议单独跟踪峰值情况）。

---

## 发现 #4 — MEDIUM — MaxDomainLength = 253 对完整的 FQDN 有误

**文件：**
- `config/defaults.go` 第 182 行（`MaxDomainLength = 253`）
- `server/handler/middleware/validation.go` 第 62 行（`len(qname) <= config.MaxDomainLength`）

**类别：** RFC 一致性 / 常量提取

**描述：**
对于完全限定域名（FQDN），`len(qname)` 包含末尾的点。例如，一个 253 字符的域名加上末尾的点是 254 个字符。`MaxDomainLength = 253` 排除了紧贴边界长度的域名，这些域名是 RFC 1035 第 2.3.4 条允许的（最大有线格式长度为 255 字节，对应一个最多 253 字符的字符串 + 1 个末尾点的字符串长度为 254）。

若一个有效域名的名称恰好是 253 个字符（例如：`a...a（253 个字符）.`），它会因为长度 254 > 253 而被拒绝。实际影响较低，因为这种边界长度的域名极为罕见。

**风险场景：**
一个 253 字符的域名会被 RFC 1035 拒绝，并返回 REFUSED 响应。任何操纵此类边界的合法查询都会失败。

**修复建议：**
将 `MaxDomainLength` 更改为 254：
```go
MaxDomainLength = 254 // FQDN 字符串包含末尾的点；RFC 1035 第 2.3.4 条最大值为 253 字符 + 1 个点
```

---

## 发现 #5 — MEDIUM — 后台刷新使用 context.Background()，不传播关闭信号

**文件：** `server/handler/middleware/cache_lookup.go` 第 152-154 行

**类别：** Context 传播 / 资源生命周期

**描述：**
在 `serveExpiredWithRefresh` 中，当 `m.refreshCtx` 为 nil 时，刷新上下文的回退值为 `context.Background()`。当服务器关闭时，该上下文永远不会被取消。如果 `refreshCtx`（来自 `server.go` 的 `cacheRefreshCtx`）为 nil，则关闭期间启动的刷新操作会一直运行，直到 `DefaultBackgroundTimeout`（10 秒）到期。

在正常操作中，`refreshCtx` 不会被设置为 nil——它在 `server.go:73` 中创建。然而，如果直接构造 `Dependencies` 而未设置 `RefreshCtx`，或者将来某个重构弄错了它，后台刷新可能会变成孤儿，导致在关闭后 goroutine 泄漏最多 10 秒。

**风险场景：**
在关闭期间，最多 64 个后台刷新 goroutine（受 errgroup 限制）继续运行最多 10 秒。如果 `m.refreshGroup` 也未被正确配置，刷新 goroutine 根本无法启动，并且陈旧响应始终需要完整的 600 毫秒超时才能返回。

**修复建议：**
移除 `context.Background()` 回退值，并让 `RefreshCtx` 成为 `Dependencies` 中的必需字段（非 nil）。如果合理的用例需要 nil，则记录日志 `log.Warnf`，指示关闭取消将不会传播。

---

## 发现 #6 — MEDIUM — 预取冷却键仅使用 qname，不包括 qtype

**文件：** `server/handler/middleware/cache_lookup.go` 第 69 行

**类别：** 性能 / 正确性

**描述：**
预热预取冷却检查传递 `qname`（来自 `qd.Header().Name`）作为 `ShouldStart` 的键。这意味着同一域名的不同类型（例如，`example.com A` 和 `example.com AAAA`）共享相同的冷却窗口（`DefaultPrefetchThrottleInterval`，3 秒）。如果 A 查询的预取刚刚发生，那么针对同一域名的 AAAA 的预取请求会被跳过，即使该 AAAA 条目的 TTL 即将过期且急需刷新。

**风险场景：**
如果一个域名同时提供 A 和 AAAA 记录，且两条记录在相近的时间范围内过期，其中一条的预热预取可能会由于冷却期而延迟最多 3 秒。在极少数情况下，这可能导致一个类型在冷却间隔期间使用陈旧条目，而另一个类型则进行刷新。

**修复建议：**
将键扩展为复合 `qname+qtype`，或使用完整的 `PendingKey`（预取冷却不需要 ECS/DNSSEC OK）：
```go
key := qname + "\x00" + strconv.Itoa(int(qtype))
m.prefetchCooldown.ShouldStart(key, ...)
```

---

## 发现 #7 — MEDIUM — Zone 中间件条件包装会阻止未来热加载

**文件：** `server/handler/middleware/chain.go` 第 119 行

**类别：** 架构设计 / 可维护性

**描述：**
`AssembleChain` 在构建时检查 `deps.ZoneEvaluator.HasRules()`。如果返回 false，`Zone` 中间件根本不会被包含在链中。虽然目前 `LoadRules()` 只调用一次（在 startup 阶段，链构建之前），且服务器没有运行时热加载机制，但如果未来添加了热加载（例如通过 SIGHUP 重新加载区域规则），新规则将永远不会被评估——因为中间件不在链中。

**风险场景：**
未来添加区域热加载的开发者需要了解这个架构陷阱。如果未修改链构建代码，在运行时对区域规则的更改会被静默忽略。查询将直接传递给 EDNS/CacheLookup/Resolution，绕过区域过滤。

**修复建议：**
移除条件包装，始终包含 Zone 中间件：
```go
h = (&Zone{...}).Wrap(h)
```
Zone 的 `Evaluate` 在规则缺失时通过检查 `!zoneResult.Matched` 来优雅地处理，因此移除条件语句后性能影响为零。或者，将 `HasRules()` 检查移到每个查询运行时。

---

## 发现 #8 — LOW — PTR.CacheHit 检查在标准链中为死代码

**文件：** `server/handler/middleware/ptr.go` 第 25 行

**类别：** 代码质量 / 死代码

**描述：**
PTR 中间件检查 `qctx.CacheHit`，并在命中时直接委托给下一个。然而，在标准组装链（chain.go）中，PTR 被包装在 CacheLookup 内部，后者仅在不命中时委托给下一个（它在缓存命中时短路）。因此，当 PTR 运行时，`CacheHit` 始终为 false。

**风险场景：**
无——这是防御性 / 死代码。如果未来缓存中间件逻辑或链顺序发生变化，可以防止错误。

**修复建议：**
可以安全移除（如果链顺序保持稳定），或者保留作为防御性编程。

---

## 发现 #9 — LOW — serveExpiredWithRefresh 在 refreshGroup 被耗尽时的回退路径

**文件：** `server/handler/middleware/cache_lookup.go` 第 140-161 行

**类别：** 性能 / Goroutine 生命周期

**描述：**
如果 `m.refreshGroup.Go()` 在面对 64 个并发限制时阻塞，则查询处理程序的执行会被暂停，直到一个槽位释放。同时，600 毫秒的陈旧服务计时器也在滴答作响。如果 `Go()` 阻塞超过 600 毫秒，计时器触发，并返回陈旧的响应——但此时代理请求甚至尚未开始。查询延迟受到 errgroup 拥塞的影响。

**风险场景：**
在并发刷新操作较多的负载下，陈旧服务超时（通常为 600 毫秒）会因 errgroup 的拥塞而延长，在某些部署中可能导致看似随机延迟的陈旧响应。

**修复建议：**
见发现 #1 的修复方案。特定的缓解措施：在 errgroup `Go()` 之前启动计时器，以确保 600 毫秒超时是准确的，无论 errgroup 的可用性如何。

---

## 发现 #10 — LOW — 区域重命名时缺失 CNAME 链恢复

**文件：** `server/handler/middleware/response.go` 第 121-140 行（`restoreDomain`），第 114-120 行的注释

**类别：** RFC 一致性 / 文档质量

**描述：**
`restoreDomain` 仅恢复与当前名称完全匹配的所有者名称。中间 CNAME 目标（例如，`*.example.com` -> `<random>.cdn.net`）不会被恢复。注释（第 114-120 行）记录了此限制。然而，对于使用 CNAME 通配符重写的区域规则，响应中的其他名称可能会保留重写形式，导致与 DNS 解析器的期望不一致。

**风险场景：**
涉及 CNAME 通配符链的区域规则会生成响应，其中部分名称以重写形式保留，可能导致客户端验证问题。

**修复建议：**
仅建议文档方面的——限制已经说明。如果要改进，可以递归跟踪 CNAME 目标，但这会增加运行时开销。对得起当前记录的行为。

---

## 发现 #11 — LOW — CacheLookup 缺少 nil resolver 保护

**文件：** `server/handler/middleware/cache_lookup.go` 第 248、158 行

**类别：** Panic 检测 / nil 解引用

**描述：**
Resolution 中间件（resolution.go:28-34）在调用 `m.resolver.Query` 之前检查 `m.resolver == nil`。CacheLookup 没有这样的检查——`m.refreshCacheEntry`（第 248 行）无条件调用 `m.resolver.Query`。如果 resolver 未正确配置，这会在刷新或预取期间 panic。

**风险场景：**
如果 Dependencies.Resolver 为 nil（编程错误），只有在缓存刷新路径（预热预取、陈旧服务）上才会 panic。正常解析查询不会受到影响，因为它们通过 Resolution 中间件路由。

**修复建议：**
在 `refreshCacheEntry` 和 `serveExpiredWithRefresh` 中添加 nil guard：
```go
if m.resolver == nil {
    log.Debugf("CACHE: resolver not set — skipping refresh")
    return nil
}
```

---

## 发现 #12 — LOW — 条件路径中的 pending key 泄漏

**文件：** `server/handler/middleware/cache_lookup.go` 第 69-70 行（预取），第 94-95 行（陈旧预取）

**类别：** 内存安全 / Goroutine 生命周期

**描述：**
在预取路径中（第 69-70 行），`tryStartRefresh` 成功注册一个 key，但随后的 `if m.refreshGroup != nil` 检查失败（在生产代码中始终为 true，但如果将来发生配置漂移可能会为 false）。该 key 已在 `m.pendingRefreshes` 中注册，但对应的 goroutine 从未启动来调用 `finishRefresh`。该 key 会泄露，从而使同一查询未来的刷新尝试永久跳过（因为它们会看到该 key 仍处于活跃状态）。

**风险场景：**
只有当 `deps.PendingRefrs` 非 nil 而 `deps.RefreshGroup` 为 nil（当前生产代码中不可能）时才会发生。尽管如此，这仍是一个微妙的风险。

**修复建议：**
将开始 / 完成配对本地化。重构为在 goroutine 启动程序内部调用 `tryStartRefresh`：
```go
if m.refreshGroup != nil {
    key := handler.BuildPendingKey(...)
    if m.pendingRefreshes != nil && !m.pendingRefreshes.Start(key) {
        // already inflight
        return
    }
    m.refreshGroup.Go(func() error {
        if m.pendingRefreshes != nil {
            defer m.pendingRefreshes.Done(key)
        }
        // ...
    })
}
```

---

## 发现 #13 — LOW — duplicate package doc comments

**文件：** `server/handler/handler.go` 第 1-3 行，`server/handler/middleware.go` 第 1-3 行

**类别：** 文档质量

**描述：**
两个文件都包含以 `// Package handler provides...` 开头的包级文档注释。Go 工具链仅使用第一个（按字母顺序，即 `handler.go`），因此第二个被忽略。

**修复建议：**
从 `middleware.go` 移除非必需的包注释，或将其缩减为一个简短的说明。

---

## 发现 #14 — LOW — 日志使用 qd.Header().Name 而非规范化的 qctx.Qname

**文件：** 多个位置：
- `server/handler/middleware/cache_lookup.go` 第 252 行（`qname` 来自 `qd.Header().Name`）
- `server/handler/middleware/zone.go` 第 37、39、44 行（使用 `qd.Header().Name`）
- `server/handler/middleware/dns64.go` 第 44、64 行（使用 `qd.Header().Name`）

**类别：** 日志质量 / 一致性

**描述：**
`qctx.Qname` 由 `handler.go:137` 的 `dnsutil.Fqdn()` 规范化，可确保一致的大小写。多个中间件使用 `qd.Header().Name`（原始的有线格式名称）进行日志记录。这可能导致日志中同一域名的大小写不一致（例如，`Example.Com.` 与 `example.com.`），使得日志分析工具难以聚合。

**风险场景：**
纯装饰性——DNS 名称大小写不敏感，因此功能上正确。但对日志解析可能造成干扰。

**修复建议：**
在所有日志语句中始终使用 `qctx.Qname`，而非 `qd.Header().Name`。

---

## 总结

| 严重程度 | 数量 | 关键发现 |
|----------|------|---------|
| CRITICAL | 0 | — |
| HIGH | 2 | errgroup.Go() 阻塞查询处理程序；BADCOOKIE 上重复的 ApplyToMessage |
| MEDIUM | 5 | LRU 驱逐导致 SERVFAIL；MaxDomainLength 边界有误；context.Background() 回退；预取冷却 ype 盲区；Zone 条件热加载 |
| LOW | 7 | 死代码、nil guard 缺失、key 泄漏、文档、日志一致性 |

文件路径约定说明：上述所有路径均为相对于仓库根目录 `/Users/hezhijie/Downloads/ZJDNS/`。