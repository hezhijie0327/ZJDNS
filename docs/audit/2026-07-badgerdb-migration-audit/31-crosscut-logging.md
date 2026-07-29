# 31 · 交叉分析：日志质量

> 审计 Agent：Phase 2b · Logging
> 范围：全项目级别审计、热路径刷屏、上下文完整性、127 条 Info/Warn/Error


现在我已收集到所有数据。以下是完整的审计报告。

---

## ZJDNS 日志质量审计报告

排除 `_test.go`。共检查 127 条 `Info`/`Warn`/`Errorf` 调用，分布在 38 个文件中。

---

### 发现 1：`cache/store.go:284` — 热路径上的 Warnf 缺少 qname/qtype 上下文

**文件+行号：** `cache/store.go:284`
**严重程度：** 中
**描述：** `Store.Set()`（per-query 缓存写入路径）在 BadgerDB 事务失败时记录 `log.Warnf("CACHE: insert entry failed: %v", err)`。该行缺少 qname、qtype、ecs 信息（这些都是该方法参数中可用的），使得调试事务失败变得困难。在高流量下，瞬态 BadgerDB 写入错误可能导致日志泛滥。
**风险：** 由于数据库写入错误，可能产生大量 warn 日志。无上下文意味着无法将错误关联到特定查询。
**修复建议：** 添加 `qname` 和 `qtype` 上下文：`log.Warnf("CACHE: insert entry failed for %s (type=%d): %v", qname, qtype, err)`。

---

### 发现 2：`cache/store.go:278` — 热路径上的 Warnf 缺少 qname 上下文

**文件+行号：** `cache/store.go:278`
**严重程度：** 中
**描述：** 位于 `Store.Set()` 内部（per-query 路径），该 Warnf 在 `insertPtrMap` 失败时记录，但没有说明是哪个域名的映射插入失败。`qname` 在作用域内但未包含。
**风险：** 与发现 1 相同——无上下文，瞬态错误时可能刷屏。
**修复建议：** 添加 `qname`：`log.Warnf("CACHE: insert ptr_map failed for %s (non-fatal): %v", qname, ptrErr)`。

---

### 发现 3：`cache/store.go:118` — 热路径上的 Warnf（缓存读取路径）

**文件+行号：** `cache/store.go:118`
**严重程度：** 低
**描述：** `Store.Get()`（per-query 缓存读取路径）在 `msg.Unpack()` 失败时记录 Warnf。上下文中包含 id、qname、qtype——很好——但任何一个被损坏的缓存条目都会对每个查询触发一次 Warnf。在实践中，数据损坏很少见，但如果发生，在此 Warnf 下日志会泛滥。
**风险：** 低。缓存损坏通常不会快速连续发生，但一旦发生就可能造成影响。
**修复建议：** 可考虑降级为 Debugf，或限制每个被损坏条目每分钟一次。作为折中方案，当前形式尚可接受。

---

### 发现 4：`server/bridge.go:49` — 热路径上的 Errorf（类型断言失败）

**文件+行号：** `server/bridge.go:49`
**严重程度：** 高
**描述：** 在 `handleDNSRequest`（per-TCP-query 热路径）中，如果 `tcpWriteMu` 映射包含错误的类型，`log.Errorf` 会触发并提前 return，查询未被处理。这是一个编程错误（type-assertion panic 防护），意味着存在 bug。`Errorf` 在此可接受（它是不可恢复的错误），但是 return 之前没有回复一个 SERVFAIL 给客户端——并且由于这是每个连接地址的共享映射，一个 bug 可能导致该地址的所有连接都被静默丢弃。
**风险：** 低（bug 意味着代码错误），但后果严重——无回复的情况下 TCP 查询会被静默丢弃。
**修复建议：** 在 return 之前发送 SERVFAIL 回复，或者在 first-chance 时使用 `sync.Once` 来避免对同一地址重复记录相同的错误。

---

### 发现 5：`server/bridge.go:202` — 热路径上的 Errorf（包 panic 恢复）

**文件+行号：** `server/bridge.go:202`
**严重程度：** 低
**描述：** `packSafe` 恢复 `dns.Msg.Pack()` 中的 panic 并记录 Errorf。这在 per-response 路径上，但 panic 极为罕见，且恢复后能保证不会崩溃。尽管如此，`Errorf` 的严重程度过高——这是一个恢复后的、受处理的错误。
**风险：** 极低（panic 很少见，且被优雅处理）。
**修复建议：** 降级为 Warnf。`"PANIC:"` 标签仅在 `HandlePanic` 中使用；此处的 `"SERVER:"` 前缀配合 Errorf 可能会在日志分析中被误认为是未处理的崩溃。

---

### 发现 6：`server/protocol/tlcp/http_tlcp.go:50` — 关闭期间缺少 ctx.Err() 检查，导致虚假 Errorf

**文件+行号：** `server/protocol/tlcp/http_tlcp.go:50`
**严重程度：** 中
**描述：** TLCP DoH accept 循环在 `Serve` 返回错误时记录 `log.Errorf("TLCP: DoH serve error: %v", err)`。与对应的 TLS DoH（`https.go:68-72`）不同，它没有在记录之前检查 `s.ctx.Err() != nil`。优雅关闭时，`Serve` 会因服务器关闭而返回一个错误——这会触发一条虚假的 Errorf。
**风险：** 每次服务器正常关闭都会产生一条虚假的 Errorf，可能错误地触发告警。
**修复建议：** 添加 `s.ctx.Err()` 守卫，与 TLS DoH 等效代码一致：
```go
if err := dohSrv.Serve(tlcpListener); err != nil && err != http.ErrServerClosed {
    if s.ctx.Err() != nil {
        return nil
    }
    log.Errorf("TLCP: DoH serve error: %v", err)
}
```

---

### 发现 7：`server/protocol/tls/dtls.go:81` — accept 错误用 Errorf 并终止监听器

**文件+行号：** `server/protocol/tls/dtls.go:81`
**严重程度：** 高
**描述：** DTLS accept 循环遇到非临时性错误时记录 `log.Errorf("TLS: DTLS accept error: %v", err)` 并 `return`，这会永久终止整个 DTLS 监听器。如果操作系统返回一个瞬时但非临时性的错误（例如 `EMFILE`、`ENFILE`，或被 Go 的 `IsTemporary` 覆盖的连接重置），DTLS 服务将无声地停止运行。
**风险：** DTLS 服务在非致命操作系统错误后可能永久不可用。
**修复建议：** 改为 Warnf 并 `continue` 而非 `return`。对于需要退出循环的严重错误，应通过 `s.ctx` 取消来传达。参考 TCP accept 循环的做法（例如 `plain/tcp.go` 或各种协议中的 `tls/tls.go`）——它们不会因单个 accept 错误而终止。

---

### 发现 8：`server/protocol/tlcp/dtlcp.go:255` — 与 DTLS 相同的问题

**文件+行号：** `server/protocol/tlcp/dtlcp.go:255`
**严重程度：** 高
**描述：** 与发现 7 相同的模式——非临时性 DTLCP accept 错误上的 `log.Errorf` 终止了该监听器。
**风险：** 与发现 7 相同。
**修复建议：** 与发现 7 相同——Warnf + continue。

---

### 发现 9：`server/tasks.go:51,66` — ECS 和 Cookie 后台任务只有 Warnf，没有降级到 Debugf

**文件+行号：** `server/tasks.go:51`, `server/tasks.go:66`
**严重程度：** 低
**描述：** 定时后台任务（cookie 密钥轮换、ECS 刷新）在失败时记录 Warnf。这些任务每 24 小时/小时运行一次，因此刷屏风险极低。但是，在长时间运行中，可预见的“失败”路径（例如 ECS 刷新因网络暂时不可用而失败）会每隔一小时产生一条 warn 日志，可能对关注运营的团队造成噪音。
**风险：** 低。更新频率低且上下文清晰。
**修复建议：** 考虑持久性/配置故障使用 Warnf，瞬态故障使用 Debugf。可接受，建议保留。

---

### 发现 10：`cache/async_writer.go:178` — WriteBatch 刷新错误缺少上下文

**文件+行号：** `cache/async_writer.go:178`
**严重程度：** 低
**描述：** 异步统计写入器在 WriteBatch 刷新失败时记录 Warnf，但没有指示哪些数据（涉及哪些查询/域）丢失。
**风险：** 低。统计数据是尽力而为的；无上下文不会影响正确性。
**修复建议：** 添加正在刷新的键数量：`log.Warnf("CACHE: async WriteBatch flush error (keys=%d): %v", len(agg), err)`。

---

### 发现 11：`server/tasks.go:172` — 关闭期间关闭错误使用 Errorf

**文件+行号：** `server/tasks.go:172`
**严重程度：** 低
**描述：** `log.Errorf("TLS: TLS server shutdown failed: %v", err)` ——关闭错误对于已经在运行的服务器可能是预期的，并且发生在关闭期间，而不是 per-query。尽管如此，由于这是按计划的关闭操作，Errorf 可以通过降级为 Warnf 来减少告警疲劳。
**风险：** 低（仅关闭期间）。
**修复建议：** 降级为 Warnf 以反映“按计划操作期间出现预期错误”的特征。

---

### 热路径分析摘要

| 包 | 每个查询的 Info/Warn/Error 调用 | 运行于查询路径 | 通过与否 |
|-------|--------------------------------------|-----------------|--------|
| `server/handler/middleware/` | 0（全为 Debugf） | 是 | 通过 |
| `server/resolver/`（排除启动） | 0 | 是 | 通过 |
| `server/upstream/client.go` | 0 per-query（1 个 Warn 按服务器执行一次） | 是 | 通过 |
| `server/bridge.go` | 2 Errorf（发现 4, 5） | 是 | **未通过** |
| `cache/store.go` | 3 Warnf（发现 1, 2, 3） | 是 | **未通过** |
| `server/protocol/tls/dtls.go` | 1 Errorf（发现 7） | 每连接 | **未通过** |
| `server/protocol/tlcp/` | 2 Errorf（发现 6, 8） | 每连接 | **未通过** |

### 前缀一致性检查

- 23 个规范前缀全部得到确认使用且一致：`TLS`、`CACHE`、`DB`、`UPSTREAM`、`SERVER`、`EDNS`、`RECURSION`、`SECURITY`、`TCPPOOL`、`LATENCY`、`CONFIG`、`ZONE`、`PLAIN`、`PPROF`、`QUERY`、`RESULT`、`SIGNAL`、`PTR`、`PANIC`、`DNSCRYPT`、`TLCP`、`RULESET`、`DNS64`。
- 在 `server/server.go:504,519` 中使用的动态 `%s` 前缀始终被调用为规范前缀 `"UPSTREAM"`。
- `internal/dnsutil/dnsutil.go:69` 中的 `CloseWithLog` 允许调用者传入 `prefix`——所有 16 个调用点都使用规范值（`SERVER`、`TLS`、`TLCP`、`UPSTREAM`）。
- **未发现前缀一致性问题。**

### 错误/Warn 日志中的上下文质量

| 调用点 | 包含 qname/qtype | 包含 server/addr | 包含 error |
|--------------|-------------------|------------------|------------|
| `cache/store.go:118` | 是（name=..., type=...） | 无 | 是 |
| `cache/store.go:278` | **无** | 无 | 是 |
| `cache/store.go:284` | **无** | 无 | 是 |
| `cache/async_writer.go:178` | **N/A**（聚合） | 无 | 是 |
| `server/bridge.go:49` | 无 | 是（addr） | 否（类型信息） |
| `server/bridge.go:202` | 无 | 无 | 否（panic 值） |
| `server/protocol/tls/https.go:72` | 无 | 无 | 是 |
| `server/protocol/tls/dtls.go:81` | 无 | 无 | 是 |
| `server/protocol/tlcp/dtlcp.go:255` | 无 | 无 | 是 |
| `server/upstream/client.go:242` | 无 | 是（ServerName） | 无 |
| `server/protocol/dnscrypt/server.go:317` | 无 | 无 | 是 |
| `zone/parse.go:62,71` | 无（域信息可用但未包含） | 无 | 是 |

### 可能刷屏的循环

- `zone/parse.go:62,71`——行解析循环，但仅在启动/加载时执行，而非每个查询。可接受。
- `ruleset/ruleset.go:219`——规则加载循环，启动时执行。可接受。
- `config/ddr.go:204`——非循环。可接受。
- 所有定时后台任务（cookie 轮换、ECS 刷新、密钥轮换）都很慢（24h/1h）——可接受。

### 每个查询的日志数

- 热路径 Info/Warn/Errorf：每个查询最多 **5** 个（如果 `Store.Set()`、`Store.Get()` 和 `bridge.go` 全部触发）。然而，通常失败路径不会同时发生。
- 更现实的估计：0-1 个 Warn/Error 调用，在最坏情况下每个查询最多 3 个。
- 目标（每个查询 ≤1 个 info/warn）在正常操作下已达标，但在有数据库或编码问题的异常路径上**未达到**。

---

### 按严重程度排序的发现总结

| # | 文件:行 | 严重程度 | 问题 |
|---|---------|----------|-------|
| 7 | `server/protocol/tls/dtls.go:81` | **高** | Accept 错误使用 Errorf 并终止监听器 |
| 8 | `server/protocol/tlcp/dtlcp.go:255` | **高** | Accept 错误使用 Errorf 并终止监听器 |
| 4 | `server/bridge.go:49` | **高** | 热路径上的 Errorf，查询被静默丢弃 |
| 1 | `cache/store.go:284` | **中** | 热路径 Warnf 缺少 qname/qtype |
| 2 | `cache/store.go:278` | **中** | 热路径 Warnf 缺少 qname |
| 6 | `server/protocol/tlcp/http_tlcp.go:50` | **中** | 关闭期间缺少 ctx.Err() 守卫，导致虚假 Errorf |
| 3 | `cache/store.go:118` | **低** | 热路径 Warnf，但上下文完整 |
| 5 | `server/bridge.go:202` | **低** | 恢复后的 panic 使用了 Errorf，应为 Warnf |
| 9 | `server/tasks.go:51,66` | **低** | 后台任务 Warns，频率低，可接受 |
| 10 | `cache/async_writer.go:178` | **低** | 刷新错误缺少键计数 |
| 11 | `server/tasks.go:172` | **低** | 关闭错误使用了 Errorf |