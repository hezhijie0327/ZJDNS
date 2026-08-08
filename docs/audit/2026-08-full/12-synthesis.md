# 12-synthesis.md — 2026-08 全库审计综合报告

## 审计元数据

- **日期**: 2026-08-08
- **方法**: docs/AUDIT-METHODOLOGY.md §1（Phase 1 包级审计 8 agent 并行 → Phase 2 交叉分析 2 agent + 机械 grep 全扫描 → Phase 3 综合）
- **覆盖**: 全部 ~115 个生产 Go 文件（~25k 行，不含测试），10 份报告
- **范围排除**: `docs/poc/*`（独立演示程序）、`scripts/*.sh`（构建脚本）、`*_test.go`（仅作行为参考）
- **工具验证**: `go build ./...` 零错误、`go vet ./...` 零警告；所有 CRITICAL 与部分 HIGH 由主审计员亲自复核代码确认

## 总览

| 严重度 | 数量 | Sprint |
|--------|------|--------|
| **CRITICAL** | **3** | Sprint 1（立即修复） |
| **HIGH** | **11** | Sprint 2（下个发布周期） |
| MEDIUM | 57 | Sprint 3 |
| LOW | 78 | Sprint 3 |

按报告分布：

| 报告 | 包范围 | C | H | M | L |
|------|--------|---|---|---|---|
| 01-foundation | internal/*（14 包） | 0 | 1 | 3 | 14 |
| 02-domain | config/database/cache/edns/zone/ruleset | 0 | 2 | 5 | 8 |
| 03-protocol | server/protocol/{plain,tls,tlcp,dnscrypt} | 0 | 3 | 5 | 3 |
| 04-upstream | server/upstream/*（7 子包） | **2** | 1 | 8 | 9 |
| 05-resolver | server/resolver/* + dnssec + probe | 0 | 1 | 2 | 10 |
| 06-handler | server/handler/* + middleware | **1** | 2 | 4 | 6 |
| 07-defense | server/defense/* | 0 | 0 | 3 | 4 |
| 08-top | server wiring + cmd/zjdns + loadtest | 0 | 1 | 8 | 9 |
| 10-docs | 全库文档一致性 | 0 | 0 | 12 | 6 |
| 13-rfc | RFC 合规交叉 | 0 | 0 | 7 | 9 |

---

## CRITICAL（3 个，全部经主审计员代码复核确认）

### C1 — spoofguard 双重池归还：同一 `*dns.Msg` 入池两次 → 响应损坏 [04-upstream]

`server/upstream/plain/udp.go:604-606, 734-736, 274-276`

`processPacket` 快速返回路径（AN≥2/NS>0/AD=1）与 `collectEDNSCandidate` TTL-confident 路径在 `Put(s.prev)` 后**未置 nil**；返回后 `executeUDPCollect` 的收养块（:274-276）对 `sg.prev` 再次 `Put` → 同一消息入池两次。此后两个并发查询 `Get()` 到同一 `*dns.Msg`，互相踩踏 → 响应损坏/交叉污染。

- **触发**: GFW 注入场景——收集 2 个歧义 EDNS 候选后，第 3 个真实响应触发快速返回；或任意 ambiguous→fast-accept 序列。远程可触发。
- **修复**: 每次 `Put` 后立即置 nil（`s.prev`/`s.last`/`s.nonEDNS`），或删除收养块中冗余的 Put。
- **验证**: 已逐路径追踪 `processPacket`→`executeUDPCollect` 调用链，确认无 nil 化、无守卫拦截（`sg.prev != resp` 恒真）。

### C2 — DNSCrypt `state()` 对 nil 缓存解引用 → 关停期间 panic [04-upstream]

`server/upstream/dnscrypt/state.go:103-105` + `client.go:390-392`

`Client.Close` 在锁内 `c.cache = nil`；`state()` 锁内 `c.cache.Get(cacheKey)` 无 nil 守卫，`lrumap.Get` 无 nil 接收者保护 → 配置 DNSCrypt 上游时，关停过程中任何在途查询必然 nil-deref panic。

- **修复**: `state()` 入口仿照 `deleteState`/`buildState` 加 nil 守卫。

### C3 — Zone 无记录规则路径静默丢弃查询（客户端超时）[06-handler]

`server/handler/middleware/cache_store.go:49` + `zone.go:101,156-160`

Zone 中间件对无记录规则（`Rcode=0`，含通配符改写场景）设 `ZoneMatched=true` 后不设 `Res` 直接下放；下游 Resolution 只填 `ResolutionResult`（响应构建是 CacheStore 的职责），CacheStore 门卫 `qctx.ZoneMatched` 恰好跳过 `qctx.Res = m.buildSuccess(qctx)` → `err==nil && Res==nil` → `ServeDNS` 返回 nil → 监听器静默丢弃。**通配符改写功能同时完全失效**（问题名从未被改写，`restoreDomain` 仅作用于响应 RR owner）。b8682dc 中间件重构引入的回归。

- **修复**: CacheStore 门卫改为 `Res != nil` 单条件；恢复问题名改写或删除死分支。

---

## HIGH（11 个）

| ID | 位置 | 摘要 | 验证 |
|----|------|------|------|
| H1 | `internal/pending/pending.go:246` | `CallGroup.Join` 超时分支无同步读 `existing.Err`，与 leader `Once.Do` 内写无 happens-before 边 → 数据竞争 | ✅ 已复核（Go 内存模型：close(ch) 仅同步接收者） |
| H2 | `cache/stats.go:118-159` + `store.go:730-749` + `init.go:88-98` | `FlushDB` 直删 `db.SQ`，批写器未刷、`s.pending` 未清 → 六个 `ZJDNS.*.clear` CHAOS 端点删后复活 + entryCount 漂移 | ✅ agent 经验证 |
| H3 | `cache/batch_writer.go:58,117` | 全库唯一无 `defer HandlePanic` 的 goroutine → flushFn panic 直接杀进程 | ✅ 简单验证 |
| H4 | `server/protocol/tls/dtls.go:138-140` | `io.ErrShortBuffer` → `continue` 忙旋：pion 不消费超长记录（已核 module 源码），>8192B 记录钉死 CPU 100% | ✅ agent 验证库行为 |
| H5 | `server/protocol/tlcp/dtlcp.go:211-229` | `s.serverGroup.Go()` 在持 `l.mu` 时调用，errgroup 饱和时 Go 阻塞 → 全客户端 datagram 分发冻结 + Shutdown 卡锁 | ✅ agent 验证 |
| H6 | `server/protocol/dnscrypt/server.go:90-103` | Ed25519 身份密钥长度未校验：circl `ed25519.Sign` 对错长输入 panic（已核 v1.6.5）→ 错误长度配置直接崩溃 | ✅ agent 验证库行为 |
| H7 | `server/bridge.go:276` + `store.go:729-748` | `truncateWire` 原地改写共享 `msgWire`（TC/ANCOUNT/NSCOUNT/ARCOUNT）→ pending 读穿缓冲被污染并刷入 SQLite，缓存行永久损坏 | ✅ agent 验证 |
| H8 | `server/resolver/recursive.go:194` | `Put(response)` 之后读 `response.Truncated` → use-after-Put 数据竞争（池置零 + 转手并发写） | ✅ 已复核 |
| H9 | `server/upstream/plain/udp.go:260` | collect 路径仅门 `len < 2` 就进入 `processPacket` 读 `raw[6..9]` → 2–9 字节 ID 匹配数据报越界 panic（多读路径门 `n < 12`） | ✅ 已复核 |
| H10 | `middleware/response.go:58-67` + `handler/response.go:45-77` | 服务期原地改写预打包 wire（TTL 扣减、ID/RD patch）与 pending 读穿缓冲别名 → 服务 goroutine 与 flush goroutine 数据竞争；两客户端 ID 互踩；入库行带服务期 TTL 与垃圾 ID | ✅ agent 验证（H7 同类别名根因） |
| H11 | `middleware/cache_lookup.go:192-234` | 前台 stale-refresh 成功路径（<600ms）不调 `store.Set`，仅 timer 路径写缓存 → 快速刷新永不治愈缓存，每查询重复全上游解析 | ✅ 已复核代码 |

---

## 系统性主题（跨包根因）

1. **共享缓冲别名（最危险的一族）**：H7 + H10 是同一根因的两个面——pre-packed wire / pending 读穿缓冲被服务期原地改写。`cache.Get` 的 pending 命中返回的 `ResponseWire == pendingEntry.msgWire`，既是批写器待提交的缓冲、又被并发服务 goroutine 复用。修复必须**复制**（truncate 路径罕见，复制免费），并注意**不破坏 0 B/op 契约**（复制只在 pending 读穿 + truncate 等非热路径）。
2. **池归还纪律**：C1（双重 Put）、H8（Put 后读）说明方法论 §4.2 的"池归还纪律"模式仍会复发——即使 TLS 模板纪律在协议层正确。修 C1 后应全库 grep 复查 `Put(` 后的字段读。
3. **防御算法状态机**：defense 包 3 个 MEDIUM 均为学习/武装阶段契约缺口（Feed 先于验证、TLL 硬拒绝无恢复、TLD 数据误判）——与历次审计根因一致，属已知模式复发。
4. **Shutdown 鲁棒性**：C2（Close 置 nil 与在途查询竞争）、H5（饱和阻塞卡 Shutdown）、03-protocol MEDIUM（DoT 连接 Shutdown 不唤醒，延迟至 60s）。DNSCrypt 是参考实现。
5. **文档腐烂**：10-docs 报 12 MEDIUM——CLAUDE.md 管道顺序、AsyncStatsWriter 已删、FLOWCHARTS 9→11 层、BENCHMARK.md 配置格式失效等。每次 PR 应检查受影响的 .md（方法论 §6.1-9）。
6. **RFC 偏离**：13-rfc 报 7 MEDIUM——NXNAME 应 FORMERR 却 REFUSED（RFC 9824 §3.5，同时 GUIDELINE 打 ✅ 互相矛盾）、TTL MSB 处理（RFC 2181 §8）、RFC 9443 未存档、4 个 GUIDELINE 徽章错误。

---

## Sprint 计划（详见 00-plan.md）

| Sprint | 范围 | 关键项 |
|--------|------|--------|
| **Sprint 1** | 3 CRITICAL | C1 池双重归还（一行 nil 化 ×3 处）；C2 nil 守卫；C3 CacheStore 门卫改 `Res != nil` |
| **Sprint 2** | 11 HIGH | H1 超时分支去读；H2 FlushDB 先刷 writer；H3 HandlePanic；H4 DTLS 忙旋改 `SetReadDeadline` 消费或计数；H5 Go 移出锁；H6 密钥长度校验；H7/H10 缓冲复制；H8 Put 前捕获；H9 统一 `len < 12` 门；H11 done 路径补 `store.Set` |
| **Sprint 3** | 57 M + 78 L | 分维度：文档（12M）、RFC 注释（7M+9L）、日志前缀、魔法数字、CLI 校验、防御算法调参等 |

## 提交规范提醒（方法论 §3.5）

- 每个修复一个 commit，主题行描述**具体修复内容**（`fix: ...` + 发现编号），如：
  - `fix: nil s.prev after Put in spoofguard fast paths (C1)`
  - `fix: capture Truncated before pool Put in root-domain branch (H8)`
- 每次提交前 `go fix ./... && golangci-lint run && golangci-lint fmt`（零警告）
- Sprint 1 后必须跑 benchmark 对比基线（§3.3，`-benchmem`），H7/H10 修复不得在热路径引入分配

## 报告索引

| 文件 | 内容 |
|------|------|
| [00-plan.md](00-plan.md) | 逐项修复计划 |
| [01-foundation.md](01-foundation.md) | internal/*（1H 3M 14L） |
| [02-domain.md](02-domain.md) | config/database/cache/edns/zone/ruleset（2H 5M 8L） |
| [03-protocol.md](03-protocol.md) | server/protocol/*（3H 5M 3L） |
| [04-upstream.md](04-upstream.md) | server/upstream/*（2C 1H 8M 9L） |
| [05-resolver.md](05-resolver.md) | server/resolver/* + dnssec + probe（1H 2M 10L） |
| [06-handler.md](06-handler.md) | server/handler/* + middleware（1C 2H 4M 6L） |
| [07-defense.md](07-defense.md) | server/defense/*（3M 4L） |
| [08-top.md](08-top.md) | server wiring + cmd/zjdns + loadtest（1H 8M 9L） |
| [10-docs.md](10-docs.md) | 文档一致性（12M 6L） |
| [13-rfc.md](13-rfc.md) | RFC 合规交叉（7M 9L） |

## 积极结论

- 池归还纪律在协议层（03-protocol）**逐路径核对全部正确**——TLS 模板范式有效，问题集中在 upstream 防御层。
- 全库 25 个 goroutine 100% 有 HandlePanic（唯一例外是 batch_writer 的 H3，即本审计发现）。
- 零 TODO/FIXME/HACK、零 `context.TODO()`、零 `%v` 错误包装、零手写有界 map、零 With* 冗余函数对、零手写反向循环。
- 导入分层 DAG 干净；lrumap OnEvict 纪律完整；Close 幂等性全部有守卫（含双重 Shutdown 测试）。
- `go build`/`go vet`/`go test -race`（defense 包）全绿。
