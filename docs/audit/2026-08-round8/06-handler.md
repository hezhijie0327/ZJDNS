# Handler 组审计 — server/handler/*（16 文件，双份独立审计合并）

## CRITICAL

### C5: server/handler/middleware/zone.go:85 — ZoneResult 无条件赋值 → 客户端静默无响应（见综合报告 C5）
- 第 85 行 `qctx.ZoneResult = &zoneResult` 在 rcode 分支（:88）与 hasRecords 分支（:104）**之前**执行；fall-through 路径（matched + NOERROR + 无记录 → :130 委托下游）带着非 nil 的 ZoneResult 返回 → CacheStore（cache_store.go:38 `qctx.ZoneResult != nil` 跳过响应构建）→ Response（response.go:32 `Res == nil` 直接返回）→ **客户端超时**。
- 可达性（两条路径）：(a) 动态 zone 规则（`DynamicContent != nil`）无条件存 qtype=0 sentinel（zone.go:222-230），非配置 qtype 查询（如 `{dynamic_content: fn, answer: [A]}` 配 AAAA 查询）命中 sentinel → Matched + NOERROR + 无记录；(b) 记录内容全部构建失败（如 `1 999.999.999.999`）的规则仍被 store（parse.go:66-70、wire.go:104-133 返回 nil）。
- :81-84 注释精确描述了此危害（"setting it before the fall-through delegation would silently drop the resolution result"）但代码与其矛盾——git 历史显示注释加入时赋值位置未动。**该路径从无测试覆盖（middleware/ 无 cache_lookup_test.go 且 Zone 委托路径无测试）。**
- 修复：赋值移入两个实际构建响应的分支内（各赋一次）。

## HIGH

### H2: server/handler/pending.go:119-139 — Done/OnEvict 竞态 + ABA（见综合报告 H2）
- (a) 数据竞争：淘汰恰在 `evicted.Load()==false` 检查（:129）与锁外 `call.result = cloneQueryResult(result)`（:137）之间发生时，与 OnEvict（lrumap 锁内）的 `call.result = evictedResult()`（:70）写-写竞争；close 唤醒的 followers 读 `actual.result`（:114）也是竞态读。
- (b) ABA：Get（:122）取到淘汰后新 leader 存入的**新** pendingCall，随后 `Delete(key)`（:132）误删新 call 并以其结果（:137-138）关闭 done——新 leader 的 followers 被旧结果唤醒，去重键提前释放 → 重复上游查询。
- 修复：`p.sets.CompareAndDelete(key, call)`（lrumap 已有，lru.go:256）替换 Get+检查+Delete——CAD 成功即保证未被淘汰。

### H8: server/handler/middleware/response.go:77-79 — 修改共享默认 ECS 对象（见综合报告 H8）
- 客户端未带 ECS 时 `ecsOpt` 来自 `ECSForQType`（edns/ecs.go:47-73）——atomic.Load 的**共享单例**指针；:78 `ecsOpt.ScopePrefix = qctx.ResolutionResult.ECS.ScopePrefix` 每查询热路径无锁写 → 并发 read-write/write-write 竞态 + 跨查询污染（查询 A 的 scope 写入共享对象后，查询 B 在 cache_store.go:130-132 读到非零 scope → 本应全局缓存（scope=0，RFC 7871 §7.3.1）的条目被按 ECS key 分区缓存）。该写是"有害空操作"（ApplyToMessage 硬编码 `Scope: DefaultECSScope`，永不达 wire）。
- 修复：`ecs := *ecsOpt; ecs.ScopePrefix = ...; ecsOpt = &ecs`，或删除该行。

### H9: server/handler/middleware/dns64.go:86-92 — 共享 ResolutionResult 并发改写（见综合报告 H9）
- singleflight followers 共享**同一个**克隆结果（pending.go:137 只克隆一次，全部 follower 取同一指针）；DNS64 中间件在各自 goroutine 中并发写 `qr.Answer/Authority/Additional/Validated`（:86-92），与 CacheStore.buildSuccess 并发读（cache_store.go:71,147-149）竞态。同模式：cache_store.go:123 `dnssec.CapValidatedTTL(qr.Answer, ...)` 对共享 RR 头原地写 `hdr.TTL`（dnssec/nsec.go:474）。
- 触发：DNS64 开启 + 并发相同 AAAA 查询（A-only 域名）——常见场景。
- 修复：改写前 per-goroutine 拷贝，或 Done 分发时按 follower 数克隆。

## MEDIUM（6 项）

| # | 位置 | 描述 |
|---|------|------|
| M1 | middleware/zone.go:126-130 + response.go:130-168 + context.go:73-82 | zone 域名重写机制整体失效：RewrittenName/OriginalName 仅被 restoreDomain 消费，但 Resolution/CacheLookup 全部读 `qctx.Req.Question[0]`（resolution.go:41-43、cache_lookup.go:42-44）——重写从不影响解析；且委托分支对合法规则不可达（规则必有记录或 rcode≠0）。FLOWCHARTS.md:398 "Rewrite for Resolution" 与代码不符。修复：删除机制或让 Resolution/CacheLookup 用 `qctx.EffectiveName()`。 |
| M2 | middleware/cache_lookup.go:137-163 | `serveExpiredWithRefresh` 在 `m.refreshGroup == nil` 时 `done` 永不被关闭——客户端每个 stale 查询白等满 600ms；且已 Start 的 pending 键永不 Done，该名字后续刷新永久跳过。Dependencies 把成对生效字段各自标 optional 并各自 nil-check——只有"同 nil 或同非 nil"安全。修复：两字段捆绑为单一可选结构。 |
| M3 | middleware/ptr.go:53-61 | PTR 命中路径设置 CacheServed/Responded 后短路，CacheStore 据此跳过全部统计——PTR 命中查询在请求统计中完全不可见（对比 cache 命中显式记录 "hit"、zone 记录 "zone"）。 |
| M4 | middleware/cache_lookup.go:71,118,125,206,210 | cache 命中/stale 路径 stats 无条件记 `RcodeSuccess`——缓存 NXDOMAIN 被记为 NOERROR（CacheStore.buildSuccess 记录真实 rcode，注释明确修复过同类 skew）。修复：命中路径用 `entry.Rcode`。 |
| M5 | middleware/dns64.go:97 | `log.Warnf("DNS64: A lookup failed...")` 每查询一条无采样——上游故障时日志海啸。修复：降 Debug 或限流。 |
| M6 | tasks.go:247,265（跨包） | shutdown 期间 errgroup `Go`/`TryGo` after `Wait` → "WaitGroup misuse: Add called concurrently with Wait" panic：in-flight 查询 goroutine（fire-and-forget，bridge.go:105-108 明确无追踪）在 shutdown 窗口内仍触发 `prober.Start` → `backgroundGroup.Go`（probe.go:150）及 CacheLookup `refreshGroup.TryGo`；后台任务在 ctx 取消后毫秒级退出（计数器归零），而查询 goroutine 未结束。cache_lookup.go:67-69 的 fresh-hit 探测路径**无 closed 守卫**（stale 路径有）。修复：探测调度统一加 closed 守卫 + TryGo 失败静默。 |
| M7 | middleware/response.go:72-73 | `hasRequestEDNS` 依赖 `Req.UDPSize/Pseudo`——fork 服务器对 plain 路径只解 question（MsgOptionUnpackQuestion），Validation 短路路径（FORMERR/REFUSED）Pseudo 为空 → shouldAddEDNS=false → **EDE（validation.go:66/138/142 设置的）与 OPT 全部丢失**；同一拒绝在 TLS 路径（全量 Unpack）正常携带。明文/加密行为不一致，违背 RFC 8914 §4 意图。修复：Pseudo 为空时对 req 全量 Unpack 判断 EDNS，或把 Validation 移到 EDNS 之后。 |

## LOW（10 项）

| 位置 | 描述 |
|------|------|
| middleware/cache_lookup.go:99-101,173 | stale 响应被刷新结果替换时旧 pooled 消息未归还（sync.Pool 丢失复用，非无界泄漏）。 |
| middleware/cache_store.go:101-108 | ECS 不匹配路径：BuildResponseMsg 取出的池化消息被新消息替换后丢弃，未 Put（仅错误路径）。 |
| middleware/cache_store.go:200-206 | `m.resolver != nil` 守卫是死守卫——分支内（DNSSECEDE 处理）完全不使用该字段。 |
| middleware/chain.go:22-27 | Dependencies "Required fields" 文档化但未校验——nil Cache 在首个查询才 panic。修复：AssembleChain 入口逐字段判 nil。 |
| middleware/validation.go:25-51 | `wireNameLength` 对 `\DDD` 转义只消费反斜杠+1 位数字，剩余 2 位按普通字节计——合法 255 字节边界名（含数字转义）误判超长 → 误 REFUSED。 |
| handler.go:161 | `log.Errorf("QUERY: chain error...")` 对可恢复链错误每查询打 Error（ErrDrop/SERVFAIL 路径已在记录）——降 Warn/Debug。 |
| middleware.go:64-66 + context.go:61 | `ErrDrop` 与 `qctx.Dropped` 全库无生产者——handler.go:145 分支不可达（死代码）。 |
| middleware/edns.go:43 | `qctx.ECSOpt = m.edns.ParseFromDNS(req)` 无 `m.edns == nil` 守卫（组内其他中间件均有）——防御不一致。 |
| middleware/cache_lookup.go:67-69 | fresh-hit 探测路径缺少 `m.closed` 守卫（与 M6 同根因）。 |
| middleware/dns64.go:86-92 | （并入 H9）。 |

## 测试覆盖缺口（MEDIUM）

- `middleware/` 无 cache_lookup_test.go——stale/fresh/preferStale/前台刷新/超时 5 条分支全部无单测。
- Response 中间件（cookie 续期、restoreDomain、EDNS 门控）与 Zone 委托路径无测试——**本次 CRITICAL 与两个 HIGH 均因此漏网**。

## 系统性根因

1. **共享可变状态跨并发写**（H2/H8/H9 同根因）：singleflight 共享 QueryResult、共享默认 ECS、pendingCall 淘汰——项目已有克隆意识（Done 注释提到 restoreDomain 竞态）但只在共享边界克隆一次，下游消费方仍原地改写。**修复纪律：共享边界之后的任何字段写必须先拷贝。**
2. **注释与代码脱节**（C5 与 M1 同源）：zone.go:81-84 注释描述正确设计但代码从未实现。
3. **可选依赖组合契约**（M2）：Dependencies 把成对生效的字段各自标 optional——产生只在一半 wiring 下的故障组合。

## 已排除疑点（有代码证据安全）

- context.go：EffectiveName/ClientAddr 契约清晰。
- response.go：BuildResponseMsg/BuildCacheEntryResponse——rcode 恢复、TTL 扣减、克隆语义正确。
- prefetch.go：CompareAndDelete 独占声明无 TOCTOU；Cleanup 由 tasks.go:128 周期调用（非死代码）。
- chain.go：9 层顺序与 CLAUDE.md 完全一致（Response→CacheStore→Validation→Zone→EDNS→CacheLookup→PTR→DNS64→Resolution）。
- resolution.go：nil 防护完整；singleflight 工作运行在 server 级 ctx、followers 60s 超时逃生。
- ptr.go：ReverseLookup 短路正确、CacheServed 语义正确。
