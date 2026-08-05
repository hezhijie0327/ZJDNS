# deadcode 审计

> agent: `a06a241f6ee0ed818`

发现数: 9

## deadcode-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: resource
- **摘要**: refs 双重 Add(1)：每 TCP 请求净 +1，refs 永不归零，sweep 成死代码，shard.entries 无界增长（H1 修复不完整 = 回归）
- **描述**: 每个 TCP 请求执行两次 `entry.refs.Add(1)`：第 98 行（shard 锁内）和第 110 行（锁外，两段注释逐字重复），但释放路径只有一个 `defer entry.refs.Add(-1)`（第 155 行 goroutine / 第 115 行 SERVFAIL 路径）。每请求净 +1。`sweepTCPWriteMu`（server/tasks.go:130-144）对 `refs.Load() != 0` 的条目直接 continue，因此任何服务过请求的连接 refs 永远 ≥1，sweep 永远不会删除该条目——每个历史 TCP 客户端地址在 `tcpWriteShards` 中永久保留一个含 writeMu+capacity channel 的 tcpWriteEntry，进程生命周期内无界增长。第一轮 H1 的提交信息明确声称 'refs now reach 0'，tasks_test.go 也按单次 Add(1) 模拟验证归零，但生产路径的实际计数是 +2/-1。round-2 人工核验（docs/audit/2026-08-round2/_manual-verification.md H3）已确认，HEAD 仍未修复。
- **风险**: 长期运行后内存无界增长（每个 TCP 客户端一条永久 entry）；writeMu 清除机制完全失效，重新变成第一轮 H1 报告过的'per-connection map grows without bound'
- **修复**: 删除第 110 行锁外的重复 `entry.refs.Add(1)` 及其重复注释，只保留锁内（第 98 行）的 in-flight ref；tasks_test.go 无需改动（其模拟已是单 Add）。

## deadcode-02 — HIGH

- **位置**: `server/handler/middleware/mqtype.go:78`
- **类别**: rfc
- **摘要**: MQTYPE merge 在递归模式缓存 miss 路径永不执行（qctx.Res 在 MQTYPE 后处理时为 nil，被第 78 行提前返回）
- **描述**: 链顺序（chain.go:141-155）：Response→CacheStore→MQTYPE→Validation→Zone→Any→EDNS→CacheLookup→PTR→DNS64→Resolution。CacheStore 位于 MQTYPE 外侧，其 buildSuccess 只在 next 返回后的后处理阶段构建 qctx.Res。因此缓存 miss 时，MQTYPE 的 `err := next.ServeDNS(...)` 返回后 qctx.Res 仍为 nil（Resolution 只设 qctx.ResolutionResult），第 78 行 `if qctx.Res == nil { return err }` 提前返回，merge 永不执行——递归模式首次查询（未缓存）必然发生。只有下游中间件已预置 Res 的路径（缓存命中、zone 规则命中、DNS64 合成）才会进入 merge。RFC 10029 §3.4 MUST：响应必须携带 MQTYPE-Response 选项。round-2 人工核验（_manual-verification.md H1）已确认，HEAD 未修复。
- **风险**: RFC 10029 特性在递归模式主路径（miss）完全失效：客户端发 MQTYPE-Query 收不到 MQTYPE-Response，按 §5 视为无效响应
- **修复**: 将 merge 移到响应构建之后——例如把 MQTYPE 的 Wrap 从 CacheStore 内侧移到其外侧，或在 CacheStore.buildSuccess 完成后触发 merge；并补一个走真实中间件链（非 fake next 直接设 Res）的集成测试

## deadcode-03 — HIGH

- **位置**: `server/handler/middleware/response.go:73`
- **类别**: rfc
- **摘要**: 缓存命中路径：MQTYPE merge 追加的合并 RR 与 MQRESPONSE 被 Response 中间件的 Unpack() 整段重建抹掉
- **描述**: 缓存命中时 CacheLookup 经 buildFromPrePacked 设置 qctx.Res（Data=pre-packed wire，Answer/Pseudo 为空）。MQTYPE.merge（mqtype.go:180-195）把附加类型 RR 追加到 msg.Answer、把 MQRESPONSE 追加到 msg.Pseudo。随后 Response 中间件：MQTYPE-Query 客户端必有 `len(qctx.Req.Pseudo) > 0` → shouldAddEDNS 恒为 true → 不走进 wire 直发快路径 → 走第 73 行 `qctx.Res.Unpack()`——miekg/dns v0.6.89 msg.go 中 `m.Answer = unpackRRs(...)`（返回全新切片）整体替换 Answer，找到 OPT 时 `m.Pseudo = make(...)`（msg.go:428）整体替换 Pseudo。合并的附加 RR 必然丢失；由于 Set 时存储的 wire 无 OPT，Pseudo 常被保留——客户端收到声称已合并某类型、但答案里没有对应 RR 的 MQTYPE-Response，自相矛盾。round-2 人工核验（_manual-verification.md H2）已确认，HEAD 未修复；mqtype_test.go 的 CacheHit 测试用 BuildResponseMsg（Data=nil）构造主响应，未覆盖真实 pre-packed 路径。
- **风险**: 递归模式缓存命中（最常见路径）上 RFC 10029 合并结果静默丢弃：客户端收到纯主响应或携带虚假完成列表的 MQRESPONSE，特性在 hit/miss 两条路径全部失效
- **修复**: merge 完成后对 qctx.Res 重新 Pack（Data=nil 或重打包 wire），或让 merge 在 Unpack 之后执行；Response 中间件 Unpack 路径不应覆盖已有合并产物。补走真实管线（含 CacheLookup 命中）的集成测试

## deadcode-04 — MEDIUM

- **位置**: `server/handler/response.go:37`
- **类别**: dead-code
- **摘要**: BuildCacheEntryResponse 的 req 与 dnssecOK 参数已完全不被使用（函数体只调 buildFromPrePacked(entry, isExpired)）
- **描述**: pre-packed 改造后函数体为 `return buildFromPrePacked(entry, isExpired)`，`req *dns.Msg` 与 `dnssecOK bool` 两个参数彻底死掉（DNSSEC 过滤已移至 Response 中间件的 WireHasDNSSEC 门 + ProcessRecords，cache/store.go 的 Get 也删除了内部 canonicalize）。唯一调用点 cache_lookup.go:282 仍传 `qctx.Req` 和 `qctx.ClientRequestedDNSSEC`，两值被静默忽略。违反方法论 §6.2 第 12 条'废弃参数应删除而非保留'。
- **风险**: 签名误导调用方（dnssecOK 语义已不存在），后续维护者误以为过滤在此完成；按方法论这是死代码，lint 无法捕获
- **修复**: 将签名改为 `BuildCacheEntryResponse(entry *cache.Entry, isExpired bool) *dns.Msg` 并更新 cache_lookup.go:282 调用点

## deadcode-05 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:131`
- **类别**: inefficiency
- **摘要**: merge 用原始 qd.Header().Name 而非规范化的 qctx.Qname 访问缓存：混合大小写查询 Get 必 miss、Set 写入大小写变体重复行
- **描述**: 本 delta 中 cache.Get 删除了内部 `qname = dnsutil.Canonical(qname)`（cache/store.go），并明确要求调用方传 canonical qname（Get 注释'caller must pass a canonical qname'）；cache_store.go 已迁移到 qctx.Qname（第 59 行），cache_lookup.go 也把 `qd.Header().Name` 改为 `qctx.Qname`（diff 中明确）。但新写的 mqtype.go merge（第 131 行 `qname := qd.Header().Name`）仍用请求原始大小写：混合大小写 MQTYPE 查询 → resolve() 里 `m.store.Get(qname,...)` 必 miss → 第 188 行 `m.store.Set(qname,...)` 以非 canonical 名写入重复缓存行，且 Set 只对新行计数，造成条目计数膨胀（第一轮 H7 同源问题）。
- **风险**: 大小写变体查询污染缓存（重复行 + 计数膨胀 → 提前驱逐有效条目）；MQTYPE 附加类型永远命中不了已有 canonical 条目，缓存收益丢失
- **修复**: 改用 `qctx.Qname`（以及 qctx.Qtype 对应的 dns.RRToType 已规范）——该中间件位于链内，qctx.Qname 由 ServeDNS 预填，与同 delta 迁移的 cache_lookup.go 保持一致

## deadcode-06 — LOW

- **位置**: `server/handler/middleware/mqtype.go:192`
- **类别**: dead-code
- **摘要**: merge 中 `len(completed) > 0 || len(mq.Types) > 0` 恒真：validate() 已保证 Types 非空（空列表 FORMERR）
- **描述**: validate()（第 104-106 行）对 `len(mq.Types) == 0` 返回 errMQTypeEmpty → Wrap 提前 FORMERR，因此到达 merge 时 mq.Types 恒非空，`len(mq.Types) > 0` 恒为 true，整个 if 条件恒真（其唯一作用是保证空合并时也追加 MQRESPONSE——无条件 append 即可）。
- **风险**: 误导读者以为存在'跳过 MQRESPONSE'分支；条件恒真属于冗余逻辑
- **修复**: 删除条件，直接 `msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{Types: completed})`，注释保留'空列表也必须返回选项'语义

## deadcode-07 — LOW

- **位置**: `cache/cache.go:83`
- **类别**: comment
- **摘要**: 孤立重复注释：Unpack 的文档注释残片悬空在 LookupResult 类型之上，与第 99-102 行真实 doc 注释逐字重复
- **描述**: 第 83-86 行存在一段描述 Unpack 的注释块（'Unpack populates Answer, Authority and Additional...'），下方是 LookupResult 类型而非 Unpack——这是本 delta 引入 pre-packed 格式时残留的悬空注释；Unpack 方法的正式 doc 注释在第 99-102 行。
- **风险**: 注释腐烂：LookupResult 上方悬挂一段与函数无关的重复注释，gofumpt/decorder 不拦截，后续维护产生困惑
- **修复**: 删除第 83-86 行孤立注释块

## deadcode-08 — LOW

- **位置**: `server/handler/middleware/chain.go:60`
- **类别**: comment
- **摘要**: 执行顺序注释（第 56-67 行）漏掉 MQTYPE，且 Any/Zone 相对顺序与代码相反
- **描述**: 注释声称 outermost→innermost 顺序为 Response→CacheStore→Validation→Any→Zone→EDNS→...，实际代码顺序是 Response→CacheStore→MQTYPE→Validation→Zone→Any→EDNS（Zone 在第 128 行 Wrap、Any 在第 123 行 Wrap，Zone 在外侧先执行，与第 120-122 行注释'Any wrapped INSIDE Zone'自洽；CLAUDE.md 的管道列表是正确的）。注释既缺失 MQTYPE 行，又把 Any 排在 Zone 前。
- **风险**: 管道顺序文档与实现不符，误导对 MQTYPE 执行时序（合并发生在 CacheStore 之后、Response 之前）的理解，正是 deadcode-02/03 两个缺陷被漏检的文档根源
- **修复**: 在注释的 CacheStore 与 Validation 之间插入 'MQTYPE — RFC 10029 多 QTYPE 合并（递归模式）'，并把 Any 行移到 Zone 行之后

## deadcode-09 — LOW

- **位置**: `cache/cache.go:121`
- **类别**: dead-code
- **摘要**: rebuildResponseWire 在 cache 包内重复实现 store.go 新加的 dnsSkipName/scanTTLOffsets（wire 名称跳过 + TTL 偏移扫描两套手写拷贝）
- **描述**: 本 delta 在 cache/store.go 新增了 `dnsSkipName`（名称压缩指针遍历）与 `scanTTLOffsets`（question 段后 TTL 偏移扫描），而 cache/cache.go 新增的 `rebuildResponseWire`（第 121-170 行）又手写了一遍完全相同的逻辑（第 134-136 行找 question 结束、第 144-156 行内联名称跳过、第 160-163 行 TTL 偏移采集），两处必须手工保持同步（压缩指针处理、边界判断）。另 server/bridge.go 的 skipWireName 是第三份跨包拷贝。
- **风险**: 同一 wire 遍历逻辑多处手写：任一处修复（如压缩指针边界）不会传播到其他拷贝，易产生偏移错位导致缓存命中后 TTL 写错字节
- **修复**: rebuildResponseWire 改用同包 `scanTTLOffsets(msg.Data, questionEnd)` 复用 TTL 偏移扫描；跨包拷贝可评估是否提升到 internal/dnsutil

