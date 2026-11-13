# ZJDNS Round 6 Handler 审计报告

**审计范围**:`server/handler/` 全部（handler 包 8 个非测试文件 + middleware 包 14 个非测试文件 + 测试/benchmark），重点维度：中间件链每查询固定开销、CacheLookup/CacheStore 与 cache.Store 交互及 serve-stale refresh 协调器、QueryContext 池化与响应 buffer 生命周期（预打包直发 Data 复用）、锁正确性 / panic / 错误处理。

**Round 5 修复回归验证**（docs/audit/2026-11-round5-audit/06-handler.md 各项）：

| Round 5 发现 | 现状 |
|---|---|
| F-1 QTx panic 不发送结果 → merge 永久阻塞 | 已修复（mqtype.go:112-114 `res := qtResult{qt: qt}; defer func() { qtResults <- res }()`），验证通过 |
| F-2 merge 不检查 no-cache EDE | 已修复（mqtype_merge.go:110 `edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE)` 进录用 gate） |
| F-3 BADVERS 双 PADDING | 已修复（middleware/response.go:154-167 `msgHasEDNSOptions` 增补 PADDING 检查） |
| F-4 历史叙述注释 | 已改写（stats.go:17-20、cache_store.go:38-42 换了新文本，但新文本仍有事实错误 —— 见 H5） |
| P-1 mergeRRs dstKeys lockstep | 已修复（mqtype_merge.go:185-188 预计算 + 208 lockstep append） |
| P-2 qtMap map 分配 | 未修（保留为性能观察 O1，不重复立项） |

**验证**:`go vet ./server/handler/...` 通过；`go test ./server/handler/... -short -count=1` 两包全部通过。本审计为只读，未修改任何仓库文件。

---

## 确认的发现

### H1 | MEDIUM | MQTYPE merge 无条件等待 QTx，本地拒绝路径（ACL/Validation/Zone）被上游解析阻塞最长 3 秒

- **编号**: H1
- **文件:行号**: `server/handler/middleware/mqtype.go:102-129` + `server/handler/middleware/mqtype_merge.go:60-97,160-164`
- **严重程度**: MEDIUM
- **类别标签**: 性能 / DoS 放大 / 协议语义

**问题描述**

MQTYPE.pre 在 `validate` 通过后**立即**启动全部 QTx goroutine（mqtype.go:102-116），然后 `next.ServeDNS` 运行内层链。Validation/ACL/Zone 都在 MQTYPE **内层**（chain.go:140-160），它们的短路只设置 `qctx.Res` 并返回；MQTYPE.post 看到 `qctx.Res != nil`（mqtype.go:119-121）便**无条件进入 merge**。merge 的接收循环（mqtype_merge.go:93-97）：

```go
for range types {
    r := <-qtResults   // 无 ctx / 无本地短路检查，收满 len(types) 个
    qtMap[r.qt] = r.qr
}
```

在 RCODE/flags gate（line 110）**之前**执行。对本地拒绝响应（REFUSED/FORMERR，Rcode ≠ 任何 QTx 的 NOERROR/NXDOMAIN）所有 QTx 结果必然被 gate 丢弃，但等待已经发生：每个 QTx 受 `DefaultMQTypeResolveTimeout = 3s`（config/defaults_dns.go:317）约束，并发启动后最坏 ~3 秒。

具体可触发路径（均通过 MQTYPE.validate，只被内层拒绝）：
- `Validation`：非法域名 / NXNAME / AXFR / IXFR / 非法 class / 多 question（validation.go:97-175）→ REFUSED/FORMERR；
- `ACL`：任意被拒客户端的任意 qname（acl.go:49-61）→ REFUSED；
- `Zone`：拦截规则命中（zone.go:114-134）→ NXDOMAIN/REFUSED。

此外 merge 尾部（mqtype_merge.go:160-163）`if len(completed) > 0 || len(mq.Types) > 0` 中 `len(mq.Types) > 0` 被 validate 的 errMQTypeEmpty 保证恒真（该条件本身冗余），导致**拒绝响应也携带空 MQTYPE-Response option** —— RFC 10029 §3.4 的 "MUST return (even empty) to signal support" 针对正常处理的响应，错误响应附加该 option 缺乏规范依据。

**风险说明**

1. ACL/Validation 是安全拒止路径，本应零成本立即返回；现在每个被拒的 MQTYPE 查询把 handler goroutine 挂住最长 3s 并白做最多 `DefaultMQTypeMaxQTx = 4` 个上游查询 —— 攻击者可用"带 MQQUERY option + 必被 ACL 拒绝的源"把 REFUSED 的成本从 0 放大为 4 个上游查询 + 3s goroutine 占用（上游查询经由 Secondary 的 PendingRequests singleflight，同 key 并发会被合并，但攻击者可轮换 qname 绕开）。
2. `handler.go:139` 的 `defer qctxPool.Put(qctx)` 使每个被阻塞查询同时钉住一个池化 QueryContext。
3. 拒绝响应附带空 MQRESPONSE 属协议语义瑕疵（无害但未定义）。

**修复建议**

merge 入口增加本地短路判定：primary 响应来自内层短路（如 `qctx.Result ∈ {"acl","blocked","zone"}` 且未经过 CacheStore 的 miss 分类，或直接判 `qctx.Res.Rcode` 为 REFUSED/FORMERR 且 `!qctx.Resolved && qctx.ResolutionResult == nil`）时跳过 merge —— QTx goroutine 向 buffered channel 发送后自然退出（channel 容量 == goroutine 数，无泄漏、无额外回收逻辑），不等待、不附加 MQRESPONSE。顺带把 line 160 的恒真条件简化为无条件 append（正常路径）。

---

### H2 | LOW | MQTYPE TC 分支的 cache-warm 承诺基本落空：晚到的 QTx 结果被静默丢弃

- **编号**: H2
- **文件:行号**: `server/handler/middleware/mqtype_merge.go:41-58`
- **严重程度**: LOW
- **类别标签**: 性能 / 注释与实现不符

**问题描述**

TC 分支的 drain 是 `for range len(qtResults)` —— 只收**此刻**已在 channel 缓冲里的结果。QTx 与 primary 并发启动；primary 截断响应通常在毫秒内返回，而 QTx 是完整 upstream round trip（缓存未命中时几十至几百毫秒），因此 drain 几乎总是空的。晚到的结果 send 进 buffered channel 后无人消费，随 channel 被 GC —— 不执行 `StoreIfCacheable`。

代码注释承诺 "the already-launched QTx results are drained and written to the cache so the client's TCP retry finds them warm"（line 43-45），该行为仅在 QTx 恰好早于 primary 完成时成立（QTx 缓存命中的场景）。

**风险说明**

无正确性风险（无泄漏：channel 容量 == goroutine 数；无阻塞）。影响是 TC 后客户端 TCP 重试大概率仍为冷缓存，与注释/设计意图不符；浪费已发起的上游查询。

**修复建议**

TC 分支不 inline drain，改为向 refreshCoordinator 的 errgroup（或独立有界 goroutine）提交一个后台任务：`for range types { r := <-qtResults; if r.qr != nil && r.qr.Err == nil { StoreIfCacheable(...) } }`，与 QTx 的 detached 生命周期对齐。

---

### H3 | LOW | EnsureFullUnpack 注释与实现不符；无 OPT 请求被双重全量解析

- **编号**: H3
- **文件:行号**: `server/handler/handler.go:100-111,164-178`
- **严重程度**: LOW
- **类别标签**: 性能 / 注释漂移

**问题描述**

`EnsureFullUnpack` 的注释声称 "Plain-transport listeners deliver question-only unpacks (listeners set MsgOptionUnpackQuestion for routing)"，其触发条件是 `len(req.Pseudo) == 0 && req.Data != nil`。实际核查：

- 全仓库**没有任何 listener 设置 `MsgOptionUnpackQuestion`**（`server/protocol/plain/udp.go:194-196`、`plain/tcp.go:254`、`tls/tls.go:292-294` 等都是 `req.Data = data; req.Unpack()`，`Options` 从池中取出时为零值 = 全量解析）；
- 因此 `len(req.Pseudo) == 0` 无法区分"question-only 解析"与"全量解析但请求无 OPT"：**不带 OPT 的请求在 listener 全量解析一次后，pipeline 入口再全量解析一次**。

miekg fork 的 `Msg.Unpack`（msg.go:366-475）不清 `m.Data`，故第二次解析总能发生。

**风险说明**

查询报文通常没有 Answer/Authority/Additional section（counts=0），重复解析成本约为一次 header+question 重解析（~百 ns + QNAME string 重新分配），仅影响无 EDNS 的 legacy 客户端（`dig +noedns`、部分健康检查）—— 真实成本小。主要问题是注释描述了一个不存在的 listener 行为，会误导后续维护与优化判断。

**修复建议**

任选其一：(a) 把触发条件改为 `req.Options > 0 && req.Options <= dns.MsgOptionUnpackQuestion && req.Data != nil`（只在真 question-only 时补全量解析），同时让 plain listener 真正设置该选项以省掉第一次的 RR 段解析；(b) 保持现状，改写注释为"无 OPT 的请求会被重复解析一次（成本可忽略），仅当 Pseudo 为空且 Data 存在时触发"。

---

### H4 | LOW | 预打包响应 unpack 失败时 SERVFAIL 只写在结构体字段，客户端实际收到 wire 内的原 rcode

- **编号**: H4
- **文件:行号**: `server/handler/middleware/response.go:73-82` + `server/handler/response.go:129-151`（UnpackPrePackedForModify 失败路径）+ `server/bridge.go:36-47`
- **严重程度**: LOW
- **类别标签**: 错误处理 / 防御路径缺陷

**问题描述**

Response 中间件对需要 EDNS 修改的预打包响应调用 `UnpackPrePackedForModify`；失败时（middleware/response.go:76-82）：

```go
if !handler.UnpackPrePackedForModify(qctx) {
    ...
    qctx.Res.Rcode = dns.RcodeServerFailure
    return err
}
```

`UnpackPrePackedForModify` 失败时**不清 `msg.Data`**（handler/response.go:134-136 提前 return false，line 148-149 的清 Data 不执行）。链返回后 bridge（server/bridge.go:38）以 `len(response.Data) == 0` 判断是否需要 pack —— Data 非 nil → 跳过 packSafe → **原 wire 原样发出**。`qctx.Res.Rcode = SERVFAIL` 只影响 Stats journal（stats.go:43-45 读 `qctx.Res.Rcode`）与 debug 日志，客户端收到的是 wire 里缓存时的 rcode，与 journal 记录不一致。

**风险说明**

触发条件几乎不可达：wire 由 cache `Set()` 成功 pack，`buildEntry` 已校验 header/offset 越界，`patchQuestionCase` 有栈备份恢复 —— `msg.Unpack()` 对该 wire 失败需要缓存数据损坏绕过上述全部校验。属于防御性代码自身逻辑失效：一旦真触发，语义是"serve 可能损坏的 wire + journal 谎报 SERVFAIL"，而非注释意图的 SERVFAIL。

**修复建议**

失败分支清 Data 并释放 wire（`pool.ReleaseWire(qctx.Res.Data); qctx.Res.Data = nil`），让 bridge 走 packSafe 以结构体字段重新打包（真正的 SERVFAIL wire）；或直接 `qctx.Res = handler.BuildResponseMsg(qctx.Req)` 重建 SERVFAIL（同时 `pool.DefaultMessage.Put` 旧 msg 以回收 wire）。

---

### H5 | LOW | CacheStore 入口注释描述不存在的执行路径（records-less zone rule）

- **编号**: H5
- **文件:行号**: `server/handler/middleware/cache_store.go:38-44`
- **严重程度**: LOW
- **类别标签**: 注释漂移

**问题描述**

注释："Gate on Res alone — every terminal path sets Res except the records-less zone rule path, which must reach buildSuccess below or the query is silently dropped."

事实：records-less zone rule **显式设置了 `qctx.Res`**（zone.go:174-179，`response := handler.BuildResponseMsg(...); response.Authoritative = true; qctx.Res = response`），因此它命中 `if qctx.Res != nil { return err }` 提前返回，**不会**到达 buildSuccess。且假设性推演也不成立：若某路径既不设 Res 也不设 Resolved，会在 `if !qctx.Resolved { return err }`（line 46-48）被挡下，同样到不了 buildSuccess —— 注释给出的理由链自相矛盾。

**风险说明**

无运行时影响；误导维护者对 gate 顺序的理解（这是 Round 5 F-4 同位置注释改写后仍存在的事实错误）。

**修复建议**

改为描述当前行为："Gate on Res alone — every short-circuit path (zone rules included, records-less ones set an empty authoritative response) returns here; only a completed Resolution reaches the build paths below."

---

### H6 | LOW | Response 中间件 benchmark 注释描述已移除的 WireHasDNSSEC wire 扫描

- **编号**: H6
- **文件:行号**: `server/handler/middleware/benchmark_test.go:78-81,117`
- **严重程度**: LOW
- **类别标签**: 注释漂移 / 基准有效性

**问题描述**

注释称 "the direct-wire fast path itself is size-independent, but the WireHasDNSSEC gate scans the whole wire for DO=0 clients"，且 line 117 标注 `qctx := ... // DO=0 → WireHasDNSSEC scan runs`。实际 fast path 使用 `qctx.ResHasDNSSEC` 预计算标志（middleware/response.go:53-54；由 `buildCacheResponse` 从 `entry.HasDNSSEC`（Set() 时写入 BLOB 头标志位）填充，cache_lookup.go:157-158），**没有** per-hit wire 扫描。该 benchmark 测的是纯 fast path（`qctx.ResHasDNSSEC` 默认 false，直接命中 direct-wire 分支），与其注释宣称测量的对象不符。

**风险说明**

无运行时影响；但 benchmark 的文档承诺（"measure the wire scan"）与实测对象脱节，未来据此基线做优化决策会跑偏。

**修复建议**

更新两处注释：说明 DO=0 的 DNSSEC 剔除由 `entry.HasDNSSEC` 预计算标志 gate（large-wire benchmark 现在测量的是 fast path 对大 wire 的纯复制/直发成本），或给 qctx 显式设置 `ResHasDNSSEC: true` 另开子基准测量 unpack+filter 路径。

---

## 性能观察（非 bug，不立项）

- **O1（Round 5 P-2 残留）**: mqtype_merge.go:93 `qtMap` 仍为 map 分配；`qtResult` 携带 types 下标改 slice 可省一次 map alloc。仅 MQTYPE 查询路径，影响微小。
- **O2**: RFC 8467 默认 padding 决定（edns/padding.go:32-34 无 EDNS 客户端视为想要 padding）使安全传输上的 legacy 无 EDNS 客户端恒走 unpack+EDNS+re-Pack 路径（response.go:118-120 `shouldAddEDNS` 含 `IsSecure && ClientWantsPadding`），无法享受预打包直发。这是有意的设计取舍（代码注释已说明），仅记录。
- **O3**: cache_lookup.go:72-84 preferStale 分支 `startThrottled` 被冷却拒绝后落到 line 81 **再调一次** `startThrottled`（必再失败 —— ShouldStart 拒绝时不记时间戳），多付一对 pending.Group Start/Done 锁操作。仅 preferStale 模式 + 冷却命中时发生，微小。

## 重点核实后排除的怀疑（回归检查通过）

| 怀疑点 | 结论 |
|---|---|
| `entry.ShouldPrefetch`/`RemainingTTL` 在 `buildCacheResponse`（已 `ReleaseOffsets`）之后调用（cache_lookup.go:55,65） | 只读 `Timestamp`/`TTL` 字段（cache/cache.go:194-213），不触碰已归还池的 `TTLOffsets`。安全 |
| `serveExpiredWithRefresh` 传 entry（offsets 已释放） | 形参 `_ *cache.Entry` 被忽略（cache_refresh.go:138）。安全 |
| `serveExpiredWithRefresh` qr 竞争 / gate 双释放 | A goroutine defer 顺序 finish(CAS)→close(done)，B timer-path goroutine CAS 兜底；写→close→读 happens-before 成立；TryGo 饱和路径 close(done) 防 timer-path 死等。与 Round 5 结论一致，无回归 |
| `buildSuccess` 中 `StoreIfCacheable`（cache_store.go:129）与随后 `ProcessRecords(qr.Answer,...)`（:141-143）共享 RR | `Cache.Set` 深克隆（cache/entries.go:303-304 `zdnsutil.CloneRRs`）；`ProcessRecords(value=0)` 原样返回或仅过滤（dnsutil/records.go:42-63），无 mutation 冲突 |
| `Secondary.Lookup` 中 `ProcessRecords(entry.Answer, elapsed,...)` 改 TTL 是否与缓存竞争 | `Entry.Unpack` 每次 `new(dns.Msg)` 解析出**新** RR 对象（cache/cache.go:103-116）；`buildEntry` 的 wire 为 per-Get 拷贝（entries.go:185-192）。per-call 独立，安全 |
| 缓存命中直发 0 B/op 契约 | fast path（response.go:53-71）只做 ID/RD/AD 的 in-place 字节 patch；patchQuestionCase 栈备份零分配（handler/response.go:168-193）；由 BenchmarkResponseServePrePacked/direct-wire pin。保持 |
| 预打包 wire 生命周期（Data 复用） | buildFromPrePacked wire→msg.Data → bridge serve → `Message.Put`→`ReleaseWire`（pool/pool.go:134-136）；serveExpiredWithRefresh fresh 替换路径 `Put(stale)` 同样回收（cache_refresh.go:182-184）；UnpackPrePackedForModify 成功路径显式 ReleaseWire（handler/response.go:148）。全路径闭环 |
| QueryContext 池化脏字段 | ServeDNS 全字段字面量覆盖（handler.go:128-138）；异步 goroutine（QTx/refresh）只值捕获 qname/qtype/ecs 等，不持 QueryContext。安全 |
| stats record 池 UAF | `Journal.Record` 同步消费（atomic add + `record(r.Rcode, r.Qname)` 拷贝 string 引用，stats/journal.go:176-186），Release 清零后 journal 持有的 string 底层仍有效。安全 |
| EDNS BADVERS / malformed-ECS / cookie 分支 | BADVERS 的 PADDING 载体经 `msgHasEDNSOptions` 防重复（F-3 修复确认）；malformed-ECS 的 in-place Pseudo 过滤改写本查询私有 req；cookie 长度分支符合 RFC 7873 §5.2.2-5.2.4。无新问题 |
| mergeRRs dstKeys lockstep（F-1/P-1 修复区） | 预计算两侧 + append 同步（mqtype_merge.go:185-210），nil RR 有显式 guard。无回归 |
| MQTYPE QTx goroutine 泄漏 | channel 缓冲 == goroutine 数；panic 时 defer 发送（F-1 修复）；`context.WithoutCancel` + 各自 timeout + `defer qtCancel()`。无泄漏、无 ctx 泄漏 |
| pending.DoJoin leader panic containment | 发布错误后 re-panic（pending.go:113-118），由 bridge HandlePanic 兜底。与 Round 5 结论一致 |
| `dns64` 与 MQTYPE QTx 重复解析同一 A 记录 | 共享同一 `Secondary`（chain.go:88-90）与 `PendingRequests` group，singleflight 合并。无重复上游查询 |
| ACL/zone 热路径分配 | `ipInNetworks` 线性 CIDR 扫描（列表小，BenchmarkACLPermits pin）；`isDestructiveChaosName` 对 lowercase 规范名零分配（dnsutil.Canonical/ASCIIFold 快速路径） |

## 审过的文件清单

**server/handler/**:handler.go、context.go、middleware.go、pending.go、prefetch.go、resolve.go、response.go、benchmark_test.go（及测试文件浏览：pending_test.go、response_test.go、store_nocache_test.go、ad_gate_test.go）

**server/handler/middleware/**:chain.go、stats.go、response.go、edns.go、mqtype.go、mqtype_merge.go、cache_store.go、cache_lookup.go、cache_refresh.go、validation.go、acl.go、zone.go、any.go、dns64.go、resolution.go、benchmark_test.go（测试文件浏览：mqtype_test.go、cache_lookup_*_test.go、cache_store_test.go、edns_test.go、response_test.go、zone_bypass_test.go、dns64_exclude_test.go、acl_test.go、any_test.go、validation_test.go、cache_refresh_test.go）

**支撑核实**（只读交叉验证）：cache/cache.go（Entry.Unpack/ReleaseOffsets/ShouldPrefetch/RemainingTTL/WireRcode）、cache/entries.go（Get/buildEntry/Set 的 wire 拷贝与 RR 克隆）、cache/stats.go、internal/pool/pool.go（Message.Put/ReleaseWire）、internal/stats/record.go + journal.go、internal/dnsutil/records.go（ProcessRecords）、internal/dnsutil/case.go（Canonical/ASCIIFold）、internal/dnsutil/dtlsframe.go（TruncateWire）、edns/padding.go、edns/tcp_keepalive.go、server/bridge.go、server/protocol/plain/{udp,tcp}.go、server/protocol/tls/tls.go（listener unpack 方式）、codeberg.org/miekg/dns@v0.6.134 msg.go（Msg.Unpack 不清 Data、Options 语义）、config/defaults_dns.go（MQTYPE 常量）
