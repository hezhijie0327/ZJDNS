# ZJDNS Round 6 — Resolver 审计报告

范围:`server/resolver/` 全部(resolver/recursive/forward/cname/zonecut/qname_minimise/delegation cache/dnssec_chain/dnssec_trust/failure_cache/mqtype_client/root_hints + `dnssec/` + `probe/`)。只读审计,仓库零修改(R1 的复现测试通过 `go test -overlay` 注入,文件在 `/tmp/zjdns-round6/zz_spin_audit_test.go`,未落入仓库)。已先行通读 Round 5 的 `05-resolver.md` 与 `12-synthesis.md`,本文不重复其已修复项(F1-F8、RC)与已接受权衡(F4 委派缓存 uncertain 门控);withEarlierTimeout、首 6+75ms widen、infra 3+500ms、四级 memo、双 singleflight、≥2-names 早退、首个 NOERROR 即时 cancel 均核实仍在位,勿回退。

基线:`go test ./server/resolver/... -short -count=1` 全绿(resolver 4.4s / dnssec 0.3s / probe 0.3s)。

## 发现

### R1 | HIGH | 性能/CPU 放大 | server/resolver/forward.go:308-316(+102-108)

**问题描述**:`queryUpstream` 的 wait loop 把 `activePrimaries`(closed channel,由 `finishPrimary` 在主 upstream 全部退出时 close)作为 `primariesDoneCh` select case。当全部 primary 在 fallback 结果落地前退出时,`tryAdopt` 返回 `done=false`(stash 为空),循环回到 select——**closed channel 永远 ready**,Go select 只剩这一个 ready case 便立即再次选中 → 无任何退避的紧自旋,直到 fallback 应答到达(500ms `DefaultFallbackTimeout` 之外还可能是 fallback 自身的数秒响应延迟)。引入于 `5e1fe713`(2026-09-02 "make fallback adoption responsive to … dead primaries"),Round 5 漏检。

**验证**(overlay 单测,`/tmp/zjdns-round6/zz_spin_audit_test.go`):primary 立即失败 + fallback 400ms 后应答、`fallbackTimeout=40ms`:
```
wall=401.3ms cpu=393.0ms share=0.98
```
单条查询即烧满一核整个窗口。

**风险说明**:配置了 fallback upstream 且 primary 批量死亡(上游宕机/被墙/限速)时,每个在途查询独占一个核自旋到 fallback 应答。N 个并发此类查询 → N 核被打满,挤占协议 listener 与其余查询的调度,形成 fallback 场景下的自我 CPU DoS 放大器;负载均衡的多 upstream 中只要 primary 全体失败就会触发,并非边角配置。

**修复建议**:该 case 只需一次性生效——case 体内处理完(无论 `tryAdopt` 结果)立即 `primariesDoneCh = nil`(nil channel 永久阻塞,即"只触发一次"语义,与 `fallbackCh` 的 timer 单发对齐);后续仍由 `fallbackReadyCh`/`resultChan`/`nxdomainCh`/`queryCtx.Done()` 唤醒。一行修复,并补一条 CPU-share 回归测试(阈值建议 <0.5)。

### R2 | MEDIUM | 资源/池契约违背 | server/resolver/cname.go:78-88(`cachedHopResult`)

**问题描述**:`cache.Get` 契约是每次命中都交给调用方一个池化 `ResponseWire`(cache/entries.go:191-193 `pool.AcquireWire`,注释明言"the copy is recycled by Message.Put after the response is written"——即消费方负责归还)。`cachedHopResult` 只 `entry.ReleaseOffsets()`(expired 分支 85 行与主路径 88 行),**从不 `pool.ReleaseWire(entry.ResponseWire)`**。克隆(96-104 行 `rr.Clone()`)完成后 wire 即被遗弃。

**风险说明**:CNAME-hop 缓存命中是递归热路径(目标名被多个源域名共享,AGENTS 自述设计意图);每次命中泄漏一个 2KB wire 池对象到 GC——非内存泄漏(GC 可回收),但 wire 池对该路径完全失效,每次命中都变成新分配 + GC churn。典型 A/CNAME 应答 <2048B(池容量级),按 50k QPS × 30% 命中 CNAME-hop 估算约 30MB/s 的无谓分配压力,直接侵蚀 0-alloc 目标。对照组:同仓库 `handler/resolve.go:46-47`、`middleware/cache_lookup.go:94/149`、`ns_addresses.go:255-262` 均正确双释放(offsets + wire)。

**修复建议**:在 `withRemaining` 三次调用完成、所有 Clone 落定之后 `pool.ReleaseWire(entry.ResponseWire)`(注意与 handler/resolve.go:38-41 相同的次序约束:先读完 wire 携带的信息再释放)。expired 分支同样补上。

### R3 | LOW | 资源/池契约违背 | server/resolver/dnssec/extract.go:206-225(`ZoneKeys`)

**问题描述**:与 R2 同类——`c.cache.Get(zone, TypeDNSKEY, ...)` 后仅 `defer cachedEntry.ReleaseOffsets()`(213 行),`ResponseWire` 未归还。

**风险说明**:频率远低于 R2——`zoneKeyMemo`(四级 memo 之一)按 key TTL(通常小时-天级)兜住,只在 memo 过期后的首次 ZoneKeys 付出一次 wire 遗弃;且 DNSKEY RRset 常 >2048B(此时 AcquireWire 本就 fresh 分配、ReleaseWire 也会因 cap 不匹配丢弃,无池影响)。属契约一致性问题而非可测的性能损失。Round 5 回归检查曾声称"ZoneKeys 每条退出路径均归还",实际未覆盖 wire 项,本轮更正。

**修复建议**:`defer pool.ReleaseWire(cachedEntry.ResponseWire)` 与现有 defer 并列(Unpack+ProcessRecords+FindDNSKEYs 完成后释放即可;`pending` 分支 entries 为 nil 无需处理)。

### R4 | LOW | 性能/一致性 | server/resolver/forward.go:323-327

**问题描述**:`case <-nxdomainCh:` 无条件 `time.NewTimer(config.DefaultNXDOMAINDeferralWindow)`;默认值为 0 时仍然创建 runtime timer、立刻到期、再被 `case <-deferralCh:` 唤醒一次才服务 NXDOMAIN。递归侧同型代码已做零窗口快路径(ns_concurrent.go:426-447:`DefaultNXDOMAINDeferralWindow <= 0` 直接服务,免 timer churn)——转发侧漏掉了同一优化(Round 5 P3 只改了递归侧)。

**风险说明**:每个收集到 NXDOMAIN 的转发查询多付一次 timer 分配 + 一次多余 select 轮转;µs 级,但 all-NXDOMAIN 流量(不存在的域名查询)下是每查询成本,且两条路径行为语义应一致。

**修复建议**:镜像 ns_concurrent.go 的零窗口快路径:`if config.DefaultNXDOMAINDeferralWindow <= 0 { 立即按 deferralCh 分支的 drain-then-serve 语义返回 }`。

### R5 | LOW | 性能/上游配额 | server/resolver/ns_concurrent.go:184

**问题描述**:MQTYPE-Query 失败回退重试用 `context.WithoutCancel(queryCtx)` + 新鲜 3s 预算。`queryCtx` 派生自 deadlineCtx ← 调用方 ctx,WithoutCancel 把**所有**取消链剪断——首个 NOERROR `cancel()` 或客户端断开后,每个仍在途的携带 MQQUERY 的 worker(首批 6 + widen 批)都会再发第二次查询、跑满自己的 3s。转发路径的同型重试(forward.go:213)用的是 `context.WithoutCancel(ctx)`(根 ctx)——既躲开查询完成的 cancel,又保留客户端断开中止。

**风险说明**:有界(每 worker ≤1 次重试、3s),仅 `mqtype` 配置开启时存在;Round 5 已注明"独立 ctx 属故意"。但转发侧证明了更优惯用法存在,两侧不对称,递归侧在取消场景下浪费权威服务器配额(对 CN 权威尤其敏感——它们会因未知 EDNS 选项 SERVFAIL/丢弃,恰好触发此重试)。

**修复建议**:改为 `context.WithoutCancel(<调用方根 ctx>)`(需要在 `queryNameserversConcurrent` 里保留入参 ctx 引用即可,该函数本就有 `ctx` 与 `queryCtx` 两个变量),保留取消传播同时维持"新鲜预算"意图。

## 回归检查(Round 5 已知模式,全部通过)

- **池化消息切片别名**:`pool.Message.Put` 只置零结构体字段不碰 backing array(internal/pool/pool.go:120-137),Get 后 worker 一律 `append(msg.Question, ...)` 从 nil 起步不复用旧数组——`stripCrossZoneRecords` 快路径/根区直取 sections/`stripMQBundled` 原地压缩后再 Put 的所有别名路径安全,Round 5 P1 结论仍成立。
- **verifyMemo 失效**:RRSIG 重试改写后立即清 memo(dnssec_chain.go:233)、MQTYPE strip 后清(recursive.go:371)、每响应到达即清(recursive.go:292)——Round 5 F6 修复在位。
- **取消误报**:waitLoop `<-ctx.Done` 经 waitErr 区分(ns_concurrent.go:475-477、508-516 deadlineCtx.Err 优先);failure_cache.go:113-117 排除 Canceled/DeadlineExceeded。
- **closer-zone 门 / referral loop**:recursive.go:470-476 在位;apexCut 经 advanceApexZoneCut 正确过链。
- **chain 并发**:DNSKEY prefetch/pendingChain 的 join 次序(297/304 先于任何 chain 读)与"pendingChain 非 nil 时不开 prefetch"(247)互斥在位;`ensureZoneDNSKEYs` singleflight leader 只改自己的 chain, followers 拷贝结果——无跨 walk 竞态。
- **委派缓存**:全零 TTL floor=10s/cap=7d(minDelegationTTL)、refresh CAS + 全局 ≤4、spill 异步写不占锁、CleanupDelegations 物理清理在位。
- **EDE 65281 链路**(Round 5 C1/F2/F3 修复):applyDefenseUncertainty 覆盖 recursive.go 全部 terminal 出口(207/391/418-424/446-448);resolveInner 聚合传播 `noCacheEDE` 且 `allCacheable` AND(cname.go:263-267/337);handleRecursiveQuery 只 AND `!server.SkipCache`(forward_process.go:304)不再覆写;fillCacheFromResult 已含 IsZJDNSNoCacheEDE 门(forward_fallback.go:109,Round 5 F7 修复在位)。
- **深度/放大**:depth ≤16、CNAME 链 ≤16(固定数组 visited 检测环)、in-flight 全局 8192、refresh ≤4、DNSKEY/NS-addr 双 singleflight、1s nsAddrFlight 内禀预算——无无界递归/泄漏路径。
- **nil/越界**:`nameservers` 空判、`len(resp.Question) > 0` 判、nxdomainMsg Load-后-非-nil(channel happens-after)、extractChildNS/advanceApexZoneCut 的 `append(Ns, Answer...)` 只写 Ns 空闲容量不与已捕获别名重叠——未发现可触发 panic 路径。

## 递归性能专项复核(勿回退清单 + 本轮新增)

已优化且核实仍在位:withEarlierTimeout(每层免冗余 timer)、首 6 + 75ms widen / infra 3 + 500ms 单 widen goroutine、fillServer 共享 backing array、nsAddrFmt/rootCache/zoneKeyMemo/verifyMemo 四级 memo、DNSKEY/NS-address 双 singleflight、≥2-names 早退、首个 NOERROR 即时 cancel + serveWinner/resultChan drain、零窗口 NXDOMAIN 快路径(递归侧)、baseMsg 在 g.Wait() 后归还、rootCache 临时集防惊群(ns_addresses.go:101-116)。

本轮新增可落地项即 R1-R5;另有两处观察不立项:resolveNextNameservers 的 glue 匹配 O(NS×Extra)(recursive_ns.go:73-94,每 referral 数百次 EqualFold/Fqdn,Fqdn 对已带点 wire 名零分配,与 Round 5 P4 同级可忽略);ancestorZones Split+Join(Round 5 P3 已记"次要",维持不动)。

## 已审文件清单

server/resolver/:resolver.go、recursive.go、recursive_helpers.go、recursive_ns.go、ns_concurrent.go、ns_addresses.go、ns_flight.go、ns_resolve_addrs.go、nameserver.go、forward.go、forward_process.go、forward_fallback.go、cname.go、zonecut.go、qname_minimise.go、delegation_cache.go、delegation_snapshot.go、dnssec_chain.go、dnssec_trust.go、failure_cache.go、mqtype_client.go、root_hints.go。
server/resolver/dnssec/:crypto.go、extract.go、nsec.go(签名级)、nsec3.go(签名级)、validate.go、trust_anchor.go(签名级)。
server/resolver/probe/:probe.go。
交叉核实:internal/pool/pool.go(池契约)、cache/entries.go+cache.go(Get/wire 契约、buildEntry 池化 wire)、server/handler/resolve.go(Secondary.Lookup 对照正确释放范式)、server/handler/middleware/cache_store.go(Err 早退门)、server/init.go+resolver_init.go(Poisonguard 非空接线)、config/defaults*.go(常量值与类型)。
验证工件:/tmp/zjdns-round6/zz_spin_audit_test.go + overlay.json(R1 复现,`go test -overlay /tmp/zjdns-round6/overlay.json ./server/resolver/ -run TestAudit_PrimariesDoneBusySpin -v`)。

**优先修复顺序:R1(HIGH,一行修复 + CPU 回归测试)→ R2(热路径 wire 池)→ R3/R4/R5。**
