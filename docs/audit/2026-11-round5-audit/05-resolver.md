# ZJDNS Round 5 — Resolver 审计报告

审计较基准 `9c6df186..HEAD`(`server/resolver/` 全部,含 dnssec/、probe/),重点为递归性能与 EDE 65281 defense-uncertain 链路。所有发现均已读取实际代码核实;`go test ./server/resolver/... -short` 与 `-race` 全部通过。

## 发现

### F1 | HIGH | EDE 65281 链路断裂(新特性在递归路径失效) | server/resolver/cname.go:326 + forward_process.go:285

本轮新增的 defense-uncertain 标记链在到达缓存门之前被两处摧毁:

1. `applyDefenseUncertainty`(recursive.go:573-581)正确设置 `Cacheable=false` + `UpstreamEDE=65281`;
2. 但 `CNAME.resolveInner` 聚合返回值**不携带 `UpstreamEDE`**(cname.go:326 的 return 语句无该字段),每跳的 `qr.UpstreamEDE` 被丢弃。所有面向客户端的递归查询都经 `handleRecursiveQuery → cname.resolve → resolveInner`(forward_process.go:284,是 `Recursive.resolve` 的唯一消费方);
3. 随后 `handleRecursiveQuery` 无条件覆盖:`qr.Cacheable = !server.SkipCache`(forward_process.go:285),把 `Cacheable=false` 又改回 true。

净效果:`StoreIfCacheable`(server/handler/resolve.go:85)看到 `Cacheable=true`、`UpstreamEDE=nil` → **hopguard 学习期 / capsguard 未验证的递归应答按完整 TTL 进缓存**,且客户端也看不到 65281(cache_store.go:154 从 `qr.UpstreamEDE` 附加 EDE,现为 nil)。这正是设计注释宣称要防止的"poisoned answer blast radius = one query"。该特性目前只在转发路径(processUpstreamResponse:210)有效。新增单测 defense_uncertain_test.go 只孤立测 `applyDefenseUncertainty`,故未暴露。

**修复建议**:resolveInner 返回值传播首个非 nil 的 `qr.UpstreamEDE`;`handleRecursiveQuery` 改为 `qr.Cacheable = !server.SkipCache && !edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE)`;补一条端到端测试(uncertain → cname.resolve → StoreIfCacheable 拒绝)。

### F2 | MEDIUM | uncertain NXDOMAIN 不传播 65281 | server/resolver/forward_process.go:248-259

NXDOMAIN 分支 `UpstreamEDE: upstreamEDE`,而 NOERROR 分支(210 行)用 `noCacheEDE`。本地 `Uncertain=true` 时(nxRes 的 `Cacheable` 正确置 false 不本地缓存)65281 不附带 → 级联下游 ZJDNS 的 receive-side 拒缓存门(以 EDE 为键)失效,下游可缓存该 NXDOMAIN。修复:nxRes 同样使用 `noCacheEDE`。

### F3 | MEDIUM | 递归侧标记覆盖不一致 | server/resolver/recursive.go:443-445

`checkLameDelegation` 的两个 terminal 返回未过 `applyDefenseUncertainty`(其他 terminal 路径 207/391-393/418-422 均已应用)。uncertain UDP 响应经 lame 路径终止时空应答以 `Cacheable: true` 返回。影响小(近负面应答)但与特性意图不一致。另:466-472 referral-loop 错误结果会被 RFC 9520 failure cache 以 5s 缓存,同样未考虑 uncertain。

### F4 | MEDIUM | 委派缓存不受 uncertain 门控(设计缺口) | server/resolver/delegation_cache.go:144-168、recursive.go:307/554

`storeDelegation` 无 uncertainty 输入——uncertain UDP referral 的 NS RRset 按 `minDelegationTTL`(NS TTL 常为 1-2 天)进委派缓存。hopguard 基线学习期的伪造 referral 可将后续整个 zone 的查询导向攻击者 NS,爆炸半径远大于 65281 特性针对的应答缓存。权衡:学习期所有 UDP 响应都是 Uncertain,硬门控会让委派缓存永不预热;折中方案是 uncertain 委派以短 TTL(如 `DefaultTTL`=10s floor/cap)存储直至 guard armed。[待核实:代码未注释说明是否为已接受的权衡]

### F5 | LOW | NXDOMAIN deferral 返回路径漏 drain 池消息 | server/resolver/ns_concurrent.go:430-438

`case <-deferralCh` 直接 `return nx.msg`,不像 `serveWinner`(385-392)和循环后 drain(451-461)那样排空 `resultChan`。若 NOERROR winner 恰在 timer 触发时进入 buffered channel(cap 1)且 select 选中 deferralCh,该 `nsResponse.msg` 永不 `pool.DefaultMessage.Put`(GC 回收,池效率损失)。默认 `DefaultNXDOMAINDeferralWindow=0` 时窗口极小;调大旋钮后概率上升。修复:返回 nx 前镜像 serveWinner 的 drain。

### F6 | LOW | verifyMemo 失效约定脆弱 | server/resolver/dnssec_chain.go:282-284 + recursive.go:292

`tryRRSIGRetry` 在 `verifyResponseOnce` 已为同一 (response, keys) 记忆化判定后**原地改写** `response.Answer/Ns/Extra`。memo 仅在下一次响应到达时清除(292 行);同层级内当前无再次验证故不可达,但与已修复的 MQTYPE-strip memo 失效同类,建议在 282-284 改写后立即 `chain.verifyMemo = dnssecVerifyMemo{}` 固化不变量。

### F7 | LOW | fillCacheFromResult 缺 EDE 保险门 | server/resolver/forward_fallback.go:109

只查 `res.Cacheable` + `DNSSECCacheable`,不查 `IsZJDNSNoCacheEDE(res.UpstreamEDE)`——`StoreIfCacheable`(handler/resolve.go:85)自述为 belt-and-suspenders,此平行缓存写路径无同款保险。当前调用方(processUpstreamResponse 两处)的 Cacheable 已含标记,属纵深防御缺口。

### F8 | LOW | 层级超时错误语义丢失 | server/resolver/ns_concurrent.go:474-478

`deadlineCtx`(3s)到期而父 ctx 无 deadline 时,`waitErr` 为 nil,返回 `errors.New("no successful response")` 而非 `DeadlineExceeded`——调用方无法区分超时与全部权威失败(仅影响日志/诊断)。

## 回归检查(已知根因模式,全部通过)

- **closer-zone 门**(RFC 1034 §5.3.2):recursive.go:466 在位;`IsBelow` 含相等语义(已核实 miekg dnsutil:`Common==Labels`),相等情形先被 checkLameDelegation 终结,向后引用无死循环。
- **MQTYPE strip 后 memo 失效**:recursive.go:366-368 清 memo,在位。
- **取消误报为权威失败**:waitLoop `<-ctx.Done()` 经 `waitErr` 显式区分(441-443、474-476);failure_cache.go:113-117 排除 Canceled/DeadlineExceeded。
- **全零 TTL 委派 7 天**:`minDelegationTTL` floor=DefaultTTL(10s)、cap=7d,在位。
- **chain 并发**:prefetch/pendingChain 的 join 次序(297/304)先于 354 行读 chain;后台 goroutine 与主 goroutine 写入的是不相交字段(verifyMemo 仅主 goroutine 触碰);`-race` 全套通过。
- **wire/offset 池归还**:lookupNSAddrsFromCache、ZoneKeys、Secondary.Lookup 每条退出路径均归还。

## 递归性能专项(用户点名)

现状优良的(有证据支撑,勿回退):`withEarlierTimeout` 消除冗余 timer;首 6 + 75ms widen、infra 3 + 500ms 的单 widen goroutine;`fillServer` 共享 backing array;baseMsg 在 `g.Wait()` 后归还;`nsAddrFmt`/`rootCache`/`zoneKeyMemo`/`verifyMemo` 四级 memo;DNSKEY/NS-address 双 singleflight;≥2-names 早退;每 worker 池化 msg 且无 per-NS 子 context。

可优化机会:

- **P1 | stripCrossZoneRecords 无符号快路径早退** | zonecut.go:30-109:每个 terminal answer 层级必跑;当 `allSigs` 为空(无符号区——代码自述 CN 域名大多如此)两趟结果为恒等映射,却已分配 CollectRRSIGs 切片 + canonName map + keepRRset map + result 切片(~4 次分配 + 哈希/层)。`if len(allSigs) == 0 { return answer }` 语义完全等价。预估:无符号热路径每层省 4+ 次分配,低风险。
- **P2 | DefaultNXDOMAINDeferralWindow=0 时仍建 timer** | ns_concurrent.go:425-429:每个 all-NXDOMAIN 层级 `time.NewTimer(0)`(runtime timer + 唤醒);可对 0 特判直接服务。µs 级,但每层都付。
- **P3 | ancestorZones Split+Join** | delegation_cache.go:46-66:每次 lookupDelegation(每查询)Split 出 []string 再逐 zone Join;可用 `dnsutil.Prev` 偏移切子串消掉中间切片。次要。
- **P4 | collectBestNSMatch 每条 NS 一次 Canonical** | recursive_helpers.go:27:ASCII 已小写时零分配,实际成本低,可不处理。
- **P5 | cachedHopResult 每 RR Clone** | cname.go:93-104:CNAME-hop 缓存命中每记录一次 Clone(TTL 改写需要);~N 次/hop,次要。
- **P6 | ProbeNSAddrs 每次 new Prober** | probe/probe.go:267-268:每次探测新建/销毁 latency.Prober(singleflight 已限流,后台路径),次要。

取消传播(用户点名):首个 NOERROR `cancel()` 即时中止 batch/widen/stragglers(ns_concurrent.go:253-254),MQTYPE 重试例外地用独立 ctx 属故意;未发现浪费上游配额的结构性问题。

## 已审文件清单

server/resolver/:resolver.go、recursive.go、recursive_helpers.go、recursive_ns.go、ns_concurrent.go、ns_addresses.go、ns_flight.go、ns_resolve_addrs.go、nameserver.go、forward.go、forward_process.go、forward_fallback.go、cname.go、zonecut.go、qname_minimise.go、delegation_cache.go、delegation_snapshot.go、dnssec_chain.go、dnssec_trust.go、failure_cache.go、mqtype_client.go、root_hints.go。
server/resolver/dnssec/:crypto.go、extract.go、nsec.go、nsec3.go(签名级审阅)、validate.go、trust_anchor.go(签名级审阅)。
server/resolver/probe/:probe.go。
交叉核实:server/handler/resolve.go、server/handler/middleware/cache_store.go(EDE 消费端)、server/upstream/client.go(Uncertain 产生端)、edns/ede.go、config/defaults*.go。

**优先修复顺序:F1(高,新特性核心失效)→ F2 → F3/F4(策略决策)→ F5-F8。**