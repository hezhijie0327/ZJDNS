# Round 6 审计 — Round C 复查报告（修复引入回归）

- 范围：`7974576d^..HEAD` 的 10 个修复 commit（b8ed2c84, a05c1a2d, 7fb0d617, febd9cd7, 8e6a11f1, 09bc21d3, 46e1a0a8, 4be9fba3, 39a34461, 560394e4）
- 方法论：docs/AUDIT-METHODOLOGY.md §4.2 "修复引入回归"。逐 commit `git show` 读 diff，对叠加文件读 HEAD 合并态全文核验，关键 API 语义（Dialer/ListenConfig Control 的 network 值、net.Buffers.WriteTo 消费语义、errgroup.Go 阻塞语义）做了本机实证测试。本审计只读，未修改任何仓库文件。
- 结论：**未发现 HIGH 级新缺陷**。2 项实质性发现（RC-1 MEDIUM 行为回归 / RC-2 LOW-MEDIUM 一侧化修复），4 项低危/记录项。全部验证通过。

## 汇总表

| 编号 | 严重度 | 位置 | commit | 摘要 |
|------|--------|------|--------|------|
| RC-1 | MEDIUM | server/upstream/client.go:279-287 | 7fb0d617 (S6) | spoofguard-only upstream 的**每一个** UDP 响应都被标 Uncertain（65281）→ 该配置下缓存整体失效 + 每响应携带 65281；超出审计建议范围（建议只标降级路径），且无任何测试钉住 spoofguard-only 行为 |
| RC-2 | LOW-MEDIUM | cache/entries.go:97 (GetTypes) vs 275 (Set) | 46e1a0a8 (D3) | Set 键 canonical 化是单侧的：GetTypes 未 canonical 化，而其调用方传 `Fqdn(ns.Ns)`（不转小写）——混合大小写 NS 名的 A/AAAA 缓存从"同源写读命中"变为"读必 miss"（部分被 nsAddrFmt memo 掩盖） |
| RC-3 | LOW | server/protocol/dnscrypt/crypto.go:226-228, 265-267, 356-358 | 09bc21d3 (P5) | decrypt 的 checkReplay 拒绝路径 Get 后不 Put（池回收 miss，GC 兜底，非泄漏/非双放） |
| RC-4 | INFO | server/handler/middleware/mqtype_merge.go:53-64 | 560394e4 (H2) | detached TC drain 的"晚到 QTx 结果入缓存"承诺无直接测试（仅钉住 primary 不被扩展）；drain goroutine 不受关停跟踪（自有 3s 超时界，可接受） |
| RC-5 | INFO | server/upstream/plain/udp.go:406, 646 | a05c1a2d (S1/S2) | `|| sg.confirmed` 子句不可达（confirmed 必经 fast-return 出口）；跨轮确证序列中第 2 轮 conn 死亡仍可服务单候选——与已接受的"单候选窗口服务"语义同类（审计的可选窗口检查建议未采纳），记录为残留 |
| RC-6 | INFO | server/protocol/tlcp/dtlcp.go:189-215 | 09bc21d3 (P10) | admitSem 容量==serverGroup 上限只挡住 DTLCP 自身洪水；同 group 被 TLCP DoT/HTTP-TLCP handler 占满时 `serverGroup.Go` 仍会阻塞 DTLCP dispatch loop（跨协议路径的 P10 同型冻结残留） |

---

## 发现详述

### RC-1 | MEDIUM | spoofguard-only 部署缓存整体失效（S6 修复的政策越界）

- **文件:行号**：`server/upstream/client.go:279-287`
- **触发路径**：`server = {Spoofguard: true, HopGuard: false, CapsGuard: false}` → `hopArmed=false`、`capsEchoVerified=false` → 标记条件 `!capsEchoVerified && (!hopArmed || !result.Verified) && (... || server.Spoofguard)` 恒真 → **每个成功 UDP 响应** `result.Uncertain=true`。
- **影响**：
  1. spoofguard-only upstream 的全部 UDP 应答（A/AAAA collect 路径 `verified=true` 也被 `!hopArmed` 短路盖过）带 noCacheEDE → resolver/下游 ZJDNS/MQTYPE merge 全部拒缓存——该 upstream 的缓存命中率归零，每查询完整上游往返 + collect 窗口延迟（正是 Round C 前一轮裁定的"缓存坍塌"形态，此次由修复自身引入到 spoofguard-only 配置面）。
  2. 每个应答对下游携带 EDE 65281。
- **为何判定为越界而非缺陷**：commit message 明言 "gains spoofguard-only coverage (S6)"，AGENTS.md 防御表同步改为 "hopguard/capsguard/spoofguard"——是自觉的政策决定（spoofguard 无 per-query 正向验证原语）。但审计 S6（LOW）的建议是"**降级单读与学习期服务时**标 65281"，非全量标记；且 `executeUDPCollect` 对 spoofguard collect 胜者自报 `verified=true`（winnerVerified 的 `hg==nil` 分支），两层对 "verified" 的语义互相矛盾，由标记层强制覆盖。
- **测试缺口**：`TestExecuteQuery_UncertaintyMarkMatrix` 的 5 个 case 均不含 `spoofguard-only`；无任何测试断言 spoofguard-only 响应被标记（或未被标记）。
- **建议**：二选一并补测试：(a) 收窄——spoofguard-only 的 collect-discipline 胜者（`result.Verified==true`）不标，仅降级单读（`!result.Verified`）标记：条件改为 `!capsEchoVerified && !result.Verified && guards` 配合 hopguard 学习期在 collect 出口报 `verified=false`（hopArmed=false 且非 collect 路径本就 false）；(b) 维持全标记——在 AGENTS.md 写明 "spoofguard-only = UDP 永不缓存" 的运维代价，并给 `TestExecuteQuery_UncertaintyMarkMatrix` 加 spoofguard-only case 钉住。

### RC-2 | LOW-MEDIUM | GetTypes 未随 Set 的 canonical 化（D3 单侧修复）

- **文件:行号**：`cache/entries.go:97`（GetTypes，契约注释仍写 "caller must pass a canonical qname"）对照 `cache/entries.go:287`（Set 现已 canonical 建键）；调用方 `server/resolver/recursive_ns.go:45/74`、`ns_resolve_addrs.go:70/105` 传 `dnsutil.Fqdn(ns.Ns)`（miekg Fqdn 只补点不转小写）。
- **触发路径**：referral 的 NS target 名携带大写（zone 存储混合大小写时真实存在；记录大小写折叠只发生在 `resolver.Query` 出口，walk 内不折叠）→ 修复前 `cacheGlueRecords`/`ns_resolve_addrs` 用同一混合大小写串写读、能命中；修复后 Set 键为小写、GetTypes 用混合大小写查询 → **miss**。
- **影响**：NS 地址缓存复用退化为重新解析（正确性无损、有界）；`nsAddrFmt` memo（键已 canonical）掩盖重复查询，只在 memo 过期/首次接触后多付一次解析。对照：`Get` 已在入口 canonical 化（entries.go:43-46），`cname.go:78` 调用方也显式 canonical——唯独 GetTypes 掉队。
- **建议**：GetTypes 入口加一行 `qname = dnsutil.Canonical(qname)`（与 Get 对称，零分配快路径），或在其两处调用方 canonical 化。补"混合大小写 NS 名写读命中"测试。

### RC-3 | LOW | DNSCrypt decrypt 重放拒绝路径的池回收 miss

- **文件:行号**：`server/protocol/dnscrypt/crypto.go` 三处 `if repErr := s.checkReplay(query); repErr != nil { return nil, nil, repErr }`（226-228、265-267、356-358）——msg 来自 `pool.DefaultMessage.Get()`（220/259/349），unpack 失败路径已补 Put，重放拒绝路径漏 Put。
- **影响**：重放拒绝是罕见路径，msg 结构体回池 miss 由 GC 兜底；无双重释放（返回 nil，调用方无 Put）。纯纪律缺口。
- **建议**：三处 return 前补 `pool.DefaultMessage.Put(msg)`。

### RC-4 | INFO | H2 detached TC drain 无行为测试

- `TestMQTYPE_Merge_TruncatedPrimary` 只钉住 TC primary 不被扩展 + 空 MQRESPONSE；没有任何测试断言"晚到的 QTx 结果经 detached goroutine 落入缓存"（需慢 QTx + TC primary + 等待后断言 store 命中）。drain 数量 `min(len(mq.Types), DefaultMQTypeMaxQTx)` 与 validate 的启动数精确一致（已核对 mqtype.go:90-116 的截断 + defer-send 契约），无 hang 风险；goroutine 捕获值而非 qctx、有 HandlePanic、自有 3s 界——实现正确，仅测试缺口。

### RC-5 | INFO | S1/S2 门的不可达子句与跨轮 conn-death 残留

- `sg.confirmed=true` 只在 `collectEDNSCandidate` 的 identical-repeat 确证路径设置，该路径 return resp → udp.go:438-463 立即服务返回——`confirmed` 状态不可能留存到 `!ok`（406 行）或 deadline（646 行）分支。两处 `|| sg.confirmed` 恒假，无行为影响（防御性冗余）。
- 跨轮确证序列（round-1 divergent → `break collect` → round-2 新 sg）中 conn 在 round-2 窗口内死亡：round-2 的 `sg.divergentEDNS` 尚为 false，单候选经 `!ok` 分支服务，不做跨轮签名比对。与正常路径"round-2 单候选窗口到期直接服务（554-567 行，同样不查 prevRoundSigs）"语义一致——审计 S1 的可选建议（`now.Sub(lastRecv) > window || packets==1` 才可服务）未采纳，属已接受残留，非修复引入。

### RC-6 | INFO | P10 门的跨协议残留

- `admitSem` 容量 == `serverGroup.SetLimit`，DTLCP 自身洪水下 `serverGroup.Go` 永不阻塞成立。但 TLCP DoT 的 `handleDOTConn` 同跑在 `s.serverGroup`（tlcp.go:112）且不占 admitSem——DoT 连接洪泛占满 group 时，DTLCP 的 `tryAdmit` 成功后 `serverGroup.Go` 仍阻塞 dispatch loop。与 P10 修复目标的冻结同型、触发面换成了同 server 的其它协议；有界（DoT handler 有 idle/handshake deadline），记录为残留。

---

## 逐 commit 审查记录（任务重点项核验）

### b8ed2c84 (U1) + a05c1a2d (S1+S2) + 7afa69b3 (R1) — 通过
- U1：HEAD 态逐一核对 `executeUDPCollect` 全部出口（ctx.Done/conn-death/fast-return/跨轮 match/无 match 两分支/pickBest/nonEDNS 三分支/retransmit rtErr/maxDeadline 三出口），每轮 `ReleaseCollect` 恰好一次，两处 `break collect` 补齐后无双放。回归测试用 maxPipe=1 池驱动两轮 divergent，断言第二查询仍获容量（<1s）——非恒真。
- S1：`!ok` 分支 gate `sg.last != nil && (!sg.divergentEDNS || sg.confirmed)` 符合审计建议（RC-5 记录 confirmed 不可达）；测试 `ConnDeathDivergentNotServed` 用 300ms 杀连接（2 包 → 500ms 窗口未过期，divergent 态可达）真实触发。
- S2：deadline 分支 `safe` 补 `&& (!sg.divergentEDNS || sg.confirmed)`；`DripDeadlineNotServed` 用 80ms 间隔变体包维持窗口活性至 1.5s 预算耗尽——正是审计滴注场景。
- R1：`primariesDoneCh = nil` 单发语义；变量为局部 `case` 体 nil 化无并发面；CPU-share 测试（阈值 0.5）钉住。

### 7fb0d617 (S3,S5-S7) — 数学核验通过；S6 见 RC-1
- S3 数学（HEAD hopguard.go:339-390 逐行验算）：rejected 合并计数上限 `verifiedMode/4` < 共晋升门槛 `merged[mode]/2`（merged mode ≥ verifiedMode 恒成立），rejected TTL 不可能成为 mode 或被共晋升；合并进 throwaway copy（`merged`）不回写 verified 直方图，不复合；rejectedHisto 键域 uint8（≤256 键有界）；FeedRejected 只走 5min 时间重建、不驱动 samples cadence，洪泛无法加速 3/4 衰减；全漂移（verified 归零 → trusted 空 → disarm）恢复路径自洽。flood/drift 测试在 hopguard_test.go。
- S5/S7 管线：`udpResult{data,ttl}` 上 resultCh 消息配对（readLoop 发 `{packet,ttl}`、close 发零值、Exchange/deferred drain 全部改 `resp.data`）——channel 携带 struct 杜绝第二数据报的 TTL 配对竞态；`executeUDPPooled` 的 verified = 武装 ∧ TTL≠0 ∧ Validate 通过；`winnerVerified` 收 TTL=0。dnscrypt 两个 Exchange 调用点 `_` 丢弃正确（nonce 即身份，注释成立）。
- S4 前提已文档化于 `confirmed` 字段（spoofguard.go:48-55）。
- U9（顺带）：acquirePacketBuf release 闭包去 clear——与 releasePacketBuf 的"写前覆盖+读者受 n 约束"论证一致，注释互指。

### febd9cd7 (U4, REF-1) — 通过；recverr 网络族实证正确
- **recverr 网络族判定**（任务点名疑问）：本机实证（go1.x darwin，net 包平台无关逻辑）——`Dialer.DialContext(ctx, "udp", addr)` 的 Control 回调收到的是**族解析后的** `"udp4"`/`"udp6"`（hostname 双栈解析同样返回 "udp6"，Go 文档明载 "passing 'tcp' to Dial will cause the Control method to be called with 'tcp4' or 'tcp6'"）。故 `strings.HasSuffix(network, "6")` 正确区分两族；不会对 AF_INET6 socket 误设 IPPROTO_IP 层选项。listen 侧同理（`ListenPacket("udp", ":port")` → Control 收 "udp6"），REF-6 的 `network[len-1]=='6'` 同样正确。
- U4 重传块：`msg.ID = trackingID → Pack → WriteQuery → ReleasePackBuf → msg.Data=nil → msg.ID=originalID` 状态恢复次序正确；WriteQuery 在 writeMu 下同步写（缓冲释放前完成）；rtErr 分支 ReleaseCollect 配对、previous Put；`roundStart=now` 重置；重传沿用同 matchKey（迟到重复仍命中本轮注册）。条件 `sg.last==nil && sg.nonEDNS==nil && sg.prev==nil` 保证只有全静默轮触发（hopguard 拒收的包不经 processPacket，漂移场景覆盖）。`dropfirst` 测试真实驱动丢包-重传-恢复。
- retransmit 与 maxDeadline 次序：deadline 已过时先重传一次再失败——多付一个数据报，无害。

### 8e6a11f1 (U2,U3,U6-U8) — 通过
- U2：DoH 三个 client 构造点 + DoH3 全部 `http.ErrUseLastResponse`；基座 `dohClient` 仅被提取 Timeout/Transport，不直接发请求，无漏网路径。`TestExecuteHTTPSRejectsRedirect` 用真实 302 + 目标服务器命中计数 0——强断言。
- U3：三 sentinel `errors.Is` 精确门，其余 Acquire 错误（ErrConnClosed/ErrKeyCollision/写失败）仍按原样落入 per-query dial。**ErrPoolShutdown 传播**（任务点名）：`TestSecureTransportPoolShutdownFailsFast`（tls + tlcp 两份）断言 Close 后 ExecuteTLS/DTLS 返回 `pool.ErrPoolShutdown` 且无回退拨号（127.0.0.1:1 立即拒绝的对照设计）——Close 后快速失败被钉住；门前的行为（回退拨号可能成功）被有意收紧，符合"池关闭=不再服务"语义。
- U6：`stdTLSConfig` 移入 dial 闭包；`tlsConfig.InsecureSkipVerify` → `server.SkipTLSVerify` 等价（client.go:172 已核对）。
- U7：`err.(net.Error)` 裸断言放行 + 其余包装，与 ReadFrom 纪律对齐。
- U8：`exchangeSegmented` ID 校验后加 `matchQuestion`；正反两测试（同 ID 异 question 拒绝 / 回显通过）。

### 09bc21d3 (P1,P2,P4-P11,REF-6 + demux RDLENGTH) — 通过（RC-3/RC-6 记录）
- **P4 net.Buffers 消费语义**（任务点名）：`frames.WriteTo(conn)` 只前移 `frames` 切片头元素（backing array 中的 slice header），不改写字节内容；`frames = frames[:0]` 后 append 逐格覆盖被消费的 header——复用安全。`tasks []dotWriteTask` 持有**原始** `t.data` 值拷贝，flush 无论成败都以原始 header Put（容量类路由正确）。writer 提前退出（flush 错误 return）后，`handleDOTConn` 的 defer（wg.Wait → drain writeCh 并 Put → close → <-writerDone）回收滞留任务——闭环（tlcp.go:161-186）。批量边界（≤16、drain 内层 `!ok` break 后仍 flush）正确。
- **P5 双重 Put**（任务点名）：decrypt 三分支 Get；unpack 失败即 Put 后返回 nil；成功路径 msg 由 listener 的 `defer pool.DefaultMessage.Put(m)`（udp.go:253 / tcp.go:266 / handleSaturated:178）唯一释放；`serveDNS` 的 identity guard（resp==m → nil）保证 serveDNS 的 `defer Put(resp)` 永不与 listener 的 m-Put 指向同一对象——无双重释放。`Decrypt` 走 `XchachaOpen(nil,...)` 新分配 + `UnPad` 子切片（独占所有权，不别名输入 b），Put 时 ReleaseWire 的容量类路由不会回收外来 buffer。仅 RC-3 的重放拒绝回收 miss。
- **P10 sem 泄漏**（任务点名）：tryAdmit 成功 → `serverGroup.Go`（errgroup.Go 阻塞不失败）→ 闭包内 `defer HandlePanic` + `defer l.release()`（LIFO：release 先跑、panic 也释放）——配对闭合，无泄漏路径。跨协议残留见 RC-6。
- **P1 standalone 路径**（任务点名）：`startDOQServer`/`startDOH3Server` 均改为局部 `addrCache` 参数下传；server 字段删除后全仓无残余引用（grep 验证）；H3 打标从 ServeHTTP 移到 accept 时点（与 DoQ 对齐，shard 自有 cache）。
- P6 数学：`len(param) ≤ maxEncoded-4` 时解码严格 < limit（floor((E-4)·3/4) ≤ L-3），仅 ≤4 字符边界带精确解码——语义与 POST 路径一致；双 Query() 解析仍存（次级，未修，可接受）。
- P2/P7：非临时错误 Warn + 100ms 退避 + continue；临时错误同样 sleep——与全库 9 个 accept 循环一致。
- P8：ParseIP 分支镜像 tls/certs.go；P9：两 worker 路径 defer 注册于 handler 之前（goroutine 内 LIFO：Put → HandlePanic → sem 释放）；P11：显式 drain 等待移除，仅 CloseWithError（quic-go 自管 drain）。
- REF-6：`IP_PMTUDISC_DONT` + SO_RCVBUFFORCE→SO_RCVBUF 降级链正确；`udpRcvBufTarget` 4MiB。记录性小注：双栈 wildcard socket（Linux 上 "udp"+":53" → Control 收 "udp6"）只设 IPV6_MTU_DISCOVER，v4-mapped 流量的 DF 行为不受控——覆盖面小缺口，非缺陷。
- demux RDLENGTH 修复：OPT 于 pos+4（root+TYPE+CLASS+TTL = pos+5..pos+13），RDLENGTH 在 pos+13:pos+15——偏移验算正确；`rest>=11` 保证越界安全；旧代码 pos+9:11 读的确实是 TTL 高位。

### 46e1a0a8 (D1,D3,D7-D9) — 通过（D3 单侧化见 RC-2）
- D1：setECS `min(SourcePrefix, 24/56)` + mask；Get fallback 候选跳过条件改比 `cand[0].ecsPref`（capped 键）——正确适配；`/0` 退化为无候选正确。`TestSet_ECSVariantsCollapse` 断言第三变体命中共享条目——真实。spill 旧键（未 capped）升级后不可达、自然过期——可接受。
- D3 Get 侧：`dnsutil.Canonical` = Fqdn 补点 + ASCIIFold（已 canonical 时零分配）；qctx.Qname 已小写路径零成本；`cname.go:78` 幂等。**GetTypes 掉队 = RC-2**。GetTypes 其余调用方（ns_addresses.go:251）正是混合大小写来源。
- D7：双侧 nil-SOA 守卫 + 注释互指 + cache_lookup_nxancestor_test 钉住；D8：`validSeen` 后置位——注释与实现一致；D9：16KiB 门 + skip 时 Put(msg)（与既有 early-return 一致）。

### 4be9fba3 (R2-R5,D2,D4-D6) — 通过
- **R2 所有权**（任务点名）：expired 与主路径均补 `pool.ReleaseWire(entry.ResponseWire)`；`rcode := entry.WireRcode()` 在 withRemaining 之前捕获（最后读 wire 处），defer 释放后不再触碰；`withRemaining` 作用于 Unpack 产出的 RR（fork Unpack 不别名 wire 缓冲），无释放后读取。
- R3：ZoneKeys expired 分支补双释放（此前 offsets+wire 双漏）；主路径 defer 双释放，memo Set 的 keys 为 Unpack 产物、自持数据。
- **R4 WithTimeout 语义 / R5**（任务点名）：R4 零窗口快路径镜像递归侧；`nxdomainCh` 为 buffered-1 单发（CAS 守护，非 close）——`continue` 重入 select 后通道已空、阻塞，**无 R1 型自旋**；NOERROR winner 优先 drain 语义一致。R5 `context.WithTimeout(ctx /*根*/, 3s)`：queryCtx 的 level cancel（首个 NOERROR）不再命中重试、客户端断开经根 ctx 传播中止重试、预算仍全新（根 ctx 自带更短 deadline 时以根为准——即意图本身）；`retryCancel()` 配对无泄漏。
- D2：tlsEnabled 补 DTLS + 无证书即报错——对既有"静默不监听"错误配置是有意破坏性收紧；两测试钉住。D4：>2 标签 skip 与 tldPlusOne（右 1-2 标签）语义精确一致（domainKey 已去尾点/通配前缀）；D5 Match→MatchTags 委托保行为，nil IP 跳过 trie 等价旧 ParseIP 失败路径；D6 `\# len hex` 校验 + 裸 hex 提取（packer 直接 hex-decode Data，前缀必须剥离——正确），`\# 0` 零长 rdata 边界通过。

### 39a34461 (H3-H6,F1-F4) — 通过
- **H4 ReleaseWire 容量类路由**（任务点名）：该路径 `msg.Data` 恒为 `cache.Get → buildEntry → pool.AcquireWire` 的池拷贝（2048 类或 fresh），ReleaseWire 是其对称释放——与成功路径同一处置；nil 化后 bridge 判 `len(Data)==0` 走 packSafe 重建真 SERVFAIL；后续 `Message.Put(msg)` 无第二 wire 可放。`TestResponseMiddleware_PrePackedUnpackFailure` 钉住 Data 清空。
- F1：`(MaxDNSUDPPacketSize-QueryOverhead)&^63 = 3968` 向下取整正确（Pad 的 64 对齐会覆盖非对齐 cap）；classical 分支补 post-seal 检查镜像 PQ。F3 预分配无语义变化。
- F2：`Len`/`Range` 降读锁——`m.len` 与链表指针仅在写锁下变更（已核对写路径），无竞争；RWMutex 语义下 fn 内再读（Get）由死锁转为合法，无新 footgun。F4：Warm 快照 + 锁外读，fd 语义（rename 后旧 fd 继续有效）与 Compact 协议一致；sparse 切片头拷贝不可变视图安全。
- H3/H5/H6：纯注释修正，现与实现一致。

### 560394e4 (H1,H2) — 通过（H2 测试缺口见 RC-4）
- H1：`Rcode ∉ {NOERROR, NXDOMAIN}` 跳过 merge——QTx goroutine 各自 defer-send 进缓冲通道后自退（容量==数量，无泄漏）；拒绝响应不再带空 MQRESPONSE。`TestMQTYPE_LocalRejectionSkipsMerge` 用阻塞 resolver + 500ms 时限证明短路（回归则 3s/2s 超时失败）——强测试。
- H2：drain 数量 `min(len(mq.Types), MaxQTx)` 与 validate 启动数（同式截断）精确相等——无计数错位 hang；goroutine 值捕获（qname/qclass/ecsOpt 拷贝）、HandlePanic、通道永不 close 按计数收——正确。

---

## 跨 commit 叠加核验

| 叠加文件 | commits | 结论 |
|---|---|---|
| `server/upstream/plain/udp.go` | b8ed2c84 + a05c1a2d + febd9cd7 | HEAD 全函数通读：每轮 ReleaseCollect 恰一次（U1）、divergent 门（S1/S2）、重传块（U4）、winnerVerified 线程（febd9cd7 改签名）相互无冲突；重传仅在全静默轮触发、与 divergent 轮流转正交 |
| `server/upstream/pool/udp_conn.go` | 7fb0d617（含 U9）+ febd9cd7 新增 WriteQuery | WriteQuery 与 readLoop 的 collectCh 投递在注册存续期内闭合 |
| `server/resolver/forward.go` | 7afa69b3 (R1) + 4be9fba3 (R4) | primariesDoneCh 单发 nil 化与 nxdomainCh 零窗口快路径分属不同 select 臂；nxdomainCh 单发（非 close）无自旋面 |
| `server/upstream/tls/https.go`（U2）vs `server/protocol/tls/https.go`（P6） | 8e6a11f1 / 09bc21d3 | 同名不同包（客户端 vs 服务端），无冲突 |
| cache 键（46e1a0a8）× MQTYPE cache 路径（560394e4） | — | merge 的 StoreIfCacheable 走同一 Set/Get（canonical 两侧一致）；GetTypes 例外见 RC-2 |

## 全量验证

```
go build ./...                     → exit 0
go vet ./...                       → exit 0
go test -short ./... -count=1      → exit 0，45 ok / 0 FAIL（cmd/zjdns 集成包含于 45 内，含新回归测试全部通过）
go test -race -short -count=1 \
  ./server/upstream/plain/... ./server/upstream/pool/... \
  ./server/defense/... ./server/protocol/shared/... \
  ./internal/lrumap/... ./internal/demux/...          → exit 0
go test -race -short -count=1 \
  ./server/handler/... ./server/resolver/... ./cache/... → exit 0
```

测试尾部：

```
ok  zjdns/server/upstream   16.489s
ok  zjdns/server/upstream/plain  4.841s
ok  zjdns/server/resolver   4.848s
ok  zjdns/server/handler/middleware  2.844s
ok  zjdns/zone              0.283s
```

## 复查结论

10 个修复 commit 的核心机制（collect 注册配对、hopguard 合并数学、verified 语义线程化、net.Buffers 批写、DNSCrypt 池化所有权、pool 饱和门、cache 键 canonical 化、MQTYPE 拒绝短路）实现与声称一致，回归测试绝大多数为真实行为断言。需要跟进的是 RC-1（spoofguard-only 全量标记的运维代价，建议收敛或补测试钉住）与 RC-2（GetTypes 补 canonical 化一行）；RC-3/RC-4 为低成本补齐项；RC-5/RC-6 为已接受残留记录。
