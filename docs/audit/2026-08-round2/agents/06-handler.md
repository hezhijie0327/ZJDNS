# handler 审计

> agent: `aa1cee1639a67255b`

发现数: 8

## server-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: TCP 请求路径 refs 每次请求净 +1 永不归零（第 98 行与第 110 行两次 Add(1)，仅一次 Add(-1)），sweep 再次成为死代码，tcpWriteShards 映射无界增长
- **描述**: handleDNSRequest TCP 分支对 entry.refs 执行两次 Add(1)：第 98 行（shard 锁内）和第 110 行（capacityOnce.Do 之后，注释与 94-97 行重复，明显是复制粘贴遗留的 placeholder ref）。但每个请求只有一处 Add(-1)：SERVFAIL 路径第 115 行 defer，或正常路径 goroutine 第 155 行 defer。每条 TCP 查询净泄漏 +1。tasks.go:137 的 sweep 仅在 entry.refs.Load()==0 时删除条目——由于任何服务过请求的条目 refs 恒 ≥1，sweep 永远无法驱逐，tcpWriteShards.entries 随每个不同 TCP 客户端地址无界增长。这是上轮 H1（9f6001c 声称 'refs 归零'）修复不完整的 regression：commit 消息说 placeholder ref 被移除，实际代码里它仍然存在（在 9f6001c 之后与 HEAD 均如此，且 bridge_test.go 没有 refs 断言），并伴随重复的 'In-flight refcount' 注释（94-97 与 106-109 行）。
- **风险**: 长期运行的服务器上每个 TCP 客户端连接（含已断开的）永久占用一个 tcpWriteEntry（两个 channel + map 槽位），数周后映射膨胀到数百万条目，内存耗尽/GC 压力；sweep 机制（H1 的修复目标）完全失效。
- **修复**: 删除第 110 行的第二次 entry.refs.Add(1)（及其重复注释），保留锁内一次 Add(1) 与路径上唯一的 Add(-1)；并在 bridge_test.go 补一条经 handleDNSRequest 完整路径的 refs 归零断言（当前测试只覆盖 truncateWire，未覆盖 refcount）。

## server-02 — HIGH

- **位置**: `server/handler/middleware/mqtype.go:78`
- **类别**: ordering
- **摘要**: 链顺序错误：MQTYPE 被 CacheStore 包在内层，merge() 的 post 代码运行时 qctx.Res 尚为 nil（Resolution 只填 ResolutionResult），递归模式缓存未命中路径上 RFC 10029 客户端合并永不执行
- **描述**: chain.go:141-152 中 MQTYPE.Wrap 在 CacheStore.Wrap 之前调用，因此 MQTYPE 位于 CacheStore 内层：执行顺序为 Response → CacheStore → MQTYPE → Validation → … → Resolution。递归模式（无 upstream）缓存未命中时，Resolution（resolution.go:69-76）只设置 qctx.ResolutionResult/qctx.Resolved，qctx.Res 保持 nil——响应由外层 CacheStore.post 的 buildSuccess 稍后才构建。因此 mqtype.go:77-80 的 `if qctx.Res == nil { return err }` 在递归缓存未命中时恒为真，merge() 永不执行（缓存命中/Zone 短路时 CacheLookup/Zone 已置 qctx.Res，merge 才会运行）。mqtype.go:21 注释声称 'runs after CacheStore (the primary response exists)'，与实际顺序相反；chain.go:56-67 的文档注释也漏列 MQTYPE。单测（mqtype_test.go）用假 next 直接置 qctx.Res，绕过了真实链顺序，未暴露此问题。
- **风险**: RFC 10029 客户端侧合并（本次审计重点新特性）在递归模式的核心路径上完全静默失效：客户端收到无 MQTYPE-Response 的普通响应，功能形同虚设，且无任何日志/错误提示。
- **修复**: 将 chain.go 中 MQTYPE.Wrap 移到 CacheStore.Wrap 之后（使 MQTYPE 成为 CacheStore 的外层，post 代码在响应构建完成后执行），同步修正 mqtype.go:21 与 chain.go:56-67 的文档注释，并补一个经 AssembleChain 全链的递归模式集成测试。

## server-03 — HIGH

- **位置**: `server/handler/middleware/mqtype.go:56`
- **类别**: ordering
- **摘要**: plain UDP/TCP 监听器（miekg/dns v0.6.89 serveDNS 以 MsgOptionUnpackQuestion 解包）请求到达链时 Req.Pseudo 为空，MQTYPE.pre 在 EDNS.pre 之前执行，MQQUERY 选项不可见——明文监听器上 MQTYPE 校验/合并完全失效
- **描述**: miekg/dns v0.6.89 server.go serveDNS 硬编码 `r.Options = MsgOptionUnpackQuestion`（仅解析 question），因此 plain UDP/TCP 的请求进入中间件链时 req.Pseudo 为空。链顺序中 MQTYPE（第 3 层）先于 EDNS（第 7 层）执行，而完整解包（Pseudo 填充）发生在 EDNS.pre（edns.go:35-44）。所以 mqtype.go:56 的 findMQQUERY(qctx.Req.Pseudo) 在明文监听器上永远返回 hasMQ=false——§3.3 的 FORMERR 校验、递归模式合并全部不可达（转发透传不受影响：resolution.go:49 在 EDNS.pre 之后执行，能看到 Pseudo）。TLS/QUIC/DTLS/DTLCP 监听器做完整 req.Unpack()，Pseudo 已填充，故该缺陷只影响最常见的明文 UDP/TCP。
- **风险**: 明文 UDP/TCP（默认且最常见的部署形态）上 RFC 10029 特性对客户端完全不可见：无效 MQTYPE-Query 不会被 FORMERR，合法 MQQUERY 不会触发合并，服务器静默退化为普通单 QTYPE 解析。
- **修复**: 在 MQTYPE.pre 的 findMQQUERY 之前镜像 EDNS.pre 的逻辑：`if len(qctx.Req.Pseudo) == 0 { qctx.Req.Options = 0; if err := qctx.Req.Unpack(); err != nil { …FORMERR… } }`，或改为直接从原始请求解析 OPT（与 edns.go:35-44 同构）。

## server-04 — MEDIUM

- **位置**: `server/handler/middleware/response.go:60`
- **类别**: rfc
- **摘要**: pre-packed 直发快速路径只补丁 ID 和 RD，CD 位（缓存写入时内部查询恒为 0）与 AD 位（validated=1 时恒为 1）按缓存时的值直接下发给 DO=0/CD=1 客户端，违反 RFC 4035 §3.2.2 的 MUST 与 RFC 6840 §5.8 的 SHOULD
- **描述**: 快速路径（response.go:58-68）对 qctx.Res.Data 仅补丁字节 0-1（ID）和字节 2 的 RD 位，字节 3（RA/AD/CD/rcode）保留缓存 Set 时的值：CD 来自 Set 时的内部查询（cache/store.go:476-477 用 dnsutil.SetQuestion 构造，CD=0），AD 来自 Set 时 validated 标记（store.go:501-502）。RFC 4035 §3.2.2 要求 'name server side MUST copy the setting of the CD bit from a query to the corresponding response'——CD=1 客户端收到的响应 CD=0；RFC 6840 §5.8 要求仅在请求带 DO 或 AD 时才设响应 AD 位——DO=0/AD=0 客户端收到 validated 条目的 AD=1（8bda354 只修了 Set 时的 RA/AD，未修逐查询回显）。
- **风险**: CD=1 的验证型 stub 无法感知服务器是否关闭了验证，可能误判响应验证状态；DO=0 客户端收到 AD=1 违反 RFC 6840 §5.8，有合规与互操作风险。
- **修复**: 在快速路径补丁字节 3：`if qctx.Req.CheckingDisabled { Data[3] |= 0x10 } else { Data[3] &^= 0x10 }`，并对 `!qctx.ClientRequestedDNSSEC && !qctx.Req.AuthenticatedData` 的客户端清除 AD 位（Data[3] &^= 0x20）。

## server-05 — MEDIUM

- **位置**: `server/handler/middleware/response.go:73`
- **类别**: memory
- **摘要**: Unpack 失败路径只改 msg.Rcode 为 SERVFAIL 但未清 Data，bridge 因 len(Data)>0 跳过 packSafe 直发旧（可能损坏的）pre-packed wire，客户端收到与声明 rcode 不符的陈旧/损坏数据
- **描述**: response.go:73-77：`if err := qctx.Res.Unpack(); err != nil { qctx.Res.Rcode = dns.RcodeServerFailure; return err }`——Unpack 失败后 qctx.Res.Data 仍然非 nil（指向未解析成功的 pre-packed wire），handler.ServeDNS 返回该 msg（qctx.Res != nil，不进入 SERVFAIL 兜底分支），bridge.go:192/233 因 `len(response.Data) != 0` 跳过 packSafe 直发原始 wire——客户端收到的是 rcode 为缓存时值（如 NOERROR）且可能已损坏的字节流，与代码声明的 SERVFAIL 矛盾。
- **风险**: 缓存条目 wire 损坏（如旧格式条目、磁盘位翻转）时向客户端投递错误 rcode 的垃圾数据而非干净的 SERVFAIL，掩盖故障且违反响应语义。
- **修复**: Unpack 失败时置 `qctx.Res.Data = nil`（并清空 Answer/Ns/Extra），使 bridge 重新 packSafe 生成干净的 SERVFAIL wire。

## server-06 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:204`
- **类别**: pool-leak
- **摘要**: cache.Get 在 store.go:268 AcquireTTLOffsets 取得的池化 offset 切片，仅 buildFromPrePacked（handler/response.go:67）与 rebuildResponseWire（cache.go:167）归还；mqtype.resolve、dns64.go:57 等仅 Unpack 的消费路径从不释放，池条目每次命中永久丢失一件
- **描述**: cache/store.go Get 无条件 AcquireTTLOffsets(numOffsets) 并挂在 entry.TTLOffsets 上；释放点只有两处（handler/response.go:67、cache.go:167），都发生在 serve 路径。mqtype.go:204 的 `m.store.Get(...)` 后只调 `entry.Unpack()` 即丢弃 entry；dns64.go:57 同型（resolver/ns_addresses.go:243、resolver/dnssec/extract.go:193 亦同，超出本包范围）。每条此类缓存命中从 ttloOffsetsPool 取走一件从不归还（下次 Get 由 New 重新分配）——池被缓慢抽干，DNS64/mqtype 高流量下变为每命中一次堆分配。
- **风险**: DNS64 AAAA-miss、MQTYPE 附加类型命中等高流量路径上 pool 形同虚设，每查询增加一次 ~32B 堆分配与 GC 压力，与零拷贝 Get 的优化目标相悖。
- **修复**: 在 mqtype.go:204 / dns64.go:57 的 entry 消费完毕处调用 `cache.ReleaseTTLOffsets(entry.TTLOffsets)`（或在 Entry 上增加一个统一的 Release 方法统一释放），并让 Unpack-only 调用点复用该入口。

## server-07 — LOW

- **位置**: `server/handler/middleware/mqtype.go:192`
- **类别**: dead-code
- **摘要**: merge() 中 `if len(completed) > 0 || len(mq.Types) > 0` 恒为真（validate 已拒绝空类型列表），条件冗余误导读者
- **描述**: mqtype.go:192：到达 merge 的请求必经 validate（mqtype.go:97-123），空类型列表已被 errMQTypeEmpty 以 FORMERR 拒绝，因此此处 len(mq.Types) > 0 恒成立，`|| len(mq.Types) > 0` 分支恒真，条件可简化为 `if len(completed) > 0`（或直接无条件 append——§3.4 要求即使空列表也返回 MQTYPE-Response 选项）。
- **风险**: 维护者可能误以为存在空列表到达此处的合法路径，掩盖对 §3.4 语义的误解；代码冗余。
- **修复**: 简化为 `if len(completed) > 0 || true` → 直接 `msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{Types: completed})`，并注释 §3.4 要求空列表也返回选项。

## server-08 — LOW

- **位置**: `server/handler/middleware/mqtype.go:145`
- **类别**: magic-number
- **摘要**: 合并预算 `config.DefaultMaxUDPResponseSize - msg.Len() - 64` 中的 '64' 为无说明魔法数字
- **描述**: mqtype.go:145：`budget := config.DefaultMaxUDPResponseSize - msg.Len() - 64`——64 字节的 EDNS/OPT 开销余量没有命名常量、没有 RFC 出处注释，且与同一文件 9715 上限的引用方式（config.DefaultMaxUDPResponseSize）不一致。若上游合并响应超过该余量会被静默跳过，估算失真。
- **风险**: 余量取值无法追溯（RFC 9715 建议的 UDP 开销约为 60-100 字节），后续调整会无从依据；违反常量提取纪律。
- **修复**: 在 middleware 包或 config/defaults.go 定义命名常量（如 mqtypeEDNSOverhead = 64）并注明其覆盖 OPT/头部开销的推导依据。

