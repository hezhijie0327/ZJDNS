# domain 审计

> agent: `a569bb39c6bf07c8f`

发现数: 9

## domain-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get 解析 pre-packed BLOB 时无格式字节校验也无边界校验，旧格式/损坏行直接触发切片越界 panic（升级回归）
- **描述**: Get() 读取 msg_wire 后仅检查 len(msgWire)==0（第 261 行），随后直接按 0x02 格式解析：`numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))`（第 267 行，len<3 即 panic）、`wireStart := 3 + numOffsets*2`（第 269 行）、`wire := msgWire[wireStart:]`（第 273 行，wireStart>len 即 panic），且从不检查 `msgWire[0] == cacheFormatPrePacked`。触发路径真实存在：0x02 头是 v3.11.12（ba1f78c）才引入的，v3.11.11 及更早版本 Set() 写入的是裸 zstd BLOB（93611d5:cache/store.go:354 `msgWire := zdnsutil.Compress(msg.Data)`，无任何前缀字节），而 database/migration.go 没有任何迁移清理 entries 表。升级后旧行 msgWire[0]=0x28（zstd magic）→ numOffsets=0xB52F=46383 → wireStart=92769 → 对典型的 <1KB 旧条目直接 `msgWire[wireStart:]` 越界 panic（被 HandlePanic 捕获，查询丢弃）；长度≥92769 的旧条目则生成垃圾 TTL offset，在 buildFromPrePacked（server/handler/response.go:54 `wire[off:]`）服务时越界写再 panic。此外任何损坏/截断行（len<3）同样 panic。
- **风险**: 升级 v3.11.11→v3.11.12+ 后持久 DB 中的全部旧缓存条目命中即 panic（查询被丢弃/客户端超时），损坏数据库导致请求路径持续 panic；新格式的健壮性完全依赖写路径正确性，无防御
- **修复**: Get 解析前校验：`len(msgWire) >= 3 && msgWire[0] == cacheFormatPrePacked`，并校验 `3+numOffsets*2 <= len(msgWire)`（wireStart 边界），不合法按 miss 处理（可顺带删除该行）；或在升级时增加 migration 清空 entries/清理非 0x02 行。建议同时把格式字节纳入校验并注释格式演进

## domain-02 — MEDIUM

- **位置**: `database/stmts.go:28`
- **类别**: dead-code
- **摘要**: StmtEntry 自 ECS 单轮查询重构后已无任何生产代码使用，仍被 prepare 并纳入 Close 清单
- **描述**: Get() 已完全改用 StmtEntryFallback（cache/store.go:251），全库生产代码中 StmtEntry 只有三处引用：db.go:45 字段声明、stmts.go:28 准备、db.go:152 Close 关闭——没有任何 Query/QueryRow 调用（grep 验证）。这是 8bda354 'ECS single-round-trip lookup' 重构遗留的死代码，每次 Open 都白白 prepare 一个永不使用的语句。
- **风险**: 维护负担：后续修改 entries 查询语义时容易误改到死语句；每次启动多一次 prepare
- **修复**: 删除 StmtEntry 的 prepare（stmts.go:28-35）、DB 字段（db.go:45）与 Close 清单项（db.go:152），或确认无测试依赖后移除

## domain-03 — MEDIUM

- **位置**: `config/resinfo.go:19`
- **类别**: rfc
- **摘要**: RESINFO exterr 键声称的 EDE 码表与实际可产生码不符：漏报 2,4,5,8,10,11,12,13，虚报 15,17,18,21,30
- **描述**: resinfo.go:19 发布 `exterr=3,6,7,9,15,16,17,18,21,22,23,24,30`，但全库实际产生的 EDE 码（grep 枚举所有 dns.ExtendedError* 与 EDE 构造点）为 2,3,4,5,7,8,9,10,11,12,13,16,22,23,24 + InvalidQueryType：StaleAnswer(4, cache_lookup.go:284)、ForgedAnswer(5, middleware/zone.go:96)、SignatureExpired(8)/DNSKEYMissing(10)/NoZoneKeyBitSet(12)/NSECMissing(13)/RRSIGsMissing(11)/UnsupportedDNSKEYAlgorithm(2)（dnssec 验证器）、UnsupportedDSDigestType(3)、DNSBogus(7)、NetworkError(24, cache_store.go:204)、Blocked(16, cache_store.go:246)、Other(22)、NoReachableAuthority(23)。声称的 15(NotReady)/17(Censored)/18(Filtered)/21(NotAuthoritative)/30(DNSNameTooLong) 无任何代码路径产生，且漏掉了实际会返回的 2/4/5/8/10/11/12/13。RFC 9606 §5.3 exterr 键定义为实现可返回的 EDE 码列表，RFC 9606 §4.2 要求声明与实际能力一致。
- **风险**: 基于 RESINFO 做能力协商的客户端（RFC 9606 用途）得到错误的能力声明，可能依赖解析器实际不会返回的 EDE 码（如 17/18/30）或错过实际会返回的码
- **修复**: 按代码库真实产生的 EDE 码枚举重建 exterr 列表（可用 grep dns.ExtendedError* 校准），并与 dnssec 验证器的 EDECode 输出保持一致

## domain-04 — MEDIUM

- **位置**: `edns/edns.go:42`
- **类别**: rfc
- **摘要**: DAU 向权威服务器通告 ED448(16)，但验证器（miekg v0.6.89 RRSIG.Verify）不支持 ED448，违反 RFC 6975 §4 仅通告可验证算法的要求
- **描述**: dauAlgorithms = {8,10,13,14,15,16}（edns.go:42）随每次上游查询经 &dns.DAU 通告（edns.go:131）。但验证路径 dnssec/crypto.go:119 `rrsig.Verify(dnskey, rrset, &dns.SignOption{})` 走 miekg v0.6.89 dnssec.go:321 的算法 switch——default 分支返回 ErrAlg（除非设置 VerifyFunc，此处未设），全库无 ED448 实现（miekg 中仅 AlgorithmToString 映射与一段注释）。crypto.go:120-125 将 ErrAlg 映射为 ErrUnsupportedAlgorithm。权威若按通告使用 ED448 签名，解析器无法验证。RFC 6975 §4（'The DAU... MUST NOT include algorithms the resolver does not support'）与注释声称的 'resolver can validate' 不符。
- **风险**: 权威使用 ED448 签名时验证失败，链路按不支持算法处理（EDE 2），可能使签名域从 secure 降级或 SERVFAIL；通告与能力不一致属于 RFC 6975 违规
- **修复**: 从 dauAlgorithms 移除 16（ED448），或实现 ED448 验证后再通告；同时核对注释 'resolver can validate' 与实现一致

## domain-05 — LOW

- **位置**: `database/db.go:151`
- **类别**: resource
- **摘要**: Close() 的语句关闭清单遗漏 StmtRulesetDomain（14 条 prepare 语句只显式关闭 13 条）
- **描述**: prepareStatements 共准备 14 条语句，Close() 的显式关闭循环（db.go:151-157）只列了 13 条，StmtRulesetDomain（db.go:59 字段，stmts.go:128 prepare）不在清单中。database/sql 的 DB.Close() 会兜底关闭全部语句，因此无实际泄漏，但与 'New 创建的资源在 Close 中全部释放' 的显式契约不一致；上轮 H 系列修复强调 Close 完备性后仍残留此不一致。
- **风险**: 仅维护性问题：清单与 prepare 列表不同步，后续若换驱动或依赖显式关闭则可能真实泄漏
- **修复**: 在 Close() 循环中补上 db.StmtRulesetDomain

## domain-06 — LOW

- **位置**: `cache/store.go:92`
- **类别**: comment
- **摘要**: AcquireTTLOffsets 文档声称返回 'zeroed slice'，但池化切片复用时不归零
- **描述**: store.go:93-99 实现为 `s := *ttloOffsetsPool.Get().(*[]uint16); if cap(s) < n { return make(...) }; return s[:n]`——直接复用池中上次内容，不执行 clear。当前所有调用点（Get 第 270-272 行全量覆盖 n 个元素、scanTTLOffsets 经 [:0]+append 覆盖）都会覆写全部元素，所以行为安全；但文档与实现不符，未来新增调用点（如只读部分元素）会读到陈旧 TTL offset。
- **风险**: 文档误导未来调用者，若按 'zeroed' 假设做部分覆盖读会产生错误 TTL 调整
- **修复**: 要么在返回前 `clear(s)`（池归还时已由 ReleaseTTLOffsets 外的调用点保证覆写，clear 成本可忽略），要么把注释改为 'caller must overwrite all n elements'

## domain-07 — LOW

- **位置**: `cache/cache.go:140`
- **类别**: perf
- **摘要**: rebuildResponseWire 重新扫描 TTL offset 时直接 make 新切片绕过 TTL-offset 池，且归还旧池化切片
- **描述**: cache.go:140 `offsets := make([]uint16, 0, 8)` 是新堆分配；随后 cache.go:167 把 Get 时从池取的旧 offsets 归还。该函数在每条 hasLatencyData 缓存命中路径（Get→sortAnswerByLatency→rebuildResponseWire）执行，新切片从未进池，TTL-offset 池在该路径上只出不进，池命中率随 latency 数据启用而下降（每次命中一次堆分配）。
- **风险**: 启用延迟数据后缓存命中路径每查询多一次堆分配，削弱 TTL-offset sync.Pool 的优化初衷
- **修复**: 改用 `AcquireTTLOffsets(0)` + append（与 scanTTLOffsets 一致），并在下次 release 时按 cap<=maxTTLOffsets 规则归还

## domain-08 — LOW

- **位置**: `cache/store.go:268`
- **类别**: perf
- **摘要**: Get 返回的池化 TTLOffsets 在命中但未服务路径被丢弃（cache_lookup 过期不可服务、cache_store 错误回退穿透）
- **描述**: Get 在非 latency 路径把池化的 TTLOffsets 挂到 Entry 上，归还职责交给消费者（buildFromPrePacked 的 ReleaseTTLOffsets，server/handler/response.go:67）。但两条路径不归还：server/handler/middleware/cache_lookup.go:145（expired 且 !CanServeExpired → return next.ServeDNS，entry 直接丢弃）与 server/handler/middleware/cache_store.go:182-197 的 buildError 回退分支（entry 过期且不可服务时穿透到 SERVFAIL 构造）。sync.Pool 对象丢失虽不构成内存泄漏（GC 回收），但每次此类查询池都要新建切片，且被释放对象不再复用。
- **风险**: 过期不可服务命中路径（占查询流量一定比例）每次浪费一次池新建，池复用率下降
- **修复**: 在这两条路径显式调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)（并把 cache_lookup.go:145 的丢弃点补上）；或在 Get 内对不可服务结果提前归还（不现实）——推荐前者

## domain-09 — LOW

- **位置**: `edns/padding.go:73`
- **类别**: validation
- **摘要**: addPadding 追加 PADDING 后的第二次 msg.Pack() 失败时静默返回 0，msg.Data 停留在无 padding 的定长包，bridge 将直接服务该旧包
- **描述**: addPadding 流程：第 46 行先 Pack 一次得到真实压缩长度（含 COOKIE/EDE/SUBNET 等选项）；追加 PADDING 后第 73 行再 Pack 写回 padding；失败则 `return 0`——此时 msg.Data 仍是第一次 Pack 的（无 padding）包，且 PADDING 留在 msg.Pseudo。server/bridge.go 以 `len(response.Data)==0` 决定是否 packSafe，Data 非空则跳过重打包直接写出——padding 在隐私敏感路径上静默丢失（返回码 0 被调用方忽略，仅影响日志）。触发条件：单包超 64KB 的 Pack 失败，现实中罕见，但失败处理与 'privacy-sensitive path' 注释的意图不符。
- **风险**: 罕见路径下加密传输的响应 padding 静默缺失，削弱 RFC 8467 防流量分析能力
- **修复**: 第二次 Pack 失败时置 `msg.Data = nil` 并清掉刚追加的 PADDING（避免下游以错误尺寸重新打包），让 bridge 走 packSafe 重打包；或至少记录一条 Debug 日志

