# rfc 审计

> agent: `a992072927acf64d8`

发现数: 7

## rfc-01 — HIGH

- **位置**: `server/handler/middleware/mqtype.go:180`
- **类别**: rfc
- **摘要**: 缓存命中（pre-packed Data）时 MQTYPE 合并的附加 RR 被 Response 中间件的 Unpack 覆盖丢弃，但 MQTYPE-Response 仍列出已完成类型
- **描述**: merge()（mqtype.go:128）假定 qctx.Res 的 Answer/Ns/Extra 已填充，但缓存命中路径 buildFromPrePacked（server/handler/response.go:45-80）只设置 msg.Data=预打包 wire，三个 section 为空。merge 把附加类型 RR 追加进 msg.Answer/Ns/Extra（180-182 行）并追加 MQRESPONSE{completed}（195 行）。外层 Response 中间件（middleware/response.go:46-87）因请求含 EDNS 选项（MQQUERY 留在 Req.Pseudo，ednsStateFor 的 shouldAddEDNS 含 len(Req.Pseudo)>0）走 Unpack 路径：dns.Msg.Unpack() 用 wire 内容整体覆盖 Answer/Ns/Extra（miekg/dns v0.6.89 msg.go:399-412 直接赋值），合并数据被静默丢弃；缓存 wire 不含 OPT（store.go:453 cloneRRsNoOPT 已剥离，Unpack 不重置 Pseudo），故 MQRESPONSE 保留。客户端最终收到列出 completed QTx 的 MQTYPE-Response 但消息中无对应 RR——违反 RFC 10029 §3.4 "If all RRs for a single QTx combination fit into the message, then the server MUST include the respective QTx in the MQTYPE-Response option's list"（列表语义是 RR 已完整包含）。同根因第二缺陷：budget（145 行）用 msg.Len() 计算，而 miekg 的 Len() 不统计 m.Data 中的主响应大小（msg.go:609-620 只累加 section），缓存命中时预算虚高约一个主响应大小。mqtype_test.go TestMQTYPE_Merge_CacheHit 用 fake next 直接填充 Answer，未覆盖 pre-packed Data 路径。
- **风险**: 递归模式（无上游配置，默认部署形态）下热缓存命中是最常见路径：MQTYPE 客户端收到"类型已完整处理"信号但数据缺失，客户端按 RFC 10029 §3.5 信任该列表得到错误解析结果；附加类型的递归解析工作也白费。TCP/UDP 两传输均受影响。
- **修复**: merge() 入口检测 qctx.Res.Data != nil：先 msg.Unpack() 再置 msg.Data=nil 后再做预算与合并（响应中间件的 Data 分支即失效，最终重新 Pack）；预算计算放在 unpack 之后；并补充"缓存命中 + pre-packed 主响应 + MQTYPE"的端到端测试（经 AssembleChain 而非 fake next）。

## rfc-02 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:145`
- **类别**: rfc
- **摘要**: 合并预算固定用 DefaultMaxUDPResponseSize(1400) 而非客户端通告 UDPSize，合并后响应可能被 bridge.go 截断（TC=1），违反 RFC 10029 §3.4
- **描述**: budget = config.DefaultMaxUDPResponseSize - msg.Len() - 64（145 行）与客户端 qctx.Req.UDPSize 无关。bridge.go:249 按 min(max(req.UDPSize,512),1400) 截断：客户端通告 1232（Flag Day 常见值）时，合并响应落在 1233-1336 字节区间会被 truncateWire 置 TC=1 并清空 RR section，而 OPT（含 MQRESPONSE 完成列表）被保留。RFC 10029 §3.4 明确："The handling of an MQTYPE-Query option MUST NOT itself trigger a truncated response"，且"If response size limits do not allow all of the data ... the server MUST NOT include the respective QTx in the MQTYPE-Response option's list"——当前实现把截断责任推给 bridge，导致 TC 由 MQTYPE 合并本身触发且完成列表与实际内容不符。
- **风险**: UDP 客户端收到 TC=1 + 声称完成的 MQTYPE-Response，被迫额外 TCP 重试，且可短暂误判 NODATA；违反 RFC 10029 规范条款（数据最终在 TCP 重试后正确，故非 HIGH）。
- **修复**: 预算上限取 min(qctx.Req.UDPSize, config.DefaultMaxUDPResponseSize)（低于 512 按 512），并保证合并后总长（含主响应实际大小）不超限；超限时从 completed 列表剔除该 QTx 而不是依赖 bridge 截断。

## rfc-03 — MEDIUM

- **位置**: `config/resinfo.go:36`
- **类别**: rfc
- **摘要**: RFC 9606 §3 要求 RESINFO 响应 AA=1，但 zone 规则合成响应经 BuildResponseMsg 固定 Authoritative=false，合规客户端必丢弃
- **描述**: addResolverInfoRecords（resinfo.go:36-66）把 RESINFO 记录注入 zone 规则，命中后由 Zone 中间件（middleware/zone.go:105）以 handler.BuildResponseMsg 合成响应，server/handler/response.go:29 固定 msg.Authoritative=false。RFC 9606 §3（docs/rfc/rfc9606.txt:158-161）："The DNS client MUST discard the response if the AA flag in the response is set to 0"。全库 grep Authoritative 赋值仅 response.go（false）与 dnscrypt/server.go（true），无任何路径为 zone 规则应答（RESINFO/DDR SVCB/CHAOS）设置 AA=1。
- **风险**: 符合 RFC 9606 的客户端（DDR/RESINFO 生态，如按规范丢弃 AA=0 响应）将静默丢弃 resolver.arpa 的 RESINFO 应答，本轮新增功能实际不可用。
- **修复**: Zone 中间件对 resolver.arpa/DDR 域名的本地权威应答（至少 RESINFO 类型）设置 msg.Authoritative=true；或在 resinfo 注入的规则上标记"本地权威"由 Zone 中间件识别。

## rfc-04 — MEDIUM

- **位置**: `config/resinfo.go:19`
- **类别**: rfc
- **摘要**: exterr 广告列表与实际可返回 EDE 码不符：漏列 1,2,4,8,10,11,12，多列 16,17,18,21,24，与注释"matching the codes used"自相矛盾
- **描述**: resinfo.go:19 广告 exterr=3,6,7,9,15,16,17,18,21,22,23,24,30。全库生产代码实际发出的 EDE 码（grep dns.ExtendedError* 计数）：0,1,2,3,4,6,7,8,9,10,11,12,15,22,23,30（如 RRSIGsMissing(10)×6、NoZoneKeyBitSet(11)、NSECMissing(12)、ForgedAnswer(4)、SignatureNotYetValid(8)、UnsupportedDNSKEYAlgorithm(1)、UnsupportedDSDigestType(2) 均来自 DNSSEC 验证器与中间件，全部未广告；16/17/18/21/24 仅在理论上经上游透传可能返回）。RFC 9606 §5 明确：客户端收到未列出的 EDE 码时可判定"resolver information is inaccurate and discard it"。
- **风险**: RESINFO 的 exterr 属性对客户端选择解析器有误导性（广告 Censored/Filtered/Prohibited 等码实际从不返回），且常见验证器错误码未广告会触发客户端弃用整个信息，损害新功能的可用性与准确性。
- **修复**: 依据实际发出集合重新生成 exterr（与 dnssec 验证器 EDE 表、middleware 各 EDE 点、上游透传能力对齐），并同步修正注释。

## rfc-05 — LOW

- **位置**: `server/handler/middleware/mqtype.go:35`
- **类别**: rfc
- **摘要**: mqtypeMetaTypes 只覆盖已分配 Meta/QTYPE（128,41,249-255,65535），未分配区间 129-248 的 QTx 与主类型未被 FORMERR
- **描述**: RFC 6895 §3.1（docs/rfc/rfc6895.txt:415-418）把 128-255 整个区间保留给 Q 和 Meta-TYPE（"Remaining RRTYPEs in this range are assigned for Q and Meta-TYPEs"）；RFC 10029 §3.1 要求 QTx 必须是 data RRTYPE，§3.3 要求 invalid QTx（如 Meta RRTYPE）返回 FORMERR。当前 mqtypeMetaTypes 仅列 ANY/AXFR/IXFR/MAILA/MAILB/OPT/TSIG/TKEY/NXNAME/Reserved，129-248 的未分配码被当作普通未知类型接受并进入递归/上游解析（RFC 3597 路径）。
- **风险**: 轻微规范偏离：非法 MQTYPE 列表被接受并产生无意义的上游查询（无安全影响，仅为协议边界合规）。
- **修复**: validate() 中对 qtype ∈ [128,255]（除已明确拒绝项）或维护完整区间判断直接 FORMERR。

## rfc-06 — LOW

- **位置**: `server/handler/middleware/cache_lookup.go:193`
- **类别**: comment
- **摘要**: 注释 "stale-answer EDE (RFC 8914 code 16)" 编号错误：Stale Answer 是 EDE 3，16 是 Censored
- **描述**: serveExpiredWithRefresh 中清除陈旧应答 EDE 的注释引用 "RFC 8914 code 16"；RFC 8914 §4.4 定义 EDE 3 = Stale Answer（docs/rfc/rfc8914.txt:260），§4.17 定义 16 = Censored（rfc8914.txt:333）。代码实际使用 dns.ExtendedErrorStaleAnswer（cache_lookup.go:284，值为 3），仅注释编号错（该注释由上一轮修复提交 93611d5 引入，非本轮 delta）。
- **风险**: 误导维护者按错误编号核对 EDE 码表，后续可能误用 Censored(16)。
- **修复**: 注释改为 "RFC 8914 code 3"。

## rfc-07 — LOW

- **位置**: `config/resinfo.go:10`
- **类别**: docs
- **摘要**: resinfo.go 引用 RFC 6763 §6.3/§6.4 作为 RESINFO TXT key/value 编码依据，但 docs/rfc/ 无 rfc6763.txt 存档
- **描述**: 本轮新增 RESINFO 实现（config/resinfo.go:10,13）的编码格式依赖 RFC 6763（DNS-SD §6.3 字符串格式、§6.4 键规则），但 docs/rfc/ 目录 113 个文件（111 个 txt + GUIDELINE.md + README.md）与 GUIDELINE.md 的 108 条目 + 3 draft 统计均不含 RFC 6763（ls 仅见 rfc6761.txt）。本轮核心 RFC（10029/9824/9606/9715/8482/6975 + draft-dnsop-deleg）均已存档 ✓，此为支持性引用缺口。
- **风险**: 开发者无法就地核对 RESINFO 编码规范（违反"实现前先存档对应 RFC"纪律），GUIDELINE 统计与目录内容一致性受影响。
- **修复**: 将 rfc6763.txt 加入 docs/rfc/，并在 GUIDELINE.md 增加条目（标注 ⚪ 参考/格式引用）。

