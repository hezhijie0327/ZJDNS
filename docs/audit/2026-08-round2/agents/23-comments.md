# comments 审计

> agent: `aa17837fbec33aa72`

发现数: 16

## comment-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get() 无条件按 0x02 预打包格式解析 msg_wire，从不校验格式标记字节 —— 旧版本（≤v3.11.11）缓存行是纯 zstd blob，命中即切片越界 panic
- **描述**: Set() 写库时在 msgWire 前写入 cacheFormatPrePacked(0x02) 标记（store.go:532），但 Get() 读取时从不检查 msgWire[0] == 0x02（grep 确认 cacheFormatPrePacked 全库只有写没有读）。Get 直接 `numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))`（store.go:267）然后循环 `offsets[i] = binary.BigEndian.Uint16(msgWire[3+i*2:])`（store.go:271）。旧版本（93611d5 基线 = v3.11.11）Set 存的是 `zdnsutil.Compress(msg.Data)` 纯 zstd 帧（基线 store.go:340），其固定魔数 0x28 B5 2F FD 使 msgWire[1:3] = 0xB52F = 46383 → AcquireTTLOffsets(46383) 分配 370KB → wireStart=92769 → 循环在 i≈(len-3)/2 处 msgWire[3+i*2:] 越界 panic。store.go:109-112 注释声称 isZstdCompressed 检查'preserving backward compatibility with entries written before threshold compression was introduced'——但该检查作用在 offsets 表之后的 wire 切片上，legacy 行在到达该检查前就已 panic，向后兼容声明是假的。store.go:265 注释 'Pre-packed format (0x02)' 也掩盖了代码无格式分派的事实。升级到 3.11.12+ 后，cache.db 中任何旧行被命中即 panic（bridge.go:59/TCP goroutine 的 HandlePanic 恢复，查询静默丢失），直到旧行被同 qname 新写入替换或过期（最长 7 天 TTL + stale 窗口）。
- **风险**: 升级后所有旧缓存条目命中即 panic + 查询丢失 + 每次 370KB 堆分配，缓存功能实际瘫痪至旧行过期；无任何测试覆盖 legacy 格式读取
- **修复**: Get() 在解析前检查 msgWire[0]：==0x02 走预打包路径；否则按 legacy 格式处理（整体 zstd 解压，无 TTL offsets，buildFromPrePacked 需兼容 offsets==nil 或直接走 Unpack 路径）。补一个写 legacy 格式 blob 再 Get 的测试

## comment-02 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: H1 修复不完整（regression）：每 TCP 请求 refs 净增 +1（两处 Add(1) 只对应一处 Add(-1)），refs 永不归零，sweep 再次成为死代码，tcpWriteShards 无界增长
- **描述**: 当前代码：line 98 `entry.refs.Add(1)`（锁内）+ line 110 `entry.refs.Add(1)`（capacityOnce.Do 之后）+ goroutine line 155 `defer entry.refs.Add(-1)`（SERVFAIL 路径 line 115 同）。正常请求净增 +1，SERVFAIL 路径净增 +1。commit 9f6001c（H1 修复，提交信息声称 'refs now reach 0'）把 in-flight ref 移到锁内后，漏删了原先的第二个 Add(1) 块——line 106-109 的注释 'In-flight refcount: incremented synchronously...' 是 line 94-97 注释的逐字重复（连注释都复制了），且没有任何路径对第二次 Add 做对应释放。sweepTCPWriteMu（tasks.go:137）`if entry.refs.Load() != 0 { continue }` 因此对任何服务过请求的 entry 永远跳过，per-connection 的 tcpWriteShards entries（含 writeMu/capacity 两个 channel + mutex）随连接数无界累积，H1 原始缺陷完整复现。注意基线 93611d5 就已存在双 Add（非本次 delta 引入），但它是 H1'修复'当时就漏掉的残留，属修复不完整。
- **风险**: 进程生命周期内每出现过的 TCP 连接（ip:port）在 map 中永久累积一条 entry，内存无界增长；sweep 彻底失效
- **修复**: 删除 line 110 的重复 Add(1)（及 line 106-109 重复注释），仅保留锁内 line 98 的 Add(1)；补一个断言测试：handleDNSRequest 完成后 entry.refs.Load() == 0（对照 tasks_test.go:37-41 的既有模式）

## comment-03 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:21`
- **类别**: comment
- **摘要**: MQTYPE 头注释声称 'runs after CacheStore (the primary response exists)'，但 chain.go 实际把 MQTYPE 包在 CacheStore 内层——递归模式缓存 miss 时 qctx.Res 为 nil，RFC 10029 合并被静默跳过
- **描述**: chain.go:141-152 的 Wrap 顺序：CacheStore.Wrap 包在 MQTYPE.Wrap 外层，因此执行时 CacheStore 的 next.ServeDNS 调用先进入 MQTYPE，而 CacheStore 的 buildSuccess（唯一为 miss 路径构建 qctx.Res 的代码）在 MQTYPE 返回后才执行。Resolution middleware 只设置 qctx.ResolutionResult（resolution.go:63-64），从不设置 qctx.Res。于是递归模式 + 缓存 miss：MQTYPE.Wrap 在 next 返回后 `if qctx.Res == nil { return err }`（mqtype.go:78-80）直接返回——不合并、不追加 MQTYPE-Response 选项。测试 TestMQTYPE_Merge_CacheHit（mqtype_test.go:157）的 next stub 手工设置 qctx.Res，模拟的正是'主响应已存在'状态，miss 路径完全未被覆盖。头注释（mqtype.go:21-24）描述的执行顺序与 chain.go 实际顺序相反：'after CacheStore'应为'在 CacheStore 内、其 post-processing 之前'。
- **风险**: RFC 10029 本地合并只在缓存命中/zone 规则/ANY 等内层已置 Res 的路径生效，递归模式对全新域名（首次查询）静默返回无 MQTYPE-Response 的普通响应，客户端无法得知服务器是否支持 MQTYPE——功能与文档双重不符合
- **修复**: 将 MQTYPE 的 Wrap 移到 CacheStore 外层（chain.go 中先 CacheStore 后 MQTYPE，使 MQTYPE 在 buildSuccess 之后执行），或 Merge 改为基于 qctx.ResolutionResult 在 CacheStore 之后运行；修正头注释的执行顺序描述；补一条递归 miss 全链路的集成测试

## comment-04 — MEDIUM

- **位置**: `edns/edns.go:35`
- **类别**: comment
- **摘要**: NewHandler 的 godoc 与新增的 RFC 6975 算法列表 var 块注释粘连成同一注释块，NewHandler（line 51）失去导出函数文档
- **描述**: 6e52ac7 在 '// NewHandler creates a Handler with the given default ECS configuration.'（line 35）与 func NewHandler（line 51）之间插入 var 块，但把 var 块的注释直接接在 NewHandler 的 godoc 后面、无空行分隔（line 36-37），Go 文档规则下整块注释（'NewHandler creates...' + 'RFC 6975 algorithm lists...'）成为 var 块的文档，而 NewHandler 变成无 godoc 的导出构造函数。同一注释块描述两个不相关主题，读代码者会误以为 NewHandler 返回前做了算法列表初始化（实际算法列表是包级静态数据）。
- **风险**: 导出构造函数失去 API 文档；注释归属错误误导读者；'static slices' 与函数语义混淆
- **修复**: 把 '// NewHandler creates...' 移到 func NewHandler 正上方；'RFC 6975 algorithm lists...' 保留在 var 块上方并与其间补空行分隔

## comment-05 — LOW

- **位置**: `server/handler/middleware/mqtype.go:131`
- **类别**: validation
- **摘要**: MQTYPE merge 用原始 question 名调 store.Get，违反 store.go:222 新增契约 'caller must pass a canonical qname'，混合大小写查询缓存恒 miss
- **描述**: mqtype.go:131 `qname := qd.Header().Name` 直接取自客户端请求（wire 原样，可含大写）；mqtype.go:204 将其传入 `m.store.Get(qname, ...)`。delta 把 Get 内部的自规范化（基线 store.go 的 `qname = dnsutil.Canonical(qname)`）删除并改为调用方契约（store.go:222 注释），mqtype.go 是新增代码但未遵守该契约。Set 路径（mqtype.go:188）因 Set 内部仍 canonicalize（store.go:450）不受影响，故混合大小写时：Get miss → DoJoin 重新解析（结果正确但绕缓存），且 Set 存的是小写 key → 该客户端后续同大小写查询永远 miss，缓存失效于特定客户端。
- **风险**: 混合大小写客户端（合法 DNS 行为）的 MQTYPE 附加类型查询永远走上游/递归，热缓存形同虚设；契约注释与调用方不一致
- **修复**: mqtype.go:131 改为 `qname := dnsutil.Canonical(qd.Header().Name)`（或复用 qctx.Qname）

## comment-06 — LOW

- **位置**: `server/resolver/ns_addresses.go:239`
- **类别**: validation
- **摘要**: lookupCachedRRs 用 Fqdn(NS 记录名)（原样大小写）调 store.Get，违反新契约；NS 名带大写时缓存 miss（基线 Get 内部 canonicalize 时的行为回归）
- **描述**: nameserver.go:290 `nsName := dnsutil.Fqdn(nsRecord.Ns)` 只补尾部点、不转小写；ns_addresses.go:239 `store.Get(name, qtype, dns.ClassINET, nil, false)` 直接传入。而写入侧 nameserver.go:333 的 Set 内部 canonicalize（store.go:450），键为小写。delta 删除了 Get 的内部规范化（基线行为）并只在 store.go:222 注释声明契约，lookupCachedRRs 未同步更新——任何混合大小写 NS 名（权威服务器以非小写发布 NS 记录时）的 A/AAAA 缓存查找恒 miss，每次递归都重新解析 NS 地址。
- **风险**: 混合大小写 NS 名导致 NS 地址缓存失效，增加递归延迟与上游负载
- **修复**: lookupCachedRRs 入口对 name 做 dnsutil.Canonical(name)（或调用方 resolveNSAddressesConcurrent/recursive_ns.go:46 传入前规范化）

## comment-07 — LOW

- **位置**: `cache/store.go:92`
- **类别**: comment
- **摘要**: AcquireTTLOffsets 注释声称 'returns a zeroed slice'，但池内元素不清零，返回的可能是上次使用的残留数据
- **描述**: ReleaseTTLOffsets（store.go:103-107）只 Put 不 clear 元素；AcquireTTLOffsets 直接 `s := *ttloOffsetsPool.Get().(*[]uint16); return s[:n]`。当前两个调用点（Get 的 offsets 循环全覆盖、scanTTLOffsets 全 append）恰好不会读到残留值，'zeroed' 是事实错误但暂无危害——若未来调用方按注释假设零值（如稀疏填充），会读到陈旧偏移导致 TTL 错改。
- **风险**: 文档承诺与实现不符，未来新增调用方按'零值'语义使用即引入 TTL 错误；属方法论 §4.2 注释腐烂类的定时炸弹
- **修复**: 注释改为 'returns a slice of length n from the pool; elements are unspecified（callers must fill all n entries）'，或 ReleaseTTLOffsets 归还前 clear(s)

## comment-08 — LOW

- **位置**: `cache/store.go:121`
- **类别**: comment
- **摘要**: scanTTLOffsets 注释引用不存在的符号 'releaseTTLOffsets'（实际函数名是导出的 ReleaseTTLOffsets）
- **描述**: store.go:121 'The returned slice is pool-owned — release with releaseTTLOffsets when done.' 引用的函数名不存在（grep 确认全库无 releaseTTLOffsets，实际调用点 store.go:541 用的是 ReleaseTTLOffsets）。注释引用错误符号名，违反方法论 §6.1.15 '注释引用符号名而非行号'——名字写错与写行号同样会在重构后失效。
- **风险**: 维护者按注释搜索 releaseTTLOffsets 找不到目标；函数重命名后注释将完全失去定位作用
- **修复**: 改为 'release with ReleaseTTLOffsets when done'

## comment-09 — LOW

- **位置**: `cache/cache.go:83`
- **类别**: comment
- **摘要**: Unpack 的 godoc 注释重复出现两份：line 83-86 是悬空孤儿副本（其正下方是 type LookupResult），line 99-102 才是函数上的有效文档
- **描述**: line 83-86 '// Unpack populates Answer, Authority and Additional... skips Unpack entirely.' 与 line 99-102 内容几乎逐字重复。line 83-86 与下方 type LookupResult（line 88）之间有空行，不构成其文档，属于 0x02 预打包改造时文档搬迁的残留——两份文档漂移后（line 99-102 提到 buildFromPrePacked，line 83-86 未提）读者无法判断哪份有效。
- **风险**: 重复文档在后续修改时只改一份，产生互相矛盾的 API 描述
- **修复**: 删除 line 83-86 的孤儿副本，仅保留 line 99-102

## comment-10 — LOW

- **位置**: `cache/cache.go:66`
- **类别**: comment
- **摘要**: Entry 文档声称 ResponseWire 非 nil 时 'Answer/Authority/Additional are nil in this case'，但 hasLatencyData 路径下 Get 会 Unpack 填充三者且 ResponseWire 同时非 nil
- **描述**: store.go:313-319：`if s.hasLatencyData.Load() { _ = entry.Unpack(); s.sortAnswerByLatency(entry); ... entry.rebuildResponseWire() }` —— 该路径返回的 entry 同时持有 ResponseWire 和已解析的 Answer/Authority/Additional。cache.go:64-66 的文档 'When ResponseWire is non-nil ... Answer/Authority/Additional are nil in this case' 与这一实际状态矛盾，调用方若按文档假设'非 nil 即未解析'会得到错误结论（如误判 entry 未被 Unpack）。
- **风险**: 文档契约与实际行为不符，误导调用方（当前调用方恰好兼容，属脆弱假设）
- **修复**: 文档改为 'Answer/Authority/Additional may be populated（latency-sorted path）；callers must not assume nil 或非 nil'

## comment-11 — LOW

- **位置**: `server/handler/middleware/response.go:48`
- **类别**: comment
- **摘要**: 注释声称直发路径 'only the client's message ID must be patched in (bytes 0..1)'，但代码同时改写 byte 2 的 RD 位
- **描述**: response.go:47-51 注释 'serve the wire directly — only the client's message ID must be patched in (bytes 0..1...)'，紧随其后的代码（line 61-67）还按请求 RD 位改写 Data[2]（`qctx.Res.Data[2] |= 0x01 / &^= 0x01`）。'only' 与实际两处改写不符。
- **风险**: 读者误以为直发路径只处理 ID，后续在字节 2 上再补逻辑时产生重复改写
- **修复**: 注释改为 'the client's message ID（bytes 0..1）and RD flag（byte 2）must be patched in'

## comment-12 — LOW

- **位置**: `server/resolver/resolver.go:199`
- **类别**: comment
- **摘要**: ConfigureServers 规范化注释的理由已过时：声称 'the client lowercases it per query on the upstream hot path'，但该 per-query ToLower 在 f7e7f13 已删除
- **描述**: resolver.go:199-201 注释 'the client lowercases it per query on the upstream hot path (strings.ToLower scan per request)' 描述的是 f7e7f13 之前的状态；当前 upstream/client.go:152 的注释明确写着 'the per-query ToLower scan is gone from the upstream hot path'（协议直接取自 server.Protocol）。两处注释互相矛盾：resolver.go 声称的理由已不存在，实际动机（客户端不再小写、注册时一次性规范化是唯一兜底）被注释弱化为 'a no-op in practice'。
- **风险**: 注释误导后续优化者：若有人按注释'反正每次查询还会小写'而删掉 ConfigureServers 的规范化，手写配置的协议字符串将静默失效
- **修复**: 注释改为 'the client no longer lowercases per query (see client.go); registration-time normalization is the only guard for hand-built configs'

## comment-13 — LOW

- **位置**: `server/handler/middleware/edns.go:28`
- **类别**: comment
- **摘要**: EDNS middleware 注释丢失首句，残留孤立的 '// (MsgOptionUnpackQuestion) for routing.' 续句
- **描述**: 6e52ac7 修改时删除了原注释首句 'The miekg/dns server only unpacks the question section by default'，但保留的续句以括号 '（MsgOptionUnpackQuestion）for routing.' 开头（line 28），读者无法得知 MsgOptionUnpackQuestion 指代什么、for routing 是哪个上下文——注释的主体被删后留下无主语的残句。
- **风险**: 无法理解的注释比没有注释更糟；后续维护者需翻 git 历史才能复原语义
- **修复**: 恢复首句或改写为完整句子，如 'The miekg/dns listener unpacks only the question section (MsgOptionUnpackQuestion) for routing; when Pseudo already carries the OPT（full unpack done），skip the redundant second parse...'

## comment-14 — LOW

- **位置**: `server/defense/poisonguard.go:45`
- **类别**: comment
- **摘要**: VerdictUncertain 注释是无限期空头支票：'Retained as a placeholder for future multi-vantage-point analysis'，无截止日期，且该值零调用者
- **描述**: poisonguard.go:44-45 注释 'No caller checks VerdictUncertain (VerdictPoisoned is the only actionable signal). Retained as a placeholder for future multi-vantage-point analysis that could resolve this ambiguity.' 属方法论 §6.2-16 的 '临时方案' 注释：grep 确认 VerdictUncertain 全库无任何调用者（含测试），'future analysis' 无版本/日期承诺，是典型的虚假安全感占位符。
- **风险**: 占位注释让未来维护者以为该状态有既定用途而不清理，状态机保留一条永不走到的分支（classify 返回它时所有路径当作 Poisoned 处理，语义上已被替代）
- **修复**: 删除该注释并说明 VerdictUncertain 归类为 Poisoned 的语义，或保留状态但把注释改为明确决策记录（为何保留、何时触发），并加截止日期

## comment-15 — LOW

- **位置**: `CLAUDE.md:139`
- **类别**: docs
- **摘要**: CLAUDE.md 声称 '107 benchmarks across 21 files'，实际 105 个 benchmark 函数分布在 23 个文件，baseline 文件只有 103 条
- **描述**: delta 把计数从 102 改为 107，但实际 `grep -rh '^func Benchmark' --include='*_test.go'` 得 105 个、23 个文件；docs/benchmark/benchmark-baseline.txt 仅 103 行（新加的 BenchmarkServerProcessQuery 等未刷入基线）。文档数字与代码和基线文件双重不符（上一轮 M25 刚修正过同类问题，本轮 delta 又引入漂移）。
- **风险**: 文档数字失去可信度；基线文件未刷新导致后续 benchmark 回归对比缺基准
- **修复**: 将 CLAUDE.md 改为实际数字（105 benchmarks across 23 files），并重新生成 docs/benchmark/benchmark-baseline.txt

## comment-16 — LOW

- **位置**: `CLAUDE.md:333`
- **类别**: docs
- **摘要**: CLAUDE.md '24 canonical prefixes' 列表缺 delta 新增的 RESPONSE 与 ANY 前缀，实际代码前缀 26 个
- **描述**: delta 新增两处日志前缀：middleware/any.go:44 'ANY: serving RFC 8482 minimal response...' 与 middleware/response.go:74 'RESPONSE: unpack pre-packed response...'，均未列入 CLAUDE.md:333 的 24 前缀清单（TLS/CACHE/DB/UPSTREAM/SERVER/EDNS/RECURSION/SECURITY/TCPPOOL/LATENCY/CONFIG/ZONE/PLAIN/PPROF/QUERY/RESULT/SIGNAL/PTR/PANIC/DNSCRYPT/TLCP/RULESET/DNS64/MQTYPE）。新增中间件引入了不属于清单的日志前缀，破坏 '24 canonical' 声明（实际 26）。
- **风险**: log_level 组件过滤（'level:comp1,comp2'）文档与实际前缀不一致，用户无法按文档配置过滤 ANY/RESPONSE 组件日志
- **修复**: 在 CLAUDE.md 前缀清单中补充 ANY、RESPONSE 并更新计数（或按既有映射惯例把 RESPONSE 并入 SERVER 等已有前缀并修正代码）

