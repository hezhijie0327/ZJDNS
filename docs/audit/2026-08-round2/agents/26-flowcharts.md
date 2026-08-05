# flowcharts 审计

> agent: `a63768d973bb65595`

发现数: 8

## flowcharts-01 — MEDIUM

- **位置**: `docs/FLOWCHARTS.md:53`
- **类别**: docs
- **摘要**: 中间件管道流程图缺少本轮新增的 MQTYPE（RFC 10029）中间件和 Any（RFC 8482）中间件，11 层管道画成 9 层
- **描述**: 中间件管道图（L53-61）仍为旧 9 层：Response → CacheStore → Validation → Zone → EDNS → CacheLookup → PTR → DNS64 → Resolution。实际代码（server/handler/middleware/chain.go:68-158）为 11 层：Response → CacheStore → MQTYPE → Validation → Zone → Any → EDNS → CacheLookup → PTR → DNS64 → Resolution。MQTYPE 于本轮新增（commit b2c9824/6e52ac7），Any 于 6e52ac7 新增（git log 确认 any.go 基线 93611d5 不存在）。整体架构图 L9 的 MW 节点同样列出 10 个旧中间件名。FLOWCHARTS.md 在整个 delta（git diff 93611d5..HEAD）中零变更。CLAUDE.md 和 chain.go 代码已是 11 层，三处文档互相矛盾。
- **风险**: 新增中间件是 RFC 10029 核心协议特性，流程图缺失使维护者按旧 9 层模型理解管道，评估中间件短路/执行顺序时产生错误判断；违反审计方法论 §6.3『新增特性/协议/中间件时必须同步更新流程图』
- **修复**: 在中间件管道图 CacheStore 与 Validation 之间插入 MQTYPE 节点（标注 RFC 10029），在 Zone 与 EDNS 之间插入 Any 节点（标注 RFC 8482）；同步更新整体架构图 L9 的中间件列表

## flowcharts-02 — MEDIUM

- **位置**: `docs/FLOWCHARTS.md:30`
- **类别**: docs
- **摘要**: 服务生命周期图 'Build Middleware Chain 9 Layers' 数字过时，实际为 11 层
- **描述**: L30 节点 INITMW[Build Middleware Chain<br/>9 Layers] 沿用了基线（93611d5）的 9 层链（Response/CacheStore/Validation/Zone/EDNS/CacheLookup/PTR/DNS64/Resolution，已由 git show 93611d5:chain.go 确认）。本轮新增 MQTYPE 与 Any 后链为 11 层（chain.go:68-158），图中数字未更新。
- **风险**: 层数数字与代码不符，读者依据错误层数评估链深度与性能开销；属文档腐烂（AUDIT-METHODOLOGY 4.2 文档腐烂模式）
- **修复**: 将 '9 Layers' 改为 '11 Layers'（不含 no-op 终端 stub；若含 stub 为 12 节点，建议注明）

## flowcharts-03 — MEDIUM

- **位置**: `docs/FLOWCHARTS.md:72`
- **类别**: docs
- **摘要**: 缓存查询流程图与本轮 pre-packed 直发/零拷贝路径矛盾：ECS 逐候选循环查询、无条件解压/Unpack 均已过时
- **描述**: 缓存查询流程图（L71-80）描述：ECSCAND → LOOP{next} 逐个候选 SQLite 查询 → 命中后无条件 zstd Decompress → Unpack dns.Msg → Sort by latency。实际新实现（cache/store.go:223-322）：(1) ECS 单轮往返 — StmtEntryFallback 一条 SQL 绑定 5 个 (addr,prefix) 槽位（L234-251），不再是逐候选循环；(2) zstd 仅当 >DefaultCompressionThreshold（256B）时解压，小条目直读（L275-299，commit 5256aec）；(3) 热路径零拷贝 — pre-packed wire 直接 serve，TTL 通过 TTLOffsets 原地改写（handler/response.go buildFromPrePacked），仅当 hasLatencyData 时才 Unpack+重排+rebuildResponseWire（store.go:308-319，commit ba1f78c/f7e7f13）。流程图展示的是旧 Unpack+Pack 路径，与本轮核心 perf 特性（cache-hit direct-wire serve）完全相反。
- **风险**: 流程图描述的缓存命中流程与实际热路径相反（图上有 Unpack，代码热路径跳过 Unpack），误导后续优化与调试方向
- **修复**: 重写缓存查询流程图：单条 SQL 多槽位 ECS 候选查询 → 阈值判断 zstd 解压 → pre-packed 直发（TTL-offset 原地调整）主路径，与 hasLatencyData 时的 Unpack+延迟排序分支

## flowcharts-04 — MEDIUM

- **位置**: `docs/FLOWCHARTS.md:207`
- **类别**: docs
- **摘要**: Poisonguard 两张流程图未反映本轮 RRSIG/NSEC/NSEC3 委派证明豁免（commit 8e51759）
- **描述**: 递归逐跳检测图 L207-208 标注 'Root: Only NS/DS for TLD' / 'TLD: Only NS/DS sub-delegation'；详解图 L329 判定节点为 'rrtype is NS/DS<br/>and name is TLD?'。实际代码（server/defense/poisonguard.go:148-193）本轮新增 delegationOrProof：NS/DS 之外还豁免 RRSIG、NSEC、NSEC3（RFC 4035 §3.1.1 委派证明，真实案例 CNNIC 以 TLD 身份返回子域 RRSIG）。两张图均未画出豁免分支，仍把 RRSIG/NSEC 归入 Poison 判定。
- **风险**: 防御机制的文档与实现不符，安全审计者按旧逻辑评估 poisonguard 判定边界，可能误报本已豁免的合法 DNSSEC 证明记录
- **修复**: 在两处图中将 'NS/DS' 判定扩展为 'NS/DS/RRSIG/NSEC/NSEC3（delegationOrProof）'，并在详解图中标注 RFC 4035 §3.1.1 豁免分支

## flowcharts-05 — MEDIUM

- **位置**: `server/handler/middleware/chain.go:56`
- **类别**: comment
- **摘要**: AssembleChain 文档注释的执行顺序列表漏掉 MQTYPE，且 Any/Zone 顺序与代码相反
- **描述**: chain.go L56-67 注释列出的执行顺序为：Response → CacheStore → Validation → Any → Zone → EDNS → CacheLookup → PTR → DNS64 → Resolution，共 10 项。实际代码（L68-158）为 11 项：Response → CacheStore → MQTYPE → Validation → Zone → Any → EDNS → …。注释既漏了 MQTYPE（L141-145 的 Wrap），又把 Any 放在 Zone 之前 — 与代码 L120-123 的注释『wrapped INSIDE Zone (earlier Wrap call = inner layer)，zone rules 优先』自相矛盾。本轮给注释补了 Any 却漏了 MQTYPE，属修复不完整的文档变更。
- **风险**: 该注释是管道的权威顺序文档，后续开发按注释理解执行顺序会在 Any/Zone 优先级上产生错误代码
- **修复**: 在 CacheStore 之后补 MQTYPE（RFC 10029）行；将 Any 行移到 Zone 之后，注明『INSIDE Zone，zone rules 优先』

## flowcharts-06 — LOW

- **位置**: `docs/FLOWCHARTS.md:240`
- **类别**: docs
- **摘要**: HopGuard 流程图中节点 ID PASS 被重复定义两次且标签不同，mermaid 后定义覆盖前定义导致首条边标签误导
- **描述**: L240 定义 PASS[Accept]，L244 再次定义 PASS[Accept<br/>Learning Phase]（同一节点 ID 两个标签）。mermaid 对重复 ID 以后者标签生效，L240 边 'CAP -->|No| PASS[Accept]' 的目标节点实际渲染为『Accept Learning Phase』——无学习阶段语义的 Accept 分支被错误标注为学习阶段，L242 'VS -->|No| PASS' 同理。
- **风险**: 图形语义歧义：无状态/未武装的接受分支与学习阶段分支被画成同一节点，读者无法区分两条路径
- **修复**: 将 L244 的 PASS 改为独立 ID（如 PASSLEARN[Accept<br/>Learning Phase]），消除重复定义

## flowcharts-07 — LOW

- **位置**: `docs/FLOWCHARTS.md:470`
- **类别**: docs
- **摘要**: 规则集引擎图中 'O-128 Trie Walk' 是 'O(128)' 的笔误
- **描述**: L470 IPQ[IP Lookup<br/>O-128 Trie Walk] 应为 O(128)（CLAUDE.md 中正确写作『binary radix trie O(128)』），笔误从 L462-480 的规则集引擎图中散落至仅此一处。
- **风险**: 仅文档表述瑕疵，无功能影响
- **修复**: 将 'O-128' 改为 'O(128)'

## flowcharts-08 — LOW

- **位置**: `docs/FLOWCHARTS.md:33`
- **类别**: docs
- **摘要**: 本轮新增的 CHAOS querylog.clear 端点、TCP 写入分片（16 shard）无任何流程图覆盖，服务生命周期后台任务列表不完整
- **描述**: 任务要求核对五类新增特性是否入图：MQTYPE（flowcharts-01/02 已覆盖）、CHAOS querylog.clear、pre-packed 直发（flowcharts-03 已覆盖）、TCP 写入分片、ECS 单轮查询（flowcharts-03 已覆盖）。剩余：(1) CHAOS .clear 端点（config/chaos.go:61 新增 zjdns.querylog.clear，另有 cache/stats/ptr/latency/dnscrypt 五个既有端点）在 FLOWCHARTS.md 中无任何一节；(2) TCP 写序列化分片（server/bridge.go tcpWriteShard，16 shard FNV-1a）无图，服务生命周期 L33 仅提『TCP WriteMu Sweep』未提分片；(3) L33 BG 节点列了 'ECS Refresh · Cookie Rotate · TCP WriteMu Sweep · Stats'，实际后台任务（server/tasks.go:16-166）还有 prefetch cooldown cleanup 与 query journal cleanup（startQueryJournalCleanup），后者未入图。
- **风险**: 新增可破坏性端点与热路径写分片机制缺少文档锚点，运维排查与协议审计时无法从流程图定位
- **修复**: 为 CHAOS .clear 端点补充一节流程图（loopback 门控 + 各表清理）；在 BG 节点补充 query journal cleanup；在连接池图中补充按连接 writeMu 串行化写入口

