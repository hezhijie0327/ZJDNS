# docs 审计

> agent: `adff4e6b63b133d08`

发现数: 8

## docs-01 — MEDIUM

- **位置**: `CLAUDE.md:306`
- **类别**: docs
- **摘要**: prepared stmts 计数 13 与实际 14 不符（新增 StmtEntryFallback 未同步）
- **描述**: CLAUDE.md Key Types 表声称 "WAL mode, 13 prepared stmts"。database/stmts.go 的 prepareStatements() 实际 Prepare 了 14 条：StmtEntry/StmtEntryExists/StmtEntryFallback/StmtEntryInsert/StmtQueryLog/StmtQueryStats/StmtInsertLatency/StmtIPLatency/StmtLastProbe/StmtRulesetDomain/StmtZoneExact/StmtZoneWildcard/StmtDNSCryptLoad/StmtDNSCryptSave（grep 'db.Stmt[A-Za-z]*, err = db.SQ.Prepare' 计数 = 14）。第一轮 M23/F3 将计数从 8 修复为 13，随后 commit 8bda354（ECS 单轮查询）新增 StmtEntryFallback 使计数漂移为 14，CLAUDE.md 未同步更新——上一轮修复被再次破坏（regression）。
- **风险**: CLAUDE.md 是文档一致性基线，计数漂移会继续积累，且与代码交叉验证时产生误导（该数字曾被作为第一轮审计发现，说明读者依赖它核对代码）。
- **修复**: 将 CLAUDE.md:306 的 "13 prepared stmts" 改为 "14 prepared stmts"。

## docs-05 — MEDIUM

- **位置**: `docs/debug/DEBUG.md:679`
- **类别**: docs
- **摘要**: DEBUG.md 只记录 7 个 CHAOS clear 端点中的 4 个——querylog.clear/ptr.clear/latency.clear 缺失
- **描述**: config/chaos.go:55-63 注册 7 个端点：stats、stats.clear、cache.clear、ptr.clear、latency.clear、querylog.clear、dnscrypt.clear。DEBUG.md:677-681 的 # Stats 段只列出 zjdns.stats、zjdns.stats.clear、zjdns.cache.clear、zjdns.dnscrypt.clear，缺少 zjdns.ptr.clear、zjdns.latency.clear，以及本 delta 新增的 zjdns.querylog.clear（commit bca34cb 新增端点，但 DEBUG.md 的改动只做了英文统一、未补端点）。
- **风险**: querylog.clear 是破坏性端点（清空 query_log 表）且仅回环客户端可调，操作者按文档无法找到清空查询日志的方法；运维排查时误以为端点不存在而改删库文件。
- **修复**: 在 DEBUG.md # Stats 段补充三行 dig 示例：zjdns.ptr.clear、zjdns.latency.clear、zjdns.querylog.clear，并注明 clear 端点仅回环客户端可用（Zone 中间件门控）。

## docs-06 — MEDIUM

- **位置**: `docs/FLOWCHARTS.md:51`
- **类别**: docs
- **摘要**: 中间件管道流程图仍是 9 层旧图——缺 MQTYPE 与 Any 两个新中间件
- **描述**: FLOWCHARTS.md:49-65 的「中间件管道」mermaid 图只画了 Response→CacheStore→Validation→Zone→EDNS→CacheLookup→PTR→DNS64→Resolution 9 层。实际链为 11 层（chain.go:83-155）：MQTYPE（RFC 10029，CacheStore 之后）与 Any（RFC 8482，Zone 之内层）均缺失。方法论 §1.1 维度 18（流程图覆盖）明确要求新增中间件必须同步更新流程图；第一轮 F16 核验时该图为 9 层是准确的，本 delta 新增两个中间件后未更新（regression）。
- **风险**: 流程图是架构速览入口，缺两个中间件导致读者遗漏 RFC 10029 合并与 ANY 最小响应两个功能在管道中的位置。
- **修复**: 在 mermaid 图中 CacheStore 与 Validation 之间插入 MQTYPE 节点，在 Zone 之后（内层）插入 Any 节点，共 11 个节点。

## docs-07 — MEDIUM

- **位置**: `docs/FLOWCHARTS.md:69`
- **类别**: docs
- **摘要**: 缓存查询流程图仍是旧路径——5 候选循环+zstd 解压+Unpack，与 ECS 单轮查询/pre-packed 直发不符
- **描述**: FLOWCHARTS.md:69-95 的「缓存查询流程」图：ECSCAND→逐候选 LOOP→SQLite Lookup→zstd Decompress→Unpack dns.Msg→按延迟排序→TTL 判断。实际代码（cache/store.go:224-261 Get()）：StmtEntryFallback 单轮查询一次绑定 5 个 ECS 候选（不再循环）；命中后 pre-packed wire（格式 0x02）按 TTL 偏移表原地调整直接服务（响应中间件只补 ID/RD 位，不 Unpack）；zstd 仅在 <256B 阈值以上的条目才压缩/解压。图中 Decompress→Unpack→Sort 路径只剩 DO=0 过滤/延迟排序的降级分支使用。
- **风险**: 流程图描述的缓存命中路径比实际慢约 3 个数量级（~0.5ms vs ~20ns），误导性能分析与新增优化方向。
- **修复**: 重画为：单轮 StmtEntryFallback 查询→命中→(阈值判定 zstd 解压)→pre-packed wire TTL 偏移调整→直发；仅 DO=0/DNSSEC 过滤时走 Unpack 分支。

## docs-02 — LOW

- **位置**: `CLAUDE.md:346`
- **类别**: docs
- **摘要**: RFC 镜像计数 "52 total" 已过时——docs/rfc/ 现有 111 个 .txt
- **描述**: CLAUDE.md Key Docs 表声称 "Mirrored RFCs and drafts (52 total)"。git ls-tree 计数：基线 93611d5 时 52 个，本 delta（93611d5..HEAD）新增 rfc10029/rfc9824/rfc9606/rfc9715/rfc8482/rfc6975/rfc9460 等 59 个文件，现为 111 个 .txt。上一轮 F5 修复（50→52）后数字再次过期（regression）。
- **风险**: RFC 存档数量是文档一致性核对点（方法论 §4.2 文档腐烂模式），数字失真后读者无法判断新 RFC 是否已镜像。
- **修复**: 更新 CLAUDE.md:346 为 "111 total"，或改为不写死数字（如 "112 files 见 docs/rfc/README.md"）。

## docs-03 — LOW

- **位置**: `CLAUDE.md:139`
- **类别**: docs
- **摘要**: benchmark 计数 "107 across 21 files" 与所引用基线（103 行）和代码（105 函数/23 文件）均不符
- **描述**: 本 delta 将 CLAUDE.md:139 从 "102 benchmarks across 21 files" 改为 "107 benchmarks across 21 files"，但：docs/benchmark/benchmark-baseline.txt 实测 103 行 '^Benchmark'（101 个唯一名），代码库 grep '^func Benchmark' 得 105 个函数、分布在 23 个文件。按 CLAUDE.md 自己给出的刷新命令（go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort）得到的可复现数字是 103，与 107 不符。上一轮 F6 即指出该计数与基线不匹配，本轮更新数字后仍未对齐（regression）。
- **风险**: 数字不可复现，后续 benchmark 基线对比（>15% 回归判定）引用错误计数产生困惑。
- **修复**: 将数字改为与 docs/benchmark/benchmark-baseline.txt 实际一致（当前 103），或注明生成命令并要求每次刷新基线时同步该行。

## docs-04 — LOW

- **位置**: `server/handler/middleware/chain.go:60`
- **类别**: comment
- **摘要**: AssembleChain 文档注释仍为 10 层旧管道——缺 MQTYPE 且 Any/Zone 顺序错误
- **描述**: chain.go:56-67 的执行顺序注释列出 Response→CacheStore→Validation→Any→Zone→EDNS→CacheLookup→PTR→DNS64→Resolution，实际代码（chain.go:83-155）外层→内层为 Response→CacheStore→MQTYPE→Validation→Zone→Any→EDNS→CacheLookup→PTR→DNS64→Resolution：注释缺 MQTYPE 层，且 Any（line 123 Wrap）与 Zone（line 128 Wrap）顺序颠倒——Zone 在外、Any 在内，注释写成 Any 在前。该注释与 CLAUDE.md 已更新的 11 层列表矛盾。
- **风险**: 维护者在 chain.go 内看到的管道描述与真实执行顺序不一致，后续插入中间件时按旧注释定位出错。
- **修复**: 更新注释为：Response→CacheStore→MQTYPE→Validation→Zone→Any→EDNS→CacheLookup→PTR→DNS64→Resolution（11 层，MQTYPE 在 CacheStore 之后、Zone 在 Any 之前）。

## docs-08 — LOW

- **位置**: `README.md:88`
- **类别**: docs
- **摘要**: README 仍称 "缓存命中 ~0.5ms"，与 pre-packed 直发新路径（~20ns、0 分配）矛盾
- **描述**: README.md:88 缓存与数据库段保留 "zstd 压缩存储，缓存命中 ~0.5ms"——这是旧 Get() 路径（解压+Unpack）的数字。commit 8bda354/f7e7f13 后缓存命中直接服务 pre-packed wire，ARCHITECTURE.md:125 明确改写为 "~20ns at the middleware layer, 0 allocs"。同一功能在 README 与 ARCHITECTURE.md 中描述的性能相差 4 个数量级，README 未随 delta 更新。
- **风险**: README 是用户最先接触的性能宣传面，过时数字低估新缓存路径收益，且与 ARCHITECTURE.md 自相矛盾。
- **修复**: 将 "缓存命中 ~0.5ms" 改为描述直发路径（如 "缓存命中直接服务预打包 wire，免解压/免组装"），或删除具体数字以避免后续漂移。

