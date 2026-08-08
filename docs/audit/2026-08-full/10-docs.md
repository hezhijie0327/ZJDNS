# 10-docs.md — 文档一致性交叉审计

审计维度：文档质量 / 注释准确性 / 流程图覆盖（AUDIT-METHODOLOGY §1.1、§6.3）
日期：2026-08-08　范围：全仓库 .md + config.example.json ↔ 代码交叉验证
方法：文档中每个类型/函数/字段/CLI flag/日志串逐一 grep 代码验证；全部发现均以 grep 实测为准，无推测项。未修改任何文件。

## Findings

### MEDIUM

- [MEDIUM/docs] docs/benchmark/BENCHMARK.md:40-45 — dnsperf 配置的 `"zone": { "rules": [...] }` 对象格式已失效：`config.Zone` 是 `[]ZoneRule`（config/config.go:10），记录字段为 `name`/`answer`/`rcode`，不存在 `rules`/`domain`/`type`(规则级)/`ttl`(规则级) 键 | risk: 照文档执行 zone 规则不加载（或直接 parse 失败），dnsperf 基准不可复现 | fix: 改为 `"zone": [{ "name": "www.baidu.com", "answer": [{ "type": 1, "ttl": 3600, "content": "1.2.3.4" }] }]`（参照 docs/benchmark/LOADTEST.md:59-61 的合法格式）
- [MEDIUM/docs] CLAUDE.md:263-279 — Query Pipeline 中间件顺序过期：文档为 Response→CacheStore→MQTYPE→Validation→Zone→Any→EDNS→CacheLookup→PTR→DNS64→Resolution；实际链（server/handler/middleware/chain.go:69-166，执行序最外→最内）为 Response→EDNS→MQTYPE→CacheStore→Validation→Zone→Any→CacheLookup→PTR→DNS64→Resolution。EDNS 实为第 2 层（文档第 7 层）、CacheStore 实为第 4 层（文档第 2 层）| risk: 开发者按文档调试 EDNS/缓存交互时序会定位错层；链序重排后文档未同步 | fix: 按 chain.go Wrap 顺序改写列表
- [MEDIUM/docs] CLAUDE.md:226,314 — `AsyncStatsWriter` 类型已不存在（全库 grep 0 命中）：异步写已重构为 `cache.BatchWriter[T]`（cache/batch_writer.go:24,43）+ `SQLiteCache.newCacheBatchWriter`/`newStatsBatchWriter`（cache/async_cache.go:72, cache/async_writer.go:14）| risk: Key Types 表引用已删除类型 | fix: 表项与项目结构树改为 `BatchWriter`（描述：通道+后台事务批量写，100ms/64 条，best-effort drop）
- [MEDIUM/docs] docs/debug/DEBUG.md:217 + docs/ARCHITECTURE.md:279 — `resolver_info` 配置键不存在（全库仅这 2 处文档出现）；RESINFO 现已随 DDR 自动启用：`shouldEnableDDR(cfg)` → `addResolverInfoRecords(cfg)`（config/load.go:49-51，config/resinfo.go:49）| risk: 用户照文档加 `"resolver_info": true` 静默无效 | fix: 两处改为"DDR 启用时随 DDR 发布（config/load.go:49）"
- [MEDIUM/docs] README.md:89 — "九表设计"过期：schema.go 实际 10 张表（version/query_stats/query_log/entries/ptr_map/ip_latency/delegations/ruleset_entries/zone_entries/dnscrypt_state）；ARCHITECTURE.md:7 "ten SQLite tables" 正确 | risk: 表数引述错误 | fix: 改"十表设计"
- [MEDIUM/docs] docs/FLOWCHARTS.md:30 — 服务生命周期图 "Build Middleware Chain 9 Layers" 过期：实际 11 层（chain.go:69-166）| risk: 流程图误导 | fix: 改 11 Layers
- [MEDIUM/docs] docs/FLOWCHARTS.md:9 — 整体架构图 MW 节点漏列 MQTYPE 与 Any 两个中间件，且 EDNS 位置错误（Response · CacheStore · Validation / Zone · EDNS · CacheLookup / PTR · DNS64 · Resolution = 10 项）| risk: 整体图与 中间件管道 图（:49-67，正确）自相矛盾 | fix: 按 :53-63 的实际顺序列出全部 11 层
- [MEDIUM/docs] docs/FLOWCHARTS.md:117 — 缓存查询流程图 "ORDER BY CASE 优先级" 过期：`StmtEntryFallback` 已去掉 ORDER BY（database/stmts.go:44-47 注释明确 "No ORDER BY"，与 LOADTEST.md:229 修复记录一致），Go 侧从 ≤5 行选最优 | risk: 流程图描述已被修复的瓶颈 | fix: 节点改为"5 候选 OR 子句，Go 侧选最优候选"
- [MEDIUM/docs] docs/ARCHITECTURE.md:251 — `pqResumedSharedKey` 大小写错误：实际为导出函数 `PQResumedSharedKey`（internal/dnscryptcrypto/pq.go:123）；且 TicketPlaintext 偏移常量实际在 pq.go（:299-323 `TicketPlaintextSecretOff` 等），不在文档所写的 `internal/dnscryptcrypto/certificate.go`（该文件 0 命中）| risk: 无法按图索骥 | fix: 更正函数名与文件路径
- [MEDIUM/docs] docs/rfc/GUIDELINE.md:33-53 — 统计摘要与正文不符：声称总计 108（87✅+4⚠️+16⚪=107）；实际 `## ` 章节 95 个（RFC 编号章节 89 个 + DELEG/DNS Stamp/DNSCrypt/SOCKS5/TLCP/已知偏离），RFC 章节含 12 个多 RFC 合并段（2065/2537/…、2845/4635、4033/4034/4035、5011/9077、6052/6147 等）| risk: 覆盖率自述不可信 | fix: 用脚本重算各状态计数
- [MEDIUM/docs] CLAUDE.md:338 与 docs/AUDIT-METHODOLOGY.md:354 — 规范前缀数自相矛盾：CLAUDE.md 27 个，AUDIT-METHODOLOGY §6.2 反模式 8 写"23 个规范前缀" | risk: 审计口径漂移 | fix: 统一为 27（或加 UDPPOOL/DOH 后 29）
- [MEDIUM/docs] docs/debug/DEBUG.md:697 — `grep -E "hijack probe|hijack detected|tcp=true"` 中 "hijack probe"/"hijack detected" 在任何日志输出中 0 命中（仅注释出现，server/resolver/recursive.go:145,355）；实际日志为 "SECURITY: poison detected"（server/defense/poisonguard.go:93）、"RECURSION: poisonguard triggered TCP fallback"（recursive.go:182,230）、"poison probe detected A/AAAA … forcing TCP"（recursive.go:391）| risk: 验证 grep 永远空手而归，误判无劫持 | fix: 改为匹配上述真实日志串（"tcp=true" 可通过 `tcp=%t` 格式化命中，保留）

### LOW

- [LOW/log] CLAUDE.md:338 未列出的实际前缀：`UDPPOOL`（server/upstream/pool/udp.go:453,465，2 处）、`DOH`（server/upstream/tls/https.go:167，1 处）——27 个规范前缀全部在用，但这两者未收录（`DOT:`/`DOQ:`/`DTLS:`→`TLS:` 映射规则未含 DOH）| fix: DOH 归入 TLS 映射，UDPPOOL 补入列表或并入 PLAIN
- [LOW/docs] README.md:114 — "4 种 Session Cache（TLS/DTLS/TLCP/DTLCP）"过期：实际 5 种，另有 QUIC session cache（server/upstream/client.go:103 `stdtls.NewLRUClientSessionCache`）| fix: 加 QUIC
- [LOW/docs] docs/benchmark/benchmark-baseline.txt — 过期：代码 105 个 Benchmark（23 文件，与 CLAUDE.md 一致），基线文件仅 104 个唯一名，缺 `BenchmarkResolveRootServers`（server/resolver 有，基线无）| fix: 重跑刷新命令
- [LOW/docs] docs/benchmark/LOADTEST.md:230 — "→ 全协议基线 0 失败"与当前 docs/benchmark/loadtest-baseline.txt（2026-08-08）不符：tls 行 377277 ok / 15 fail | risk: 基线宣称与实测数据矛盾 | fix: 更新该行描述或注明新基线
- [LOW/docs] 新功能未入文档：`zjdns.whoami` CHAOS TXT（config/chaos.go:56、server/init.go:80，commit a8f15d4）在全部 .md 文档 0 提及；config.example.json 的 `prefer_ipv4`、`mmap_size_mb`、`cache_size_mb` 亦未在任何指南文档说明 | fix: DEBUG.md/ARCHITECTURE.md 补录 whoami 端点与配置键
- [LOW/godoc] internal/dnscryptcrypto/pq.go:299 `EncodeTicketPlaintext` 与 internal/dns64/dns64.go:85 `Synthesize` 缺 doc 注释（其余 34 处缺失均为 net.Conn/ResponseWriter 等接口方法实现，可接受）| fix: 补两处注释

## Checks performed

1. **符号存在性检查** — PASS（12 处引用已删除/改名符号，见 M3/M4/M9/L5；全表其余符号均存在：10 表 schema、Store/Entry/DB/Server/Resolver/Recursive/Client/Conn/ConnPool/Detector/Engine/Map/DTLSSessionStore/Message/Buffer/DNSStamp/ZoneStorage、WireHasDNSSEC/ProbeNSAddrs/sortAnswerByLatency/ensureZoneDNSKEYs/queryNameserversConcurrent/probeTLDForPoison/truncateWire/PruneQueryJournal/GenerateDNSCryptConfig/VerifyDelegationDS/SelfVerifyDNSKEY/verifyOfflineKSK/verifyViaCDS/verifyViaCDNSKEY/HasCompactNXNAME/decryptPQResumed/ResetKeys/rotateKeys/WriteTCPMsgSegmented/StmtZoneWildcard/QueryZoneExact/QueryZoneWildcard/dnssecCacheable/buildFromPrePacked/tcpWriteShard/findMQQUERY、11 个中间件类型、全部 CLI flag（--sql/--rw/--dnsstamp/--probe/--pipeline/--conn-reuse/--idle-timeout/--generate-config/--dnscrypt/--provider/--stamp-*）、benchclient 8 flag、8 种 stamp 协议、debug 目录全部配置文件、7 个 CHAOS clear 端点 + whoami）
2. **CLAUDE.md 准确性** — FAIL（Query Pipeline 顺序过期 M2；AsyncStatsWriter 已删 M3；前缀 27 vs 实际 29 L1；11 中间件名单、import DAG 例外（edns→config、cache→database、zone→database、ruleset→config、internal/latency→config、middleware→handler 全部实测满足）、105 benchmarks/23 文件、Key Types 其余条目均正确）
3. **日志前缀审计** — PASS（27 个规范前缀全部在用；额外 2 个未收录：UDPPOOL×2、DOH×1，见 L1）
4. **FLOWCHARTS.md 覆盖** — PASS（§6.3 清单 18 项全部有图；29 个 ```mermaid 块与 29 个闭合围栏平衡；TC→TCP/连接池/单飞/异步写/DNSCrypt 密钥管理等流程与代码一致；3 处过期节点 M6/M7/M8；中间件管道图 :49-67 与 chain.go 实际顺序一致）
5. **注释准确性** — PASS（生产代码 TODO/FIXME/HACK = 0；无 "Phase 3"、行号引用、已删符号注释残留；chain.go:54-68 头注释 11 层顺序正确）
6. **godoc 覆盖** — PASS（全仓库仅 36 处导出声明无 doc 注释，34 处为接口方法实现；真实缺口 2 处 L6）
7. **docs/audit/ 归档** — PASS（docs/audit/2026-08-full/ 已存在；检查时含 01-foundation.md、03-protocol.md、04-upstream.md、05-resolver.md、07-defense.md、08-top.md，其余文件由并行 agent 写作中）

### 通过项（无发现）

- DB schema 10 表 ↔ ARCHITECTURE.md 完全一致（表名/列/索引）；README "九表" 例外见 M5
- ARCHITECTURE.md DNSCrypt 线格式/证书布局/防污染机制/Zone 接口描述全部命中代码
- RFC 合规抽查（9606/9462/9824/10029/8482/9715/9156/7873/8467/6147）GUIDELINE 状态与实现一致
- config.example.json 全部键 ↔ config/config.go JSON tag 一致
- 连接池/单飞（10000 容量、60s 超时）、异步写（cap 64、100ms、batch 64）、16 shard FNV-1a 写注册表、ECS 15min 刷新、Cookie 24h 轮换、padding 128/468、CNAME 16 级、DNS64 64:ff9b::/96、1400 字节截断：流程图/README 描述与常量一致
