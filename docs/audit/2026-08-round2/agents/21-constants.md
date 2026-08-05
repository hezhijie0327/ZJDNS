# constants 审计

> agent: `a90f5e0e720bdc376`

发现数: 6

## regression-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: H1 修复不完整（regression）：TCP 请求路径对 entry.refs 双重 Add(1)，refs 永不归零，sweep 成死代码，tcpWriteShards.entries 无界增长
- **描述**: 每 TCP 请求在 bridge.go:98（锁内）和 :110（capacityOnce.Do 之后）各执行一次 entry.refs.Add(1)，而完成路径只有两处 Add(-1)（:115 SERVFAIL defer、:155 goroutine defer），二者互斥只会执行其一。因此每个请求净增 +1，refs 单调增长永不回 0。tasks.go:137 的 sweep 要求 refs==0 才删除条目，导致任何服务过请求的 entry（含 writeMu/capacity 两个 channel）永久滞留。上一轮 H1 修复提交 9f6001c（12-synthesis.md 第 19-30/162 行声称 "refs now reach 0"）只是把 placeholder 换成锁内加锁，但 :110 的重复 Add(1) 原样保留（:94-99 与 :106-110 两段几乎相同的注释是复制粘贴痕迹）；tasks_test.go:27-40 手工 Add(1)/Add(-1) 模拟 refs 归零，未走请求路径，测试无法发现该缺陷。
- **风险**: 长期运行的高并发 TCP 服务器上，按客户端地址（ip:port）累积的 tcpWriteShards.entries 无界增长（每个条目两个 channel + mutex + map 槽），且 writeMu 清理机制完全失效——正是 H1 已判定并声称修复的资源泄漏，现仍在生产代码中
- **修复**: 删除 bridge.go:110 处的第二个 entry.refs.Add(1)（连同 :106-109 重复注释），恢复每请求一次递增的语义；补充一个走 handleDNSRequest 真实请求路径的集成测试断言请求完成后 refs==0；或在 tasks_test.go 中按生产路径的两次 Add 建模以暴露该 bug

## constants-01 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:145`
- **类别**: rfc
- **摘要**: MQTYPE merge 预算用固定 1400 上限并减魔法数 64，未考虑客户端 EDNS 缓冲（qctx.Req.UDPSize），小缓冲客户端收到截断响应后 MQTYPE-Response 仍声称 QTx 完整（RFC 10029 §3.4/§3.5）
- **描述**: budget := config.DefaultMaxUDPResponseSize - msg.Len() - 64：合并上限固定为 RFC 9715 R3 的 1400，忽略客户端实际通告的 UDP 缓冲（如 512 或 1232）。当合并后响应超过客户端 udpSize 时，bridge.go:257 truncateWire 会按 RFC 2181 §9 截断——保留 header+question+尾部 OPT（truncateWire 显式保留 type-41 OPT，MQRESPONSE 选项存活），但丢弃所有 RR。结果 MQTYPE-Response 列表仍在声称 QTx "completely answered and contained within the received response"（RFC 10029 §3.5），而客户端实际收到的回答已被截断，且 §3.4 要求 "The handling of an MQTYPE-Query option MUST NOT itself trigger a truncated response" 且仅列出完整放入响应的 QTx。另外 -64 是无注释魔法数（EDNS 开销估算）。
- **风险**: 通告 512/1232 字节 EDNS 缓冲的客户端（IPv6-only 网络、老旧中间件常见）请求 MQTYPE 合并时，被列出的附加 QTYPE 回答被截断丢失，客户端按 §3.5 不再发起独立查询，静默数据丢失
- **修复**: budget 改为 min(max(qctx.Req.UDPSize, dns.MinMsgSize), config.DefaultMaxUDPResponseSize) - msg.Len() - <命名常量>，将 64 抽取为带注释的命名常量（如 mqtypeEDNSOverhead = 64）；确保任何被列入 completed 的 QTx 都完整落在客户端通告的缓冲内

## constants-02 — LOW

- **位置**: `cache/store.go:60`
- **类别**: perf
- **摘要**: maxTTLOffsets=16 的注释"never in practice"不准确——DNSSEC 签名响应（RRSIG 使 RR 数翻倍）和 TCP 大响应经常超过 16 条 RR，TTL-offset pool 对这些常见响应完全失效
- **描述**: AcquireTTLOffsets（:93-99）在 cap<n 时直接 make 新切片且 ReleaseTTLOffsets（:103-107）丢弃 cap>16 的切片；池初始 cap 仅 8，scanTTLOffsets append 超过 8 条时池数组即被放弃。而带 DNSSEC 的权威响应（NS+glue+DS+RRSIG）或大 A/AAAA 集合轻易超过 16 条 RR——这些恰是缓存命中热路径上最需要复用缓冲的响应，却每次 Get 都重新分配 []uint16 并丢弃。注释断言"never in practice — DNS responses are bounded by transport size"与 TCP 响应可携带数百条 RR 的事实相悖
- **风险**: 缓存命中热路径上常见的 DNSSEC 大响应每次产生堆分配，池化优化的实际收益远低于设计意图
- **修复**: 将 maxTTLOffsets 提升到覆盖典型响应（如 64）并同步提高池初始容量（AcquireTTLOffsets 内按需增长后仍归还），或删除/修正"never in practice"注释并接受该上限为有意的退化策略

## constants-03 — LOW

- **位置**: `cache/store.go:243`
- **类别**: magic-number
- **摘要**: ECS 回退槽位数硬编码字面量 5 在文件内 3 处重复（:86 make cap、:243 for i := range 5、:832 释放上限），未命名常量
- **描述**: 新 ECS 单轮查询代码中，槽位数 5 同时以字面量出现在 ecsCandidatesPool 初始容量（:86 "make([]ecsCandidate, 0, 5)"）、Get() 的占位循环（:243 "for i := range 5" + :248 fallbackSentinelAddr 填充）和 releaseECSCandidates 的丢弃阈值（:832 "cap(candidates) <= 5"）。该数字与 StmtEntryFallback 的 5 组 (addr,prefix) 绑定列严格耦合，改一处漏改其余会静默破坏 SQL 绑定或池复用
- **风险**: 未来调整候选槽位或 SQL 语句时漏改任一字面量导致查询错位/池膨胀，编译不报错
- **修复**: 在 store.go const 块新增命名常量（如 maxECSFallbackSlots = 5），三处字面量全部引用该常量，并在注释中注明与 StmtEntryFallback 绑定列数的耦合

## constants-04 — LOW

- **位置**: `cache/store.go:618`
- **类别**: magic-number
- **摘要**: 新 evictIfNeeded 中淘汰节流阈值（maxEntries*9/10、%20、%10）与 PruneQueryJournal 的 86400 均为无命名裸数字
- **描述**: 本轮新增代码：:618 "count < maxEntries*9/10"（90% 触发线）、:625 "s.evictCount.Load()%20 == 0"（每 20 次淘汰重同步）、:639 "s.evictCount.Add(1)%10 == 0"（每 10 次淘汰跑 PRAGMA optimize）、:655 "log.NowUnix()/86400 - retentionSec/86400"（秒/天）。baseline 93611d5 中不存在这些行（旧版 store.go 无 evictIfNeeded/PruneQueryJournal），全部为本轮新代码。其中 86400 与 config/defaults.go 中 3*86400 表达同一单位但未复用
- **风险**: 节流参数散落业务逻辑中，调整淘汰频率/清理窗口需通读代码找数字，且跨包重复的 86400 存在将来不一致的风险
- **修复**: 分别抽取命名常量（如 evictHighWaterRatio=9/10、evictResyncInterval=20、evictOptimizeInterval=10，86400 可提为 config 层 secondsPerDay 或直接用 time.Second 表达式）并加注释说明来源

## constants-05 — LOW

- **位置**: `server/bridge.go:286`
- **类别**: magic-number
- **摘要**: truncateWire 内 12 字节 DNS header 长度硬编码，而同函数其余位置（:282/:292/:317/:321）使用 dns.MsgHeaderSize，常量使用不一致
- **描述**: truncateWire 中 "pos := 12"（:286）、"return wire[:dns.MsgHeaderSize]"（:292/:317/:321）混用：同一函数内 12 与 dns.MsgHeaderSize 表达同一值。store.go 的 dnsSkipName/WireHasDNSSEC 亦硬编码 12（:147/:285 等，有注释说明）。wire 偏移常量在库中已存在（dns.MsgHeaderSize），应统一
- **风险**: 维护者改一处忘改另一处时引入细微 wire 解析偏移错误；语义不一致降低可读性
- **修复**: truncateWire :286 改用 dns.MsgHeaderSize（或包内统一命名常量如 wireHeaderLen=12 并在注释引用 RFC 1035 §4.1.1）

