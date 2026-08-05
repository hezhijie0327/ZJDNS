# validation 审计

> agent: `ae28a17defe388d2f`

发现数: 8

## validation-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get() 解析 pre-packed BLOB 头部无任何校验（无 0x02 格式字节检查、无长度/numOffsets 边界检查），旧版格式条目触发切片越界 panic
- **描述**: Set() 在 ba1f78c 起将 BLOB 格式从"纯 zstd 压缩 wire"改为 "[0x02][num_offsets(2)][offsets...][wire]"，但没有任何数据迁移清理 entries 表中的旧行（migrations 仅改 schema；grep 全库无启动时 DELETE FROM entries）。旧条目（≤3.11.11 写入，最长存活 7 天 TTL + 3 天 stale 窗口）以 zstd magic 0x28 0xB5 0x2F 0xFD 开头，Get() 在 line 267 读 msgWire[1:3] = 0xB52F = 46383 个 numOffsets，line 270-272 循环 `binary.BigEndian.Uint16(msgWire[3+i*2:])` 和 line 273 `wire := msgWire[wireStart:]`（wireStart=92769）对几千字节的 BLOB 直接越界 panic。panic 仅在 bridge.go 的 HandlePanic 处被恢复 → 该查询静默失败，客户端超时重试；升级后所有命中旧条目的查询全部失败且 PANIC 日志刷屏。同样缺失的校验还使小于 6 字节的 wire 进入 WireHasDNSSEC（response.go:59 读 wire[4:6] 无守卫）和 truncateWire（bridge.go:287）引发二次 panic。
- **风险**: 就地升级后缓存命中路径对旧格式条目每条查询 panic；任意损坏的 0x02 行同样崩溃；服务器核心缓存功能在升级后 10 天内不可用
- **修复**: 在 Get() 解析 BLOB 前校验：`len(msgWire) >= 3 && msgWire[0] == cacheFormatPrePacked && 3+numOffsets*2 <= len(msgWire) && len(wire) >= dns.MsgHeaderSize`，任何不符按 miss 处理（Debug 日志 + return nil）；可选在启动时对非 0x02 前缀行执行一次清理

## validation-02 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: regression: refs.Add(1) 重复执行（line 98 锁内 + line 110 Do 之后），每条 TCP 请求净 +1，refs 永不归零，sweep 永不淘汰，tcpWriteShards 无界增长
- **描述**: 上一轮 H1 修复（9f6001c，声称 "refs now reach 0"）在锁内新增了 line 98 的 entry.refs.Add(1)，但未删除原有的 line 110 entry.refs.Add(1)（注释与 line 94-97 完全相同，是合并残留）。每个 TCP 请求：+1(line 98) +1(line 110) -1(line 115 SERVFAIL defer 或 line 155 goroutine defer) = 净 +1，refs 永远 > 0。sweepTCPWriteMu（tasks.go:137）`if entry.refs.Load() != 0 { continue }` 因此永不删除任何服务过请求的 entry——每连接（IP:port 唯一）累积一条含 writeMu+capacity 两个 channel 的 tcpWriteEntry，16 个 shard 的 map 在进程生命周期内无界增长。tasks_test.go 的测试只手工模拟单次 +1/-1，未覆盖真实路径。
- **风险**: 长时间运行后每唯一 TCP 客户端地址泄漏一条 entry（含两个 channel），内存无界增长直至 OOM；sweep 成为死代码
- **修复**: 删除 line 110 的 entry.refs.Add(1)（锁内 line 98 的 Add 已覆盖同步阶段，decrement 在 goroutine/SERVFAIL defer 中严格更晚执行）；并在 tasks_test.go 增加真实请求路径的 refs==0 断言

## validation-03 — MEDIUM

- **位置**: `server/handler/middleware/dns64.go:46`
- **类别**: validation
- **摘要**: regression: Get() 不再内部 canonicalize qname，DNS64/MQTYPE 仍传原始 wire 名（qd.Header().Name），大小写变体查询永远缓存 miss
- **描述**: 本轮 delta 从 Get() 移除了 `qname = dnsutil.Canonical(qname)`（cache/store.go:222 新契约："caller must pass a canonical qname"），但两个新/旧调用点未跟随：dns64.go:46 `qname := qd.Header().Name` → line 57 `m.store.Get(qname, dns.TypeA, ...)`；mqtype.go:131 同样取原始名 → line 204 Get、line 213 DoJoin。客户端发送混合大小写 QNAME 时（0x20 随机化/IDN/应用构造），SQL 精确匹配 canonical 小写存储列必然 miss，每条大小写变体都触发一次额外上游查询；DoJoin/BuildPendingKey 的 key 也区分大小写，并发单飞去重失效。旧版 Get 内部 canonicalize 时无此问题——属回归。主路径 cache_lookup.go:47 用 qctx.Qname（handler.go:148 已 ToLower）不受影响。
- **风险**: 混合大小写查询的 DNS64 二次 A 查找和 MQTYPE 附加类型查找绕过缓存与单飞去重，每变体一次上游查询，放大上游流量
- **修复**: dns64.go:46 与 mqtype.go:131 改用 qctx.Qname（已规范化），或在调用 Get/DoJoin 前对 qname 做 dnsutil.Canonical

## validation-04 — LOW

- **位置**: `cache/cache.go:124`
- **类别**: validation
- **摘要**: rebuildResponseWire 中 `_ = msg.Unpack()` 丢弃 error 且无失败回退，Unpack 失败时 Pack 产出无 question 段的 wire 直接下发给客户端
- **描述**: rebuildResponseWire（延迟排序后重建 wire）中 `_ = msg.Unpack()` 无注释说明 error 丢弃原因（§6.1-11 要求注释）。若 Unpack 失败，msg 的 Question 为空、头部字段为零值，随后 msg.Answer = e.Answer 后 msg.Pack() 产出的 wire 缺 question 段，作为响应下发给客户端（畸形响应）。实际触发概率极低（同一 wire 在 store.go:314 刚成功 Unpack 过且 len(Answer)>0 才走到这里），但缺少守卫与注释。
- **风险**: 极端情况下（内存/驱动层数据损坏）客户端收到无 question 的畸形响应；错误被静默吞掉难以排查
- **修复**: 改为 `if err := msg.Unpack(); err != nil { return }`（保留原 wire 与 offsets 不重建），并补注释

## validation-05 — LOW

- **位置**: `cache/store.go:314`
- **类别**: validation
- **摘要**: Get() 中 `_ = entry.Unpack()` 丢弃 error 未注释原因，失败时静默跳过延迟排序
- **描述**: latency 排序分支 `_ = entry.Unpack()` 无注释（§6.1-11：丢弃必须注释类型与原因）。失败后果较轻（Answer 为 nil，sortAnswerByLatency 与 rebuildResponseWire 自动跳过，条目仍按原始顺序直发），但属于 hot path 上未注释的 error 丢弃，函数签名重构时是定时炸弹。
- **风险**: 违反 §6.1-11 纪律；重构时 Unpack 签名变更会被静默吞掉
- **修复**: 补注释 `// _ = error: 排序失败时退回原始 wire 顺序` 或显式 `if err := entry.Unpack(); err == nil { ... }`

## validation-06 — LOW

- **位置**: `server/handler/middleware/response.go:75`
- **类别**: validation
- **摘要**: pre-packed Unpack 失败路径设置 Rcode=SERVFAIL 但 Data 未置 nil，bridge 仍直发旧 wire，SERVFAIL 永远不会到达客户端
- **描述**: line 73-77：`if err := qctx.Res.Unpack(); err != nil { qctx.Res.Rcode = dns.RcodeServerFailure; return err }` —— Data 仍非 nil，bridge.go:192/233 的 `if len(response.Data) == 0` 跳过 packSafe，直接写出损坏的原始 wire（携带原 rcode），设置的 SERVFAIL 与 handler.go:155 的兜底（需 qctx.Res == nil）均失效。仅在 pre-packed wire 损坏（与 validation-01 同根因）时触发。
- **风险**: 损坏条目被原样下发给客户端而非 SERVFAIL，错误处理成为死代码
- **修复**: Unpack 失败时同时 `qctx.Res.Data = nil`（并清空 TTLOffsets 已由 buildFromPrePacked 释放），让 bridge 走 packSafe 重建 SERVFAIL

## validation-07 — LOW

- **位置**: `config/resinfo.go:21`
- **类别**: validation
- **摘要**: DDR.InfoURL 未校验直接拼入 RESINFO TXT key：无 https:// 前缀检查（RFC 9606 §5）、无 TXT character-string 255 字节上限检查（RFC 6763 §6.1）
- **描述**: resinfoKeys 将 cfg.Server.Features.DDR.InfoURL 原样拼为 "infourl="+InfoURL 并 quoteTXT 后注入 resolver.arpa RESINFO 记录（zone/wire.go buildRecord → dns.New 解析）。全库无 InfoURL 校验（config 层只有 ECSConfig.Validate）。超长 URL（>255 字节）或含空格/控制字符的 URL 会产生畸形 TXT character-string，dns.New 解析失败时回退 RFC3597（wire.go:101），服务给所有查询客户端一个损坏的 RESINFO 记录。
- **风险**: 运营商配置错误静默产生损坏的 RESINFO 广播记录；不符合 RFC 9606 的 https URL 要求
- **修复**: 配置加载处校验 InfoURL：非空时须以 https:// 开头且长度 ≤200（预留 "infourl=" 前缀空间），否则拒绝或忽略该 key

## validation-08 — LOW

- **位置**: `cache/store.go:121`
- **类别**: comment
- **摘要**: scanTTLOffsets 注释引用不存在的函数名 releaseTTLOffsets（实际为 ReleaseTTLOffsets）
- **描述**: line 121 注释 "release with releaseTTLOffsets when done" 引用的小写函数名 releaseTTLOffsets 在代码中不存在（实际导出函数为 line 103 的 ReleaseTTLOffsets），引用失效符号（§6.1-10/注释腐烂模式）。
- **风险**: 误导阅读者；符号名注释无法 grep 定位
- **修复**: 改为 "release with ReleaseTTLOffsets when done"

