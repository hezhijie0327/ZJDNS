# locks 审计

> agent: `abfaddd9f98390992`

发现数: 4

## locks-02 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get() 读取 msg_wire 时未校验 0x02 格式标记与长度，旧版本（≤v3.11.11）写入的无标记行在升级后每次缓存命中都触发切片越界 panic
- **描述**: 新的 pre-packed 格式（0x02 标记 + 2 字节 offset 数 + offset 表 + wire，commit ba1f78c 引入）在 Get() 中没有做任何格式验证：line 261 仅检查 `len(msgWire) == 0`，line 267 直接 `numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))`，line 270-272 循环读 `msgWire[3+i*2:]`，line 273 `wire := msgWire[wireStart:]`（wireStart = 3+numOffsets*2）。而数据库的 entries 表跨版本持久化（无任何迁移清除旧行，database/migration.go 的迁移列表不含 entries 格式处理，StmtEntryFallback 的 SQL 也不过滤格式），≤v3.11.11 的 Set() 写入的是裸 zstd 帧或裸 DNS wire（git show 93611d5:cache/store.go 确认 `msgWire := zdnsutil.Compress(msg.Data)`，无标记字节）。旧行被新代码读取时：zstd 帧 byte[0:4]=0x28 B5 2F FD → numOffsets=0xB52F=46383 → wireStart=92769，任何消息（最大 65535 字节）都必然 `msgWire[92769:]` 越界 panic；即使 numOffsets 偶然较小，offset 表读取也是垃圾数据。每次命中旧行的缓存查询都在 bridge.go 的 HandlePanic 处被捕获（internal/dnsutil/dnsutil.go:76 recover），查询被静默丢弃、客户端超时，且每条查询打一条 PANIC error 日志。
- **风险**: 从任何 ≤v3.11.11 版本升级且保留 cache.db 后，TTL 有效期内的所有旧格式条目每次命中即 panic：查询失败 + 日志刷屏，构成对升级用户的功能性崩溃。
- **修复**: Get() 读取时先验证 `len(msgWire) >= 3 && msgWire[0] == cacheFormatPrePacked`（并校验 `3+numOffsets*2 <= len(msgWire)` 与 wireStart 边界），不匹配则视为 miss（可顺带 DELETE 该行自愈，或在启动时做一次格式迁移：旧行直接丢弃/重写）。

## locks-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: lock
- **摘要**: regression：shard 重构后 entry.refs.Add(1) 被复制成两处，每请求净泄漏 +1，sweep 永远等不到 refs==0，TCP 写注册表无界增长
- **描述**: handleDNSRequest 的 TCP 路径对同一请求执行了两次 entry.refs.Add(1)：第一次在 shard 锁内（line 98，shard.mu.Lock 期间 lookup-or-create + refs.Add，注释见 94-97 行），第二次在 capacityOnce.Do 之后无条件执行（line 106-110，注释与 94-97 行逐字重复——是 f7e7f13 shard 重构时把旧代码整块复制后忘了删掉锁内那份）。而递减只有一处：SERVFAIL 分支 line 115 的 `defer entry.refs.Add(-1)` 或 goroutine line 155 的 `defer entry.refs.Add(-1)`（二者互斥）。因此每个 TCP 请求 refs 净增 +1，永不归零。tasks.go:137 的 sweepTCPWriteMu 检查 `entry.refs.Load() != 0 → continue`，导致所有服务过请求的 entry 永远无法被删除，s.tcpWriteShards 的 entries map 按客户端地址无界累积（每 entry 含 writeMu + capacity(16) 两个 channel）。git 对比确认：93611d5（第一轮修复后）只有锁内一次 Add(1)，重复 Add 是本次 delta 引入。这是第一轮 H1（9f6001c 修复『tcpWriteEntry refcount 永不归零，sweep 成死代码，tcpWriteMu 无界增长』）的回归。
- **风险**: 每个访问过服务器的 TCP 客户端地址在注册表中永久残留一条 entry（含 2 个 channel），进程长时间运行后 map 无界增长导致内存持续膨胀；同时 sweep 完全失效，与第一轮 H1 相同的资源耗尽问题回归。
- **修复**: 删除 line 110 的第二个 `entry.refs.Add(1)`（保留 shard 锁内的唯一一次，并删除重复的注释块）。修复后补充断言测试：请求完成后 `entry.refs.Load() == 0`（第一轮 H1 修复时的测试模式），防止再次回归。

## locks-03 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:204`
- **类别**: pool-leak
- **摘要**: MQTYPE/DNS64/NS-address 三处 cache.Get 调用不释放 Entry.TTLOffsets 池切片，TTL-offset sync.Pool 在这些热路径上完全失效且持续膨胀
- **描述**: TTL-offset sync.Pool（cache/store.go:90 AcquireTTLOffsets/ReleaseTTLOffsets）随 0x02 格式引入后，Entry.TTLOffsets 成为池所有（pool-owned）字段，唯一释放点是缓存命中服务路径 buildFromPrePacked（server/handler/response.go:67 `cache.ReleaseTTLOffsets(entry.TTLOffsets)`）。但另外三个只读取 Answer 的 Get 调用方从不释放：mqtype.go:204 `m.store.Get(...)` 命中后直接 `entry.Unpack()` 取 Answer 返回；dns64.go:57 相同模式（`m.store.Get(qname, dns.TypeA, ...)`）；ns_addresses.go:238 lookupCachedRRs（递归模式下每次 NS 地址缓存查询都会走）。这些路径每次命中都从池 Get 一个从未归还的切片，池只能通过 New() 新建、跨 GC 周期累积（每个 GC 周期内最多等于并发命中数×16 字节），池化目标完全落空——每次调用反而多一次堆分配。
- **风险**: MQTYPE 合并查询、DNS64 A 记录查找、递归 NS 地址缓存查找三条热路径的 TTL-offset 池退化：分配量回升、池内存随并发峰值膨胀，性能优化（P3 目标）部分失效。
- **修复**: 三处 Get 命中分支在取出 Answer 后调用 `cache.ReleaseTTLOffsets(entry.TTLOffsets)`（或给 Entry 增加一个统一的 release 方法，如 `entry.Release()`，内部释放 TTLOffsets，并让 buildFromPrePacked 也改用它，防止将来新增调用方再次遗漏）。

## locks-04 — MEDIUM

- **位置**: `server/handler/middleware/response.go:73`
- **类别**: rfc
- **摘要**: 缓存命中时 MQTYPE 合并结果被 Response 中间件的 Unpack 整体覆盖：合并的 RR 与 MQTYPE-Response 选项全部丢失，RFC 10029 §3.4 违规
- **描述**: 链序（chain.go）：Response 最外层，MQTYPE 在 CacheStore 之后、Response 之前。缓存命中时 CacheLookup 设置的是 pre-packed 响应（msg.Data 非空、Answer 为空、msg.Rcode 恒为 0——rcode 只在 wire 里）。MQTYPE.merge（mqtype.go:128）把附加类型的 RR 追加进 msg.Answer（line 180-182）、把 `&dns.MQRESPONSE{Types: completed}` 追加进 msg.Pseudo（line 195）。随后 Response 中间件：`st.shouldAddEDNS` 含 `len(qctx.Req.Pseudo) > 0`，MQTYPE 客户端必然走 unpack 分支（line 46-88），`qctx.Res.Unpack()`（line 73）是 miekg/dns 的 Msg.Unpack——v0.6.89 msg.go:399/417 确认 `m.Answer = unpackRRs(...)`、`m.Pseudo = make(...)` 是整体赋值（替换而非追加），合并的 RR 与 MQRESPONSE 被静默丢弃。客户端最终收到只有主答案、无任何附加类型、无 MUST 的 MQTYPE-Response 的响应，与 RFC 10029 §3.4『服务器必须返回 MQTYPE-Response』直接冲突。附带：merge 用 `msg.Rcode`（pre-packed 时恒 0）作 §3.4 RCODE 一致性比较（mqtype.go:135/156），NXDOMAIN 条目命中时还会错误跳过全部合并（mqtype.go:267 已有 entryRcode 却未使用）。
- **风险**: RFC 10029 功能在递归模式 + 缓存命中的主路径上完全失效：客户端请求的附加 QTYPE 永远得不到合并，且缺少协议要求的 MQTYPE-Response 选项，客户端无法感知失败（静默降级）。
- **修复**: 二选一：(a) MQTYPE.merge 在追加前先对 pre-packed 主响应执行一次 `msg.Unpack()`（与 DNS64 中间件一致的先解包再合并模式），并用 `entryRcode` 逻辑从 wire 提取真实 RCODE 参与 §3.4 比较；(b) Response 中间件在 Unpack 后保留既有 Pseudo（如先保存再恢复），并确保合并路径在任何情况下不先改 msg.Answer/Pseudo 后又被整体替换。补一条『缓存命中 + MQTYPE 合并』的端到端测试。

