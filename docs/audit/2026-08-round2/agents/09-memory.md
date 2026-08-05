# memory 审计

> agent: `a60fdbc685c7f262d`

发现数: 4

## mem-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: memory
- **摘要**: cache.Get 从不校验 BLOB 格式标记 msgWire[0]==0x02，旧版本写入的缓存行被按 pre-packed 格式解析 → 越界 panic 或静默返回损坏的 DNS 响应
- **描述**: Set()（store.go:532）写入 msgWire 时前置 0x02 标记，但 Get() 第 267 行直接 `numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))`，从不检查 msgWire[0]。cache.db 是跨版本持久化的（无启动清空、无 schema 变更触发迁移），v3.11.10 及更早版本写入的每一行都是无前缀的 zstd 压缩 wire（基线 Set 存 `zdnsutil.Compress(msg.Data)`）或更早的裸 wire。对旧行：msgWire[1]=0xB5、msgWire[2]=0x2F（zstd magic 字节）→ numOffsets=46383 → `for i := range numOffsets { offsets[i] = binary.BigEndian.Uint16(msgWire[3+i*2:]) }`（store.go:271）在 i≈(len-4)/2 处切片越界 panic；裸 wire 旧行（ID 低字节+flags 组合）同样越界，或当计算恰好在界内时 wireStart=3+2*numOffsets 切进消息中段，把中间字节当完整 DNS 响应直发客户端（静默数据损坏）。升级后首个旧行缓存命中即触发，直到 TTL 过期刷新为止每个旧行命中都会 panic（被 HandlePanic 恢复，查询失败）。
- **风险**: 用户原地升级二进制后，缓存 DB 中所有旧格式条目被误读：每查询 panic 一次（恢复后查询失败）+ 日志刷屏，或更糟——在边界算巧时向客户端直发被截断/错位的 wire 响应，客户端缓存到错误数据。
- **修复**: Get() 第 265 行解析前先校验 `msgWire[0] != cacheFormatPrePacked`：旧格式行走兼容路径（isZstdCompressed 判断后 DecompressTo + Unpack 填充 Answer/Authority/Additional，沿用基线行为），或至少视为 miss/过期（log + return nil,false,false），绝不按 0x02 布局解析。建议补一个写旧格式 BLOB 再走新 Get 的回归测试。

## mem-02 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: regression(H1)：每请求 refs 两次 Add(1)（第 98、110 行）却只有一次 Add(-1)（第 115/155 行），refs 永不归零 → sweep 仍成死代码 → tcpWriteShards.entries 无界增长
- **描述**: handleDNSRequest TCP 路径中：第 98 行锁内 `entry.refs.Add(1)`（in-flight ref）+ 第 110 行 `entry.refs.Add(1)`（注释与 94-97 行逐字重复，同样是“in-flight refcount”），而释放只有一处——goroutine 路径第 155 行 defer Add(-1) 或 SERVFAIL 路径第 115 行 defer Add(-1)。每请求净 +1，连接处理过任意请求后 refs ≥ 1，永不为 0。H1（9f6001c）移除了占位 ref（newEntry.refs.Add(1)）但漏删这个遗留的第二个 Add(1)。sweepTCPWriteMu（tasks.go:137 `if entry.refs.Load() != 0 { continue }`）因此仍然永远跳过所有服务过请求的条目，per-客户端地址的 map 项（含两个 channel 字段）随唯一 TCP 客户端数量无界累积。
- **风险**: 长运行服务器上内存随历史 TCP 客户端数线性增长（每个条目持 capacity/writeMu 两个 channel），资源耗尽；且上一轮声称修复的 H1 实际未修复，sweep 路径从未生效。
- **修复**: 删除第 110 行重复的 `entry.refs.Add(1)`（保留锁内那一次，与 goroutine/SERVFAIL 的单次 -1 配对）；补一个并发请求 + sweep 的集成测试断言 refs 归零后可被驱逐。

## mem-03 — MEDIUM

- **位置**: `server/handler/middleware/dns64.go:57`
- **类别**: pool-leak
- **摘要**: DNS64 与 MQTYPE 中间件的 cache.Get 入口（dns64.go:57、mqtype.go:204）取得 entry 后从不 ReleaseTTLOffsets，池内 TTL-offset 切片每次被丢弃到 GC
- **描述**: 新 pre-packed 格式下 cache.Get 每次命中都会 `AcquireTTLOffsets(numOffsets)` 从 ttloOffsetsPool 取一块池切片放入 entry.TTLOffsets（store.go:268/306）。释放点只有两处：handler/response.go:67（buildFromPrePacked 用完即还）与 cache.go:167（rebuildResponseWire 换新）。DNS64（dns64.go:57，每 AAAA miss 都会走）与 MQTYPE merge（mqtype.go:204，每附加类型一次）Get 后只 Unpack 读 Answer 就丢弃 entry，池切片未归还。同类问题在 round-1 M1（cache_lookup.go 快速刷新路径未 Put 旧池消息，评 MEDIUM）修复时已确立先例。
- **风险**: 这两个热路径每次命中都让一块池切片（cap≤16 的 []uint16）脱离池被 GC，下次 Get 重新 make——池周转损耗 + 热路径堆分配回升，削弱本轮缓存优化的分配收益。
- **修复**: 两处 Unpack 后用完后调用 `cache.ReleaseTTLOffsets(entry.TTLOffsets)`（mqtype 的 resolve 与 DNS64 的缓存命中分支）；或在 cache 包提供 `Entry.Release()` 统一归还，供所有消费方调用。

## mem-04 — LOW

- **位置**: `cache/store.go:289`
- **类别**: pool-leak
- **摘要**: Get 解压失败路径 return 前未 ReleaseTTLOffsets(offsets)，已取出的池切片被丢弃
- **描述**: store.go:268 `offsets := AcquireTTLOffsets(numOffsets)` 之后，zstd 解压失败分支（store.go:284-291）只归还 decompressBufPool 的 dbuf 就 `return nil, false, false`，offsets 未通过 ReleaseTTLOffsets 归还 ttloOffsetsPool。defer 归还语句（291 行）只在解压成功路径注册。虽然 sync.Pool 丢对象只是池周转损耗（GC 会回收，非内存泄漏），但该路径上已取得的两块池资源只还了一块，与代码库“Get/Put 成对”的纪律不符。
- **风险**: 仅在解压失败（数据损坏）错误路径触发：每失败一次丢一块池切片，累积在持续损坏的条目上放大池周转成本；后续修复或审计时容易被忽略而成为既成反例。
- **修复**: 在解压失败 return 前补 `ReleaseTTLOffsets(offsets)`；或把 offsets 的获取移到解压成功之后（解压失败分支根本不需要 offsets）。

