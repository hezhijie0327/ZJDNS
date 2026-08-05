# resource 审计

> agent: `accc48f9627dee442`

发现数: 7

## resource-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: tcpWriteEntry.refs 每个 TCP 请求净增 1（双重 Add，单次释放），sweep 永不删除任何条目 → 按客户端 IP 无界增长（regression）
- **描述**: handleDNSRequest 的 TCP 分支对同一 entry.refs 执行了两次 Add(1)：第 98 行（shard 锁内，git blame 93611d5 审计修复轮新增，用于关闭与 sweep 的 TOCTOU）和第 110 行（git blame 86e6d1f0 原有的 in-flight 计数）。但释放路径只有互斥的两处：第 115 行 defer refs.Add(-1)（capacity 满走 SERVFAIL 提前返回）与第 155 行 goroutine defer refs.Add(-1)（正常路径）。两条路径二选一，每请求净 +1。两段注释（94-97 行与 106-109 行）完全重复，是复制粘贴残留的直接证据。后果链：tasks.go:137 sweep 只删除 refs.Load()==0 的条目 → 任何条目 refs 永远 ≥1 → tcpWriteShards 的 per-IP 条目（2 个 buffered channel + atomic 字段 + map 开销 ~300B）永不清除；活动连接的 refs 还随请求数逐条累加。
- **风险**: 无界内存增长：每个曾发起 TCP 查询的客户端 IP（含端口扫描、单次查询）永久占用一个条目，公网长期运行可累计数十万条目；长连接 refs 无限累加。这是上一轮审计修复提交 93611d5 自己引入的回归（86e6d1f0 时代 +1/-1 平衡）。
- **修复**: 删除第 106-110 行的重复 refs.Add(1) 及重复注释，保留锁内的第 98 行 Add(1) 与两处既有 -1。锁内 Add 已保证 sweep 的 refs==0 检查与请求路径互斥（sweep 与 create+ref 同持 shard.mu），SERVFAIL 同步路径从 unlock 到 defer -1 期间 refs=1 也不会被删除。

## resource-02 — MEDIUM

- **位置**: `server/resolver/ns_addresses.go:239`
- **类别**: pool-leak
- **摘要**: lookupCachedRRs 调用 store.Get 后从不 ReleaseTTLOffsets，递归热路径每次缓存命中泄漏池化 TTL-offset 切片
- **描述**: cache/store.go:268 中 Get() 对每个 pre-packed（0x02）条目无条件 AcquireTTLOffsets(numOffsets)（store.go:92-99，来自 ttloOffsetsPool）。契约要求调用方用完释放（store.go:121 注释 'release with releaseTTLOffsets when done'；唯一释放点在 handler/response.go:67 buildFromPrePacked 与 cache.go:167 rebuildResponseWire）。但 lookupCachedRRs（ns_addresses.go:239）在递归解析的 NS 地址查询路径上调用 Get 后只做 entry.Unpack()/遍历，条目直接丢弃，offsets 切片从不归还池。该路径每次递归查询都会执行（root/TLD/权威委派的 NS A+AAAA 各 2 次 Get），是 5 处同类泄漏中最热的。
- **风险**: 每个缓存命中的 NS 地址查询丢失一个池化切片 → sync.Pool 槽位逐次流失、GC 后重复分配（每次 Get 一个 ~16-32B 堆分配），高 QPS 递归模式下放大为持续的池抖动与额外分配。
- **修复**: 在 entry 使用完毕后调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)（注意 Unpack 后 Answer 非空即直接返回的早退路径也要覆盖）；同法修复 dns64.go:57、mqtype.go:204、cache_store.go:182、cache_lookup.go:145 四处同类漏释放。

## resource-03 — MEDIUM

- **位置**: `server/handler/middleware/dns64.go:57`
- **类别**: pool-leak
- **摘要**: DNS64 中间件从 store.Get 取 A 记录条目后从不释放 TTLOffsets 池切片
- **描述**: dns64.go:57 `entry, found, _ := m.store.Get(qname, dns.TypeA, ...)` 命中缓存 A 记录后 entry.Unpack() 用于 AAAA 合成（第 57-62 行），随后条目连同池化 TTLOffsets 切片一并丢弃，从未调用 cache.ReleaseTTLOffsets。Get 的契约（cache/store.go:121-122）要求释放；同类正确用法见 handler/response.go:67。在启用 DNS64 的 NAT64 部署上，每次 AAAA 查询（缓存含 A 记录）都触发一次泄漏。
- **风险**: 池化切片每次 DNS64 合成后流失，pool 命中率下降、每次 AAAA-miss 查询多一次堆分配；与 ns_addresses.go 同根因。
- **修复**: 在第 62 行条目使用完毕后调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)（覆盖 found 但 Unpack 失败/Answer 为空的所有分支）。

## resource-04 — LOW

- **位置**: `server/handler/middleware/mqtype.go:204`
- **类别**: pool-leak
- **摘要**: MQTYPE 中间件 resolve() 缓存命中分支丢弃条目且不释放 TTLOffsets 池切片
- **描述**: mqtype.go:204 `entry, found, _ := m.store.Get(qname, qt, qclass, ecsOpt, dnssecOK)` 命中后 entry.Unpack() 构造 QueryResult（第 204-210 行），条目随后丢弃，未调用 cache.ReleaseTTLOffsets（Get 契约见 cache/store.go:121-122，正确释放见 handler/response.go:67）。触发条件为客户端带 MQTYPE-Query 且附加类型在缓存中，RFC 10029 新特性客户端较少，故严重性低于 ns_addresses.go/dns64.go。
- **风险**: 每次 MQTYPE 附加类型的缓存命中泄漏一个池化切片；后续缓存落空时多一次分配。
- **修复**: 在第 210 行 return 前调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)。

## resource-05 — LOW

- **位置**: `server/handler/middleware/cache_store.go:182`
- **类别**: pool-leak
- **摘要**: CacheStore buildError 的缓存回退路径在条目过期且不可 stale 服务时丢弃条目、不释放 TTLOffsets
- **描述**: cache_store.go:182 `if entry, found, isExpired := m.store.Get(...); found {` — 当第 183 行条件 `!isExpired || entry.CanServeExpired(...)` 为假（过期且超过 stale 窗口）时，函数落入第 197 行 SERVFAIL 构建路径，entry 及其池化 TTLOffsets 切片被静默丢弃，未调用 cache.ReleaseTTLOffsets。触发条件为解析失败且缓存条目过期超窗，相对罕见。
- **风险**: 错误回退路径上偶发池槽流失，pool 命中率轻微下降。
- **修复**: 在第 183 行条件不满足的分支 return 前调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)。

## resource-06 — LOW

- **位置**: `server/handler/middleware/cache_lookup.go:145`
- **类别**: pool-leak
- **摘要**: CacheLookup 过期且不可 stale 服务的条目（第 145 行委派 next）从不释放 TTLOffsets 池切片
- **描述**: cache_lookup.go:47 的 Get 命中了条目；当条目已过期且 CanServeExpired 为假（第 95 行条件不满足），直接 `return next.ServeDNS(ctx, qctx)`（第 145 行）把条目连同池化 TTLOffsets 切片丢弃，未调用 cache.ReleaseTTLOffsets（正确释放点在 handler/response.go:67）。与 cache_store.go:182 同属错误/边界路径的同类漏释放。
- **风险**: 条目过期超过 stale 窗口（如服务中断数日后恢复）的首次查询泄漏一个池槽，pool 命中率轻微下降。
- **修复**: 在第 145 行 return 前调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)。

## resource-07 — LOW

- **位置**: `server/upstream/tls/http3.go:85`
- **类别**: comment
- **摘要**: http3.go:85 注释声称 'Close() nils the map'，与实际代码相反（tls/client.go:106-108 明确注释 map 不置 nil）
- **描述**: ExecuteHTTP3 中 `if c.doh3Transports != nil { // Close() nils the map — a racing query must not panic`（http3.go:85）——但 tls.Client.Close()（tls/client.go:101-132）实际执行 Range 关闭后明确保留 map（'the LRU maps are intentionally NOT nil'd here'，第 106-108 行）。同包内两处注释自相矛盾，http3.go:85 的描述是过时的（可能在早期版本 Close 确实置 nil）。nil 防御本身无害，但注释会误导后续维护者以为 Close 会置 nil 而依赖该行为。
- **风险**: 误导性注释：维护者可能基于错误假设调整 nil 检查或在 Close 中真的置 nil 引入竞态。
- **修复**: 将 http3.go:85 注释改为与 tls/client.go:106-108 一致：'Close() 不置 nil（避免与在途查询的读竞态）——nil 检查为防御性保留'。

