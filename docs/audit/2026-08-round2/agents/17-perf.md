# perf 审计

> agent: `ab92a82624b388f30`

发现数: 7

## perf-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get() 读取 msg_wire 时从不校验 0x02 格式标记，升级后命中旧格式行必 panic
- **描述**: Set() 写入新 BLOB 格式 [0x02][2:num_offsets][2*n:offsets][wire]（cache/store.go:531-540），但 Get() 读取端（cache/store.go:261-273）只检查 `len(msgWire) == 0`，从不校验 msgWire[0] == cacheFormatPrePacked(0x02)，也无 `3+numOffsets*2 <= len(msgWire)` 边界检查。v3.11.12 之前（93611d5）的 Set 写入的是纯 zstd 压缩帧（旧 store.go:340 `msgWire := zdnsutil.Compress(msg.Data)`，或 v3.11.11 的未压缩裸 wire），且 database/migration.go 的 migrations 列表（止于 3.7.1）没有任何清理 entries 的迁移——DB 文件持久化（database/db.go:89 file: DSN），升级后旧行原样保留。旧 zstd 行的 msgWire[0..3] = zstd magic 0x28 0xB5 0x2F 0xFD，于是 `numOffsets := binary.BigEndian.Uint16(msgWire[1:3])` = 0xB52F = 46415，`AcquireTTLOffsets(46415)` 分配 92KB，随后 `offsets[i] = binary.BigEndian.Uint16(msgWire[3+i*2:])` 对约 300 字节的 msgWire 越界切片 → 请求热路径 panic（被 bridge.go:59 HandlePanic 捕获），该查询被静默丢弃；92KB 切片随 panic 泄漏。v3.11.11 的未压缩旧行则 numOffsets 为随机值，可能误把压缩/裸数据当 wire 直发或同样越界 panic。
- **风险**: 升级到 v3.11.12+ 后，每个旧格式缓存行命中即 panic + 查询丢弃 + 92KB 分配泄漏，直到旧行 TTL 过期/淘汰（窗口可达 DefaultMaxCacheableTTL），实际等同对已缓存域名降级为不可服务，且是确定性的。
- **修复**: 在 Get() 解析前校验：`len(msgWire) >= 3 && msgWire[0] == cacheFormatPrePacked && 3+2*numOffsets <= len(msgWire)`，不满足则按 miss 处理（Debug 日志 + 可选删除该行），绝不能把不可信字节当偏移表。建议同时加对 0x01/旧格式的识别日志以定位脏行来源。

## perf-02 — MEDIUM

- **位置**: `cache/store.go:313`
- **类别**: perf
- **摘要**: hasLatencyData 为 true 后每次缓存命中都执行 Unpack + 每命中 map 分配 + 第二次 SQL 往返 + 重新 Pack，且无已排序标记导致反复重排
- **描述**: cache/store.go:313-319：`if s.hasLatencyData.Load() { _ = entry.Unpack(); s.sortAnswerByLatency(entry); if len(entry.Answer) > 0 { entry.rebuildResponseWire() } }`。UpdateLatency（cache/stats.go:365）一旦置位 hasLatencyData（配置 latency_probe 特性的服务器首个探测后即为 true），此后**每个缓存命中**都执行：(1) 全量 Unpack（分配全部 RR）；(2) sortAnswerByLatency 中 `rrToIP := make(map[dns.RR]string, ...)`（store.go:337，每命中一次 map 分配）；(3) `s.db.StmtIPLatency.Query(argsPtr[:]...)`（store.go:415）——每个命中第二趟 SQLite 往返（SQL N+1，直接抵消 8bda354 单轮查询优化）；(4) rebuildResponseWire（cache/cache.go:121-170：Unpack+Pack+偏移重扫，且 offsets 用裸 `make` 而非池）。Entry 无『已按延迟排序』标记，Set 时已排序（store.go:486-490）的条目、非 A/AAAA 条目（TXT/MX/NS，Answer>0 时也执行 repack）、以及 FlushDB('latency') 清空后（hasLatencyData 不清零，SQL 返回空仍每命中执行）全部重复此开销。
- **风险**: 启用 latency_probe 后热路径 QPS 上限显著下降：每命中 2 次 SQLite 往返 + 全量 unpack/pack + map 分配，违背 f7e7f13/8bda354 pre-packed 直发设计意图（其对标的正是消除 Unpack+Pack 和每查询 DB 调用）。
- **修复**: 给 Entry/BLOB 增加持久化的『latencySorted』标记位（Set 排序时与 rebuildResponseWire 后置位），Get 仅在标记未置位时执行排序+rebuild，已排序条目只做一次布尔判断；或将 ip_latency 整表加载为内存快照（表很小，rdata_ip 为 PK），Get 读快照免 SQL；rebuildResponseWire 的 offsets 改用 AcquireTTLOffsets/ReleaseTTLOffsets。

## perf-03 — MEDIUM

- **位置**: `cache/store.go:223`
- **类别**: perf
- **摘要**: 新 Get() 移除了内部 dnsutil.Canonical(qname)，但 dns64.go:49 与 mqtype.go:131 仍传原始大小写 qname，混合大小写查询缓存全部 miss（回归）
- **描述**: 旧 Get()（93611d5）首行执行 `qname = dnsutil.Canonical(qname)`；新 Get()（store.go:223-251）删除该规范化，仅在注释（store.go:222）要求调用方传入 canonical qname，SQL 按 `qname = ?` 精确匹配（schema 默认 BINARY collation，大小写敏感）。调用方核查：cache_lookup.go:41 用 qctx.Qname（handler.go 中 `strings.ToLower(qd.Header().Name)`，规范）；但 dns64.go:49 `qname := qd.Header().Name` 与 mqtype.go:131 `qname := qd.Header().Name` 仍传客户端原始大小写。对混合大小写查询（用户输入 'WWW.Example.COM' 或 0x20 case 随机化客户端）：DNS64 的 A 缓存 Get 必然 miss → 每 AAAA miss 触发一次完整上游 A 解析（dns64.go 注释明言要避免的正是此场景）；MQTYPE 的附加类型 Get miss → 重复解析，且 mqtype.go:188 `m.store.Set(qname, ...)` 以原始大小写写入缓存，产生按大小写变体的重复行、污染 entries 表。
- **风险**: 启用 DNS64 的部署中，混合大小写查询每次 AAAA miss 都多一次上游往返（延迟+上游负载）；MQTYPE 查询累积大小写变体脏行，占用缓存容量并可能撑高 evictIfNeeded 的 COUNT 重扫频率。
- **修复**: 二选一：在 Get() 内恢复 `qname = dnsutil.Canonical(qname)`（对已规范输入是廉价 no-op，且防御所有调用方）；或把 dns64.go:49 与 mqtype.go:131 改为 qctx.Qname / strings.ToLower(qd.Header().Name)。建议两者都做：Get 内兜底 + 调用方修正。

## perf-04 — LOW

- **位置**: `cache/store.go:268`
- **类别**: pool-leak
- **摘要**: Get() 解压失败路径泄漏池化的 TTL-offset 切片
- **描述**: cache/store.go:268 `offsets := AcquireTTLOffsets(numOffsets)` 从池获取切片；解压失败分支（store.go:285-289）在 clear 并归还 dbuf 后直接 `return nil, false, false`，未执行 `ReleaseTTLOffsets(offsets)`——偏移切片随该次 Get 泄漏（正常路径由 handler/response.go:67 buildFromPrePacked 归还）。此外 per 命中纠错：解压失败还会连带丢弃已分配的 offsets（若 numOffsets>8 为 92KB 级新分配）。触发条件是损坏/旧格式 BLOB（与 perf-01 同源），非正常热路径，但每次失败都漏一个池对象。
- **风险**: 损坏行被反复命中时池泄漏累积（每个泄漏对象 16B 头+底层数组），配合 perf-01 的升级场景放大内存压力。
- **修复**: 在 `offsets := AcquireTTLOffsets(numOffsets)` 后立即 `defer` 一个在成功路径（buildFromPrePacked 已归还）可被剥离的归还，或至少在解压错误 return 前显式 ReleaseTTLOffsets(offsets)。

## perf-05 — LOW

- **位置**: `cache/store.go:797`
- **类别**: inefficiency
- **摘要**: maskIP 双重分配：net.IP.Mask 已返回全新切片，额外的 make+copy 冗余
- **描述**: cache/store.go:788-801：`masked := ip.Mask(mask)` 之后又 `result := make(net.IP, len(masked)); copy(result, masked)`。net.IP.Mask（标准库）总是分配并返回新切片（`out := make(IP, n)`），因此第二次 make+copy 是纯冗余——每次 Get 的 ECS 回退候选（最多 4 个，store.go:821）多一次堆分配；注释声称的『防止调用方篡改原 IP』由 Mask 本身已保证。
- **风险**: ECS 命中路径每次 Get 最多 4 次冗余堆分配，高 QPS ECS 部署下放大 GC 压力。
- **修复**: 直接 `return ip.Mask(mask)`（保留 mask==nil 时返回原 ip 的分支），删除 make+copy 两行。

## perf-06 — LOW

- **位置**: `server/bridge.go:215`
- **类别**: perf
- **摘要**: TCP 写路径每个响应分配一次 2+N 字节 frame 切片
- **描述**: server/bridge.go:215 `frame := make([]byte, zdnsutil.DNSFramePrefixLen+len(response.Data))`——每个 TCP 响应（包括高命中率直发路径）都分配一个新的 frame 并 copy。注释说『Msg.WriteTo 会每响应分配 2+len 新 frame；改为预分配一次』——但预分配一次仍是每响应一次分配。写入在 writeMu 串行化临界区内同步完成，frame 生命周期明确，适合 sync.Pool 复用。
- **风险**: TCP 流水线高 QPS 下每响应一次中尺寸分配，可占热路径分配的相当比例（与 qctxPool/requestRecordPool 等已池化对象形成对照）。
- **修复**: 增加固定容量 frame 池（如 pool.Buffer 或专门 sync.Pool，容量 = DNSFramePrefixLen + 常见最大响应），Get/写/归还；长度>池容量的响应仍现场分配。

## perf-07 — LOW

- **位置**: `server/handler/middleware/mqtype.go:262`
- **类别**: inefficiency
- **摘要**: MQTYPE mergeRRs 用 equalRR 的演示格式 String() 比较做 O(n*m) 去重，每次比较两次分配
- **描述**: server/handler/middleware/mqtype.go:241-258 mergeRRs 对每个 src RR 线性扫描 dst，相等性判定走 equalRR（mqtype.go:262-264）`a.String() == b.String()`——每次比较生成两个演示格式字符串（每 RR 至少一次分配），在 O(n*m) 循环内放大。合并发生在每个 RFC 10029 MQTYPE 查询（新特性、非每查询热路径），但附加类型较多（如 NS+MX+TXT）时分配量可观。
- **风险**: MQTYPE 查询的合并阶段分配放大；String() 还会被 RR 的顺序敏感字段（如 AAAA 的地址格式）影响，理论上不如 wire 比较严格。
- **修复**: 改为先按 (Type, Class, 归一化 Name) 分桶缩小比较域，桶内用 packRR 后的 wire 字节比较（slices.Equal）替代 String()，或在桶内仅比较确定性字段。

