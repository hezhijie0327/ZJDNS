# 29 · 交叉分析：性能

> 审计 Agent：Phase 2b · Perf
> 范围：全项目热路径分配、前缀扫描效率、QPS 瓶颈


现在我已进行彻底审计，拥有了所有必要的数据。以下是完整的性能审计报告。

---

## ZJDNS 性能审计报告

### 1. 严重：`ttl.NowUnix` 默认为 `time.Now().Unix()` 而非 `log.NowUnix()`

- **文件:** `internal/ttl/ttl.go:15`
- **严重程度:** 高
- **问题:** 变量 `NowUnix` 默认为 `func() int64 { return time.Now().Unix() }`。所有 TTL 函数（`IsExpired`、`RemainingTTL`、`CanServeExpired`、`ShouldPrefetch`）都调用 `ttl.NowUnix()`，而这些函数在每个 DNS 查询的热路径上被调用（`cache.Get`、`cache.store.go` 中的 `minTTL`、`ProcessRecords` 等）。生产代码中没有任何地方覆盖此默认值（验证：`grep -rn 'ttl\.NowUnix'` 返回空结果）。`time.Now().Unix()` 会触发系统调用，而 `log.NowUnix()` 执行的是来自缓存时间的原子加载操作。
- **风险:** 每次 DNS 查询都会产生多个不必要的系统调用。每收到一个查询，`cache.Get` 就会调用 `IsExpired`，而每条缓存记录可能被多次检查（在 `shouldPrefetch`、`canServeExpired` 等中）。在每秒数千次 QPS 的情况下，这会导致大量时间花在 `time.Now()` 上。
- **建议修复:** 将 `internal/ttl/ttl.go:15` 的默认值更改为：
    ```go
    var NowUnix = func() int64 { return log.NowUnix() }
    ```
    需要导入 `zjdns/internal/log`。`internal/ttl` 和 `internal/log` 都位于 `internal/` 层级，因此这是允许的。如果测试需要确定性时间，它们会自行重写该变量。

### 2. 严重：在递归名称服务器热循环中 `baseMsg.Copy()` 产生堆分配

- **文件:** `server/resolver/nameserver.go:71`
- **严重程度:** 高
- **问题:** 在 `queryNameserversConcurrent` 中（针对每个授权名称服务器运行一个 goroutine），`msg := baseMsg.Copy()` 会对整个 DNS 消息（包括问题、额外 EDNS OPT 记录等）执行深层复制。`dns.Msg.Copy()` 会对消息结构体和每个 RR slice 进行堆分配。对于典型的递归查询，这发生在：13 个根服务器 + 约 4 个 TLD NS + 约 2 个权威 NS = 每次递归解析约 19 次分配。（CNAME 追踪会增加更多。）
- **风险:** 每次递归解析时 GC 压力显著增加。19 次分配 × 每条消息约 500 字节 = 每次递归查询约 10KB 的 GC 压力。
- **建议修复:** 使用池化消息代替 Copy：
    ```go
    msg := pool.DefaultMessage.Get()
    msg.Question = make([]dns.Question, 1)
    msg.Question[0] = baseMsg.Question[0]
    msg.RecursionDesired = baseMsg.RecursionDesired
    msg.CheckingDisabled = baseMsg.CheckingDisabled
    msg.UDPSize = baseMsg.UDPSize
    ```
    然后通过等效的 `dnsutil.SetQuestion` 设置问题，而不是深度复制整个消息。

### 3. 严重：在 zone 前缀扫描热路径中 `PrefetchValues=true`

- **文件:** `zone/zone.go:268`（在 `queryExact` 中）和 `zone/zone.go:350`（在 `scanWildcardSuffix` 中）
- **严重程度:** 高
- **问题:** 区域评估中的两个 BadgerDB 前缀扫描都设置 `opts.PrefetchValues = true`。这会强制 BadgerDB 在迭代时预取每个匹配键的值数据，即使在 `item.Value()` 回调中按需加载已经足够。区域评估在每个 DNS 查询上运行（在区域中间件的热路径中）。
- **风险:** 每次查询在区域前缀扫描中增加不必要的内存带宽和 I/O。对于大型区域规则集（数千条记录），会预取大量键不需要的值。
- **建议修复:** 将两个调用都设置为 `PrefetchValues = false`。`item.Value()` 回调本身确保按需加载：
    ```go
    opts.PrefetchValues = false
    ```

### 4. 中等：在 zone 前缀扫描热路径中将 BadgerDB 键从 `[]byte` 转换为 `string`

- **文件:** `zone/zone.go:276`（`extractMatchTagsFromZoneKey(string(item.Key()))`）和 `zone/zone.go:356`（`k := string(item.Key())`）
- **严重程度:** 中等
- **问题:** 从 BadgerDB 键获得的 `[]byte` 被转换为 `string`，这会在堆上分配。在 `queryExact` 和 `scanWildcardSuffix` 中，这发生在区域评估的每次迭代中，而区域评估在每个 DNS 查询上运行。
- **风险:** 每次区域扫描命中时都会发生堆分配。特别是 `scanWildcardSuffix` 会对每个后缀运行一次迭代器扫描（最多 16 个标签后缀），匹配时会调用 `string(item.Key())`。
- **建议修复:** 重写 `extractMatchTagsFromZoneKey` 和 `parseZoneKeyTypeClass` 以使用 `[]byte` 而非 `string`。在 `parseZoneKeyTypeClass` 中，`[]byte(key[...])` 的转换可以通过直接在 `[]byte` 上进行 `binary.BigEndian.Uint16` 来消除。

### 5. 中等：在 ReverseLookup 前缀扫描中将 BadgerDB 键从 `[]byte` 转换为 `string`

- **文件:** `cache/stats.go:78`
- **严重程度:** 中等
- **问题:** `k := string(item.Key())` 在 `ReverseLookup` 内部的前缀扫描中被调用。`ReverseLookup` 在 PTR 中间件中为每个 PTR 查询调用（`server/handler/middleware/ptr.go:43`）。每次迭代都会分配键字符串，这在 PTR 查询的热路径上。
- **风险:** PTR 查询时堆分配。如果逆向缓存较大，此扫描会检查多个条目，每个条目都有一次分配。
- **建议修复:** 通过使用 `item.Key()` 的 `[]byte` 重写 `ReverseLookup` 来消除 `string()` 转换。在 `string(k)` 上进行 NUL 字节扫描也可以直接在 `[]byte` 上进行：`bytes.IndexByte(k, 0)`。

### 6. 中等：在 stats 前缀扫描中 `PrefetchValues=false`，但在 ReverseLookup 中丢失

- **文件:** `cache/stats.go:63`（ReverseLookup）对比 `cache/stats.go:166,186`（Stats 方法）
- **严重程度:** 中等
- **问题:** `cache/stats.go:63` 上的 ReverseLookup 前缀扫描设置 `PrefetchValues = true`，这意味着每次都会预取值数据。ReverseLookup 可能会在 PTR 中间件的每个 PTR 查询中被调用（每次 DNS 查询可能发生一次）。
- **风险:** 在 PTR 查找期间预取不必要的值数据，这会导致额外的 I/O。
- **建议修复:** 在 `cache/stats.go:63` 上设置 `PrefetchValues = false`。

### 7. 中等：`RecordRequest` 每次都规范化 qname

- **文件:** `cache/stats.go:33`
- **严重程度:** 中等
- **问题:** `qname := dnsutil.Canonical(r.Qname)` 在每次 `RecordRequest` 调用时都会被调用，而该调用发生在每个 DNS 查询上（命中、未命中、过期、错误）。大多数调用者已经规范化了 qname（`cache/store.go:78` 中的 `Get` 在查找前执行 `Canonical`，`store.go:230` 中的 `Set` 也执行 `Canonical`）。
- **风险:** 对于大多数记录（已经规范化的），每次查询都进行一次不必要的字符串规范化分配。
- **建议修复:** 添加可选字段或约定，当调用者已经规范化 qname 时跳过规范化。

### 8. 低：`net.JoinHostPort` 在 NS 地址解析中的分配

- **文件:** `server/resolver/nameserver.go:422,427,436`（`resolveNSAddrType`）
- **严重程度:** 低
- **问题:** 每个 NS 地址都调用 `net.JoinHostPort` 以创建 `ip:port` 字符串。对于具有 13 个根服务器（每个有两个地址）和后续层的递归解析，这会有多次分配。
- **风险:** 每次递归解析大约有 30+ 次小字符串分配。
- **建议修复:** 使用 `ip + ":" + port` 连接，并配合预分配的端口字符串常量（例如 `":"+config.DefaultUDPPort`），或者缓存常用的 `JoinHostPort` 结果。
    ```go
    var defaultUDPPortSuffix = ":" + config.DefaultUDPPort
    *nsAddrs = append(*nsAddrs, ip + defaultUDPPortSuffix)
    ```

### 9. 低：TCP `exchangeViaProxy` 中的 `writeBuf` 堆分配

- **文件:** `server/upstream/plain/tcp.go:86`
- **严重程度:** 低
- **问题:** `writeBuf := make([]byte, 2+len(msg.Data))` 在 TCP 非池化回退路径上为每次 TCP 交换分配一个新的缓冲区。
- **风险:** 每个 TCP 回退查询都有一次分配。缓冲区大小在 2 字节到 ~65535 字节之间，具体取决于消息。
- **建议修复:** 添加一个 `sync.Pool` 用于临时写入缓冲区。

### 10. 低：`time.Now()` 在 `ExecuteQuery` 中的使用（上行客户端热路径）

- **文件:** `server/upstream/client.go:137`
- **严重程度:** 低
- **问题:** `start := time.Now()` 在每次上游查询时都被调用；`result.Duration = time.Since(start)` 需要使用 `time.Time`。这无法简单地替换为 `log.NowUnixNano()`，因为 Duration 需要纳秒精度的时间差。
- **风险:** 每次上游查询时产生一次系统调用，但相比于网络延迟（10-100 毫秒），开销（约 100ns）可以忽略不计。
- **建议修复:** 可以忽略，但可以参考：如果不需要 `time.Duration` 类型，可以使用 `log.NowUnixNano()` 作为替代方案。

### 11. 低：`time.Now()` 在 spoofguard 多读取循环的 `processPacket` 中

- **文件:** `server/upstream/plain/udp.go:184,319`
- **严重程度:** 低
- **问题:** `now := time.Now()`（第 184 行）位于多读取循环内部，每轮最多调用一次。`s.lastRecv = time.Now()` 位于每个 `processPacket` 调用的内部（第 319 行）。循环轮询间隔为 `DefaultSpoofguardPollInterval`（通常为 50-100 毫秒），因此相对于轮询延迟来说，每秒只增加了一次 `time.Now()` 调用，开销较小。
- **风险:** 低——额外开销相较于网络轮询可以忽略不计。
- **建议修复:** 可选：将 `time.Now()` 调用提升到循环顶部，但鉴于回报微乎其微，不建议费心。

### 12. 低：在热路径上重复的 `cloneRRs` 函数（`cache/cache.go` 和 `server/handler/pending.go`）

- **文件:** `cache/cache.go:176-185` 和 `server/handler/pending.go:148-158`
- **严重程度:** 低
- **问题:** `cloneRRs` 在两个包中重复实现，具有略微不同的 nil 检查行为。`cache` 版本总是为所有 RR 调用 `Clone`；`pending` 版本有 nil 检查。这种重复意味着一个可能会在另一个之前被优化或修复，从而导致细微的错误或低于标准的性能。
- **风险:** 低——主要是代码质量问题。两个包中的 `dns.RR.Clone()` 都会产生堆分配。
- **建议修复:** 将 `cloneRRs` 提取到一个共享位置（例如 `internal/dnsutil`）。但这可能会引入导入循环；将检查作为次要问题处理。

---

**总结:** 首要修复事项是 `ttl.NowUnix`（影响所有缓存路径）、`baseMsg.Copy()`（在递归解析中影响大对象分配）和 `PrefetchValues=true`（在区域扫描中增加不必要的 I/O 开销）。这三项修复可显著减少每次查询的分配和系统调用。