# logging 审计

> agent: `a92d3d6b944521981`

发现数: 3

## bridge-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: H1 修复不完整（regression）：TCP 请求路径 refs 双重 Add(1)（98 行锁内 + 110 行 Do 后），每个请求只减一次，refs 永不归零，sweep 再次成为死代码，tcpWriteShards 每连接无界增长
- **描述**: handleDNSRequest 的 TCP 分支对 entry.refs 无条件执行两次 Add(1)：line 98（shard.mu 锁内）与 line 110（capacityOnce.Do 之后，注释与 line 94-97 完全重复）。而释放只有两条互斥路径：line 115（capacity 饱和 SERVFAIL 分支 defer）与 line 155（goroutine 退出 defer）。逐请求计数：正常路径 +1+1-1=+1，SERVFAIL 路径 +1+1-1=+1，任何路径都残留 +1。9f6001c（H1 fix）声称 refs 现在能归零，但该提交只是在锁内新增了一个 Add(1) 而保留了 Do 后原有的 in-flight Add(1)——placeholder 删了，ref 却翻倍了。后果：sweepTCPWriteMu（tasks.go:137 要求 refs.Load()!=0 则跳过）对任何服务过请求的 entry 永远无法删除，tcpWriteShards[16].entries 随每个不同 (ip:port) TCP 连接永久累积 entry（含 writeMu + capacity 两个 channel），与第一轮 H1 同型的无界内存增长。tasks_test.go 的测试手工模拟 +1/-1（tasks_test.go:27,38），不经过 handleDNSRequest 真实路径，未捕获该残差。这是上一轮 H1 修复不完整引入的回归。
- **风险**: 长时间运行的服务器在持续 TCP 流量（尤其客户端轮换源端口/NAT 场景）下，每连接一条永久 entry，tcpWriteShards 地图无界增长直至内存耗尽；sweep 机制形同虚设。
- **修复**: 删除 line 110（或 line 98）两个 Add(1) 之一：锁内 Add 已封堵 create→ref 窗口的 TOCTOU（sweep 与请求共享 shard.mu），单个 Add(1) 即可，同时删除重复的 'In-flight refcount' 注释之一。补充断言测试：通过 handleDNSRequest 真实路径发一个 TCP 请求后断言 entry.refs.Load()==0。

## logging-01 — MEDIUM

- **位置**: `server/handler/middleware/response.go:58`
- **类别**: perf
- **摘要**: pre-packed 直发快速路径用全局 log.IsDebug() 门控，组件过滤的 debug 配置（如 log_level: "debug:UPSTREAM"）会静默禁用全部查询的直发路径
- **描述**: line 58：`if !st.shouldAddEDNS && qctx.OriginalName == "" && !log.IsDebug() && !cache.WireHasDNSSEC(qctx.Res.Data)`。log.IsDebug()（internal/log/log.go:344）只读全局 level（m.level.Load()），不检查 componentFilter。ParseLevelFilter 对 "debug:UPSTREAM" 这种组件过滤配置同样把全局 level 置为 Debug（log.go:280-285）。因此用户仅为排查某个组件（如 UPSTREAM）开启 debug 时，所有查询的 cache-hit 直发路径（~21ns/0 allocs，见 f7e7f13 提交信息）被跳过，退化为 Unpack+EDNS+Pack 路径（~300ns/9 allocs），而实际产生的 debug 输出只有 UPSTREAM 组件——RESULT/QUERY 组件被过滤不打印。性能代价白白付出且完全静默。handler.go:127/179 的 IsDebug() 门控只多一次 TypeToString 查表，无此问题；dnsutil.go:185 LogHandshake 在握手路径，也无此问题。
- **风险**: 用户按文档配置组件过滤 debug（config.example/文档推荐用法）后，缓存命中热路径整体回退一个数量级而没有任何提示，且无法通过日志观察到原因。
- **修复**: 快速路径门控改为检查实际消费解包结果的组件过滤（如 RESULT 组件是否 debug），或在 log 包暴露 IsComponentDebug("RESULT") 之类的组件感知查询；或在 doc/注释中明确说明 debug 级别（含组件过滤）会禁用直发路径。

## logging-02 — MEDIUM

- **位置**: `cache/store.go:254`
- **类别**: logging
- **摘要**: 每查询缓存路径存在错误门控的 Warnf：Get() 254/288/429 与 ReverseLookup（stats.go:88/108）在持续 SQLite 故障时每查询打一条 Warn 刷屏
- **描述**: store.Get 由 CacheLookup.Wrap 每查询调用（cache_lookup.go:47），其内部非 ErrNoRows 的 SQL 错误打 log.Warnf（store.go:254 'get query failed'），zstd 解压失败打 Warnf（store.go:288），lookupIPLatencies 迭代失败打 Warnf（store.go:429）；cache/stats.go:88/108 的 PTR 查询同理位于每 PTR 查询路径。三者均为错误门控（正常时不触发），但方法论 §6.1-8 明确要求 info/warn 不得出现在每查询路径（ServeDNS/Wrap/Exchange/每查询中间件路径）。一旦 SQLite 持续故障（磁盘满、库损坏、modernc 驱动 busy），每次查询都产生一条 Warn 日志刷屏，淹没真正需要人工介入的信号。
- **风险**: 数据库故障期间日志洪泛（QPS×1 条/秒），日志文件/终端被刷屏、磁盘压力加剧，掩盖故障本身；违反每查询一条日志原则。
- **修复**: 对这几处每查询路径的错误门控 Warn 加采样/限流（如 errors 计数到 N 才打一条），或将级别降为 Debug 并在 Stats 中暴露计数器；PTR 路径（stats.go:88/108）同法处理。

