# context 审计

> agent: `ac56552430636a420`

发现数: 3

## context-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: regression: TCP 请求路径 refs 双次 +1 单次 -1，refcount 永不归零，sweep 永久死代码，shard.entries 无界增长（第一轮 H1 修复不完整）
- **描述**: handleDNSRequest TCP 分支对 entry.refs 执行两次 Add(1)（line 98 锁内、line 110 锁外，两处注释完全相同），而每次请求只有一次 Add(-1)（line 115 SERVFAIL defer 或 line 155 goroutine defer，互斥分支）。净效果每请求 +1：第 N 个请求完成后 refs = N，永不为 0。tasks.go:137 sweep 检查 `if entry.refs.Load() != 0 { continue }`，因此任何服务过请求的 entry 永远无法被淘汰——这正是第一轮审计 H1（12-synthesis.md 第 19-30 行）描述的"refs 永不归零，sweep 成死代码，tcpWriteMu 无界增长"缺陷。第一轮修复（93611d5，声称"refs 归零 + 单测"）实际保留了旧 placeholder 的 +1（旧代码 newEntry.refs.Add(1) 占位被改为锁内 Add 后未删除锁外重复 Add），bridge_test.go 中也不存在"请求完成后 refs.Load()==0"的断言测试（仅 truncateWire 测试）。delta 中的 shard 重写（f7e7f13）原样保留了双 Add。
- **风险**: tcpWriteShards.entries 随每个客户端连接累积一条永久 entry（含 writeMu+capacity 两个 channel），进程生命周期内无界内存增长；同时 sweep 每次持 shard.mu 迭代持续膨胀的 map，与每个 TCP 请求热路径的 shard.mu.Lock 竞争，运行越久锁竞争越重——长期运行高并发 TCP/DoT 场景下资源耗尽（§4.1 HIGH）。
- **修复**: 删除 line 110 的重复 refs.Add(1)（保留锁内 line 98 的 Add 作为唯一 in-flight ref——shard.mu 已保证 create+Add 与 sweep check+delete 原子互斥，无 TOCTOU，无需占位 ref），SERVFAIL/goroutine 的 -1 即与之平衡；并补上第一轮推荐的断言测试：请求完成后 entry.refs.Load() == 0（该测试在第一轮即被要求但从未实现）。

## context-02 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:148`
- **类别**: resource
- **摘要**: MQTYPE-Query 附加类型数量无上限校验，单查询触发 N 次串行完整解析（放大攻击向量）
- **描述**: RFC 10029 MQTYPE 新中间件（本 delta 新增）的 validate()（line 97-123）只检查 meta 类型与重复，不限制 mq.Types 的数量；merge()（line 148-190）对每个附加类型同步串行调用 m.resolve()——cache miss 时在递归模式下执行完整递归解析（resolver.Query 内部 WithTimeout DefaultRecursiveResolveTimeout=30s），转发模式下是完整上游查询（9s）。OPT 选项数据上限使单查询可携带约 2000 个类型（4KB 查询），而整个循环在响应发出前完成（Wrap line 90 同步调用 merge），无整体 WithTimeout 聚合约束。恶意客户端一条 500 字节 UDP 查询可迫使服务器做最多约 2000 次串行完整解析（每次 9-30s 窗口），每次解析又产生多条上游查询——每个攻击包放大为数千次上游解析工作。
- **风险**: 新的资源放大 DoS 向量：1 条 MQTYPE-Query 触发 ~2000 倍服务器解析工作（递归模式最严重），攻击者用少量 UDP 包即可打满服务器上游负载与 CPU；长时间占用查询 goroutine 也阻塞 TCP sem 配额。
- **修复**: validate() 中增加附加类型数量上限（如 RFC 10029 精神下的合理值，建议抽取为 config 常量如 DefaultMQTYPEListLimit，超限 FORMERR），或在 merge() 中设置整体工作预算（累计超时或按已完成类型数上限截断并返回已合并部分）。

## context-03 — LOW

- **位置**: `server/handler/middleware/cache_lookup.go:149`
- **类别**: context
- **摘要**: serveExpiredWithRefresh 接收 ctx 但函数体完全不使用——客户端取消信号既未传播也未检查，参数为死参数
- **描述**: serveExpiredWithRefresh(ctx context.Context, ...)（line 149）的参数 ctx 在函数体内（line 149-276）零引用：前台刷新 goroutine 使用 m.refreshCtx（服务器后台 ctx）+ WithTimeout(DefaultBackgroundTimeout)（line 170-174），后台更新 goroutine 同样只 select refreshCtx.Done()（line 266），等待主循环只 select done/timer.C。属于方法论 §4.2 的"Context 断裂"弱形式——函数签名声明 ctx 但内部绕过取消链，且该 ctx 实际就是服务器根 ctx（handler.go 以 h.ctx 贯穿整个链），参数对任何调用方都不具备可观察语义。
- **风险**: 误导性 API：调用方会以为传入的 ctx 可以终止刷新/限制等待，实际完全无效；后续若有人试图依赖它（如按客户端断连取消前台刷新）会得到与直觉相反的行为；维护者也无法从签名判断该函数真正受哪个上下文约束。
- **修复**: 从签名删除 ctx 参数（保留 qctx 与 m.refreshCtx 的约束），并在函数注释中明确"刷新受 refreshCtx + DefaultBackgroundTimeout 约束，与客户端查询生命周期无关"；或在 Wrap 调用处（line 141）传递时显式注释 ctx 未使用的设计原因。

