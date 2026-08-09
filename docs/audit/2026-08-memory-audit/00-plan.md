# 00 — 修复计划（逐项）

审计：2026-08 全内存迁移后大审计（第 1 轮）。报告：`12-synthesis.md` 及各分册。

## Sprint 1 — CRITICAL/HIGH（立即修复）

| ID | 修复动作 | 涉及文件 | 验证 |
|----|----------|----------|------|
| H1 | UDP 池键空间有界化：(a) 周期清扫所有键下的死 conn 并删除空键（复用现有 idle 回收 + 新 reaper 或惰性删除——`Acquire`/`replaceDead` 路径补空键删除）；(b) 可选：键空间 LRU 有界（lrumap 化 `conns` 或按最近使用清扫） | server/upstream/pool/udp.go | `go test -race ./server/upstream/...` + 递归压测观察 `conns` 长度稳定 |
| H2 | readLoop 发送与 close() 关闭协调：(a) 发送前持有 `c.mu.RLock` 直到 send 完成（close 持写锁，互斥）；或 (b) 不 close channel，改 per-pending `closed` 标志 + 唤醒；恢复兜底用 `recover()` 或非阻塞确认 | server/upstream/pool/udp.go:354-362 | `go test -race -run UDP ./server/upstream/pool/...`；关停风暴下无 panic 日志 |
| H3 | QUIC 代理路径归还 relay：`quic.Dial` 成功后注册 `go func(){ <-conn.Context().Done(); pconn.Close() }()`（pooled conn 在 pool 移除时同样触发——Done 在 conn 关闭时必然关闭）；错误路径已有 `pconn.Close()` 保持不变 | server/upstream/tls/quic.go:58-64 | 代理压测 DoQ 后 `lsof` 确认 fd 数稳定 |
| H4 | latencies 字段改 `atomic.Pointer[lrumap.Map[...]]`（Load/Store 三处：stats.go:61/263、store.go:457、latency_snapshot.go:62），或 `FlushDB("latency")` 改 `s.latencies.Clear()` 就地清理（与 cache 分支一致，零同步） | cache/stats.go:61 | `go test -race ./cache/...` + 压测中触发 `zjdns.latency.clear` |
| H5 | 快照两阶段写盘：锁内只把条目序列化进本地缓冲（或先拷贝 msgWire 引用），释放锁后写 + Sync + rename。lrumap.Range 的锁范围只覆盖拷贝 | cache/snapshot.go:19、cache/latency_snapshot.go:20 | 压测 + 快照周期内 `p99` 延迟无尖峰 |

## Sprint 2 — HIGH/MEDIUM（下个发布周期）

| ID | 修复动作 | 涉及文件 | 验证 |
|----|----------|----------|------|
| M1 | `lookupNSAddrsFromCache` 循环内对每个 entry `defer`/显式 `cache.ReleaseTTLOffsets(entry.TTLOffsets)`（参照 cache_lookup.go:148 模式） | server/resolver/ns_addresses.go:240 | `go test -short ./server/resolver/...` |
| M2 | byRcode 有界化：固定 canonical 桶（0-23 + 1 个 extended 桶合并 4095 扩展 RCODE），或 lrumap.Map[int,*topk.Map] 小容量；`ResetJournal` 同时删除 map 键 | cache/statsjournal.go:76 | 单测：注入 4096 个 RCODE 后内存有界 |
| M3 | 快照加载边界校验：wire_len ≤ 64KB（DefaultMaxMsgSize 系）、key_len ≤ 255、ns_count/addr_count/ds_len 有界（≤ 合理上限，如 64）；加载失败时已 Set 条目回滚或至少日志如实说明"部分加载" | cache/snapshot.go:80、server/resolver/delegation_snapshot.go:105,143 | 单测：构造损坏文件不 OOM、不 panic |
| M4 | 接入 delegation 快照加载：`server/server.go` 启动路径调用 `LoadDelegationSnapshot`（与 cache/latency 加载并列，同样区分冷启动/损坏）；或明确移除保存端 | server/server.go、server/resolver/resolver.go:203 | 重启后 delegation 缓存命中日志 |
| M5 | DoT 首读限定握手 deadline：`firstRead := true`，首读前 arm 10s，之后永久 60s（删掉循环顶部的 SetReadDeadline） | server/protocol/tls/tls.go:187 | 慢速客户端测试：>10s 间隔的查询不被断开 |
| M6 | CallGroup entry 身份化：`Join` 返回 leader 的 entry 令牌（或 Done 接收 entry 指针），Done 不再按 key 重查——发布前验证 entry 仍是 map 中的当前条目 | internal/pending/pending.go:287 | `-race` 单测：LRU 淘汰 + 并发 Join/Done 交错 |
| M7 | CleanupLatency 门控改为 latencyPath（或任一 state file 配置时都执行） | server/tasks.go:47 | 仅配 latency 文件时观察 CleanupLatency 运行日志 |
| M8 | collect 循环归还纪律：(a) 短包/错 ID `continue` 前 `pkt.Release()`；(b) hopguard 拒绝 `continue` 前 `pkt.Release()`；(c) `ReleaseCollect` 补 `drainCollectCh`（或调用方统一 drain） | server/upstream/plain/udp.go:295,304、server/upstream/pool/udp.go:268 | `-benchmem` 观察 spoofguard 路径 allocs 下降 |
| M9 | Exchange ctx 取消 drain 改为调用 `releasePacketBuf`（按 cap 分类归还）+ 修正过期注释 | server/upstream/pool/udp.go:183 | 同上 |
| M10 | first-wins 后非阻塞排空 resultChan（`for { select { case m := <-resultChan: pool.Put(m); default: return } }`） | server/resolver/nameserver.go:160 | `-race` 递归压测 |

## Sprint 3 — LOW（顺带清理）

| ID | 修复动作 |
|----|----------|
| L1 | 删除嵌套重复的 `if probe.TryProbeNSAddrs` 内层 |
| L2 | 移除 zjdns.delegation.clear 端点（FlushDB 无 delegation 分支），或让 FlushDB("delegation") 真正清空 delegation 缓存 |
| L3 | 关停快照包一层 `context.WithTimeout`（复用 DefaultShutdownTimeout） |
| L4 | 删除 parse.go 孤儿 "// SQL" 注释 |
| L5 | 协议处理器加 `if response == query { response = nil }` 守卫（dtls.go:186、tls.go、tlcp、dnscrypt） |
| L6 | stale-prefetch 路径补 `m.refreshGroup != nil` 守卫（与 fresh 路径 76 行一致） |

## 提交规范提醒

- 一个 commit 一类修复；主题行描述具体修复内容（`fix: bound UDP pool key space ... (H1)`），不做跨维度混提
- 每个 Sprint 后：`go build` + `go test -short ./...` + `go test -race`（涉及并发修改的包）+ benchmark 对比（带 `-benchmem`）
- 热路径修改（H2/H4/M1/M8/M9）注意 allocs/op 契约：任何新增分配即为回归
