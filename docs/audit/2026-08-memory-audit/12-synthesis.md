# 12 — 综合报告（2026-08 全内存迁移后大审计）

> 审计轮次：第 1 轮（见 AUDIT-METHODOLOGY.md §概述 历史记录表）
> 主题：SQLite 移除后的全内存架构首轮大审计，重点排查内存泄漏 corner case
> 方法：AUDIT-METHODOLOGY.md 框架 — 7 个包级 agent + 5 个交叉 agent 并行审查（12 agent，827 次工具调用），随后由主会话对全部 HIGH/MEDIUM 发现逐条人工读码复核
> 结论先行：**未发现 CRITICAL 级泄漏；确认 5 个 HIGH、10 个 MEDIUM、6 个 LOW，其中与用户怀疑的"内存泄漏 corner case"直接相关的有 5 个（H1/H2/H3/M1/M2），其余为竞态、阻塞和迁移残留。**

## 一、发现汇总（按严重程度）

| ID | 严重度 | 类别 | 位置 | 一句话 |
|----|--------|------|------|--------|
| H1 | HIGH | unbounded | server/upstream/pool/udp.go:71,327 | UDP 连接池 conns map 无界增长（递归模式按权威 NS 地址为键），死连接被钉住不回收 |
| H2 | HIGH | race | server/upstream/pool/udp.go:356 | readLoop 向已关闭 collectCh 发送 → 竞态 panic（被 HandlePanic 恢复）+ 池缓冲丢失 + 连接静默死亡 |
| H3 | HIGH | leak | server/upstream/tls/quic.go:58 | 代理路径 DoQ/DoH3 连接关闭时泄漏 SOCKS5 UDP relay：2 个 fd + 1 个 monitor goroutine/连接 |
| H4 | HIGH | race | cache/stats.go:61 | FlushDB("latency") 无同步替换 latencies 指针，与热路径 + 探测 goroutine 竞态 |
| H5 | HIGH | blocking | cache/snapshot.go:19 + lrumap.Range | 快照保存持 entries LRU 锁跨磁盘写，周期/关停保存时全部缓存操作停顿 |
| M1 | MEDIUM | pool-leak | server/resolver/ns_addresses.go:240 | lookupNSAddrsFromCache 未归还 GetTypes 的 TTLOffsets 池切片（4 个 agent 独立命中） |
| M2 | MEDIUM | unbounded | cache/statsjournal.go:76 | rcodeJournal.byRcode 按 RCODE 键无界增长，永不收缩，键空间受攻击者影响 |
| M3 | MEDIUM | snapshot | cache/snapshot.go:80 + delegation_snapshot.go:105,143 | 快照加载按 uint32 计数无界 make → 损坏文件可 OOM；错误后部分加载且日志误导 |
| M4 | MEDIUM | dead-code | server/resolver/resolver.go:203 | delegation 快照只写不读 — LoadDelegationSnapshot 无生产调用点 |
| M5 | MEDIUM | timer | server/protocol/tls/tls.go:187 | DoT 10s 握手 deadline 每次读取重新武装，60s 空闲超时从未生效 |
| M6 | MEDIUM | race | internal/pending/pending.go:287 | CallGroup.Done 把被淘汰 leader 的结果发布到替代 entry 并误删之 |
| M7 | MEDIUM | unbounded | server/tasks.go:47 | CleanupLatency 错误挂在 cache state file 门控下，仅配 latency 文件时不物理清理 |
| M8 | MEDIUM | pool-leak | server/upstream/plain/udp.go:295,304,349 | spoofguard collect 循环 3 条路径漏归还 tiered 池缓冲（短包/错 ID、hopguard 拒绝、ReleaseCollect 不 drain） |
| M9 | MEDIUM | pool-leak | server/upstream/pool/udp.go:183 | Exchange ctx 取消 drain 丢弃池缓冲且注释已过期（声称 plain allocation） |
| M10 | MEDIUM | pool-leak | server/resolver/nameserver.go:160 | first-wins 双发竞态把第二条池响应驻留在 resultChan，函数返回后池消息丢失 |
| L1 | LOW | dead-code | server/resolver/ns_addresses.go:123 | 嵌套重复 TryProbeNSAddrs 调用 |
| L2 | LOW | dead-code | server/init.go:93 | zjdns.delegation.clear 是静默 no-op（FlushDB 对 delegation 无操作） |
| L3 | LOW | snapshot | server/tasks.go:328 | 关停快照保存无超时，磁盘挂起可永久阻塞关停 |
| L4 | LOW | dead-code | cmd/zjdns/cli/parse.go:29 | 孤儿 "// SQL" 注释块 |
| L5 | LOW | pool-leak | server/protocol/tls/dtls.go:186 | DTLS/DTLCP/DoT 处理器对 ServeDNS 返回请求本体无守卫（当前不可达，防御性缺口） |
| L6 | LOW | other | server/handler/middleware/cache_lookup.go:103 | stale-prefetch 路径在 refreshGroup==nil 时获取 gate 无释放（test-only 布线） |

## 二、主题分析

### 主题 1：UDP 连接池是泄漏高发区（H1/H2/M8/M9，4 个发现）

`server/upstream/pool/udp.go` 是本轮最大热点。三个独立问题叠加：

1. **无界键空间**（H1）：递归模式下每个权威 NS 地址一个键，`Acquire` 的 liveConns 修剪从不删除空键，`readLoop` 空闲回收只标记 conn 死亡、不移出列表 —— 死 conn（16KB 读缓冲 + fd + goroutine）在键下钉住直到该键被再次获取。权威 NS 集合随查询多样性无界增长（攻击者可控）。
2. **关闭协调缺失**（H2）：`close()` 在锁内关闭 collectCh，而 readLoop 在锁外发送 —— 竞态 panic（恢复后 readLoop 死亡、连接静默失效）+ 池缓冲丢失。
3. **归还纪律缺口**（M8/M9）：collect 模式的短包/错 ID/拒包路径和 ctx 取消 drain 路径共 5 处漏归还 tiered 池缓冲；`ReleaseCollect` 从不 drain 排队中的 collectCh（每次最多 4 条）。

**根因**：池代码是 M-3-6 轮修复中逐步打补丁演化的结果，归还纪律和关闭协调分散在多个路径，缺乏统一约定。

### 主题 2：快照持久化（新基础设施）的正确性缺口（H5/M3/M4/L3，4 个发现）

迁移引入的 snapfile 层基础实现正确（temp+rename 原子、.tmp 清理、Save 错误返回），但三个使用点有缺口：

1. **锁内写盘**（H5）：`lrumap.Range` 持锁全程，SaveSnapshot 在锁内做每个条目的 `w.Write` + `f.Sync` —— 大缓存 + 慢盘（HDD/NAS）时每 5 分钟一次全缓存停顿数秒，且关停时同样发生。
2. **无界加载**（M3）：`cache/snapshot.go:80` 与 `delegation_snapshot.go:105,143` 用文件中的 uint32 直接 make —— 损坏/篡改文件可一次性分配 4GB 崩溃。部分加载后条目残留，日志却声称"starting cold"。
3. **只写不读**（M4）：delegation 快照周期性保存 + 关停保存都执行，但 `LoadDelegationSnapshot` 没有任何生产调用点 —— 重启后 delegation 缓存从未恢复，功能半成品。

### 主题 3：迁移后竞态（H4/M6，2 个发现）

- `FlushDB("latency")` 的指针替换是迁移后唯一未用 `Clear()` 就地清理的分支（其他分支都正确），与热路径和探测 goroutine 竞态（H4）。
- `CallGroup.Done` 的 key 查找式发布在 LRU 淘汰后会把旧 leader 结果写进替代 entry（M6）—— 这是 pending 包在 lrumap 化（OnEvict 引入）后遗留的语义缺口：**entry 身份应由 Join 返回给 leader，而非按 key 重查**。

### 主题 4：池归还纪律总体健康，个别路径漏网（M1/M8/M9/M10/L5）

33 处 `pool.Get/Put` 对中大部分正确（defer Put + 错误路径归还 + `resp.Data = nil` 纪律良好），漏网集中在：
- `GetTypes` 的 TTLOffsets 池（M1，4 agent 命中，热路径）
- spoofguard collect 循环（M8）
- first-wins 双发窗口（M10）
- 协议处理器对"ServeDNS 返回请求本体"的防御性守卫缺失（L5，当前不可达）

### 主题 5：SQL 迁移残留（M4/M7/L2/L4，4 个发现）

`cee48da` 的清扫不彻底：`// SQL` 孤儿注释、`zjdns.delegation.clear` 死端点、CleanupLatency 门控错位、delegation 快照只写不读。均非 SQL 代码残留（代码已 100% 无 SQL），是**文档/端点/逻辑门控**层面的残留。

## 三、Sprint 行动计划（按方法论 §2.1）

| Sprint | 范围 | 内容 |
|--------|------|------|
| **Sprint 1（立即）** | HIGH | H1（池键空间有界化 + 死连接回收）、H2（collectCh 关闭协调）、H3（QUIC 代理 relay 归还）、H4（latency 原子指针）、H5（快照两阶段写盘） |
| **Sprint 2（下个发布）** | MEDIUM | M1（TTLOffsets 归还）、M2（byRcode 有界化）、M3（快照加载边界校验）、M4（接入 delegation 快照加载）、M5（DoT deadline 首读限定）、M6（CallGroup entry 身份化）、M7（CleanupLatency 门控修正）、M8（collect 归还纪律）、M9（drain 归还）、M10（first-wins 排空） |
| **Sprint 3（顺带）** | LOW | L1-L6 全部 |

每个 Sprint 完成后：`go build` + `go test -short ./...` + benchmark 对比基线（`-benchmem`，分配回归判定）。

## 四、覆盖清单

- [x] internal/* 基础包（pool/pending/lrumap/topk/snapfile/stamp/log/ttl/ipdetect）
- [x] config / cache / edns / zone / ruleset
- [x] server/protocol/{plain,tls,tlcp,dnscrypt}
- [x] server/upstream/*（含 pool/socks5/doh/doq）
- [x] server/resolver/*（含 dnssec/probe/delegation 快照）
- [x] server/handler + middleware 全链
- [x] server/defense/*（hopguard/poisonguard/spoofguard/splitguard）
- [x] server/tasks.go 后台任务 + 关停路径
- [x] cmd/zjdns CLI 残留
- [x] 全部 `go func`（~30 处）：均确认有 HandlePanic；除 H3 的 socks5 monitor 与信号 handler 外均有 owner/cancel 路径
- [x] 全部 `sync.Pool`（DefaultMessage/DefaultBuffer/tiered packet pools/ttloOffsetsPool/socks5 池/zstd 缓冲池）：33 对 Get/Put，除 M1/M8/M9/M10 外全部配对
- [x] 全部 `Close()`：除 L3 外幂等（sync.Once/atomic 守卫确认）
- [x] 全部 lrumap.New 调用点：值类型持资源者均设 OnEvict（pending CallGroup、DTLS 会话、hopguard）
- [x] 全部 ticker/AfterFunc：runBackgroundTicker 统一管理，ticker.Stop 确认
- [x] 快照 Save/Load 全部调用点：任务调度、错误路径、.tmp 清理、重启加载

## 五、正向确认（无问题项）

- HandlePanic 覆盖率 100%（含 UDP 池 reader、socks5 relay monitor、后台 ticker）
- `runBackgroundTicker` 模式正确（errgroup + ctx cancel + ticker.Stop）
- snapfile 基础实现正确：temp+rename 原子、所有错误路径清 .tmp、Sync 先于 rename
- DTLCP 代理路径**无** relay 泄漏（gotlcp `Conn.Close` → `pconn.Close`，conn.go:1235 已核实）
- 迁移后所有 map 均有界（lrumap/topk），唯一例外 M2（byRcode）
- shutdownServer 多层超时保护完善（唯一缺口 L3）
- 缓存 Get 克隆-per-命中正确（slices.Clone），共享 wire 竞态未复发
