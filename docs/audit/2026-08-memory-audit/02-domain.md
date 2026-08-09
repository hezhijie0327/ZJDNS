# 02 — cache / config / edns / zone / ruleset / snapfile 审计

## H4 [HIGH] FlushDB("latency") 无同步指针替换竞态

- **位置**：cache/stats.go:61（`s.latencies = lrumap.New[...]`）
- **类别**：race
- **问题描述**：迁移后唯一未用就地清理的 FlushDB 分支。`s.latencies` 是普通字段，替换写入与两类并发读者竞态：
  - 热路径：cache/store.go:457 `s.latencies.Get(ip)`（每次带延迟数据的缓存命中）；
  - 后台探测：cache/stats.go:263 `s.latencies.Set(ip, ...)`（latency probe goroutine）。
  触发点：CHAOS `zjdns.latency.clear`（loopback-only）或 `.db.flush latency`。对比：`cache` 分支用 `s.entries.Clear()`（lrumap 内锁，零同步），`hasLatencyData` 已是 atomic.Bool —— 只有 latencies 替换漏网。
- **风险**：`-race` 必报；64 位下表现为"flush 丢失"（并发 Set 落入废弃旧 map）；32 位构建为撕裂指针 → 下一次热路径 Get 解引用 nil → panic。压测 + 清理命令并发即复现。
- **修复建议**（二选一，推荐后者，零同步）：
  1. 与 cache 分支一致：`s.latencies.Clear()` 就地清空；
  2. 或 `atomic.Pointer[lrumap.Map[string, latEntry]]`，stats.go:61 Store、store.go:457 / stats.go:263 / latency_snapshot.go:62 Load。

## H5 [HIGH] 快照保存持 entries LRU 锁跨磁盘写

- **位置**：cache/snapshot.go:19（SaveSnapshot）、cache/latency_snapshot.go:20（SaveLatencySnapshot）、internal/lrumap/lru.go:188-196（Range 持锁）
- **类别**：blocking
- **问题描述**：`snapfile.Save` 的回调内 `c.entries.Range(...)` 对每个条目执行 `w.Write`（每次写 = syscall），而 `lrumap.Range` 全程持有写锁（lru.go:189 `m.mu.Lock()` + defer Unlock）。`snapfile.Save` 末尾还有 `f.Sync()`。调度点：server/tasks.go:46-64（周期 5 分钟）+ shutdownServer（tasks.go:327-341）。
- **风险**：大缓存（默认 10000 条目 × 最大 64KB）在慢盘（HDD/NAS）上每次周期保存停顿**所有**缓存 Get/Set 数秒——全局 DNS 延迟尖峰，无日志、无超时，静默。迁移前 SQLite 路径从不在持久化期间串行化查询访问，属迁移引入的回归。
- **修复建议**：两阶段——锁内只做轻量拷贝（把每个条目的 msgWire 引用 + 元数据拷入本地缓冲，或序列化到 `bytes.Buffer`），释放锁后统一 Write + Sync + rename。Range 锁范围只覆盖拷贝，绝不覆盖 I/O。
- **注**：同样模式在 `SaveDelegationSnapshot`（resolver/delegation_snapshot.go:44）—— delegation 缓存小，风险低，但建议一并修复（同一模板）。

## M2 [MEDIUM] rcodeJournal.byRcode 无界增长

- **位置**：cache/statsjournal.go:76（`record` 惰性创建）、:61（map 定义）
- **类别**：unbounded
- **问题描述**：`byRcode map[int]*topk.Map[string]` 为每个首次出现的 RCODE 分配一个满容量（1000 键）的 topk journal，**无任何删除路径**（`ResetJournal` 只对既有 map 调 Clear）。键空间受攻击者影响：`rec.Rcode` 来自 `uint16` RCODE + OPT 扩展位（cache_store.go:157 → resolver.go:41），0..4095 任意值可被上游/递归响应对手驱动。
- **风险**：极端情况 4096 个桶 × 1000 键 ≈ 250-400MB 永久占用；现实场景 rcode 多样性小（个位数），暴露限于恶意上游或长跑高多样流量——但它是迁移后**唯一**无界结构（其余全部 LRU/topk 有界）。
- **修复建议**：固定 canonical 桶（RCODE 0-23 各自 + 1 个 "extended" 桶吞并 4095 个扩展值），或 `lrumap.Map[int, *topk.Map[string]]` 小容量；`ResetJournal` 顺便删除键。

## M3a [MEDIUM] cache 快照加载无界分配 + 部分加载误导

- **位置**：cache/snapshot.go:80（`wire := make([]byte, int(uint32))`）、:69（key_len 64KB 上限 OK）
- **类别**：snapshot
- **问题描述**：`wire_len` 是文件中的 4 字节 uint32，直接 `make([]byte, n)` —— 损坏/篡改文件可一次性申请最大 4GB。且 readEntry 中途出错时已 `Set` 的条目保留（84 行先 Set 后返回 err），`LoadSnapshot` 注释（61-62 行）声称"truncated snapshot is silently ignored — starts cold"——实际是**部分加载** + 冷启动日志误导（调用点 server/server.go:94 的日志措辞）。delegation 侧同构问题见 M3b。
- **风险**：本地文件损坏（磁盘坏块、旧版本格式错乱）→ OOM 崩溃；部分加载导致缓存含过期/半旧数据而无感知。
- **修复建议**：加载侧边界校验（与保存侧 nolint 注释的"bounded"假设对齐）：wire_len ≤ 64KB、key_len ≤ 255、失败时如实记录"部分加载 N 条"。

## 其余（edns / zone / ruleset / snapfile 基础层）

- **无发现**。已确认：
  - zoneTable/ruleTable atomic.Pointer 快照替换正确（旧快照 GC 释放，无 goroutine 持有）；
  - snapfile 基础实现正确：temp+rename 原子、错误路径清 `.tmp`（snapfile.go:25）、`f.Sync` 先于 rename；
  - edns cookie/padding 无 per-client 状态泄漏；
  - config 默认值无孤儿字段（其余见 09-migration-remnants.md）。
