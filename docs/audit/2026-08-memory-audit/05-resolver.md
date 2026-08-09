# 05 — server/resolver/* 审计

## M1 [MEDIUM] lookupNSAddrsFromCache 未归还 GetTypes 的 TTLOffsets 池切片

- **位置**：server/resolver/ns_addresses.go:240
- **类别**：pool-leak
- **问题描述**：`GetTypes`（cache/store.go:268）→ `buildEntry`（store.go:312）从 `ttloOffsetsPool`（store.go:99）获取偏移表切片并放入返回的 `Entry.TTLOffsets`。契约：调用方消费后必须 `cache.ReleaseTTLOffsets(entry.TTLOffsets)`。仓库内其他 5 个调用点全部正确归还（response.go:67、cache_store.go:215、dns64.go:67/75、cache_lookup.go:148、cache/cache.go:166）——**唯独本函数缺失**。本函数在递归模式每个 delegation 跨越时执行（NS 地址查询是递归热路径）。
- **风险**：`ttloOffsetsPool` 被永久抽干 → 每次调用重新 `make([]uint16, ...)`（分配 + GC 压力），池机制形同虚设；4 个交叉 agent 独立命中，确认度高。非无界内存（GC 可回收），属池纪律 + 热路径分配问题。
- **修复建议**：循环内对每个 `found[i] && entry != nil` 的 entry 归还：
  ```go
  defer func() { for _, e := range entries { if e != nil { cache.ReleaseTTLOffsets(e.TTLOffsets) } } }()
  ```
  或按现有风格在 return 前显式归还（注意 entries 是数组，遍历即可）。

## M10 [MEDIUM] queryNameserversConcurrent first-wins 双发竞态驻留池消息

- **位置**：server/resolver/nameserver.go:160-163（winner send + cancel）、:46（`resultChan := make(chan *dns.Msg, 1)`）
- **类别**：pool-leak（race 窗口）
- **问题描述**：winner 发送后调用 `cancel()`，但 cancel 传播有窗口。时序：winner 发送填满 resultChan → 消费者读走（缓冲空）→ 另一 goroutine 在 cancel 生效前通过校验并 `select` —— send 成功（缓冲空）→ 它自己也调用 `cancel()` 并返回。第二条响应驻留在 resultChan，函数返回后 channel 不可达 → 池消息被 GC 丢弃（pool 流失）。消费者只读一次（first-wins 语义正确，不会错发第二条）。
- **风险**：每次 first-wins 竞态窗口丢 1 条池消息；递归 fan-out（首胜取消）高频触发。影响为池 churn + GC 压力，非永久泄漏。
- **修复建议**：消费者取到首个响应后、函数返回前非阻塞排空：
  ```go
  for {
      select {
      case m := <-resultChan:
          pool.DefaultMessage.Put(m)
      default:
          return resp, verdict, err
      }
  }
  ```
  （或把 winner 的 `cancel()` 提前到 send 之前 + 接受双发送由 drain 兜底。）

## M3b [MEDIUM] delegation 快照加载无界分配

- **位置**：server/resolver/delegation_snapshot.go:105（`make([]string, 0, n)` n=uint32）、:143（`dsWire := make([]byte, uint32)`）
- **类别**：snapshot
- **问题描述**：与 cache/snapshot.go:80 同构（见 02-domain.md M3a）：文件内 uint32 计数直接驱动 `make` 容量，损坏文件可触发 4GB 级分配 OOM；`readStrings` 的 `n` 无上限且与文件剩余内容无一致性校验。
- **风险**：同 M3a —— 本地文件损坏 → OOM 崩溃。
- **修复建议**：n ≤ 合理上限（如 64）；与 M3a 同批修复（同一加载模式，建议抽共用校验辅助或统一约定）。

## M4 [MEDIUM] delegation 快照只写不读

- **位置**：server/resolver/resolver.go:203（LoadDelegationSnapshot 定义）、server/tasks.go:58-62（周期保存）、tasks.go:337-341（关停保存）
- **类别**：dead-code / 功能缺口
- **问题描述**：保存端完整（周期 + 关停），但 `LoadDelegationSnapshot`（含 resolver.go 包装）**无任何生产调用点** —— grep 全库仅定义处命中。对比：cache/latency 快照在 server/server.go:94/101 正确加载。即 delegation 缓存的重启恢复功能是半成品：文件照写，重启从不读回。
- **风险**：配置了 delegation state file 的用户获得"持久化已启用"的假象；重启后 delegation 缓存冷启动，从 root 重新 walk（性能回归但功能正确）。
- **修复建议**：在 server/server.go 启动路径补 `LoadDelegationSnapshot`（与 cache/latency 并列，错误处理对齐"文件不存在=冷启动 / 损坏=告警"）；或若刻意不做持久化，删除保存端（二选一，别留半成品）。

## L1 [LOW] 嵌套重复 TryProbeNSAddrs

- **位置**：server/resolver/ns_addresses.go:123-127
- **类别**：dead-code
- **问题描述**：`if probe.TryProbeNSAddrs(r.cache, addrs) { if probe.TryProbeNSAddrs(r.cache, addrs) { go ... } }` —— 内层调用与外层完全相同，第二次调用要么冗余执行（两者都 true 时探测函数跑两遍），要么外层 true 内层 false 时**抑制**后台探测。任何情况下都是错误的。
- **修复建议**：删除内层 if，保留单层。
- **注**：x-resource agent 将其描述为"抑制后台 NS 延迟探测"（即第二条返回 false 时探测被跳过），与本描述一致，同一发现。

## 其余（递归 walk / DNSKEY singleflight / probe / delegation 周期清理）

- **无发现**。已确认：
  - delegation 周期清理（delegation_snapshot.go:158-170）正确：Range 收集过期键 + Delete，且由 runBackgroundTicker 托管（errgroup + ctx cancel + ticker.Stop）；
  - DNSKEY singleflight（commit b84906e）无等待者泄漏：错误/超时路径均释放；
  - 递归 walk 每跳 ctx 超时正确，无嵌套 timer 泄漏（迁移声明的修复未复发）；
  - probe 包 goroutine 均有 owner + HandlePanic。
