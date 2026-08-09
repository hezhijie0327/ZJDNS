# 04 — server/upstream/* 审计

> 本轮最高危包：37 个发现中 8 个落在此包（H1/H2/H3/M8/M9 + 2 个 LOW）。所有发现均经人工读码复核。

## H1 [HIGH] UDP 连接池 conns map 无界增长 + 死连接钉住

- **位置**：server/upstream/pool/udp.go:71（`UDPPool.conns`）、:327（`Acquire` 修剪）、:547（`replaceDead`）
- **类别**：unbounded
- **问题描述**：`conns map[string][]*UDPConn` 以"上游地址"为键。递归模式下键 = 每个不同的权威 NS 地址。三处缺口叠加：
  1. `Acquire` 的 liveConns 修剪（439-463 行）把死 conn 过滤后写回 `p.conns[key] = liveConns`，但 liveConns 为空时**不删除键**——空键永远留在 map 中。
  2. `readLoop` 空闲回收（327 行 `return` → `defer c.close()`）只标记 conn 死亡，**不通知池**；死 conn 留在 `p.conns[key]` 列表中，直到该键被再次 `Acquire` 或 `dialAndAdd` 触发 `replaceDead` 才被移除。若该地址不再被查询，死 conn（16KB 读缓冲 + socket fd + readLoop goroutine）无限期钉住。
  3. 键空间无上限：权威 NS 地址集合随查询域名多样性单调增长（攻击者可用大量唯一域名驱动大量 delegation，每个产生新键 + 最多 maxConns 个 conn）。
- **风险**：内存 + fd 随查询多样性单调增长，永不回落；死 conn 的 16KB 缓冲 × 键数堆积；maxConns/maxPipe 对全池无约束意义（只约束单键）。
- **修复建议**：
  - `Acquire` 修剪后若 liveConns 为空 → `delete(p.conns, key)`；
  - 新增周期 reaper（或复用 runBackgroundTicker）：遍历所有键，移出死 conn、删除空键；超出键数上限时按 LRU 关停最久未用键的 conn；
  - 对照点：TCP pool 的 idle 回收已正确（conn 出池即删除），UDP 池缺同一逻辑。

## H2 [HIGH] readLoop 向已关闭 collectCh 发送 → 竞态 panic + 池缓冲丢失

- **位置**：server/upstream/pool/udp.go:354-362（readLoop 发送）、:374-396（`close()` 关闭 collectCh）
- **类别**：race / panic
- **问题描述**：readLoop 在无锁状态下发送 `p.collectCh <- collectPacket{...}`（355-356 行），而 `close()`（379-392 行）持写锁关闭所有 collectCh。竞态窗口：readLoop 的 RLock 查找（338-340 行）与发送之间，`close()` 可以执行完 —— 随后 send 到已关闭 channel → **panic**。`HandlePanic` 恢复（295 行）但不 re-panic：readLoop goroutine 死亡、该 conn 静默失效（下次 Acquire 才发现）、已 acquire 的 tiered 池缓冲丢失（349 行 acquire 后 panic 前未 Release）。
- **风险**：-race 必报；运行期表现为偶发 panic 日志（`send on closed channel`）+ 连接损耗 + 池缓冲流失。多读循环的探测连接（spoofguard collect）在关停/替换时高频触发此窗口。
- **修复建议**：
  - 方案 A（最小）：发送与 close 互斥 —— readLoop 在 `c.mu.RLock()` 内做查找 + 发送（close 持写锁，天然互斥）；
  - 方案 B：不关闭 collectCh，改 per-entry `done` 原子标志 + `close()` 只置标志并 drain（配合 `!ok` 读分支）—— 但注意 executeUDPCollect 依赖 channel close 唤醒（385 行注释），方案 B 需同步改唤醒路径；
  - 无论哪种方案，`select` 的 `default` 分支已正确 Release，保持。

## H3 [HIGH] 代理路径 DoQ/DoH3 泄漏 SOCKS5 UDP relay

- **位置**：server/upstream/tls/quic.go:58-64（`dialQUIC` 代理分支）
- **类别**：leak（fd + goroutine）
- **问题描述**：`proxyDialer.ListenPacket()` 建立 SOCKS5 UDP relay（TCP 控制连接 + UDP relay 连接 + monitor goroutine，见 socks5/udp.go NOTE(M20)：**必须 Close()，否则泄漏**）。成功后 `quic.Dial(timeoutCtx, pconn, ...)` 把 pconn 交给 quic-go —— 但 quic-go 对调用方传入的 PacketConn **从不负责关闭**（`setupTransport` 设 `createdConn: false`，transport.go:423/465 只在 `createdConn=true` 时关闭）。ZJDNS 代码只在**失败**路径关闭 pconn（59-63 行），**成功**路径的 pconn 在 quic.Conn 关闭时（CloseWithError / pool 移除 / 空闲淘汰）无人关闭。
- **风险**：每个代理 DoQ/DoH3 连接 teardown 泄漏 2 个 fd + 1 个永久阻塞在 ctrlConn.Read 的 goroutine。池化连接随 pool 换手累积；长跑进程 fd/goroutine 单调增长，最终 `too many open files`。
- **已排除**：DTLCP 代理路径无此问题 —— gotlcp `Conn.Close()` 会关闭 pconn（dtlcp/conn.go:1235 `c.pconn.Close()`）；tlcp/dtlcp.go:149-163 错误路径也正确关闭。
- **修复建议**：成功 dial 后注册生命周期钩子：
  ```go
  done := conn.Context().Done()
  go func() { defer zdnsutil.HandlePanic("QUIC proxy relay"); <-done; _ = pconn.Close() }()
  ```
  quic.Conn 关闭（含 pool 移除）时 Context 必然 Done → relay 随 conn 生命周期归还。注意与 quicPool.Put 并存：conn 存活期间 relay 保持，恰为所需语义。

## M8 [MEDIUM] spoofguard collect 循环 3 条路径漏归还 tiered 池缓冲

- **位置**：server/upstream/plain/udp.go:295-297（短包/错 ID `continue`）、:300-305（hopguard 拒绝 `continue`）、:349 + pool/udp.go:268（`ReleaseCollect` 不 drain 旧 collectCh）
- **类别**：pool-leak
- **问题描述**：readLoop 为每个 datagram 执行 `acquirePacketBuf`（pool/udp.go:349-350），契约要求消费后恰好一次 `Release`（308 行正常路径）。三条违反：
  1. `len(pkt.Data) < 12 || ID 不匹配` → `continue`（无 Release）；
  2. hopguard `Validate` 拒绝 → `continue`（无 Release）；
  3. 歧义重询轮（`break collect`，384 行）经 `ReleaseCollect` 释放注册，但 `ReleaseCollect`（pool/udp.go:268-274）**不 drain** collectCh —— 排队中的 ≤4 条 collectPacket 随 channel 弃置（GC 回收，池流失）。
- **风险**：每条歧义/拒绝响应丢 1-4 条池缓冲 → 热路径持续向 GC 泄漏分配（池失效 → 每查询重新 make），违背 0-alloc 契约；-race 下高频收集器轮询加剧。
- **修复建议**：(a)(b) 两个 `continue` 前补 `pkt.Release()`；(c) `ReleaseCollect` 末尾调 `drainCollectCh`（复用 278 行已有函数）—— 注意 drain 与 readLoop 发送的竞态由 H2 修复后互斥保证。

## M9 [MEDIUM] Exchange ctx 取消 drain 丢弃池缓冲 + 过期注释

- **位置**：server/upstream/pool/udp.go:176-187（defer 清理）
- **类别**：pool-leak
- **问题描述**：ctx 取消后的晚到响应 drain（183-186 行）只 `<-resultCh` 丢弃。注释（181-182 行）声称 "The payload is a plain allocation" —— **已过期**：M-3-6 轮将 readLoop 改为 `acquirePacketBuf` tiered 池后，resultCh 载荷是池缓冲。另有 `ReleaseUDPPayload`（112 行）就是为此导出的，drain 处未用。
- **风险**：每条被取消的查询最多丢 1 条池缓冲；上游首胜取消（resolver first-wins fan-out）高频触发。
- **修复建议**：drain 改为 `if resp := <-resultCh; resp != nil { ReleaseUDPPayload(resp) }`，并修正注释。
