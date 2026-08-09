# 08 — 交叉审计：内存 / 池纪律 / 资源生命周期 / goroutine

> 全库 grep 驱动的 4 项交叉扫描结果。除已归档至各分册的发现外，其余全部干净。

## 8.1 Goroutine 生命周期（~30 处 `go func` 逐一核对）

- 全部有 `defer HandlePanic`；
- 全部有 owner / cancel 路径（errgroup 追踪、ctx.Done、channel 关闭、conn 关闭）—— 唯一例外：
  - **H3**：socks5 relay monitor goroutine（socks5/udp.go:201-210）—— 它本身有正确退出路径（ctrlConn.Read 返回即清理），但持有它的 QUIC 代理路径泄漏 pconn 导致 goroutine 永不退出（04-upstream.md H3，根因在调用方）；
  - `setupSignalHandling` goroutine（tasks.go:194）：注释明确说明不被追踪、随信号/ctx 退出 —— 设计如此，非泄漏（但关停路径若新增 Wait 依赖需同步追踪，注释已提醒）。
- `errgroup.SetLimit`：queryNameserversConcurrent（limit=min(NS数, DefaultMaxConcurrentNS)）、cache refreshGroup、TLCP serverGroup、backgroundGroup 全部正确限流。

## 8.2 sync.Pool 纪律（33 对 Get/Put + 4 个独立池）

| 池 | 结论 |
|----|------|
| `pool.DefaultMessage` / `pool.DefaultBuffer` | 健康：defer Put + 错误路径归还 + `Data=nil` 纪律；唯一缺口 L5（防御性身份守卫，当前不可达） |
| tiered packet 池（packetBufSmall/Medium，udp.go:87-129） | **4 处缺口**：H2（panic 丢失）、M8（3 条 collect 路径）、M9（drain 不归还） |
| `ttloOffsetsPool`（store.go:99） | **M1**：ns_addresses.go:240 唯一不归还调用点（其余 5 处正确） |
| `socks5ReadBufPool` / `socks5WritePool` | 健康：defer 归还 + 只清已用前缀 |
| zstd `decompressBufPool` | 健康：defer 归还 + clear |
| `spoofguardBufPool` | 健康：defer 归还 + 只清已用前缀 |

**模式教训**：池归还缺口全部集中在"多轮循环 + continue 分支"和"ctx 取消竞态窗口"两类路径 —— 单返回点函数（defer 覆盖全部路径）无一出错。修复 M8/M9 时应优先考虑单返回点重构或 defer。

## 8.3 Close() 幂等性（全部 `func.*Close()` 核对）

- `UDPConn.close`：`closeOnce` 正确；
- `Dialer.Close`（socks5）：锁内清理 + nil 检查，幂等；
- `Cache.Close`：no-op（纯内存，合理）；
- 各 protocol Server Shutdown：`shutdownOnce` / 状态守卫确认；
- `dtlcpListener.Close`：先收集后关闭（锁外 IO，符合方法论 §6.1.2）；
- **唯一例外**：L3 —— 关停快照保存无超时（tasks.go:328，见 09 分册）。

## 8.4 Timer / Ticker / AfterFunc

- `runBackgroundTicker`（tasks.go:70-84）：统一 errgroup + ctx cancel + `ticker.Stop()` —— 全部 6 个周期任务（state maintenance / cookie rotation / ECS refresh / prefetch cooldown / tcpWriteMu sweep）走此通道，正确；
- follower 超时 timer（pending.go:264-278）：`timer.Stop()` + 未取通道 drain 正确；
- spoofguard pollTimer：循环内 Reset 正确；
- **唯一例外**：M5 —— DoT 10s deadline 重武装（03 分册）。

## 8.5 无界增长清单（全库 map/channel 核对）

| 结构 | 结论 |
|------|------|
| cache.entries / latencies / delegations（lrumap） | 有界（maxEntries/latencyMax/配置上限）✓ |
| hopguard 基线（lrumap 256） | 有界 ✓ |
| pending CallGroup（lrumap maxPending） | 有界（但见 M6 语义竞态）✓ |
| tcpWriteShards（周期 sweep） | 有界（sweep 验证：refs==0 + cutoff 双条件）✓ |
| prefetch cooldown（周期清理） | 有界 ✓ |
| DNSCrypt ticket / keys | 固定窗口轮换 ✓ |
| **rcodeJournal.byRcode** | **无界（M2）** ✗ |
| **UDPPool.conns** | **无界键空间 + 死连接钉住（H1）** ✗ |
| quicPool / tlsPool conn 池 | 有界（maxConns）✓ |

## 8.6 Context 传播

- `context.Background()`/`TODO()`：仅 main 与 shutdown 根 ctx —— 符合方法论排除项；
- `WithoutCancel`：仅后台 DNSKEY fetch 等有明确设计意图处；
- 所有 I/O 函数第一参数为 ctx（协议 handler 的 `ServeDNS` 为接口签名例外）。
