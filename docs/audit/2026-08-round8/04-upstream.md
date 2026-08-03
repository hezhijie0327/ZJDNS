# Upstream 组审计 — server/upstream/*（24 文件，双份独立审计合并）

## CRITICAL

### C3: server/upstream/dnscrypt/state.go:126 + tlcp/http_tlcp.go:54 — Close 置 nil 后查询路径无守卫（见综合报告 C3）
- `dnscrypt.Client.Close()`（client.go:254-261）置 `c.cache = nil`；`tlcp.Client.Close()`（client.go:43-54）置 `c.httpClient = nil`。查询路径 `c.cache.Get(cacheKey)` / `c.httpClient.Get(key)` 无 nil 守卫 → nil 指针解引用 panic。同文件 buildState:237 / deleteState:262 有守卫；tls/https.go:44 有守卫——跨协议一致性遗漏。
- 触发：SIGTERM 关停期间 in-flight 查询；DNSCrypt UDP→TCP fallback（client.go:173）在 GFW 环境每查询重入 state()——panic 概率高。
- 修复：补 nil 检查，或 Close 不置 nil（改用 lrumap.Clear()，参照 upstream/client.go:312-315 已确立的"不置 nil"模式）。

## HIGH

### H10: 手工 dial 路径无 I/O 期限（系统性，见综合报告 H10）
- 根因：`socks5.DialContext`（socks5/tcp.go:47-48）握手后 `SetDeadline(time.Time{})` 清除全部 deadline，注释称"调用方管理 I/O 超时"。
- 受影响调用方（均未恢复 deadline，`Read` 不观察 ctx）：
  1. `plain/tcp.go:73-109 exchangeViaProxy` — 对端挂死时永久阻塞（代理路径无 keepalive 兜底）
  2. `plain/udp.go:256-287 exchangeViaProxyUDP` — UDP 丢包时永久阻塞（高频路径）
  3. `tls/tls.go:78-98 exchangeOverTLS` — TCP keepalive 4.5 分钟兜底但 9s 契约失效
  4. `tlcp/tlcp.go:61-84 exchangeOverTLCP` — 违反 ReadTCPMsg 自身 godoc（"caller MUST set read deadline"）
  5. `tls/dtls.go:88-112` — pion 默认 readDeadline 永不过期，握手+读均无界
  6. `tlcp/dtlcp.go:36-101` — 握手有 ctx 但握手后读写无 deadline
- 后果：每次故障查询永久泄漏 goroutine + fd，且上游组 first-win 逻辑被拖死。
- 修复模板（已存在）：`dnscrypt/cert.go:63-68`（context.AfterFunc + SetDeadline）+ `client.go:130-133`（ctx.Deadline 派生）——抽 `setConnDeadline(ctx, conn)` 辅助函数推广全部 6 处。

### H11: server/upstream/tls/http3.go:167-178 — quic.Dial 失败 pconn 未关闭
- 代理路径 `quic.Dial(ctx, pconn, ...)` 失败时 UDP PacketConn 泄漏。同包 quic.go:56-63 有注释 "quic-go 不接管失败 dial 的 PacketConn——不要泄漏 UDP socket" 并做了 `_ = pconn.Close()`。
- 修复：错误路径照抄 quic.go 关闭。

## MEDIUM（9 项）

| # | 位置 | 描述 |
|---|------|------|
| M1 | warmup.go:69-82 | `warmUpConnection` switch 缺 dtls/tlcp/http-tlcp/dtlcp 四个分支（IsSecureProtocol 过滤包含它们）——预热静默空转，首查询仍付完整握手延迟。 |
| M2 | warmup.go:28-42 | proxyDialer 失败不缓存 → 无效 proxy 每查询重新解析 + Warn 刷屏（skipVerifyWarned/hopguardWarned 有 dedup，此处没有）。 |
| M3 | tls/client.go:184-199 | `getQUICConfig` check-then-set（Get→New→Set 非 LoadOrStore）——并发 miss 产生多份 QUIC Config/TokenStore，0-RTT token store 分裂，resetQUICConfig 无法自愈被覆盖者。修复：LoadOrStore（与 createDOHClient 一致）。 |
| M4 | tls/quic.go:149-228 | doQUICQuery 流读取不响应 ctx 取消（固定 9s deadline），`CancelRead` 在 defer 中执行但返回等读取结束——取消后最多延迟 9s（对照 pool/tcp.go Exchange 用 select ctx.Done 可立即返回）。修复：AfterFunc(ctx, CancelRead)。 |
| M5 | dnscrypt/client.go:207-231 | minQueryLen 达 4096 上限后 TCP 上的 truncated 响应被直接返回成功（RFC §5.4.2 要求 TCP fallback；TCP 上仍 TC 属异常应报错）。 |
| M6 | dnscrypt/client.go:149 + cert.go:76 | 每查询 `make([]byte, 4096)` 热路径堆分配（其余协议均复用 pool.DefaultBuffer）。 |
| M7 | dnscrypt/client.go:101-104 | `prepareQuery`（含 X-Wing KEM encapsulate）在 state.mu 持锁期间执行——PQ 模式下同服务器并发查询序列化在 KEM 计算上。 |
| M8 | pool/tcp.go:190-196 | `writeMu.Lock()` + WriteTCPMsgSegmented 无写 deadline——停滞对端（窗口满）时排队查询阻塞到 60s 空闲超时（9s 超时语义被破坏）。 |
| M9 | plain/udp.go:285 | `exchangeViaProxyUDP` 强制 `response.ID = msg.ID`，静默接受 ID 不匹配响应——TCP 代理路径（tcp.go:104-107）明确校验拒绝。 |
| M10 | tls/client.go:106-123 + tlcp/client.go:47-53 | Close 置 nil 与在途查询 Get 构成无同步数据竞争（https.go:44 的 nil 检查只防 panic 不防 race）——违背 upstream/client.go:312-315 "不置 nil" 模式。 |

## LOW（9 项）

| 位置 | 描述 |
|------|------|
| pool/tcp.go:47,311 | `done` channel 只被 close 无人消费（死字段）。 |
| socks5/socks5.go:157 | `_, _ := net.SplitHostPort(...)` 丢弃错误无注释。 |
| tls/https.go:114 | 使用已弃用的 `net.Error.Temporary()`（Go 1.18+ deprecated）。 |
| tls/tls.go:84-97 + quic.go:226 | 响应 ID 校验跨协议不一致：代理 TCP 路径校验、exchangeOverTLS 不校验、DoQ 不校验 ID==0（RFC 9250 §4.2.1）。 |
| dnscrypt/client.go:208 | `maxQueryLen = 4096` 函数内魔法数字与已有常量重复。 |
| pool/quic.go:143-149 | WarmUp 注释"池满时连接被丢弃"与实际行为（复用现有连接）不符。 |
| dnscrypt/client.go:149-155 | UDP 响应读取无 `n >= len(buf)` 截断检查（cert.go:83-85 有）——超限数据报静默截断触发误 deleteState。 |
| tlcp/tlcp.go:71-75 | ALPN 检查的类型断言恒真（dialTLCPConn 返回类型即 *tlcp.Conn）——防御分支不可达。 |
| tls/quic.go:89-97 | 0-RTT 拒绝后的 fresh 重试二次失败时连接不移除不关闭（注释声明"被拒连接不得再入池"未落实）。 |
| 测试覆盖 | plain/、tls/、tlcp/ 三个包均无 _test.go——5 个无界 I/O 泄漏与 Close 竞态全部无测试防护。 |

## 已排除疑点（有代码证据安全）

- upstream/client.go：closeOnce、fallback 逻辑、池归还核查通过。
- dnscrypt/crypto.go：state 可变字段全部在 state.mu 下读写，executeOnce 预取字段均不可变。
- dnscrypt/cert.go：context.AfterFunc 取消模式是组内唯一正确的 read 中断实现——**应作为模板推广**。
- socks5/udp.go：monitor goroutine 有 HandlePanic + 身份检查；Close 幂等；池缓冲 clear 后归还。
- pool/quic.go：Put 去重、dead conn 拒绝、Shutdown 锁外 close 正确。
- pool/tcp.go：readLoop 双重 RLock 校验+投递原子性、ABBA 规避、resp.Data=nil 纪律均正确。
- warmup.go：`proxyDialer` 不缓存失败有注释解释（nil 入 LRU 会 poison 条目 + 跳过 OnEvict）。
