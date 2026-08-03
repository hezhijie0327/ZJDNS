# Protocol 组审计 — server/protocol/{plain,tls,tlcp,dnscrypt}（22 文件，双份独立审计合并）

## CRITICAL

### C1: server/protocol/dnscrypt/udp.go:81,88,118 — 池双重归还（见综合报告 C1）
- 第 65 行 `defer func() { pool.DefaultBuffer.Put(buf) }()`（闭包捕获 buf 变量）与第 81、88、118 行三处显式 `pool.DefaultBuffer.Put(buf)` 叠加——4 条退出路径中 3 条双重归还。路径 118（`isStarted()` 循环退出）**每次优雅关停必然触发**。pool.go:125-131 无双重归还防护 → 同一 8KB 数组进池两次 → 并发 Get 双写同一缓冲 → DNS 数据损坏。第 63-64 行注释声称 "Single deferred Put covers every exit path"——显式 Put 本应在加 defer 时删除。
- 修复：删除 81、88、118 行显式 Put，只保留 defer。

## HIGH

### H6: server/protocol/tls/dtls.go:130-140 — 空闲连接永不关闭（见综合报告 H6）
- 读超时（`Timeout()==true`）被 `IsTemporaryError` 分类为临时错误 → continue → 无限续期。注释（:122-124）声称 "deadline fires → connection is closed"。**tlcp/dtlcp.go:321-327 已修复**（"a timeout was being classified as temporary and the loop spun"）——跨协议一致性遗漏。僵尸连接永久占用 serverGroup 槽位（1024 限额）→ 未认证远程 DoS 整个 TLS 协议族。
- 修复：仿 tlcp 加 `errors.As(err, &ne) && ne.Timeout() → return`。

### H7: server/protocol/tls/server.go:198-280 — Start 部分启动失败永久死锁（见综合报告 H7）
- 某协议启动失败（如 QUIC 端口被占）→ errgroup cancel ctx → DoT/DoH/DTLS goroutine 阻塞在无 ctx 感知的 `ln.Accept()`（tls.go:62、https.go:70、dtls.go:82）→ `g.Wait()` 永不返回 → errChan 永无消息 → `Start()` 挂死。DoQ/DoH3 的 `Accept(s.ctx)` 可退出——不对称。错误路径从未调用 Shutdown。
- 修复：错误路径先关闭已绑定 listener 再返回（defer 清理）。

## MEDIUM（13 项）

| # | 位置 | 描述 |
|---|------|------|
| M1 | tls/server.go:41,60-71,289-345 | listener 切片 append（errgroup goroutine 内）与 Shutdown 遍历无锁——启动失败瞬间收到信号时 data race。 |
| M2 | tls/server.go:347 + tls.go | DoT 活动连接关停无中断机制：handler 阻塞在 `io.ReadFull`，读 deadline 60s；Shutdown 的 serverGroup.Wait() 可阻塞数十秒，超 15s 预算（对照 dnscrypt 用 tcpConns 跟踪 + `SetReadDeadline(time.Unix(1,0))` 中断）。 |
| M3 | tls/tls.go:74-79,173 | 握手超时被覆盖：accept 时 `SetDeadline(10s)` 意图限制懒握手，但首次 ReadFull 前 `SetReadDeadline(60s)` 覆盖——预握手空闲连接洪泛占用槽位 60s 而非 10s。74-79 注释声称 "handler clears the deadline once the handshake completes"，实际无清除代码。 |
| M4 | tls/tls.go:241,252 | worker 中双 `defer Put`（query + response）无身份守卫——handler 返回请求本身时（quic.go:267-269 承认此场景）同一指针双 Put。修复：参照 quic.go 身份守卫。 |
| M5 | tls/dtls.go:162-164 + tlcp/dtlcp.go:352-354 | `Put(query)` 先于 `sendDTLSResponse` 使用 response——若 response==query，query 已被清零（pool.go:77），response 双 Put + Pack 空消息。修复：先响应后 Put + 身份守卫（tlcp.go:118-129 顺序正确可参照）。 |
| M6 | tls/quic.go:260-272 | 身份守卫有但顺序错：`Put(req)`（:262）先于 `respondQUIC(response)`（:264）——response==req 时 Pack 前已清零，客户端收空响应。 |
| M7 | tls/dtls.go:82-95 + dnscrypt/tcp.go:67-69 | accept 循环临时/非临时错误无退避——100% CPU 空转（其余 4 协议均有 `time.Sleep(DefaultAcceptRetryDelay)`）。 |
| M8 | tls/dtls.go:125-128 + tlcp/dtlcp.go:314-317 | SetReadDeadline 失败 `continue` 可无限空转（conn 持续失败状态）——改为 return。 |
| M9 | tls/quic.go:245-251 | 0-RTT 处理偏离 RFC 9250 §4.5：NOTIFY 被错误拒绝（注释自相矛盾，"QUERY and NOTIFY are replayable" 但代码只放行 QUERY）；不可重放事务用流级 CancelWrite（stream reset）而非排队/REFUSED+EDE。 |
| M10 | plain/server.go:61-86 | Shutdown 被 miekg 实现阻塞（fork 的 Shutdown 忽略 ctx，无条件等全部活跃连接，空闲 TCP 120s）；调用方预算仅 15s。watcher（tcp.go:42-45）用 Background ctx 无界等待。修复：Shutdown 前主动关活跃连接（SetReadDeadline(time.Unix(1,0))）。 |
| M11 | dnscrypt/tcp.go:71-72 | 非临时 accept 错误（EMFILE 等）静默 `return`——整个 TCP 监听器永久退出仅留 Debug 日志。修复：Sleep + continue + Warn。 |
| M12 | dnscrypt/tcp.go:140-145 | 证书握手回复路径未设置写 deadline，违反 WritePrefixed 的文档契约（"caller MUST set a write deadline"）——客户端停止读取时 Write 可无限阻塞，worker 槽位泄漏。 |
| M13 | tlcp/http_tlcp.go:86 | GET 请求用 base64 编码长度比对 65535——编码膨胀 4/3，合法 49-64KB wire 消息被 400 拒绝；TLS DoH（https.go:146-150）先解码再比较。 |
| M14 | tlcp/http_tlcp.go:95-99 | POST 错误 Content-Type 未返回 415（RFC 8484 §4.2.1；https.go:158-162 已实现）。 |
| M15 | dnscrypt/server.go:308,342 | `close(s.rotateCh)` 二次关闭 panic + 重启后 rotationLoop 命中已关闭 channel 立即返回——密钥停止轮换，24h 后证书过期全线失效（ErrServerAlreadyStarted 暗示重启受支持）。 |
| M16 | dnscrypt/server.go:380-384 | `current()` 对空 keys 裸索引 `s.keys[0]`——无显式不变量保护。 |
| M17 | dnscrypt/server.go:354-362 | WaitGroup Add 与 Wait 无同步（wg.Go 内部 Add 在派生 goroutine 中）——关停紧跟启动时 Wait 漏排空。 |
| M18 | tlcp/dtlcp.go:268 | 50ms 退避硬编码魔法数字（DefaultAcceptRetryDelay=100ms 已存在且值不一致）。 |
| M19 | tlcp/http_tlcp.go:24-29 | DoH 启动缺 `bound == 0` 检查——全部地址绑定失败时静默无监听（DoT 有，https.go 有）。 |
| M20 | tlcp/certs.go:75 | 叶证书未钳制到 CA 过期（tls/certs.go:109-115 有 leafNotAfter 钳制）——改小 CA 有效期即断链。 |
| M21 | dnscrypt/crypto.go:185 + generate.go:115,153,state.go:151 | `Certificate.Sign` 对 ClientMagic 前 7 字节零或 PQ 公钥长度错误直接 panic（certificate.go:330/334）；旋转路径 panic 被 HandlePanic 捕获后 rotationLoop 永久退出——密钥停止轮换。 |

## LOW（11 项）

| 位置 | 描述 |
|------|------|
| tls/server.go:58,180 | `serverCtx` 字段存储后从未读取（死字段）。 |
| tlcp/server.go:39,131 | 同上。 |
| tls/quic.go:148-149 | `streamGroup, streamCtx := errgroup.WithContext(...); _ = streamCtx`——派生 ctx 未使用。 |
| tls/quic.go:254-259 | conn 取消路径 `return` 未 `Put(req)`（轻微池周转损失）。 |
| tls/dtls.go:118-119 | 固定 8192 字节读缓冲截断大记录（>8KB 查询静默丢失；tlcp/dtlcp.go:310 同型且连接失步）。 |
| tlcp/http_tlcp.go:101 | `SplitHostPort` 丢弃有注释 ✓（符合纪律）。 |
| dnscrypt/server.go:58 | udp.go:59/tcp.go:53 wg.Add 与 Wait 无同步（漏排空窗口，LOW 级）。 |
| dnscrypt/tcp.go:140-145 | 握手响应无写 deadline（并入 M12）。 |
| tls/tls.go:192,205 | （无独立项）。 |
| tlcp/tlcp.go:100 | DoT 热路径每查询 2 次堆分配（new(dns.Msg) + slices.Clone），未走 pool——TLCP 查询路径分配开销。 |

## 跨协议一致性对照表

| 缺陷模式 | 已修复位置 | 仍存在位置 |
|----------|-----------|-----------|
| 读超时被当临时错误 → 连接不关闭 | tlcp/dtlcp.go:321-327 | **tls/dtls.go:130-140（H6）** |
| accept 错误无退避紧循环 | tls.go/quic.go/http3.go/tlcp.go | **tls/dtls.go:82-95、dnscrypt/tcp.go:67-69** |
| 池双重归还 / response==query 身份 | tls.go（有守卫但顺序错）；tlcp.go:118-129（正确参照） | **dnscrypt/udp.go（C1）；tls.go:241；dtls.go:162；dtlcp.go:352；quic.go:262** |
| 启动失败错误路径不关 listener | — | **tls/server.go Start（H7）** |
| 绑定失败检查 | tls.go DoT、https.go | tlcp/http_tlcp.go（M19） |
| 证书叶钳制 | tls/certs.go | tlcp/certs.go（M20） |

## 已排除疑点（有代码证据安全）

- tls/tls.go：池归还纪律标准模板；writer 排水逻辑无竞态。
- tls/https.go：RFC 8484 GET/POST/415/404/Cache-Control 均符合。
- tls/http3.go：连接准入 sem + errgroup 限流配合正确、0-RTT 政策与 DoQ 对称。
- tls/addr_validator.go：RFC 9000 128 条目边界 + 5min TTL。
- dnscrypt/crypto.go：decrypt 密钥快照/共享密钥缓存/票据边界均安全。
- dnscrypt/state.go：编解码长度校验完整。
- plain/tcp.go、udp.go：shutdownOnce 防护、ctx 观察 goroutine 正确。
