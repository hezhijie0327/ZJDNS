# upstream 审计

> agent: `ab33a6eae1ebf2285`

发现数: 6

## upstream-01 — MEDIUM

- **位置**: `server/upstream/dnscrypt/state.go:104`
- **类别**: resource
- **摘要**: state() 读取 c.cache 无 nil 守卫，Close() 置 nil 后任何 DNSCrypt 查询在 lrumap.Get 的 nil 接收者上确定性 panic
- **描述**: dnscrypt.Client.Close()（client.go:277-284）在 cacheMu 下执行 c.cache = nil。state()（state.go:103-105）`c.cacheMu.Lock(); state, ok := c.cache.Get(cacheKey)` 读取该字段后直接调用 Get——lrumap.Map.Get 内部 `m.mu.Lock()` 对 nil 接收者解引用即 panic（lru.go:68）。同一文件另外两处读取点都做了守卫：buildState（state.go:220 `if c.cache == nil { return nil, errors.New("dnscrypt client closed") }`）和 deleteState（state.go:237 `if c.cache != nil`）——state() 是唯一缺失守卫的读取点，是 H5 同类模式（Close 写 nil 与热路径读）在 dnscrypt 中的保留实例，虽受 cacheMu 保护无数据竞态，但 Close 之后（或关闭窗口内）任何到达 Execute 的查询都会命中 nil map panic。可达路径：server/tasks.go 关闭流程中 background/refresh 组等待超时（DefaultBackgroundShutdownTimeout 到期仍继续）或监听器仍有 in-flight 查询时执行 queryClient.Close()，后续查询调用 state() 即 panic（被 HandlePanic 恢复后查询静默失败并打 PANIC 日志）。
- **风险**: 关闭窗口内（shutdown 超时、listener 未排干）的 DNSCrypt 查询确定性 panic：每次关闭都产生 PANIC 日志与查询丢失，违背 buildState/deleteState 已实现的"client closed 干净错误"契约；与 H5 修复方向（不置 nil 或加守卫）相矛盾。
- **修复**: 在 state() 的 Get 调用前加 nil 守卫（对齐 buildState）：`c.cacheMu.Lock(); if c.cache == nil { c.cacheMu.Unlock(); return nil, errors.New("dnscrypt client closed") }; state, ok := c.cache.Get(cacheKey); c.cacheMu.Unlock()`。

## upstream-02 — MEDIUM

- **位置**: `server/upstream/plain/udp.go:166`
- **类别**: pool-leak
- **摘要**: executeUDPMultiRead 的 ctx.Done 早退路径未归还已收集的池化候选（sg.last/sg.prev/sg.nonEDNS），与错误路径 214-223 行的归还不一致
- **描述**: 多读循环顶层 `select { case <-ctx.Done(): return nil, ctx.Err() }`（udp.go:164-167）直接返回，此时 spoofguardState 可能已持有 1-2 个来自 pool.DefaultMessage.Get() 的候选（s.last/s.prev/s.nonEDNS，均为 *dns.Msg）。同一函数 214-223 行的网络错误路径显式 Put 这三个候选，ctx 取消路径却全部丢弃。该路径非常常见：queryUpstream（forward.go）first-win 后 cancel(groupCtx)，其余上游 goroutine 的 spoofguard 多读循环立即被取消；被取消时循环中已收集的候选池项被 GC 而非归还，sync.Pool 每次丢失都重新分配。在 spoofguard/hopguard 开启且多上游配置下，几乎每次查询都丢 1-2 个池项。
- **风险**: 池归还纪律破坏：每次被取消的 spoofguard 查询泄漏 1-2 个池化 *dns.Msg，持续 QPS 下 sync.Pool 命中率下降、每查询额外分配，与错误路径（已归还）行为不一致。
- **修复**: 在 ctx.Done 分支归还候选：`case <-ctx.Done(): if sg.last != nil { pool.DefaultMessage.Put(sg.last) }; if sg.prev != nil { pool.DefaultMessage.Put(sg.prev) }; if sg.nonEDNS != nil { pool.DefaultMessage.Put(sg.nonEDNS) }; return nil, ctx.Err()`。

## upstream-03 — MEDIUM

- **位置**: `server/upstream/dnscrypt/cert.go:83`
- **类别**: context
- **摘要**: fetchCertOverTCP/UDP 用裸 net.Dial（无 ctx）拨号，deadline 在拨号完成后才应用——TCP connect 可超出查询预算数倍
- **描述**: fetchCertOverTCP（cert.go:83）与 fetchCertOverUDP（cert.go:52）使用 `net.Dial("tcp", addr)` / `net.Dial("udp", addr)`，ctx 的 deadline 只在 dial 成功之后通过 SetDeadline 应用到连接（cert.go:89-91）。TCP connect 期间 ctx 取消/过期完全无效：对黑洞/防火墙丢弃 SYN 的 DNSCrypt 服务器，connect 阻塞到操作系统超时（Windows 约 21s，Linux 可达 2 分钟），远超 DefaultDNSQueryTimeout（9s）的查询预算，state() 调用方（Execute→executeOnce）所在 goroutine 被按住。对比同包 executeOnce（client.go:129-130 用 dialer.DialContext(ctx,...)）和 plain/tls/tlcp/socks5 全部走 ctx 感知拨号，cert.go 是唯一裸 net.Dial 的路径。
- **风险**: DNSCrypt 证书获取（state miss 时每次查询必经）在服务器不可达时阻塞 goroutine 超过查询预算 2-13 倍，超时契约失效；并发证书 miss 时 goroutine 堆积（有界但延迟放大）。
- **修复**: 改用 `(&net.Dialer{}).DialContext(ctx, "tcp", addr)`（TCP）并为 dial 设置 `net.Dialer{Timeout: time.Until(deadline)}`（复用 plain/udp.go 或 socks5.DialContext 的既有模式）；UDP 拨号非阻塞可保留 net.Dial。

## upstream-04 — LOW

- **位置**: `server/upstream/tlcp/tlcp.go:89`
- **类别**: validation
- **摘要**: exchangeOverTLCP 不回验响应 ID（response.ID != msg.ID），与 exchangeOverTLS（tls.go:107-110）、exchangeViaProxy（plain/tcp.go:114-117）的既有校验不一致；DTLS/DTLCP 同缺
- **描述**: exchangeOverTLCP 用 WriteTCPMsg + ReadTCPMsg 完成单次交换后直接返回 response，无 ID 校验。同构路径均已有校验：tls/exchangeOverTLS（tls.go:107 `if response.ID != msg.ID`）、plain/exchangeViaProxy（tcp.go:114）、DoQ（quic.go:229 校验 ID==0）；而 tlcp.go:86-93、tls/dtls.go:145-155、tlcp/dtlcp.go:124-134 三处都没有。虽然 1:1 连接上 ID 错配不破坏帧流，但响应 ID 与查询不符会被当作该查询的答案继续上抛（resolver 侧不再校验 ID），最终以客户端收不到匹配响应（下游 ID 不匹配丢弃）形式表现为查询失败，且无法区分"服务器故障"与"响应被替换"。
- **风险**: TLCP/DTLS/DTLCP 路径对错误 ID 响应静默透传：跨协议行为不一致，诊断困难；skip_tls_verify 配置下 MITM 篡改 ID 无任何检测信号。
- **修复**: 在三处 ReadTCPMsg/Read 之后、返回之前补 `if response.ID != msg.ID { pool 归还（若来自池）；return nil, fmt.Errorf("...response id mismatch: expected %d, got %d", msg.ID, response.ID) }`，与 exchangeOverTLS/exchangeViaProxy 保持一致。

## upstream-05 — LOW

- **位置**: `server/upstream/plain/tcp.go:50`
- **类别**: coupling
- **摘要**: poolKey 不含 Splitguard，SetSegmentation 每次查询前在共享连接上重写 segmentSize——两个同地址不同 splitguard 配置的上游共享连接时，写入分段模式被互相覆盖
- **描述**: ExecuteTCP 的 poolKey 仅 = Address(+Proxy)（tcp.go:38-41），不含 splitguard 标志；SetSegmentation(segSize) 在每次 Exchange 前设置共享 Conn 的 c.segmentSize（pool/tcp.go:93-97，写锁内），Exchange 在写锁内读取该字段做分段。并发场景：上游 A（splitguard=on）SetSegmentation(16) 后尚未取写锁，上游 B（同地址、splitguard=off）SetSegmentation(0)，A 的 Exchange 取到 0 并以不分段方式写出——用户为 A 配置的 Splitguard 防御被静默旁路。pool 是全局共享实例，任意两个同地址上游（即使不同 server_name/验证配置的明文 TCP）都复用一个连接池。
- **风险**: Splitguard 反 DPI 防御在混合配置下随机失效（大约一半并发查询以不分段写入），用户配置的防御机制被静默降级且无日志提示。
- **修复**: 将 splitguard 状态并入 poolKey（如 Address|Proxy|splitguard=on/off），或把 segSize 作为 Exchange 参数传递（Conn.Exchange(ctx, msg, segSize) 在写锁内使用本次查询的值），消除跨查询共享状态覆盖。

## upstream-06 — LOW

- **位置**: `server/upstream/tls/http3.go:85`
- **类别**: comment
- **摘要**: http3.go:85 注释称"Close() nils the map"，与实际行为矛盾——tls/client.go 的 Close 明确不置 nil（只 Range 关闭 transport）
- **描述**: ExecuteHTTP3 中 `if c.doh3Transports != nil { // Close() nils the map — a racing query must not panic` ——但 tls/client.go Close()（client.go:101-132）的注释明确写道"the LRU maps are intentionally NOT nil'd here"，只做 Range+关闭 transport，从不写 nil。同文件 https.go:45 的注释才是正确的（"Close() never nils the map (tls/client.go) — guarded for symmetry"）。http3.go 的注释描述了不存在的行为，误导后续维护者（若有人据此相信 map 会被置 nil，反而可能引入真正需要守卫的代码）。
- **风险**: 注释与代码矛盾：维护者按"Close 会置 nil"的假设做防御或修改，可能在真实行为上引入错误判断；跨文件同类注释自相矛盾。
- **修复**: 将 http3.go:85 注释改为与 https.go:45 一致：`// Close() never nils the map (tls/client.go) — guarded for symmetry`。

