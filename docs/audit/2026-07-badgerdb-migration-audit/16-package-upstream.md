# 16 · Upstream 包深度审计

> 审计 Agent：Phase 1 · Upstream
> 覆盖：server/upstream/* 全部 24 个非测试文件，4873 行


Now I have analyzed all ~4,873 lines across 24 non-test Go files. Here is the comprehensive audit report.

---

## server/upstream/ 审计报告

**审计范围**: 24 个非测试 .go 文件，4,873 行代码
**审计维度**: 18 项（代码质量、内存安全、锁正确性、耦合度、架构设计、性能、Panic 检测、错误处理、Context 传播、Goroutine 生命周期、资源生命周期、日志质量、文档质量、参数校验、常量提取、RFC 一致性、函数排序、BadgerDB 存储）
**日期**: 2026-07-29

---

### HIGH 严重度

#### H1 [`pool/tcp.go:221-227`] 连接关闭后 readLoop 仍尝试读取 (资源生命周期 / Goroutine 生命周期)

`readLoop` 使用 `c.conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))` 设置读超时。当 `close()` 并发关闭连接时，readLoop 的 `io.ReadFull` 可能返回错误并退出。但 `close()` 通过 `closeOnce` 保证仅执行一次；若 readLoop 的 defer `c.close()` 与外部 `Exchange` 调用的 `c.close()` 同时触发，`closeOnce` 确保安全。

**风险**: readLoop 的 defer 在返回前调用 `close()`，`close()` 发送 nil 到所有 `resultCh`。`Exchange` 在 write 失败路径下也会调用 `close()`，`closeOnce` 防止重复关闭。但若 write 成功后在 select 等待响应时 readLoop 因连接断开而退出并触发 close，Exchange 的 resultCh 收到 nil 并返回错误。流程正确。

**结论**: 实际安全，但 shutdown 路径复杂，需警惕未来修改引入竞态。

#### H2 [`plain/udp.go:139-151`] HopGuard 启用但 TTL 捕获不可用时静默失败 (Panic 检测 / 性能)

```go
if server.HopGuard && conn != nil {
    hg = c.hopGuard
    udpConn, ok := conn.(*net.UDPConn)
    if !ok { return nil, errors.New(...) }
    tc = ipttl.New(udpConn)  // 返回 nil 表示不支持
    if tc == nil {
        // 仅日志警告，hg 非 nil
    }
}
```

当 `ipttl.New` 返回 nil（平台不支持 TTL 捕获）时，`hg` 仍被设置为 `c.hopGuard`。后续循环中 `ttl` 变量保持零值，`hg.Feed(addr, 0)` 将 TTL=0 喂入直方图，`hg.Validate(addr, 0)` 与实际 TTL 不匹配导致所有包被拒绝。多读循环持续到超时，无法返回任何响应。

**风险**: 在 macOS/Linux 上 IP_RECVTTL 失败后，启用了 HopGuard 的 UDP 查询会永久超时，无降级路径。

**修复**: 当 `tc == nil` 时，应将 `hg` 也置 nil 以绕过 HopGuard 验证，或仅记录警告并完全跳过 HopGuard 路径。

#### H3 [`tls/quic.go:79-85`] 0-RTT 拒绝后在相同连接上重试，违反 RFC 9250 (RFC 一致性)

```go
if errors.Is(err, quic.Err0RTTRejected) {
    c.resetQUICConfig("doq:" + key)
    response, err = c.doQUICQuery(ctx, pc.Conn, msg, c.timeout)
    // 使用相同 pc.Conn 重试
}
```

RFC 9250 §4.2.1 要求 0-RTT 被拒绝后必须建立新连接。当前代码因 quic-go 内部会在同一个连接上进行完整握手而工作，但违反规范。注释已自认此偏差。

**风险**: quic-go 版本升级可能改变此行为，导致重试失败或静默数据损坏。

**修复**: 捕获 `Err0RTTRejected` 后调用 `quicPool.Remove(pc)` 删除旧连接，然后建立新连接。

#### H4 [`dnscrypt/client.go:137-158`] PQ 控制块处理后 `state.mu` 加解锁不一致 (锁正确性)

```go
if len(resp.PQControl) > 0 {
    ticket, lifetime, parseErr := ...
    if parseErr == nil && len(ticket) > 0 {
        if oversized { log.Debug } else {
            state.mu.Lock()
            pqResumeSecret, err := ...
            if err != nil {
                state.mu.Unlock()           // path A: 解锁
                log.Debugf(...)
            } else {
                state.pqResumeSecret = ...
                state.pqTicket = ticket
                state.pqTicketExpiry = ...
                state.mu.Unlock()           // path B: 解锁
                log.Debugf(...)
            }
        }
    }
}
```

`state.mu.Unlock()` 在 if/else 的两个分支中均出现，正确覆盖了所有路径。但 if `parseErr != nil` 或 ticket 为空时，锁从未被获取，流程安全。

**风险**: 低 — 当前所有路径正确释放。但结构脆弱，未来添加分支易遗漏解锁。

**修复**: 使用 `defer state.mu.Unlock()` 将锁的范围包裹整个临界区。

#### H5 [`pool/tcp.go:294-310`] `close()` 设置 `c.inflight = nil` 后 `readLoop` 可能正在读取 (内存安全)

`close()` 在 `closeOnce` 保护下执行：
1. close `c.conn`
2. Lock `c.mu`，发送 nil 到所有 `resultCh`，设置 `c.inflight = nil`
3. Unlock

`readLoop` 读取响应后 Lock `c.mu` 查找 `c.inflight[resp.ID]`。若 `close()` 已将 `c.inflight` 置 nil，map 读返回零值、ok=false，响应被丢弃。此竞态在实际运行中安全（readLoop 的 defer 也会调用 `close()`，`closeOnce` 保证只执行一次清理）。

**风险**: 低 — 当前实现经 `closeOnce` 保护。但并发路径多（readLoop defer、Exchange write error、Pool.Remove、Pool.Shutdown），未来修改容易引入 double-close 或 use-after-free。

#### H6 [`socks5/socks5.go:438-457`] `readAddress` 使用 `context.Background()` 硬编码超时 (Context 传播)

```go
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
```

BND.ADDR 解析使用 `context.Background()` 而非传递的 `ctx`，且硬编码 10 秒超时。当父上下文已在更短时间内取消时，此调用会持续阻塞。

**风险**: 可能阻塞 SOCKS5 握手完成，延迟后续查询。DNS 解析依赖可能在递归服务器中产生循环依赖。

**修复**: 使用上层传入的 deadline；若无可用的 deadline 则使用 dialer 的 `timeout` 字段。

#### H7 [`warmup.go:30`] 代理创建失败时缓存 nil Dialer 阻止后续重试 (资源生命周期)

```go
d, err := socks5.New(server.Proxy, c.timeout)
if err != nil {
    c.proxyDialers.Set(server.Proxy, nil)  // 永久缓存 nil
    return nil
}
```

`lrumap` 在 `DefaultTransportMax * 2` 个写入后才会驱逐此 nil 条目。若代理因临时网络问题创建失败，后续查询在该条目被驱逐前无法使用代理。

**风险**: 临时代理故障导致该代理线路永久不可用，直到 LRU 填满或进程重启。

**修复**: 不在错误时缓存 nil；或使用短 TTL 的过期机制。

#### H8 [`pool/tcp.go:152-163`] trackingID 写入在 `writeBuf` 切片上的潜在越界 (Panic 检测)

```go
if len(writeBuf) < zdnsutil.DNSFramePrefixLen+2 {
    return nil, fmt.Errorf("client: writeBuf too small...")
}
binary.BigEndian.PutUint16(writeBuf[zdnsutil.DNSFramePrefixLen:zdnsutil.DNSFramePrefixLen+2], trackingID)
```

trackingID 冲突检测后更新 writeBuf 中的 DNS ID 字段。若 writeBuf 不够长（`< DNSFramePrefixLen+2`），返回错误而非 panic。此检查正确。

**风险**: 低 — 保护到位。但注释称"此条件在实践中从不触发"，不完全准确：`msg.Pack()` 后若 msgData 长度为 0，writeBuf 为 2 字节，而 `len(writeBuf) >= 4` 不成立。虽然 `msg.Pack()` 对空消息不会返回 0 长度，但此假设不安全。

#### H9 [`plain/udp.go:354-356`] 非 NOERROR 非 EDNS 响应进入 EDNS 候选路径 (架构设计)

```go
if rcode != dns.RcodeSuccess && !hasEDNS {
    log.Debugf(...)  // 仅日志，不返回
}
// 继续到 line 364 的 EDNS-gate 检查
if rcode == dns.RcodeSuccess && !hasEDNS && queryUDPSize > 0 { ... return nil }
// 继续到 line 404 创建 EDNS 候选
resp := pool.DefaultMessage.Get()
```

非 NOERROR 响应（如 SERVFAIL、NXDOMAIN）如果没有 EDNS OPT 记录，会跳过 EDNS-gate（`rcode != RcodeSuccess`），然后被当作 EDNS-bearing 候选处理。GFW 的 NXDOMAIN 注入可能被接受。

**风险**: 低 — GFW 主要注入 A/AAAA 而非 NXDOMAIN。但非 NOERROR 响应应作为明确的权威信号处理，不应进入模糊候选收集。

**修复**: 在 rcode != NOERROR 且无 EDNS 时，直接返回而非进入候选路径。

#### H10 [`socks5/udp.go:286,358`] 魔法数字 1500 应使用命名常量 (常量提取)

`WriteTo` 和 `Write` 中：
```go
if totalLen <= 1500 {
```
`1500` 已在文件顶部定义为 `socks5WriteBufSize` 常量。两处应改为 `socks5WriteBufSize`。

**风险**: 低 — 若 MTU 相关常量日后调整，此处的魔法数字可能被遗漏。

---

### MEDIUM 严重度

#### M1 [`pool/tcp.go:85`] `Conn.done` channel 已分配但从未被读取 (代码质量)

```go
type Conn struct {
    // ...
    done      chan struct{}
}
func newConn(...) *Conn {
    c := &Conn{
        // ...
        done:     make(chan struct{}),
    }
}
func (c *Conn) close() {
    c.closeOnce.Do(func() {
        close(c.done)  // 关闭但无接收方
    })
}
```

`done` channel 在 `newConn` 中创建，在 `close()` 中关闭，但没有任何 goroutine 在 `c.done` 上执行 receive 或 select。该字段是死代码。

**修复**: 移除 `done` 字段及其在所有构造函数和 `close()` 中的引用。

#### M2 [`pool/tcp.go:354-377`] `Acquire` 中非满连接查找后的 `liveConns` 重建逻辑易错 (代码质量)

```go
for i, c := range conns {
    if c.IsDead() { continue }
    liveConns = append(liveConns, c)
    if !c.IsFull() {
        for j := i + 1; j < len(conns); j++ {
            if !conns[j].IsDead() { liveConns = append(liveConns, conns[j]) }
        }
        p.conns[key] = liveConns
        return c, nil
    }
}
```

当在索引 i 找到第一个非满连接时，通过内层循环追加 `conns[i+1:]` 中的所有存活连接。但 `liveConns` 已包含 `conns[0..i]` 中的存活连接，下一行 `p.conns[key] = liveConns` 覆盖池列表。逻辑正确但易错：若未来修改跳过或重新排序前导连接，将破坏池状态。

#### M3 [`pool/tcp.go:80`] `conn` 字段是 `net.Conn` 接口而非具体类型 (架构设计)

`Conn.conn` 定义为 `net.Conn`，但实际使用中它必须是 `*net.TCPConn`（`SetKeepAlive`、`SetNoDelay` 需要具体类型）。`newConn` 中做了类型断言，但若 Dialer 返回 TLS 包装的连接，类型断言静默失败，keep-alive 未设置。`pool/tcp.go:71-74` 仅在 `newConn` 中设置一次，返回的 `Conn` 不保留对 TCP 级别的控制。

#### M4 [`tls/http3.go:77-79,132-134`] `createDOH3Client` 双重 Get 窗口易浪费 (性能)

`ExecuteHTTP3` 检查 `c.doh3Transports.Get(key)` 后，若未命中则调用 `createDOH3Client`。后者内部再次检查 `Get(key)`。两次检查间的 TOCTOU 窗口可能导致并发创建多个 HTTP/3 传输层（每个都需要完整的 QUIC 握手），其中只有一个被保留。

**风险**: 高并发场景下 DoH3 启动时可能进行多次不必要的 QUIC 握手。

**修复**: `createDOH3Client` 应使用单次 `LoadOrStore` 模式，避免在创建前额外 `Get`。

#### M5 [`pool/quic.go:115-131`] Pool 关闭时在 dial 间隙检测 (Goroutine 生命周期)

```go
if p.closed {
    p.mu.Unlock()
    pc.close()
    return nil, fmt.Errorf(...)
}
if len(p.conns[key]) >= p.maxConns {
    p.mu.Unlock()
    pc.close()
    return nil, fmt.Errorf(...)
}
```

双重检查锁定模式正确。dial 阶段释放 `p.mu` 后池可能被关闭或填满，重新获取锁后检查有效。

#### M6 [`socks5/socks5.go:362-392`] `buildSOCKS5Request` 返回 nil 但调用者未检查 (Panic 检测)

```go
func buildSOCKS5Request(cmd byte, host string, port int) []byte {
    if port < 0 || port > 65535 { return nil }
    // ...
}
// socks5/tcp.go:60:
req := buildSOCKS5Request(socks5CmdConnect, host, port)
if _, err := conn.Write(req); err != nil { ... }
```

若 `port` 无效，`req` 为 nil。`conn.Write(nil)` 写入 0 字节，不返回错误，导致 SOCKS5 连接静默失败。

**风险**: `splitHostPort` 已验证端口范围，实践中不会触发。但防御性编程应检查 nil 并返回错误。

#### M7 [`dnscrypt/client.go:217-224`] `Close()` 仅置 nil 缓存而不清理 LRU 条目 (资源生命周期)

```go
func (c *Client) Close() {
    if c == nil { return }
    c.cacheMu.Lock()
    c.cache = nil
    c.cacheMu.Unlock()
}
```

未设置 `OnEvict` 回调，因此 State 条目仅由 GC 回收。每个 State 持有 `sync.Mutex`，GC 安全。但析构模式不对称 — 其他 Close 方法（如 `Client.Close` 在 client.go:289-310）显式关闭每个组件。

#### M8 [`tls/client.go:106-131`] `Close()` 无锁 Range (锁正确性)

```go
func (c *Client) Close() {
    if c.dohTransports != nil {
        c.dohTransports.Range(func(key string, client *http.Client) bool {
            // ...
        })
        c.dohTransports = nil
    }
}
```

依赖 `lrumap` 内部线程安全性。Range 期间无外部锁；并发调用 Close 可能导致 Range 与 Delete 冲突。

**风险**: 低 — `Close()` 预期只调用一次。但若两次并发推出，`dohTransports` 可能已被 nil，导致 nil map Range panic。

#### M9 [`dnscrypt/crypto.go:15-80`] `prepareQuery` 需调用者持有 `state.mu` 但文档未说明 (文档质量)

```go
func prepareQuery(state *State, q *EncryptedQuery, packet []byte) (...) {
    // 访问 state.sharedKey, state.secretKey, state.ephemeralKeys, state.pqTicket 等
}
```

godoc 未说明调用者必须持有 `state.mu`。调用方 `client.go:69-72` 在调用前后加锁/解锁，但协议易被遗忘。

#### M10 [`socks5/udp.go:248-268`] `socks5ReadBufPool` 类型断言失败时缓存泄漏 (内存安全)

```go
buf, ok := socks5ReadBufPool.Get().(*[]byte)
if !ok {
    return 0, nil, errors.New("socks5 read buffer pool type error") // buf 丢失
}
```

当池中误存入非 `*[]byte` 类型时，`Get()` 取出的对象丢失。相同模式出现在 `spoofguardBufPool`（plain/udp.go:127）和 `socks5WritePool`。

**风险**: 仅编程错误时发生。可增加 `socks5ReadBufPool.Put(buf)` 清理但此时 buf 类型未知。

#### M11 [`socks5/socks5.go:168-172`] `ctrlClosed` 初始 channel 泄漏 (内存安全)

`New()` 创建 `ctrlClosed: make(chan struct{})`。此 channel 仅当 `establishUDPRelay` 被调用时才会被替换并最终关闭。若 Dialer 仅用于 TCP CONNECT（从不调用 `ListenPacket` 或 `DialUDP`），初始 channel 永远不会被关闭，监视器 goroutine 不会被派生。

**风险**: 单个 channel 的内存泄漏忽略不计。但若 `New()` 从不与 UDP 一起使用，`ctrlClosed` 是冗余字段。

#### M12 [`pool/tcp.go:174-188`] `Exchange` defer 从 `resultCh` 排空孤儿响应 (资源生命周期)

```go
defer func() {
    c.mu.Lock()
    if c.inflight != nil { delete(c.inflight, trackingID) }
    c.mu.Unlock()
    select {
    case orphan := <-resultCh:
        if orphan != nil { zpool.DefaultMessage.Put(orphan) }
    default:
    }
}()
```

若 `Exchange` 因 ctx 超时而返回，但 `readLoop` 已经在同一 `trackingID` 上路由了响应，该响应从 `resultCh` 排空并归还池。正确。但若 `close()` 已发送 nil，`orphan` 为 nil 则不归还。

#### M13 [`plain/tcp.go:20-68`] TCP 非池化回退路径不使用 SOCKS5 分段支持 (一致性)

`ExecuteTCP` 的非池化回退中：
```go
response, _, err := c.tcpClient.Exchange(ctx, msg, config.ProtoTCP, server.Address)
```

此路径忽略 `server.Splitguard`（不设置分段）。仅池化路径和 `exchangeViaProxy` 路径使用 `zdnsutil.WriteTCPMsgSegmented`。

**风险**: 当 `c.tcpPool` 为 nil 或 `Acquire` 失败时，SplitGuard 降级不生效。DNSCrypt 客户端也不支持分段。

#### M14 [`pool/quic.go:167-188`] `QUIC.Put` 去重使用指针相等 (内存安全)

```go
func (p *QUIC) Put(key string, conn *quic.Conn) {
    for _, existing := range p.conns[key] {
        if existing.Conn == conn { return }
    }
    // ... append ...
}
```

使用 `*quic.Conn` 指针相等做去重。若 `quic-go` 内部复用相同底层连接但返回不同指针，此检查失效。但 `quic-go` 的语义保证每个 `Dial` 返回唯一的连接指针。

#### M15 [`tlcp/http_tlcp.go:60-61`] HTTP TLCP 客户端缓存永不清理 (内存安全)

```go
c.httpClient.Set(key, httpClient)
```

`httpClient` 是 `lrumap`，在构造函数中设置了 `OnEvict` 回调（关闭 idle 连接）。但 LRU map 仅在达到容量上限时驱逐条目。长期运行的服务器会累积大量 `http.Client`（每个上游的 TLCP 配置一个），其中大量可能已变为死连接。

**风险**: 低 — 受 `config.DefaultHTTPTLCPClientMax * 2` 限制。但每个客户端包含一个完整的 `http.Transport`，内存占用可观。

---

### LOW 严重度

#### L1 [`pool/tcp.go:71-73`] `newConn` 与 `dialTLSConn` 中重复设置 TCP KeepAlive (代码质量 / 冗余)

`pool/tcp.go:71-73` 和 `tls/tls.go:65-68` 中分别设置了 TCP KeepAlive。池化 DoT 连接在两个地方都被设置，第二次覆盖首次的值（相同配置值）。

#### L2 [`tls/dtls.go:58-82`] DTLS 代理与非代理路径重复地址解析 (代码质量 / 低效)

代理路径在 `line 63` 调用 `net.ResolveUDPAddr("udp", addr)`，非代理路径在 `line 74` 也调用。可提取公共分支。

#### L3 [`client.go:50-51`] `Client` 的 `tlsClient`/`tlcpClient` 字段仅用于 `Close()` (架构)

与 `plainClient` 不同，这两个字段仅在构造时赋值和 Close 时调用。查询路径通过 `executeSecureQuery` 调用子客户端方法而不通过字段。若 `Close()` 直接调用子客户端方法而非字段，这两个字段可被移除。

#### L4 [`dnscrypt/cert.go:19-48`] `FetchCert` 在 UDP 失败且 TCP 也失败时返回 UDP 的截断响应 (错误处理)

```go
tcpResp, tcpErr := fetchCertOverTCP(ctx, addr, query)
if tcpErr != nil {
    if err != nil {
        return nil, fmt.Errorf("udp: %w; tcp: %w", err, tcpErr)
    }
    return resp, nil  // UDP 失败但 TCP 也失败时返回截断的 UDP 响应
}
```

当 `!preferTCP` 且 UDP 返回了 `Truncated` 响应且 TCP 重试失败时，返回 `(截断响应, nil)` — 假装成功。调用方构建的证书可能不完整。

#### L5 [`pool/quic.go:34-38`] `QUICConn.close()` 使用 `closeOnce` 但 `isDead()` 检查 `closed` atomic 可能不安全 (内存安全)

```go
func (c *QUICConn) isDead() bool {
    if c.closed.Load() { return true }
    select {
    case <-c.Conn.Context().Done():
        c.closed.Store(true)  // 在 closeOnce 之外设置
        return true
    default:
        return false
    }
}
```

`isDead` 在 `closeOnce.Do` 之外写 `c.closed`。若多个 goroutine 同时调用 `isDead` 且连接已断开，每个都可能写 `c.closed`。这对 `atomic.Bool` 是安全的（所有写相同值）。

#### L6 [`pool/tcp.go:91`] `writeBuf` 写入 `DefaultBuffer` 返回的切片后可能被其他 goroutine 重用 (内存安全)

`Exchange` 从 `pool.DefaultBuffer.Get()` 获取缓冲区，填充 DNS 帧，然后通过 `c.conn.Write(writeBuf)` 写入连接（在 `writeMu` 下）。在 `Write` 返回前，缓冲区不能被其他 goroutine 获取。这是正确的。

#### L7 [`socks5/socks5.go:31-33`] `Dialer` 的 `udpConn`/`relayAddr`/`ctrlConn` 字段在主 dialer 上总是 nil (代码质量)

注释说明这些字段仅克隆实例使用。保留在结构体上是为清晰起见，但可通过提取 `udpRelay` 子类型来避免。

#### L8 [`plain/udp.go:306-309`] `copyData` 中 `copyBuf` 容量不足时重新分配 (性能)

```go
func (s *spoofguardState) copyData(raw []byte, n int) []byte {
    if cap(s.copyBuf) < n {
        s.copyBuf = make([]byte, n)
    }
    s.copyBuf = s.copyBuf[:n]
    copy(s.copyBuf, raw[:n])
    return s.copyBuf
}
```

每次 `make` 分配新缓冲区覆盖旧缓冲区，旧缓冲区变为垃圾。在多读循环中，若 DNS 响应大小剧烈变化，可能导致多次重新分配。实际上 DNS 响应大小相对稳定。

#### L9 [`tls/http3.go:105-113`] 重试循环中检查 `cached == client` 的条件竞态 (锁正确性)

```go
if cached, ok := c.doh3Transports.Get(key); ok && cached == client {
    _ = t.Close()
    c.doh3Transports.Delete(key)
}
```

`Get` 和 `Delete` 之间另一 goroutine 可能存储了新的 client。`cached == client` 检查防止误删新 client。正确但竞态窗口可能导致新旧 client 同时存在。

#### L10 [`pool/tcp.go:10-24`] 大量标准库导入但部分仅用于类型转换 (耦合度)

`math` 用于 `math.MaxInt`（一行），可改为自定义大整数或 `var leastCount *int`。

---
### 分类统计

| 类别 | HIGH | MEDIUM | LOW |
|------|------|--------|-----|
| 代码质量 | 0 | 2 | 3 |
| 内存安全 | 1 | 2 | 1 |
| 锁正确性 | 1 | 1 | 1 |
| 架构设计 | 1 | 1 | 1 |
| 性能 | 0 | 1 | 1 |
| Panic 检测 | 1 | 1 | 0 |
| 错误处理 | 0 | 0 | 1 |
| Context 传播 | 1 | 0 | 0 |
| Goroutine 生命周期 | 1 | 1 | 0 |
| 资源生命周期 | 1 | 2 | 0 |
| 文档质量 | 0 | 1 | 0 |
| RFC 一致性 | 1 | 0 | 0 |
| 常量提取 | 1 | 0 | 0 |
| **合计** | **10** | **15** | **10** |

### 关键发现总结

1. **`pool/tcp.go` 的 `done` channel 死字段** — 分配且关闭但从未使用，建议移除。

2. **H2: HopGuard + TTL 捕获不可用导致全部 UDP 查询被拒绝** — 当前在平台不支持 `IP_RECVTTL` 时无降级路径，是隐性的完全中断。

3. **H3: QUIC 0-RTT 拒绝后未建立新连接** — 违反 RFC 9250。依赖 quic-go 实现细节，不保证跨版本兼容。

4. **H6: SOCKS5 `readAddress` 使用 `context.Background()`** — 10 秒硬编码超时忽略调用方 deadline。

5. **H7: 代理创建失败缓存 nil** — 临时故障永久锁定代理路径。

6. **M1: `pool/tcp.go:85` `done` 字段完全无用** — 创建、关闭但无人读取。

7. **M11: `ctrlClosed` 初始 channel 泄漏** — 仅 TCP 场景下泄漏一个 channel。

8. **M15: TLCP HTTP 客户端缓存无限增长** — 受 LRU 限制但有大量泄漏可能。

9. **L3: `tlsClient`/`tlcpClient` 字段仅用于 `Close()`** — 可通过方法名哈希或闭包简化。

整体 `server/upstream/` 代码质量高：SOCKS5 实现正确（包括 UDP ASSOCIATE 生命周期管理），连接池设计健壮，错误处理仔细。最关键的未解决问题是 H2（HopGuard 静默拒绝）和 H3（RFC 合规偏差），其次是 H6/H7 的 Context 传播和缓存策略问题。