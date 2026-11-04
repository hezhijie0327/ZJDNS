# ZJDNS Round 5 Protocol 审计报告(`server/protocol/`,基线 9c6df186..HEAD)

先跑了 `git diff 9c6df186..HEAD -- server/protocol/`(10 文件,+96/-68),逐 hunk 审查并 Read 了全部相关实现;为验证迁移正确性还对照了 Go 1.27.3 GOROOT 源码、quic-go v0.65.0、pion/dtls v4(rc.8)、eTLS 源码。`go build`/`go vet`/`go test -short`(protocol + ktls + demux 全部包)通过。

## 发现(按严重程度)

**1 | MEDIUM | 测试缺口/迁移风险 | server/protocol/tls/https.go:49-62、server/protocol/shared/tcp.go:98、internal/ktls**
eHTTP→net/http 迁移的核心机制没有任何集成/E2E 测试。整条链路依赖四个脆弱接合点:(a) Go 1.27 net/http 对 Accepted 连接做 `ConnectionState() tls.ConnectionState`/`HandshakeContext` 接口探测(GOROOT server.go:1973-2016,已核实);(b) eTLS `Conn.Compatible()` 的 `ConnectionState.Compatible()` 映射 `NegotiatedProtocol`(compatible_common.go:20,已核实);(c) `http.Server.TLSConfig == nil` → `shouldConfigureHTTP2ForServe()` 返回 true → 内置 h2 配置(server.go:3493-3513,已核实);(d) `ktls.limitConn` 转发这两个接口。现有测试只覆盖了假连接的接口转发(`internal/ktls/limit_test.go` 用 `tlsPipeConn` 伪造 ConnectionState)和 `ServeHTTP` 逻辑(`https_test.go`),没有一处真正用 TLS 客户端(h2 或 http/1.1)打穿 `http.Server.Serve(ktls.NewListener(...))`。eTLS 升级若改动 `Compatible()` 行为会静默上线。建议:补一个 startDOHServer E2E 测试(127.0.0.1:0,`http.Client{ForceAttemptHTTP2: true}` + 显式 TLS1.2/http1.1 客户端各一),同时覆盖专用口与共享口 demux 路径。

**2 | LOW(有界资源驻留,pre-existing)| server/protocol/shared/tcp.go:51-53 + internal/demux/tcp.go:70-72、queue.go:22**
TLCP 路由无条件注册:当共享组没有任何 TLCP 消费者(`DOHTLCP`/`DOTTLCP` 均为 nil,如 443 = DoH+DNSCrypt、未配置 TLCP 证书时,`wantShared` 只需 DNSCrypt==HTTPS.Port 即成立,protocols.go:31-37),形如 TLCP 记录(首字节 0x14-0x17 + 版本 0x0101)的连接会被 wrap 后 push 进永无人 Accept 的 `tlcpQueue`,最多 64 个(queueDepth)连接/fd 无限期驻留(无 deadline、无消费者),直到 Shutdown 才被 `q.Close()` 排空。已核实 9c6df186 版本同样如此(非本轮回归)。建议:仅在存在 TLCP handler 时注册该路由,或对无消费者队列直接关连接。

**3 | LOW(pre-existing,但与本次 credit 变更相关)| server/protocol/tls/quic.go:362(respondQUIC)**
DoQ 的 `stream.Write` 没有设置写 deadline:不读响应的客户端会无限期钉住 stream handler goroutine(KeepAlive 使连接保活);且新增的 `RequireStreamCreditRelease` 纪律下,stream-credit 槽位也一并被钉住(quic.go:198-206 的 defer 直到 handler 返回才 release)。实际影响自限:客户端会耗尽自身 stream 配额,`DefaultMaxConcurrentStreams=64`/连接 + `quicConnSem` 封顶。建议写前 `stream.SetWriteDeadline(time.Now().Add(config.DefaultDNSQueryTimeout))`,与 DoT writer 的 flush deadline 对齐。

**4 | LOW | 关停延迟 | internal/ktls/limit.go:69**
`Accept` 先阻塞在 `l.sem <-` 上,listener `Close()` 不能唤醒它。Shutdown 时若全部 slot 被活跃连接占满且 `srv.Shutdown(ctx)` 超时返回,Serve goroutine 会滞留到连接自然退出(受 WriteTimeout 10s/IdleTimeout 60s 约束,有限)。与旧 `zdnsutil.NewLimitListener`(keepalive.go:66)完全同构 —— 非回归,但 ktls 是照抄该模式的新代码,值得改为 `select { case l.sem<-...: case <-l.closed: }`。

**5 | LOW(pre-existing)| 启动失败清理 | server/protocol/shared/manager.go:158-170 + server/server.go:206-209**
`Mux.Start` 中途失败(如第二个 bind 地址 `net.Listen` 失败)直接返回错误,先前已启动组的 demux accept 循环、http.Serve goroutine、已绑定 socket 无人关闭(该错误路径不调用 `Mux.Shutdown`);当前靠进程退出兜底。对应审计维度 7 "bind 失败清理" 的残余缺口。

**6 | LOW(pre-existing)| ALPN 不一致 | config/defaults.go:217 vs server/protocol/tls/handlers.go:43**
专用 DoH 口 ALPN 只有 `["h2"]`,共享口 DoH 是 `["h2","http/1.1"]`。只提供 `http/1.1` ALPN 的客户端在专用口会收到 no_application_protocol 告警断连(不发送 ALPN 的客户端不受影响,回落 HTTP/1.1 正常)。迁移前后行为一致;建议统一为 `["h2","http/1.1"]`。

**7 | LOW(pre-existing)| 优雅降级不一致 | server/protocol/tls/handlers.go:94-97、148-151**
`HandleDOQFromPacketConn`/`HandleHTTP3FromPacketConn` 中 `transport.ListenEarly` 失败仅返回错误(一条 Warn),transport 已注册进 `s.doqTransports`,dispatch 循环继续把 QUIC 数据报喂进黑洞直到关停;而独立口路径(quic.go:73-77)失败即关闭 conn 并让 startup 失败。共享口 QUIC 绑定失败应同样硬失败或至少关闭 transport。

**8 | INFO(核对结论,无问题)| DoQ stream-credit 顺序 | server/protocol/tls/quic.go:198-206**
针对"先 release 后 close 是否泄漏/双重释放":对照 quic-go v0.65.0 源码,`ReleaseStreamCredit` 文档明确 "once the stream has completed **and** ReleaseStreamCredit has been called, **in any order**. Calling it multiple times is a no-op"(receive_stream.go:135-144),实现经 `incomingStreamsMap.ReleaseStreamCredit`(streams_map_incoming.go:183-196)幂等保护,`maybeDeleteStream` 要求 completed+creditReleased 双条件。当前 defer 顺序(先 ReleaseStreamCredit 再 Close)安全;probe 读到 EOF 时接收侧在 handler 内已 completed,release 即刻生效。无泄漏、无双重释放。

## 核对通过的关键项(证据)

- **池归还纪律**(头号维度):DoT(tls.go)、plain TCP(tcp.go)、TLCP DoT(tlcp.go)、DTLS(dtls.go)、DTLCP(dtlcp.go)、DoQ(quic.go)、DoH(https.go/http_tlcp.go)、DNSCrypt(crypto.go/handshake.go)、plain UDP(udp.go)—— 每个 Get 在所有路径(含错误/饱和/identity-guard 路径)均有 Put;`pool.Message.Put`→`ReleaseWire` 按 cap==2048 容量类路由(内部 pool/pool.go:92-97),跨池污染和 use-after-release 均无;DTLS/DTLCP 每数据报新缓冲、所有权转移正确。
- **预打包响应重 Pack 守护**:全部写入方守护 `len(...Data)==0`(https.go:198、quic.go:337、http_tlcp.go:164、dnscrypt crypto.go:41、dnsutil/dtlsframe.go:90、tcpframe.go:70);dnscrypt TC 截断重打包(udp.go:214-219)基于刚 Unpack 的真实 RR 段,正确。
- **MSG_PEEK sniff**:短读循环、EOF/ECONNRESET、非 syscall 连接回退破坏性读、poll(2) 预算、deadline 均正确;peek 平台字节保留在队列、非 peek 平台 bufferedConn 重放,DNSCrypt 从字节 0 读,两条路径一致。
- **迁移机制**:如发现 1 所列四点全部对照 Go 1.27.3 源码核实成立;`limitConn` 转发接口;admission cap 从 eTLS 之下移到之上后封顶语义等价且保住 KTLS 的 `*net.TCPConn` 要求;shared DoH 无 ConnContext 属正确(TLCP 专用)。
- **双栈 TLS/DTLS**:eTLS `MinVersion: VersionTLS12`(server.go:184)、pion v4 [1.2,1.3] 两个监听器一致(dtls.go:43、handlers.go:170);RFC 8998 SM 套件仅 1.3 不受影响;`lrumap.DTLSSessionStore` 与 v4 `SessionStore`(Set/Get/Del)接口匹配;`warnKTLSNotTCPConn` 一次性告警正确。
- **锁/goroutine/关停**:DoT writer 单写者 + writeCh 排空覆盖写错误路径;Shutdown 快照在锁内、close 在锁外;DoT 活跃连接经 SetReadDeadline 唤醒;所有 accept 循环有退避;demux sniff 并发有 sem 封顶(256)。
- 本轮 diff 新增的 4 处 unpack-error Debug 日志均为 Debug 级、含 remote 上下文,`w.RemoteAddr()`/`conn.RemoteAddr()` 无 nil 风险(已核 sess.Addr 先于调用赋值)。

## 审过的文件

变更:`server/protocol/tls/{tls,https,quic,dtls,handlers,server}.go`、`server/protocol/shared/{tcp,manager}.go`、`server/protocol/plain/{tcp,udp}.go`;未变更但在范围内通读/抽查:`server/protocol/tls/{http3,addr_validator,certs}.go`、`server/protocol/tlcp/{tlcp,dtlcp,http_tlcp,server,certs}.go`、`server/protocol/dnscrypt/{server,tcp,udp,handshake,crypto,persist*}.go`、`server/protocol/plain/server.go`、`server/protocol/shared/{udp,udp_dispatch,packet_conn,reuseport_*}.go`;支撑代码:`internal/ktls/*`、`internal/demux/{detect,sniff_peek,sniff_read,queue,tcp}.go`、`internal/pool/pool.go`、`internal/dnsutil/{tcpframe,dtlsframe,keepalive}.go`、`internal/lrumap/dtls_session.go`、`server/{protocols,server,tasks}.go`;外部依赖源码:Go 1.27.3 net/http、quic-go v0.65.0、pion/dtls v4-rc.8、eTLS v0.0.0-20260930。

无 CRITICAL/HIGH 发现;本轮核心变更(迁移、双栈、credit、sniff)实现正确,主要缺口是迁移路径的 E2E 测试空白(发现 1)。