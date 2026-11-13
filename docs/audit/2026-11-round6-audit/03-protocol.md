# ZJDNS Round 6 Protocol 审计报告（`server/protocol/{plain,tls,tlcp,dnscrypt}` + `shared` demux，只读）

范围：`server/protocol/` 全部 server listener（含 `server/protocol/shared` 端口共享 demux 与其依赖 `internal/demux`），共 33 个非测试文件 ~9.9k 行，全部逐行通读；支撑代码（`internal/pool`、`internal/dnsutil/{tcpframe,dtlsframe,dnsutil}`、`internal/dnscryptcrypto/dns.go`、`server/protocols.go`、`server/{server,init}.go`、codeberg dns@v0.6.134 dnshttp 源码）对照核读。`go build ./...`、`go vet ./server/protocol/... ./internal/demux/...`、`go test -short ./server/protocol/... ./internal/demux/...` 全部通过。

Round 5（docs/audit/2026-11-round5-audit/03-protocol.md）已报告项不再重复；本轮核实其修复已落地：TLCP 路由按消费者条件注册（shared/tcp.go:55-59，Round5#2 已修）、DoQ 响应写 deadline（quic.go:362-367，Round5#3 已修）。Round5#1（E2E 测试空白）、#4（ktls Accept 阻塞）、#5（Mux.Start 半程失败清理）、#6（专用口 ALPN 只有 h2）、#7（共享口 ListenEarly 失败仅 Warn）为已知 pre-existing LOW，不重复计入本轮汇总。

## 发现（按严重程度排序）

### P1 | MEDIUM | 性能/协议正确性 + 数据竞争 | 共享口多 shard 下 QUIC Retry 白名单失效（3/4 客户端永远多付一个 RTT）

- **文件:行号**：`server/protocol/tls/handlers.go:61-69`（`HandleDOQFromPacketConn`）、`server/protocol/tls/handlers.go:112-118`（`HandleHTTP3FromPacketConn`）、`server/protocol/tls/quic.go:119`（`markAddrVerified(s.doqAddrCache, ...)`）、`server/protocol/tls/https.go:139-141`（`markAddrVerified(s.h3AddrCache, ...)`）、`server/protocol/shared/udp_dispatch.go:41-44, 83-98`
- **问题描述**：共享 UDP 口按 `DefaultUDPDispatchShards = 4`（config/defaults.go:116）分 shard，`startUDPGroup` 对每个 shard 各调用一次 `g.DOQHandler`/`g.HTTP3Handler`（即 `HandleDOQFromPacketConn`/`HandleHTTP3FromPacketConn`）。这两个函数每次都新建 `addrCache` 并赋给 **server 字段** `s.doqAddrCache`/`s.h3AddrCache`（handlers.go:68、117）——4 次赋值 last-wins；而 `VerifySourceAddress = make_addr_validator(addrCache)` 绑定的是**各 shard 自己的局部 cache**。打标点 `handleDOQConnections`（quic.go:119）与 `ServeHTTP`（https.go:141）写的是 `s.doqAddrCache`/`s.h3AddrCache`（最后一个 shard 的 cache）。注释只考虑了"standalone 与 shared 互斥（SkipDOQ）"，没有考虑 shard×shard。
- **风险说明**：内核按 4 元组把每个客户端哈希到固定 shard。哈希到 shard 0–2 的 DoQ/DoH3 客户端：validator 永远查自己那份空 cache → **每次新建连接都付一次 Retry 往返**（RFC 9000 §8.1.1 白名单永不生效）；shard 3 的 cache 则被所有 shard 的地址污染（功能性偏差）。DoQ/DoH3 是低延迟协议，首连接延迟系统性 +1 RTT。另外 `s.doqAddrCache` 在 quic.go:119 无锁读、handlers.go:68 在 listenerMu 下并发写（4 个 shard 启动期重叠），按 Go 内存模型构成数据竞争（-race 在共享口多 shard + 并发连接下可命中）。
- **修复建议**：把 per-shard cache 作为参数传入 `handleDOQConnections(listener, addrCache)` / `handleHTTP3Connections`（打标点改用参数），不再经 server 字段中转；或 `s.doqAddrCache` 只在 standalone 赋值、shared 模式改为从 transport 侧回查。改动是纯参数传递，无行为风险。

### P2 | MEDIUM | 错误处理/可用性 | TCP demux accept 循环：非临时错误静默永久退出，`Done()` 通道无人消费

- **文件:行号**：`internal/demux/tcp.go:112-131`（`acceptLoop`）、`internal/demux/tcp.go:107-110`（`Done()`）
- **问题描述**：`acceptLoop` 对 Accept 错误只区分两类：`closed` 标志已置（正常关停）→ return；`Temporary()` → bare `continue`。**其余任何错误（EPERM、ENOMEM、EBADF、EINVAL 等 accept(2) 可返回的非临时错误）直接 return，一行日志都没有**。`defer close(d.done)` 关闭的 done 通道在全仓库没有任何消费者（已 grep 验证：无 `demux.*Done` 引用）。
- **风险说明**：整个共享 TCP 口（DoH + DoT(TLS) + DoT/DoH(TLCP) + DNSCrypt-TCP）的入口 accept 循环死亡且完全无告警——其他 9 个 accept 循环（plain/tcp.go:78-85、tls/tls.go:71-79、tls/http3.go:101-109、tls/dtls.go:86-103、tlcp/tlcp.go:97-105、tlcp/dtlcp.go:126-147、dnscrypt/tcp.go:73-91、shared/tcp.go:196-213）全部是"日志 + 退避 + 永不退出"（dnscrypt 甚至对非临时错误也只 Warn + 重试）。触发概率低（需内核/内存压力返回非临时错误），但一旦触发 = 静默摘端口，直到进程重启，且无任何可观测信号。
- **修复建议**：对齐其余循环：非临时错误 `log.Warnf` + `DefaultAcceptRetryDelay` 退避 + continue；或至少 Warn 后 return 并让上层消费 `Done()` 触发关停。顺手补上临时错误的退避（见 P7）。

### P3 | MEDIUM | 测试缺口 | `server/protocol/shared` 全包零测试——全树最复杂的并发层无任何覆盖

- **文件:行号**：`server/protocol/shared/`（manager.go / tcp.go / udp.go / udp_dispatch.go / packet_conn.go 共 ~1500 行，`go test` 报 `[no test files]`）
- **问题描述**：grep 全仓库 `*_test.go`：没有任何测试引用 `shared.Mux`/`UDPGroup`/`TCPGroup`/`DemuxPacketConn`/`udpDispatchLoop`，也没有测试触达 `HandleSharedUDPPacket`/`HandleSharedTCPConn`/`ServeDTLCPClient`/`HandleDOQFromPacketConn` 等共享口 handler。`internal/demux` 有单测，但 Mux 调度层（分类优先级、per-client 队列 + `Send`/`Close` 竞态守护、idle reap、`clientSem` 洪水上限、shard 语义）完全无覆盖。
- **风险说明**：这一层集中了本项目最容易出错的并发原语（channel 所权转移、sendMu/CAS 双重守护、reap 与 dispatch 的单一发送者约定），且是 P1 这类"多 shard 组合才暴露" bug 的温床。回归全靠手工双端压测（docs/debug），CI 无防护。
- **修复建议**：至少补三类单测（可用 net.Pipe/localhost UDP socket，无需真实协议栈）：(a) dispatch 分类优先级与 fallback（DNSCrypt magic 优先于 QUIC 长头、plain-DNS 负检）；(b) `DemuxPacketConn` Send/Close/reap 竞态与 deadline 语义（含 `copyPacket` 短缓冲路径的池归还）；(c) 两个 UDP 协议 + 2 shard 的端到端路由（能直接抓出 P1 类 bug）。

### P4 | MEDIUM | 性能/跨协议一致性 | TLCP DoT 写路径无 write 合并——每响应 2 次系统调用 + 独立 TLS 记录

- **文件:行号**：`server/protocol/tlcp/tlcp.go:148-163`（writer goroutine）
- **问题描述**：plain TCP（plain/tcp.go:131-175）与 TLS DoT（tls/tls.go:143-186）的 writer 都用 `net.Buffers` 批量 flush（≤16 帧一次 writev，每批一次 `SetWriteDeadline`，注释明确"loaded-server profile is syscall-bound"）。TLCP DoT 的同构 writer 却是逐帧 `conn.SetWriteDeadline(...)` + `conn.Write(task.data)`——pipelined 客户端每响应固定 2 次系统调用，且每帧独立 TLCP 记录（多一次记录层加密/成帧开销）。
- **风险说明**：同一模式在三个 DoT 实现里出现两份合并、一份不合并；TLCP DoT 吞吐在 pipelining 负载下系统性劣于 plain/TLS 孪生路径。gotlcp 遵循 crypto/tls 语义：单次 Write 产出单条（或少数）记录，RFC 7858 §6 允许一记录多消息，合并安全。
- **修复建议**：把 tls.go:143-186 的 `net.Buffers` 批量 flush（frames/tasks 双队列 + drain 循环）原样移植到 tlcp.go 的 writer，删除逐帧 deadline。纯热路径收益，无协议行为变化。

### P5 | LOW | 性能/热路径分配 | DNSCrypt 每查询新分配 `dns.Msg`（未走消息池），注释误标"cold path"

- **文件:行号**：`server/protocol/dnscrypt/crypto.go:214-215`（PQ initial）、`crypto.go:253-254`（classical）、`crypto.go:342-343`（PQ resumed）、`crypto.go:369`（`checkReplay` 的 `string(kb[:])`）
- **问题描述**：`decrypt` 三个分支全部 `msg = &dns.Msg{}`，注释写 "Could use pool.DefaultMessage.Get(); left as &dns.Msg{} — cold path"——但 decrypt 处理的是**每一条加密 DNSCrypt 查询**，是该协议最热的路径（cert 握手才是 cold path）。其余全部协议入口（plain UDP/TCP、DoT、DoQ、DTLS、DTLCP、DoH）的请求消息均走 `pool.DefaultMessage`。另 `checkReplay` 每查询 `string(kb[:])`（~28B）作为 LRU key 再分配一次。无泄漏（未 Get 也就无需 Put，`serveDNS` 不回 Put `m` 是自洽的），纯粹是池化缺席。
- **风险说明**：每查询多一次 ~300B 结构体分配 + Unpack 内部切片分配（池化路径可复用 Msg 骨架与 Data 背板），高 QPS DNSCrypt 下 GC 压力高于孪生路径。基准影响可量化（docs/benchmark 基线有 DNSCrypt 项）。
- **修复建议**：三个分支改 `msg := pool.DefaultMessage.Get()`，`serveDNS`/`handleSaturated`/`handleTCPMsg` 各自在响应写出后补 `pool.DefaultMessage.Put(m)`（注意与 identity-guard 的 resp Put 互斥，参照 quic.go:310-315 的 `response != req` 守护）。`checkReplay` 可用 `lrumap.Map[[24]byte, replayEntry]`（定长数组 key）消掉 string 分配。

### P6 | LOW | 性能/热路径分配 | DoH GET 双重 base64 解码

- **文件:行号**：`server/protocol/tls/https.go:162-172`、`server/protocol/tlcp/http_tlcp.go:125-132`；对照 `codeberg.org/miekg/dns@v0.6.134/dnshttp/dnshttp.go:84`
- **问题描述**：GET 路径先 `base64.RawURLEncoding.DecodeString(dnsParam)` 仅为做尺寸门检（分配 decoded），随后 `dnshttp.Request(r)` 内部对同一参数**再解码一次**。每次 GET 请求多一次 3/4·len(param) 的分配 + 解码 CPU。`r.URL.Query()` 也被解析两次（两次都生成 query map）。
- **风险说明**：DoH GET 是常见客户端形态（浏览器/移动端偏好 GET 便于缓存），高 QPS 下每请求白付一次解码+分配。两处（TLS/TLCP）一致地重复，属同一模式。
- **修复建议**：门检改为免解码上界：`len(dnsParam) > base64.RawURLEncoding.EncodedLen(config.DefaultDOHMaxRequestSize)` 直接 400（覆盖绝大多数超限场景），仅边界值才解码；或把 decoded 传给一个接受预解码字节的构造路径（需要 fork 侧 `dnshttp` 支持或本地构造 `dns.Msg{Data: decoded}` + Unpack + accept-func，与 dnshttp.Request 语义对齐后替换）。

### P7 | LOW | 跨协议一致性/CPU | demux accept 循环临时错误重试无退避（EMFILE 热自旋）

- **文件:行号**：`internal/demux/tcp.go:128-130`
- **问题描述**：`Temporary()` 错误（含 EMFILE/ENFILE——Go 归类为 temporary）走 bare `continue`，无 sleep。fd 耗尽风暴下该循环以每次一 syscall 的节奏 100% 空转，且因它是共享口唯一 accept 入口，会与受害进程抢 CPU。注释声称 "mirrors the pattern used by all other accept loops"，但其他所有循环（见 P2 列表）都带 `time.Sleep(config.DefaultAcceptRetryDelay)`。
- **风险说明**：fd 压力场景下放大自身负载；与全代码库退避约定不一致。
- **修复建议**：与 P2 一并修：temporary 分支补 `time.Sleep(config.DefaultAcceptRetryDelay)`（或 select ctx）。

### P8 | LOW | 跨协议一致性/互操作 | TLCP 自签名证书不处理 IP 字面量 domain（无 IP SAN）

- **文件:行号**：`server/protocol/tlcp/certs.go:69-84`（`serverTemplate` 恒填 `DNSNames`）对照 `server/protocol/tls/certs.go:79-85`（`net.ParseIP(domain)` → `IPAddresses`）
- **问题描述**：TLS 证书生成器对 IP 形态的 domain 走 `IPAddresses` SAN；TLCP 版没有该分支，IP 字面量被塞进 `DNSNames`——SM2 客户端按 iPAddress SAN 匹配会失败。
- **风险说明**：`domain` 配成 IP（内网/直连部署常见）时 TLCP/DTLCP 证书校验客户端侧不通过，而孪生 TLS 路径正常。低频但属同一模式两处实现漂移。
- **修复建议**：移植 tls/certs.go:79-85 的 ParseIP 分支（smx509.Certificate 同样有 `IPAddresses` 字段）。

### P9 | LOW | 内存安全/池归还纪律 | 共享口 DNSCrypt worker：Put 未 defer，panic 路径丢池缓冲

- **文件:行号**：`server/protocol/shared/udp_dispatch.go:411-424`
- **问题描述**：per-client worker 的两条路径（inline 饱和处理与 `go func(pkt DemuxPacket)`）都是 `capturedHandler(...)` **之后**才 `PacketBufPool.Put(&full)`，没有 defer。handler panic 时 `HandlePanic` 恢复后 Put 被跳过，8KiB 池缓冲脱离池（GC 兜底，非泄漏，但破坏了 Round 5 验证过的"每条路径均 Put"纪律——其余路径都用 defer Put 或单点 defer 覆盖 panic，如 dnscrypt/udp.go:78-81 的注释明确为此设计）。
- **风险说明**：仅 panic 时损失池复用；频度极低。属于纪律缺口而非可用性风险。
- **修复建议**：goroutine 内改为 `defer func() { full := pkt.Data[:cap(pkt.Data)]; PacketBufPool.Put(&full) }()`，inline 路径同理（handler 调用前注册 defer）。

### P10 | LOW | 拒绝服务/跨协议一致性 | 独立口 DTLCP 准入阻塞式（errgroup.Go 满载时冻结整个端口），与共享口的 drop 语义不一致

- **文件:行号**：`server/protocol/tlcp/dtlcp.go:151-175`（`handleDTLCPConnections` 新客户端路径）对照 `server/protocol/shared/udp_dispatch.go:326-357`（共享路径 `rt.admit()` 满则丢包）
- **问题描述**：独立口每个新 (IP,port) 起一个握手 goroutine：`s.serverGroup.Go(...)`（SetLimit=256）在满载时**阻塞** accept 循环（Go 已在 l.mu 外调用，无死锁，但 read loop 停摆）。spoofed-source 洪泛下 256 个握手 goroutine 各占位 `DefaultDTLSIdleTimeout`（30s，握手 ctx）→ 端口整体停摆 ~30s/波。共享口同逻辑是 `admit()` try-acquire 满则丢（注释明确为此设计）。
- **风险说明**：单端口 UDP 放大面（DTLCP 首包触发 SM2 握手计算）+ 停摆窗口；有界（errgroup 256）但语义与共享路径漂移。
- **修复建议**：对齐共享路径：try-acquire 一个本地 sem（或直接用 `select { case s.serverGroup.Go 不阻塞 }` 不可行——errgroup.Go 无 TryGo），满则丢包并计数（复用 `noteDispatchDrop` 风格采样日志）。

### P11 | LOW | 拒绝服务 | DoQ 优雅关闭握着 `quicConnSem` 槽位等 peer ACK（最长 10s）——约 13 conn/s 的僵尸客户端可耗尽 128 槽

- **文件:行号**：`server/protocol/tls/quic.go:150-165`（graceful-close defer：`CloseWithError` 后等 `conn.Context()` 完成，上限 `DefaultBackgroundTimeout`=10s）+ `quic.go:127-139`（sem 在 goroutine defer 才释放）
- **问题描述**：`handleDOQConnection` 的收尾 defer 先等连接 draining 完成（对端 ACK CONNECTION_CLOSE 或 10s 超时）才返回，期间 `quicConnSem`（128，DoQ+DoH3 共享）槽位仍被占用。恶意客户端完成握手后静默消失：每连接钉住槽位 ~10s。稳定 128/10s ≈ 12.8 个/s 握手即可让后续 DoQ/DoH3 连接全部收到 ExcessiveLoad 拒绝。
- **风险说明**：quic-go 的 `CloseWithError` 本身已进入 closing/drain 状态、其内部定时器会自行收尾，调用方显式等待对资源回收并非必需；等待发生在持有准入槽位期间放大了占用。合法客户端通常 1 RTT 内结束，正常负载无感。
- **修复建议**：去掉显式等待（信任 quic-go drain），或先 `<-s.quicConnSem` 释放准入再等，或把等待上限压到 ~1 个 RTT 量级。

## 核对通过的关键项（证据）

- **池归还纪律（头号维度）**：plain TCP/DoT/TLCP DoT 的 `pooledBuf`/`writeTask{pooled}` 全路径（读错、unpack 错、workerCap 拒绝、connCtx.Done、writer flush 错、panic 前的 reader drain）均恰好 Put 一次；`pool.Message.Put → ReleaseWire` 的容量类路由（2048）与 `DefaultBuffer`(8192)/`PacketBufPool`(8192)/DTLS buf[2:] 切片均不匹配，无跨池污染与双重释放；`PackStreamFrame`（tcpframe.go:68-100）的 aliased/heap 双路径与 `resp.Data` 清空契约在 plain/TLS/TLCP 三个调用点使用正确；DTLS/DTLCP 每数据报新缓冲 + worker defer Put、DNSCrypt UDP serveUDP 的 buffer 换手（packet/buf 分离 + 单点 defer）正确；`copyPacket`/`Close` drain 的 `pkt.Data[:cap]` 复原均从偏移 0 切出，与 dispatch 侧 `(*pb)[:n]` 对称。
- **锁与并发**：`DemuxPacketConn` 的 sendMu+closed-CAS 使 Send/Close/reap 三方无 panic 路径（bare channel send 不存在）；`queue.push` 的 send-then-recheck 处理了 Close 竞态（双重 Close 由幂等 Close 吸收）；DoT writer 单写者 + reader 侧 wg.Wait→drain→close(writeCh)→writerDone 顺序在三个 DoT 实现中一致且正确；`udpDispatchLoop` 作为 per-client 通道唯一发送者使内联 reap 无竞态；dnscrypt 的 wg-swap 与 RLock-Add 纪律自洽。
- **demux 嗅探**：MSG_PEEK 循环的零进度退避、RDHUP 后二次 peek、poll 预算、非 peek 平台 bufferedConn 重放（含缓冲耗尽后同调用续读）均正确；UDP 检测的 DNSCrypt 优先级 + plain-DNS 结构负检 + 1200 字节 QUIC 门槛组合无已知误路由；QUIC 与 HTTP3 同口已在 wiring 层显式拒绝（protocols.go:261-269）。
- **洪水上限**：共享 UDP `clientSem`（256，跨 shard 共享）+ `peerProtoMax`(64K) 重置 + 60s idle reap + per-client 队列 256/drop 采样日志，链条完整；TCP 侧 sniffSem try-acquire + queueDepth 64 + LimitListener/errgroup 分层封顶。
- **Round 5 修复落地确认**：TLCP 无消费者路由条件注册（shared/tcp.go:55-59）、DoQ 写 deadline（quic.go:362-367）已在位。
- 其余 Round 5 已报项（E2E 测试空白、ktls Accept 阻塞、Mux.Start 半程失败清理、专用口 ALPN 单 h2、共享口 ListenEarly 失败仅 Warn）本轮维持现状，未重复计入。

## 汇总表

| 编号 | 严重程度 | 类别 | 位置 | 一句话 |
|------|----------|------|------|--------|
| P1 | MEDIUM | 性能/协议正确性+数据竞争 | tls/handlers.go:61-69,112-118; tls/quic.go:119; tls/https.go:139-141 | 共享口 4 shard 下 `s.doqAddrCache`/`s.h3AddrCache` last-wins，3/4 客户端 Retry 白名单永不生效（每连接 +1 RTT），且字段无锁读写 |
| P2 | MEDIUM | 错误处理/可用性 | internal/demux/tcp.go:112-131 | demux accept 非临时错误静默永久退出、无日志，`Done()` 无消费者——共享 TCP 口整体静默死亡 |
| P3 | MEDIUM | 测试缺口 | server/protocol/shared/（全包） | 全树最复杂的并发 demux 层（Mux/udpDispatchLoop/DemuxPacketConn）零测试覆盖 |
| P4 | MEDIUM | 性能/跨协议一致性 | tlcp/tlcp.go:148-163 | TLCP DoT writer 缺 `net.Buffers` 写合并（孪生 plain/TLS 路径均有），pipelined 每响应 2 syscall+独立记录 |
| P5 | LOW | 性能/热路径分配 | dnscrypt/crypto.go:214,253,342,369 | decrypt 每查询 `&dns.Msg{}` 不走消息池（注释误标 cold path）+ replay key string 分配 |
| P6 | LOW | 性能/热路径分配 | tls/https.go:162-172; tlcp/http_tlcp.go:125-132 | DoH GET 尺寸门检与 dnshttp.Request 双重 base64 解码 |
| P7 | LOW | 一致性/CPU | internal/demux/tcp.go:128-130 | demux accept 临时错误重试无退避，EMFILE 下 100% 空转（其余循环均 sleep） |
| P8 | LOW | 一致性/互操作 | tlcp/certs.go:69-84 vs tls/certs.go:79-85 | TLCP 自签名证书无 IP-literal domain 分支（缺 IPAddresses SAN） |
| P9 | LOW | 池归还纪律 | shared/udp_dispatch.go:411-424 | 共享口 DNSCrypt worker 的 Put 未 defer，panic 路径丢 8KiB 池缓冲 |
| P10 | LOW | 拒绝服务/一致性 | tlcp/dtlcp.go:151-175 | 独立口 DTLCP 准入阻塞式（errgroup 满载冻结端口 ~30s/波），共享口是 drop 语义 |
| P11 | LOW | 拒绝服务 | tls/quic.go:150-165,127-139 | DoQ 优雅关闭握 `quicConnSem` 槽等 ACK 最长 10s，~13 僵尸 conn/s 耗尽 128 槽 |

无 CRITICAL/HIGH。本轮与 Round 5 结论一致：核心机制（池化、锁、嗅探、洪水上限、关停时序）实现质量高；剩余问题集中在**多 shard/多实例组合暴露的一致性缺口（P1）**、**唯一偏离全库约定的错误路径（P2/P7）**与**测试空白（P3）**。
