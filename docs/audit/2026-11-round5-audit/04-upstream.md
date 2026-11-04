# ZJDNS Round 5 Upstream 审计报告(基线 9c6df186 → HEAD)

本轮变更:`0d7dfd43`(EDE 65281)、`f8730200`(eHTTP→原生 net/http)、`7bd0118b`(pion/dtls v3→v4)。逐 hunk 审查 + 全包复检 + 对照 v4 源码(`v4.0.0-rc.8.0.20261101`)与 Go 1.27 stdlib 源码核实。`go build`/`go vet`/`go test -short ./server/upstream/...` 全绿。

## 发现

**U-1 | MEDIUM | 语义/文档不符 | server/upstream/client.go:267-274(对比 client.go:39-47 注释)**
```go
hopArmed := server.HopGuard && c.plainClient.HopGuard().Confident(server.Address)
if result.Error == nil && result.Response != nil && result.Protocol == config.ProtoUDP && !hopArmed {
    if (server.CapsGuard && caseUnverified) || server.HopGuard {
        result.Uncertain = true
```
当 CapsGuard 与 HopGuard **同时启用**且 0x20 回显已验证(`caseUnverified=false`)、而 hopguard 基线仍在学习期(`Confident=false`)时,`|| server.HopGuard` 仍然无条件置 `Uncertain=true`。但 `Result.Uncertain` 的文档(client.go:45-46 "A positive verification from either guard (armed TTL fingerprint, successful 0x20 echo) clears the mark")和 AGENTS.md("An armed hopguard fingerprint **or a successful 0x20 echo** clears the mark")都声明 0x20 回显成功即可清除标记。代码与声明矛盾:双 guard 配置下,已通过 16+ bit 事务熵验证的响应仍被永久 no-cache(hopguard 学习期可能很长),缓存命中率无谓受损,且日志打印 `caps-unverified=false` 却仍标记,误导运维。方向保守(无安全损失),但属文档-代码二选一的缺陷。建议:`if (server.CapsGuard && caseUnverified && !echoVerified) || (server.HopGuard && !capsEchoVerifiedThisQuery)` 或修正注释/AGENTS.md 声明。

**U-2 | MEDIUM(既有,非本轮引入)| 配置校验缺口/RFC 8484 | server/upstream/tls/endpoint.go:37-45 + config/validate_upstream.go:59-68**
DoH/DoH3 上游地址 scheme 未强制 https:validate_upstream.go 只查 `u.Scheme == ""`,`tls/dohEndpointFor` 也不校验(对比 tlcp/http_tlcp.go:40-42 显式拒绝非 https)。配置 `http://host/dns-query` 的 `protocol: https` 上游可通过校验;Go stdlib `transport.go dialConn` 对 `cm.scheme()=="http"` 不走 `customDialTLS`(`DialTLSContext` 被绕过),查询以**明文 HTTP** 发出(隐私降级,静默)。且 endpoint.go:44 会把 Host 改写为 `host:443`,明文打到 443。建议在 `dohEndpointFor` 或 config 校验中拒绝非 https scheme(与 HTTPTLCP 对齐)。

**U-3 | LOW | 潜在双重池化(当前为无害 no-op)| server/upstream/dnscrypt/client.go:292-315**
非池化 UDP 路径:`respBuf` 取自 dnscrypt 私有 `respBufPool`(cap=`MaxDNSUDPPacketSize`=4096),`defer respBufPool.Put(respBufPtr)`(line 298)归还本池;而 line 315 又对同一 slice 调 `zpool.ReleaseUDPPayload(respPayload)`。当前 4096 不匹配 pool 包的 512/1500/16384 三档,`releasePacketBuf` 落空,侥幸无害;若日后 `MaxDNSUDPPacketSize` 或 tier 常量改动到重合(如都改成 16384),同一缓冲会同时进入两个 sync.Pool,双查询并发复用同一 buffer → 数据损坏。建议非池化路径不调 `ReleaseUDPPayload`(它只该归还 `acquirePacketBuf` 来源的池化路径)。

**U-4 | LOW | 注释失实 | server/upstream/tls/dtls.go:220-223**
注释称握手超时后 "the caller's existing fallback (pool re-acquire, then a fresh dial) recovers in one round"——`ExecuteDTLS`(dtls.go:51-77)池 Acquire 失败后**直接**走 fresh dial,不存在 pool re-acquire。注释与代码不符,易误导后续维护。

**U-5 | LOW | RFC 8310 合规(既有)| server/upstream/tls/tls.go:36-38, 59-60**
eTLS DoT 路径 `dotConfig.NextProtos = config.NextProtoDOT` 但从不校验协商结果;TLCP 路径有强制校验(tlcp.go:85-90 `dialTLCPConnForDOT`,ALPN≠"dot" 即断连)。DoT 对等端忽略 ALPN 时静默继续。建议对齐 TLCP 的 dial 时校验。

**U-6 | LOW | 边界(既有,v3 同样)| server/upstream/tls/dtls.go:93-95**
非池化回退只挡 `queryLen > 65535`;pion v4(已核 v4 conn.go `prepareOutbound`:app-data 单记录、不 fragmentation,v3 相同)`Write` 一个 2+N 整帧超过 DTLS 单记录上限(~16K)会产生超限记录。实际 DNS 查询远小于此、大响应走 TC/TCP,仅记录为边界事实,无需修复。

## 重点变更逐项核实结论(均通过)

1. **DTLS v3→v4 迁移正确**:`dtls.Client/Dial/WithSessionStore/WithVerifyConnection/WithMin/MaxVersion` 签名逐一对上 v4 源码;`lrumap.DTLSSessionStore` 的 `Set/Get/Del` 满足 v4 `SessionStore`(v4 `Session` 结构体扩字段但按值存取,pion 读取侧 `bytes.Clone`,无别名);v4 读写 deadline 分离且层内管理(`SetWriteDeadline` 不干扰 readLoop 的读 deadline,tcp_conn.go 的 write-deadline-then-reset 模式安全);v4 `Read` 仍 ErrBufferTooSmall → `dtlsStreamConn` bufio 包装仍必需;`HandshakeContext` 显式调用 + `DefaultDTLSHandshakeTimeout` 对 v4 dual-stack 协商挂起的兜底仍然成立;v4 新增 `bytes.Clone` 每次 Write(微 perf,可忽略)。
2. **DoH eHTTP→原生迁移正确**:`tc.Compatible()`(compatibleConn 实现 `ConnectionState() tls.ConnectionState`)正是 Go 1.27 `dialConn` 自定义 DialTLSContext 契约;h2 经由新的 `t.h2Transport.AddConn` 路径(transport.go:2055-2070)接受任意 net.Conn,不依赖旧 `*tls.Conn` 分支;stdlib 会对已握手 conn 幂等重调 `HandshakeContext`(eTLS 语义安全);`NextProtoDOH=["h2"]`、ForceAttemptHTTP2 经 Clone 保留;LoadOrStore 竞败方关空闲连接无泄漏;Close/evict 三个站点类型断言同步改为 `*http.Transport` 一致。
3. **`KernelOptions: ktls.Options(...)` 迁移正确**:Linux/FreeBSD 构建 `eTLS.KernelOptions{TX,RX}`,其余平台 no-op,与旧 KernelTX/KernelRX 语义等价。
4. **EDE 65281 全链路核实**:`Result.Uncertain`(client.go:268-274)→ 转发路径 forward_process.go:141-145(`fallbackMarked`→`Cacheable: !server.SkipCache && !fallbackMarked`)→ 递归路径 recursive.go:573-581(`applyDefenseUncertainty`:`Cacheable=false`+EDE)→ 唯一缓存写入门 handler/resolve.go:85(双保险:`!qr.Cacheable || IsZJDNSNoCacheEDE`)→ 级联接收侧 forward_process.go:141 采纳下游标记。链路完整、无旁路。ptr 豁免/降级地址/§6.4 重试三种 unverified 来源均已置位;`Confident` nil-receiver 返回 true 且生产构造路径必建 HopGuard,无 panic 路径。
5. **Close 幂等与子 client**:upstream Client.Close 关闭全部 4 个子 client + 等待 warmWg + Range 关 proxy dialers,无遗漏(历史上漏关 tlcpClient 已修复);所有池 Shutdown 幂等,conn close 走 closeOnce。
6. **已知根因模式复查**:DTLS/DTLCP/TLS/QUIC/TCP 非池化回退全部有 `ctx.Err()` 门(tls.go:54、dtls.go:69、dtlcp.go:90、quic.go:153、tcp.go:67);池 dial 失败路径 fallback 计数与 wire/缓冲释放逐条核对无泄漏(`dialing` 计数、`ErrMaxConnsReached` 时 `c.close()`、UDP/TCP/Raw 三池一致)。
7. **pool 无回归**:Acquire 单遍 dead-filter 的 `p.total` 记账(含 early-return 路径)验算正确;readLoop 全部 HandlePanic + owner;RFC 7766 §7 question 回显校验在 TCP 池(tcp_conn.go:287-301)、UDP 池(plain/udp.go:234、636)、one-shot、Raw 池二层校验均存在;QUIC 池 Put 去重 + 死连接拒收。

## 审过的文件清单

- server/upstream/:client.go、execute.go、capsguard.go、warmup.go、defense_uncertain_test.go
- server/upstream/plain/:client.go、udp.go、tcp.go、spoofguard.go(结构复查)
- server/upstream/tls/:client.go、https.go、dtls.go、http3.go、quic.go、tls.go、endpoint.go
- server/upstream/tlcp/:client.go、tlcp.go、dtlcp.go、http_tlcp.go(头部)
- server/upstream/dnscrypt/:client.go、state.go(结构复查)
- server/upstream/pool/:tcp.go、tcp_conn.go、udp.go、udp_conn.go、raw.go(头部)、raw_conn.go、quic.go、errors.go
- 关联核实:server/defense/hopguard.go、internal/lrumap/dtls_session.go、internal/ktls/、internal/dnsutil/https_dns.go、server/resolver/{forward_process,recursive,ns_concurrent}.go(消费侧)、server/handler/resolve.go、config/validate_upstream.go、eTLS(.etls-patched)、pion/dtls v3/v4 源码、Go 1.27 net/http transport 源码

socks5/ 子包仅按调用面复查(Close/OnEvict 契约),未逐行审计。无 CRITICAL/HIGH 发现。