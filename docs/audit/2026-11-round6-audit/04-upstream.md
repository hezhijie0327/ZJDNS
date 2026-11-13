# ZJDNS Round 6 Upstream 审计报告（基线 bce1518c → HEAD 88de480b）

范围：`server/upstream/*` 全部 —— 根包（client/execute/capsguard/warmup）、`plain/`、`pool/`（TCP/UDP/Raw/QUIC 四池）、`tls/`（DoT/DoQ/DoH/DoH3/DTLS）、`tlcp/`（TLCP/DTLCP/HTTP-TLCP）、`dnscrypt/`、`socks5/`（Round 5 明确未逐行审计的盲区，本轮逐行补审）。Round 5 之后 `server/upstream` 零提交（`git log bce1518c..HEAD -- server/upstream/` 为空），故本轮为全量新鲜审计而非增量 diff 审计；Round 5 六项发现（U-1..U-6）均已核对确认已修复，未重复报告。`go test -short -count=1 ./server/upstream/...` 全绿作为基线。

## 发现

**U1 | HIGH | pool-leak / 资源耗尽（攻击者可触发）| server/upstream/plain/udp.go:495,509（对照 pool/udp_conn.go:264-266 契约）**

`executeUDPCollect` 的发散 EDNS 跨轮确认路径在两处 `break collect` 跳出本轮 collect 循环时**不调用 `uc.ReleaseCollect(matchKey)`**：
- udp.go:495（跨轮无匹配签名 → `break collect // fresh divergent round`）
- udp.go:509（首轮发散 → `prevRoundSigs = sigs; break collect // re-query in the next round`）

`ExchangeCollect` 的契约（pool/udp_conn.go:264-266 "The caller must call ReleaseCollect when done to clean up"）要求严格配对；泄漏一次即永久丢失：
1. 一个 `capacity` 槽（`c.capacity`，maxPipe=16）—— `ExchangeCollect` 里 `c.inFlight.Add(1)` 只有 `ReleaseCollect` 会 `Add(-1)`；
2. 一个 `c.inflight[matchKey]` 表项 + collectCh（缓冲 4）—— readLoop 后续匹配该 ID 的数据报持续入队，最多钉住 4 个 tiered payload 缓冲；
3. 连接永不空闲回收：readLoop 超时后 `idle := len(c.inflight) == 0`（udp_conn.go:367-369）永远为 false，readLoop goroutine + fd 每 30s 循环一次直到进程重启；
4. 永不被容量驱逐：`evictOne` 跳过 `inFlight > 0` 的连接（udp.go:302），`ReapDead` 只清 dead。

对比之下同函数其余全部 11 个出口（355/361/425/480/492/502/523/528/576/587/595）都正确调用了 ReleaseCollect——唯独两个 `break collect` 漏掉（nonEDNS 确认轮的 566 处 break 前在 528 已释放，无此问题）。

**风险**：触发条件是"一个窗口内收到两条答案不一致的 EDNS 响应"——这正是 spoofguard/capsguard 所防御的在路注入者的标准行为（注入假答案 + 真答案同窗到达）。每次发散查询最多泄漏 2 个注册（r0 在 509 泄漏、r1 在 495 泄漏，r2 正确返回）。maxPipe=16：一个地址约 8 条被注入的查询即可将一条 pooled UDP 连接的 capacity 永久占满；该连接此后对所有查询表现为 `IsFull` 且永不回收，后续查询在 `capacity` chan 上阻塞到 ctx 超时。maxConns=8 全部僵尸化后该地址 UDP 路径彻底不可用（Acquire 只能返回满载连接或 ErrNoAvailableSocket），只能靠 TCP fallback 续命直到进程重启。防御机制自身成为资源耗尽放大器。Round 4 的注入测试台未覆盖多轮 collect 循环的注册配对（pool/udp_test.go 仅覆盖单轮；spoofguard_test.go 只测状态机层），故此前未被发现。

**修复**：两处 `break collect` 前调用 `uc.ReleaseCollect(matchKey)`（与 528 处 nonEDNS 分支在 pickBest 后立即释放的写法对齐）。建议补一条"发散轮 + 注册配对"回归测试：循环调用 `ExchangeCollect` 两次后断言 `uc.inFlight.Load()==0` 且 `len(inflight)==0`。

---

**U2 | MEDIUM | 安全一致性 / DoH 重定向 | server/upstream/tls/https.go:194-197 + tls/http3.go:217-220（对照 tlcp/http_tlcp.go:105-110）**

DoH（h2）与 DoH3 的 `http.Client` 未设置 `CheckRedirect`，默认跟随最多 10 跳重定向。共享的 `zdnsutil.ExecuteDoHRequest`（internal/dnsutil/https_dns.go）也不设。而 HTTP-over-TLCP 路径显式禁用了重定向，注释写明理由（http_tlcp.go:105-110）："Never follow redirects: a 3xx would re-send the full DNS query (dns= URL) to an arbitrary host — query leak + SSRF, and a redirect to http:// would bypass TLCP entirely"。

**风险**：恶意/失配置的 DoH 上游收到 GET `?dns=<base64-wire>` 后完全知晓查询内容，返回 `302 Location: http://attacker.example/?dns=<原参数>` 即可让 net/http 将 DNS 查询以**明文 HTTP** 重发到攻击者选定的主机（http scheme 走 `transport.DialContext`，`DialTLSContext`/eTLS 被绕过——与 endpoint.go:42-44 拒绝非 https scheme 的理由完全同源）；重定向到其他 https 主机则构成出流量改向。DoH3 因 http3.Transport 拒绝非 https scheme，明文泄漏不通，但 https→https 的查询外带/SSRF 同样成立。两条 DoH 实现一条防一条不防，属同一仓库内安全加固不对称，且已写明的一侧论证对另一侧逐字成立。

**修复**：在 `createDOHClient` 与 `createDOH3Client` 构造 `http.Client` 时加 `CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }`，与 http_tlcp.go 对齐。

---

**U3 | MEDIUM | 吞吐/一致性：池饱和旁路 | server/upstream/tls/tls.go:32-61、tls/dtls.go:51-71、tlcp/tlcp.go:32-56、tlcp/dtlcp.go:72-92（对照 plain/tcp.go:70-76、plain/udp.go:83-88）**

plain 路径在池 `Acquire` 返回饱和类错误（`ErrNoAvailableSocket` / `ErrMaxConnsReached` / `ErrPoolShutdown`）时**立即返回错误**，注释明示理由（plain/tcp.go:73-75）："The pool's saturation errors exist precisely to bound concurrent dials — falling through to a per-query dial bypasses the caps"（f22ce3df，pprof 驱动的 dial-churn 修复）。但四个安全传输路径（ExecuteTLS / ExecuteDTLS / ExecuteTLCP / ExecuteDTLCP）对**所有** Acquire 错误一律穿过 ctx 检查后落入逐查询手工拨号 + 完整 TLS/TLCP 握手。

**风险**：池饱和的定义就是"该 key 已有 8 个并发拨号在途/8 条连接满载"——此时每个后续查询各自再起一次 TCP+TLS 握机，恰好重建 f22ce3df 在递归路径上消灭的拨号风暴（递归行走大量 NS 地址、TCP/TLS fallback 本身是 evictOne 注释点名的场景 "recursive TCP fallbacks, forced-TCP configs"）。安全传输握手成本（1-2 RTT + 证书解析）远高于 plain 拨号，churn 放大更明显；同时逐查询连接绕开全局 maxTotal 上限。正确性无损，属吞吐与上限旁路问题。

**修复**：四个 Execute* 补上与 plain/tcp.go:70-76 相同的三错误 sentinel 门（返回 acqErr 而非落入 fallback）。DNSCrypt 路径（dnscrypt/client.go:203-207）同样穿过，但注释声明是有意为之（"the pool must not become a new failure mode"）——若统一策略应一并决策并写明。

---

**U4 | MEDIUM | 吞吐/延迟：collect 模式无重传 | server/upstream/plain/udp.go:299-601 + pool/udp_conn.go:268-315（对照 Exchange 的重传 214-259）**

`UDPConn.Exchange` 实现了丢失恢复：静默 `DefaultUDPRetransmitInterval`（1s）后重传、最多 `DefaultUDPRetransmitCount`（2）次（udp_conn.go:214-259）。而 collect 模式的 `ExchangeCollect` 只写一次，无任何重传；`executeUDPCollect` 在**完全静默**（响应数据报丢失，或 hopguard 基线漂移期 `Validate` 拒掉全部数据报）时没有任何窗口内出口——443/526 两个窗口分支都要求已有候选——只能等 `now.After(maxDeadline)`（= 整个 `c.timeout` 预算）后返回 `errNoResponse`。随后 ExecuteUDP 落入 `executeUDPPooled` 时 ctx 预算已被 collect 耗尽，Exchange 立即超时，实际结局是整个查询失败或再花一份完整预算走 TCP fallback（延迟翻倍）。

**风险**：所有启用 `spoofguard || hopguard || capsguard` 的 A/AAAA 查询都走 collect 模式——这是防御配置的默认热路径。单丢一个响应数据报（日常概率事件）在无 guard 时由 1s 重传覆盖、在 full-guards 下变成整预算超时 + TCP 重询。hopguard 学习期 TTL 漂移（路由变更后 ±2 窗口外的真响应被全部拒收）同样落入此路径。

**修复**：在 executeUDPCollect 的 pollTimer 分支中，当本轮 `sg.last == nil && sg.nonEDNS == nil && sg.packets == 0` 且静默超过 `DefaultUDPRetransmitInterval` 时重发一次 `msgData`（复用 round 内已有的 wire；计数上限对齐 `DefaultUDPRetransmitCount`），或给 ExchangeCollect 增加与 Exchange 相同的内部重传定时器。

---

**U5 | LOW | 内存（池回收缺失，非泄漏）| server/upstream/plain/udp.go:401-427、515-524、568-597、461-509**

`prevRoundSigs`（前一轮发散候选，所有权已移交给本函数）只在 ctx.Done（352）、连接关闭（371）和发散分支内部（475/486）归还 `pool.DefaultMessage`；四个出口漏放：
- 快速返回路径 401-427（Puts sg.last/prev/nonEDNS/previous，**无** prevRoundSigs 循环）；
- 窗口到期 pickBest 返回 515-524（上一轮发散后本轮收敛为单候选时到达）;
- nonEDNS 窗口分支 526-566（上一轮发散、本轮全 nonEDNS 时到达）；
- maxDeadline 出口 568-597。
同理，发散分支（451-509）的所有出口都不归还 `sg.nonEDNS`（takeCandidates 只清 prev/last；fast-return 404-412 与 pickBest 内部都处理 nonEDNS，唯独发散分支不处理）。

**风险**：均为 `*dns.Msg` 错过 sync.Pool 回收、由 GC 兜底——无泄漏，仅 guarded 热路径上的回收效率损失（每次 1-3 条消息）。可达性已核实（发散后下一轮收敛/全静默/超时都是正常转移）。

**修复**：上述出口补 `for _, c := range prevRoundSigs { pool.DefaultMessage.Put(c.msg) }`（可提为局部 `releaseSigs()` 闭包）；发散分支入口处补 `sg.nonEDNS` 归还。

---

**U6 | LOW | 每查询分配（DoQ 热路径）| server/upstream/tls/quic.go:48**

`ExecuteQUIC` 在 `Acquire` 之前无条件 `tlsConfig := c.stdTLSConfig(server)`——含 VerifyConnection 闭包 + 握手日志结构体的整份 `tls.Config` 每查询分配一次，**池命中路径（常态）分配后即弃**。同包的 DoT 已把 config 构建下沉到 dial 闭包内（tls.go:33-38 注释 "Config built only on dial — the pool-hit path skips the per-query config Clone"），DoH/DoH3 有 per-upstream endpoint 缓存（endpoint.go，91441af2），唯独 DoQ 未做。

**修复**：仿 DoT：把 `c.stdTLSConfig(server)` 移入 `dialQUIC` 闭包（仅拨号时构建），或在 dohEndpoint 中一并缓存 base config。

---

**U7 | LOW | 一致性（socks5 net.Error 保留）| server/upstream/socks5/udp.go:360-370（对照同文件 275-285）**

`socks5PacketConn.ReadFrom` 刻意**不包装** read 错误以保留 `net.Error` 类型身份（udp.go:276-284，带 `//nolint:errorlint` 注释：gotlcp DTLCP 客户端用裸类型断言 `err.(net.Error)` 判定重传，fmt.Errorf 包装会破坏断言）。而紧邻的 `socks5UDPConn.Read` 对所有错误一律 `fmt.Errorf("socks5: read: %w", err)` 包装（udp.go:369）。当前无受害消费者（UDP 池 readLoop 用 `errors.As` 可解包；DNSCrypt 路径不做超时分类；gotlcp/pion/quic 都走 PacketConn/ReadFrom），但两者语义差异正是 ReadFrom 注释警告的那类坑——一旦某个 net.Conn 消费者（或升级后的 gotlcp/pion 路径）改用裸断言即触发。

**修复**：`socks5UDPConn.Read` 与 ReadFrom 对齐：`net.Error` 原样返回，其余才包装。

---

**U8 | LOW | RFC 7766 §7 一致性（one-shot 流式路径）| server/upstream/plain/tcp.go:126-139（对照 pool/tcp_conn.go:287-301）**

池化 plain TCP 严格校验问题回显（qname/qtype/qclass，且 qdcount=0 视为不匹配，tcp_conn.go:287-301），但同一协议的非池化回退 `exchangeSegmented` 只校验 ID（tcp.go:136-138）。UDP 三条路径（one-shot 150 / pooled 242 / proxy 647）全部有 matchQuestion——唯独 plain TCP 的 one-shot 回退缺失。RFC 7766 §7 要求客户端校验响应问题段。风险低（专用新鲜连接，错配需要对端主动作恶），但该路径正是 UDP 截断 fallback 的承接者，且同协议池化路径已实现该校验、spoofguard.go 的 matchQuestion 可直接复用。

**修复**：`exchangeSegmented` 在 ID 校验后加 `if !matchQuestion(response, msg) { Put; return err }`。

---

**U9 | LOW | 微优化不一致（collect 路径 16KB memset）| server/upstream/pool/udp_conn.go:96-102（对照 114-119 注释）**

`acquirePacketBuf` 的 release 闭包 `clear(*bp)` 清空整个 tier 缓冲（small 512B / large 16KB）；该闭包只随 `collectPacket.Release` 在 collect（spoofguard/hopguard/capsguard A/AAAA 热路径）上执行。姊妹函数 `releasePacketBuf` 特意不清并写明理由（"clearing would add a memset of up to 16KB per released packet on the large tier"）；安全性论证（readLoop 投递前总是覆写 [0:n]、读者长度受 n 约束）对 collect 数据报逐字成立。collect 路径每候选包白付一次最高 16KB 的 memset。

**修复**：闭包去掉 `clear(*bp)`（保留 Put），与 releasePacketBuf 的不清理纪律统一；或在 releasePacketBuf 注释处补一句 collect 路径同理。

## 重点核实通过项（无发现）

1. **Round 5 六项修复落地核实**：U-1（hopArmed/capsEchoVerified 语义，client.go:282-292 现与文档一致）；U-2（DoH scheme 强制 https，endpoint.go:45-47 + config 校验）；U-3（dnscrypt 双池化，client.go:253-259 `pooledPayload` 门已隔离）；U-4（dtls.go:222-223 注释已改为 "a fresh non-pooled dial"）；U-5（DoT ALPN 校验仍未加但 TLCP 有——见 Round 5 记录，本轮未再报）；U-6（边界注释保留为已知事实）。
2. **socks5/ 逐行补审（Round 5 盲区）**：parseDatagram 边界（4/10/22 字节三档 ATYP 全检）、writeDatagramHeader 缓冲尺寸推导、srcAddr 从池缓冲拷贝（datagram.go:75-81 注释所记 DTLCP 0.0.0.0 回归已修）、monitor goroutine 生命周期（cleanupLocked 关 ctrlConn 解锁 Read，`d.ctrlConn == ctrlConn` 防双清）、ReadFrom/Read 池缓冲 clear 前缀后 Put、splitHostPort 的 IPv6 去括号启发式、DialContext/establishUDPRelay 无 deadline 时回落 d.timeout——除 U7 外无发现。
3. **池配对与计数**：UDP/TCP/Raw 三池 Acquire 单遍 dead-filter 的 `p.total` 记账（含 early-return 与尾部补扫）、dialAndAdd 重检、replaceDead 净零交换、evictOne 死先闲后、Shutdown 幂等、ReapDead 原位过滤——逐行验算正确。Exchange/Exchange(Raw) 的注册-注销-排水三元组在全部错误路径闭合；ExchangeCollect 自身四个早退路径的 inFlight/capacity 手工释放全部闭合（泄漏在调用方 plain/udp.go，即 U1）。
4. **tcp_conn.go readLoop**：verify+deliver 在 RLock 下原子化（晚到响应不落已清空的 chan）、qdcount=0 拒收、拆包错误容忍不杀连接、write-deadline-set-then-reset 在 writeMu 内序列化。
5. **ExecuteQuery capsguard 状态机**：随机名 RR 私有拷贝（防 fan-out 共享 Header 竞写）、defer 恢复原名、连续失配计数/降级窗口/成功复位（capsguard.go LoadOrStore 竞败取实际值）、PTR 豁免、Uncertain 标记条件与 client.go:39-56 及 AGENTS.md 文档逐条吻合；Downgrade map 无 OnEvict（值丢失即计数重置，安全方向）。
6. **proxyDialer 并发建 dialer 竞态**：lrumap.Set 覆盖时调 OnEvict（lru.go:140-149）——败者的 base Dialer 无 relay 资源（cleanupLocked 全 nil no-op）、base dialer 无状态可继续用，无泄漏，非发现。
7. **QUIC 池**：0-RTT 拒绝双路径（池内 + 非池化）的 reset/Remove/Put 纪律、proxy PacketConn 三处泄漏钩子（失败即关 / conn.Context().Done() 后台关）、Put 去重 + 死连接拒收；isQUICConnFatal 只删传输级致命连接（ deadline/配额瞬态保留）。
8. **dnscrypt**：cert 状态单飞 + 提升 follower 的 certFetchTimeout 预算、cache=nil 关闭语义全路径 nil-guard、TC 升级有界循环（maxTCRetries=7）、decrypt/unpack/ID 三类失败各自正确的 state 处置（读错误保留 state、解密失败删 state）。
9. **Close 对称性**：upstream Client.Close（4 子 client + warmWg.Wait + proxy Range）、tls/tlcp/dnscrypt 各自的 LRU 故意不置 nil 的竞态注释与调用侧 nil 守卫成对成立。

## 审过的文件清单

- server/upstream/：client.go、execute.go、capsguard.go、warmup.go
- server/upstream/plain/：client.go、udp.go、tcp.go、spoofguard.go
- server/upstream/pool/：tcp.go、tcp_conn.go、udp.go、udp_conn.go、raw.go、raw_conn.go、quic.go、errors.go
- server/upstream/tls/：client.go、tls.go、endpoint.go、https.go、http3.go、quic.go、dtls.go
- server/upstream/tlcp/：client.go、tlcp.go、dtlcp.go、http_tlcp.go
- server/upstream/dnscrypt/：client.go、state.go（cert.go/crypto.go 结构复查）
- server/upstream/socks5/：socks5.go、tcp.go、udp.go、datagram.go（逐行，Round 5 盲区补审）
- 关联核实：internal/lrumap/lru.go（Set/OnEvict/LoadOrStore 语义）、internal/dnsutil/https_dns.go（ExecuteDoHRequest 重定向）、internal/pending/pending.go（单飞）、config/defaults*.go（池/窗口/重传常量）、测试覆盖面（pool/udp_test.go、plain/spoofguard_test.go、dnscrypt/state 层）

## 汇总表

| 编号 | 严重程度 | 类别 | 位置 | 摘要 |
|------|----------|------|------|------|
| U1 | HIGH | pool-leak / 资源耗尽 | plain/udp.go:495,509 | 发散 EDNS 轮 break collect 漏 ReleaseCollect——collect 注册（capacity 槽 + inflight 表项 + ≤4 payload 缓冲）永久泄漏，连接永不空闲回收/驱逐；注入者 ~8 查询/地址即可僵尸化 UDP 池（DoS 直到重启） |
| U2 | MEDIUM | 安全一致性 / DoH 重定向 | tls/https.go:194、tls/http3.go:217 | DoH/DoH3 未禁用重定向（TLCP 路径已禁并写明理由）——恶意上游 302 到 http:// 可使查询明文外发/SSRF |
| U3 | MEDIUM | 吞吐/池上限旁路 | tls/tls.go、tls/dtls.go、tlcp/tlcp.go、tlcp/dtlcp.go | 四个安全传输路径在池饱和错误下落入逐查询拨号，绕过并发拨号上限（plain 路径 f22ce3df 已修复的同款 churn） |
| U4 | MEDIUM | 吞吐/延迟 | plain/udp.go:299-601 | collect 模式无重传——单丢响应数据报 = 整预算超时后必然失败/TCP 翻倍延迟；guarded A/AAAA 默认热路径 |
| U5 | LOW | 池回收缺失 | plain/udp.go:401-427 等 | prevRoundSigs / sg.nonEDNS 在 4+3 个出口错过 DefaultMessage 回收（GC 兜底，非泄漏） |
| U6 | LOW | 每查询分配 | tls/quic.go:48 | DoQ 池命中路径白付一份 tls.Config+闭包/查询（DoT/DoH 已缓存） |
| U7 | LOW | 错误包装一致性 | socks5/udp.go:369 | socks5UDPConn.Read 包装破坏 net.Error 身份，与同文件 ReadFrom 刻意保留的纪律相悖（暂无受害消费者） |
| U8 | LOW | RFC 7766 §7 | plain/tcp.go:126-139 | one-shot plain TCP 只校验 ID 不校验问题回显（同协议池化路径已校验） |
| U9 | LOW | 微优化不一致 | pool/udp_conn.go:96-102 | collect 路径 release 闭包 clear 整 tier 缓冲（≤16KB memset/包），与 releasePacketBuf 特意不清理的纪律矛盾 |
