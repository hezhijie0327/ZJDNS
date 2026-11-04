审查完成。7 个 commit 全部逐 diff 对抗性审查完毕,所有相关测试套件通过(`go build ./...` 干净;resolver/upstream/cache/config/handler/protocol 包 `go test` 全绿)。以下为最终报告。

---

# Round 5 Round C 修复面复查报告

## 发现清单

### 1. [2f5ec4be] MEDIUM | server/upstream/client.go:278-286 + server/upstream/plain/udp.go:44-48
**问题**:H2 的三值签名使 hopguard 启用 upstream 的**所有非 A/AAAA qtype 永久不可缓存**。唯一产出 `Verified=true` 的 collect 纪律只对 A/AAAA 运行(`isAQtype` 门,udp.go:44-48,注释明言 "GFW only hijacks A/AAAA");非 A/AAAA 查询必然走 single-read(verified=false)。清标条件 `!capsEchoVerified && (!hopArmed || !result.Verified)` 中 `!result.Verified` 恒真 → 即使基线已 armed,TXT/MX/SRV/HTTPS/NS/DS/DNSKEY 等响应全部标记 `Uncertain`(65281)、永不入缓存。修复前(基线 7bd0118b 已核实)`!hopArmed` 单独决定,armed 即清标、正常缓存。影响:转发路径非 A 流量 + 递归路径非 A/AAAA 终端应答(经 C1 传播链 cname.go:266 `allCacheable=false`)缓存命中率坍塌,客户端每次收到 EDE 65281 噪音。与代码自身威胁模型(isAQtype 注释:注入只针对 A/AAAA)自相矛盾。
**修复建议**:`(!hopArmed || (!result.Verified && isAQtype))` 形态——把 per-datagram 验证要求限定在确实存在 collect 纪律的 A/AAAA 上;或 hopguard 下对所有 qtype 运行 collect。

### 2. [e1207ac1] LOW | internal/demux/sniff_peek.go:101-105
**问题**:POLLRDHUP 捷径用**过期的 `n`** 判定 `io.ErrUnexpectedEOF`。时序:首次 recvfrom 得部分头(n=2)→ 对端补齐剩余字节并 FIN → poll 返回 POLLIN|POLLRDHUP(同时就绪)→ 直接返回 ErrUnexpectedEOF,**不再重读**——5 字节完整头已在队列却判死,handleConn 关闭连接(demux/tcp.go:159-161)。修复前的循环在此场景会经 POLLIN 唤醒重读满 5 字节并成功——这是修复引入的回归窗口。仅影响首飞后立即半关闭的客户端(合规 TLS 客户端不做;朴素 DNSCrypt-TCP 客户端可能做)。
**修复建议**:`hup && n > 0 && n < len(buf)` 时先再做一次 recvfrom,凑满即成功。

### 3. [a1223255] LOW | server/resolver/ns_concurrent.go:426-434
**问题**:新加的零窗口 NXDOMAIN 捷径**缺少同 commit 给延迟窗口路径补上的 resultChan 排空**。当某权威的 NXDOMAIN CAS+channel-arm 与另一权威的 NOERROR 入队(缓冲 channel)在 wait loop select 观察前都完成时,两个 case 同时就绪、随机选择;选中 nxdomainCh 即以 NXDOMAIN 压过已就绪的 NOERROR 正确答案,且 winner 的 pooled message 永不归还。修复前(已核实 7bd0118b 版本)该竞争需两次硬币(25% 错选),新捷径升为 50%,且 `DefaultNXDOMAINDeferralWindow=0` 是默认配置路径。同 commit 在 timer 路径(448-456 行)修的正是这个洞,零窗口路径漏了。
**修复建议**:返回 `nx` 前镜像 448-456 行的非阻塞排空。

### 4. [f6e4c2c5] LOW(瑕疵) | server/upstream/tls/endpoint.go:44-46
**问题**:运行时门只查 `Scheme != "https"`,未查 `Hostname() == ""`(tlcp 孪生 server/upstream/tlcp/http_tlcp.go:40 两者都查)。"https:" 无 host 形态经配置校验的路不可达(validate_upstream.go 已查 `u.Host == ""`),但编程式构造的配置(绕过 LoadConfig)仍会归一化为拨号 ":443"。
**修复建议**:补 `parsedURL.Hostname() == ""` 判空,与 tlcp 版对齐。

---

## 重点线索核查结论(验证实现,均属实)

- **P1 快路径别名**:`stripCrossZoneRecords` 无符号快路径(a1223255 新增,zonecut.go:48-50)与根区路径(recursive.go:205)确实返回池化 msg 的 backing array 别名。链条核实无跨所有者突变:cname 聚合只 append(cname.go:300/309);`filterRecordsByCIDR`/`mergeRRs` 新建切片;`cache.Set` 入库前深拷贝(cache/entries.go:303-304)。唯一 Put 后的切片写是 `FoldCase` 的 `rrs[i] = foldCaseRR(rr)`(resolver.go:312 → dnsutil/case.go:24-29)——机制上安全:`pool.Put` 仅清结构体(pool.go:137),数组与池断开;Get+Unpack 从 nil 追加、不复用旧数组。`ShuffleSlice` 只用于 NS 地址表,不触及答案切片。结论:契约边缘但无实际缺陷。
- **Batch A(C1)**:`allCacheable` 初值 true 正确——递归走查所有终态 QueryResult 均显式 `Cacheable:true`(recursive.go/recursive_helpers.go 全枚举),唯一置 false 者是 `applyDefenseUncertainty`;Err 路径提前返回不参与聚合。`cachedHopResult` 返回 true。lame 终端补标后 resolve() 全部 5 类终态覆盖(root/processAnswerWithDNSSEC/collectBestNSMatch/checkLameDelegation/TCP 重启内部自覆盖)。干净。
- **Batch C(2f5ec4be)**:ExecuteUDP 全部 return 路径三值齐(编译器强制);TCP fallback 同时置 `Verified=true` 与 `Protocol=ProtoTCP`,ProtoUDP 门不会误判;§6.4 重试整体重赋 result,Verified 反映重试。发现 1 之外干净。
- **Batch E(M1)**:`qtResults` 以 `len(qtTypes)` 缓冲(mqtype.go:101),defer 发送永不阻塞、无泄漏;panic 槽 qr=nil 被 merge 端 100 行 `qr == nil` 先于字段访问跳过;截断路径同样安全。干净。
- **M9**:已核实 host:port 形态此前确实不工作——`url.Parse("dns.example.com:443")` 解析为 scheme="dns.example.com"、Host=""(字母+点为合法 scheme 字符),dohEndpointFor 归一化拨 ":443";IPv4 形态直接 parse 报错。拒绝是修复而非破坏。
- **M6**:`QUIC`(string)与 `HTTP3.Port`(string)同型比较;监听器仅在端口非空时启动,无默认端口注入绕过路径(protocols.go 核实)。
- **L15**:`NewTCPDemux` 只为已注册 route 建队列(tcp.go:68-70),`Listener(ProtoTLCP)` 对未注册返回 nil(tcp.go:83-90),`startTCPGroup` 的 `tlcpQueue != nil` 门正确跳过;到达的 TLCP 形连接经 handleConn `!ok` 即时关闭。正确。
- **L16**:写 deadline 在 Write 返回后立即清除,respondQUIC 单次写、调用方随后关流,清除时序无害。

## 逐 commit 结论表

| Commit | 内容 | 结论 |
|--------|------|------|
| b50927b5 | C1: EDE 65281 递归传播 | **干净** — 传播范围/终态覆盖/测试均核实,回归测试非恒真且通过 |
| 2f5ec4be | H2/H3/M8: 三值签名+Verified | **1 个 MEDIUM**(发现 1:非 A/AAAA qtype 在 hopguard 下永久 no-cache,缓存回归);其余矩阵逻辑、TCP 交互、测试均正确 |
| ae506dad | H4: nonEDNSSafe Feed 门 | **干净** — 门与 pickBest feed 一致;`sg.packets==1` 为真实静默佐证(Validate 拒收的包不计数) |
| a9a2ed6e | M1/M2: QTx defer+merge 门 | **干净** — 缓冲 channel 无死锁面,nil 槽覆盖,merge/store 同步跳过一致 |
| f6e4c2c5 | M6/M7/M9 | **1 个 LOW 瑕疵**(发现 4:endpoint.go 缺 Hostname 判空);M6 类型/默认形态、M7 TTL 算术与 NSEC3 NODATA 既有存活门、M9 host:port 确认本就坏 |
| e1207ac1 | H1: sniff 退避+POLLRDHUP | **1 个 LOW**(发现 2:POLLRDHUP 捷径用过期 n,完整头+FIN 竞争由可成功变为关闭);FreeBSD 交叉编译通过,退避/CPU 界测试有效 |
| a1223255 | LOW 批 | **1 个 LOW**(发现 3:零窗口 NXDOMAIN 捷径缺排空);其余 13 项(dnscrypt 池标志、DoQ deadline、takeCandidates、verifyMemo、captureUpstreamEDE、NSEC 容量、mergeRRs、zonecut 快路径等)逐一核实无新缺陷 |

**总评**:7 commit 中 4 个完全干净;3 个引入了可定位的新缺陷(1 MEDIUM + 3 LOW,其中 MEDIUM 是行为/性能回归而非安全洞)。所有回归测试断言有效、全部通过。