# Round 6 审计 — 逐项修复计划(2026-11)

基线:`88de480b`(Round 5 收尾)→ HEAD。重点面:Round 5 后依赖全量浮动(miekg/dns v0.6.134、pion/dtls v4.0.3、quic-go 20261110、gmsm v0.45.3、compress 20261111)+ 全项目 20 维度新鲜审计 + 对标项目分析(dnscrypt-proxy / encrypted-dns-server / coredns,报告见 08-reference-comparison.md)。

基线状态:build ✓ / `go test -short ./...` 43+ 包 ✓ / golangci-lint 0 警告 ✓。

## 发现汇总(8 份报告,7 个包级 agent + 1 个对标分析 agent)

交叉确认:U1 与 S1/S2/S3 同文件族(hopguard/spoofguard 状态机);R2/R3 与 F 系池契约同族。

### Sprint 1 — HIGH(4 项,全部修复)

| 编号 | 严重度 | 位置 | 问题 | 修复 commit |
|------|--------|------|------|------------|
| R1 | HIGH | resolver/forward.go waitLoop | `primariesDoneCh`(closed channel)在 tryAdopt 返回 done=false 后永久 ready → 紧自旋烧满一核直到 fallback 应答(CPU share 0.98 实证);primary 批量死亡时 N 并发查询 = N 核自我 DoS | `7afa69b3` case 体内 `primariesDoneCh = nil`(一次性语义)+ CPU share 回归测试 |
| U1 | HIGH | upstream/plain/udp.go:495,509 | 发散 EDNS 轮两个 `break collect` 不释放 ExchangeCollect 注册(容量槽+inflight 表项+≤4 payload 缓冲永久泄漏,连接永不回收)——注入者 8 条查询僵尸化一个 UDP 池连接,防御层自身成为资源耗尽向量 | `b8ed2c84` break 前 ReleaseCollect + maxPipe=1 池回归测试 |
| S1 | HIGH | upstream/plain/udp.go conn-death 分支 | collect 期间连接死亡(伪造 ICMP 可触发)时未确证候选 `sg.last` 以 err=nil 返回 → 绕过静默窗口与跨轮确证,注入者置后发包选定赢家 | `a05c1a2d` 分歧未确证一律 errCollectClosed(TCP 回退)+ 注入复现测试 |
| S2 | HIGH | upstream/plain/udp.go deadline 分支 | `safe` 无视 `divergentEDNS`:滴注攻击(<500ms 间隔变体假包)使窗口永不过期,9s 预算耗尽后末包假答案按 safe 服务 + 延迟 DoS(~23 包/查询成本) | `a05c1a2d` safe 排除分歧未确证态(→ errAmbiguous)+ 滴注复现测试 |

### Sprint 2 — MEDIUM(13 项,全部修复)

| 编号 | 位置 | 问题 | 修复 commit |
|------|------|------|------------|
| R2 | resolver/cname.go:78-88 | CNAME-hop 缓存命中只 ReleaseOffsets 不 ReleaseWire——热路径每次命中遗弃 2KB 池对象(≈30MB/s @50k QPS×30% 命中) | `4be9fba3` |
| D1 | cache/key.go+entries.go | 客户端 ECS 变体无上限繁殖缓存键(/32//128 各占一条);~2000 报文清空默认缓存 + 上游放大 | `46e1a0a8` 键前缀封顶 24/56 + 掩码(与出站截断对齐) |
| D2 | config/validate_tls.go | TLS 族配端口但 certificate.tls 未配置 → 静默不监听;DTLS 证书路径不在校验集 | `4be9fba3` |
| H1 | middleware/mqtype.go | merge 无条件收满 QTx:本地拒绝(ACL/Validation/Zone)被上游解析阻塞最长 3s + 4 个上游查询/包的放大 + 拒绝响应附空 MQRESPONSE | `560394e4` 非 NOERROR/NXDOMAIN 主响应跳过 merge |
| U2 | upstream/tls/https.go+http3.go | DoH/DoH3 未禁重定向:302 → http:// 使 DNS 查询明文外发(query leak + SSRF) | `8e6a11f1` CheckRedirect=ErrUseLastResponse |
| U3 | tls/{tls,dtls}.go + tlcp/{tlcp,dtlcp}.go | 池饱和错误穿透到逐查询拨号+完整握手(dial-churn,递归 TCP fallback 场景放大) | `8e6a11f1` 三 sentinel 门(对齐 plain) |
| U4 | upstream/plain/udp.go | collect 模式无重传:单丢响应 = 整预算耗尽 + TCP 双倍延迟 | `febd9cd7` 静默轮 1s 重传(对齐 Exchange) |
| S3 | defense/hopguard.go:212-224 | 武装态 1/16 拒绝采样无内容门/计数上限:~32 包/查询同 TTL 洪泛两个 rebuild 周期捕获 mode → 基线投毒 → fast-accept 可缓存 | `7fb0d617` 拒绝样本独立直方图,rebuild 按 mode/4 上限合并(一次性副本防复利),永不驱动 rebuild 节拍但保留 5min 时间重建(防纯漂移锁死) |
| S4 | plain/spoofguard.go(设计边界) | identical-repeat/跨轮签名确证可被确定性伪造者自证——"corroborated-only"的非确定性先验未显式化 | `7fb0d617` 注释+AGENTS.md 显式化威胁模型边界 |
| S5 | upstream/client.go:282-292 | 非 A/AAAA 单读凭地址级武装清标入缓存(违反文档不变量"armed baseline alone never clears");单读 TTL 采集被丢弃 | `7fb0d617` Exchange 携带 TTL→单读跑 Validate→per-datagram 验证;标记条件收紧为 `!hopArmed || !result.Verified` |
| P1 | protocol/tls/handlers.go 等 | 共享口 4 shard 下 doqAddrCache/h3AddrCache last-wins:3/4 客户端 Retry 白名单永不生效(+1 RTT/连接)+ 字段无锁读写竞态 | `09bc21d3` per-shard cache 参数传递,server 字段删除 |
| P2+P7 | internal/demux/tcp.go | accept 非临时错误静默永久退出(共享 TCP 口整体死亡无告警);临时错误无退避(EMFILE 自旋) | `09bc21d3` Warn+退避+continue,对齐其余 9 个循环 |
| P3 | server/protocol/shared(全包) | 全树最复杂并发 demux 层零测试;**补 24 个测试**过程中抓到生产 bug:detect.go OPT rdlength 偏移读错(读 TTL 高位字节) | `09bc21d3` |

### Sprint 3 — LOW(全部修复)

| 编号 | 摘要 | commit |
|------|------|--------|
| P4 | TLCP DoT writer 移植 net.Buffers 批量 flush(+9.5% bench) | `09bc21d3` |
| P5 | DNSCrypt decrypt 池化 + replay key 定长数组(每查询省 ~300B+28B) | `09bc21d3` |
| P6 | DoH GET 尺寸门检免解码上界(省一次 base64 解码) | `09bc21d3` |
| P8 | TLCP 自签证书 IP SAN 分支 | `09bc21d3` |
| P9 | 共享口 DNSCrypt worker defer Put | `09bc21d3` |
| P10 | 独立口 DTLCP 准入 try-acquire 丢包(满载不再冻结端口) | `09bc21d3` |
| P11 | DoQ 优雅关闭不再握 sem 等 drain(~13 僵尸连接/s 可耗尽 128 槽) | `09bc21d3` |
| U5 | prevRoundSigs/sg.nonEDNS 出口归还(与 U1 同文件族,Sprint 1 一并覆盖核对) | — |
| U6 | DoQ tls.Config 下沉 dial 闭包(池命中省 140ns/976B/3allocs) | `8e6a11f1` |
| U7 | socks5 Read 保留 net.Error 身份 | `8e6a11f1` |
| U8 | one-shot plain TCP 补 question 回显校验(RFC 7766 §7) | `8e6a11f1` |
| U9 | acquirePacketBuf release 闭包去掉 16KB clear | `7fb0d617` |
| R3 | ZoneKeys wire/offsets 双释放 | `4be9fba3` |
| R4 | 转发侧 NXDOMAIN 零窗口快路径 | `4be9fba3` |
| R5 | MQTYPE 回退重试挂根 ctx(客户端断开传播;审计原文的 WithoutCancel(根) 建议经实测证伪——WithoutCancel 剪断一切取消链,改 WithTimeout(ctx)) | `4be9fba3` |
| D3 | Set 键 canonical 化(混合大小写 glue 名死条目) | `46e1a0a8` |
| D4 | ruleset >2 标签 domain 规则 Warn+跳过 | `4be9fba3` |
| D5 | Engine.MatchTags 直收 net.IP(每查询省 2-3 分配) | `4be9fba3` |
| D6 | zone RFC3597 回退内容校验 + 裸 hex 提取 | `4be9fba3` |
| D7 | NXDOMAIN-cut nil-SOA 潜在 panic 固化 | `46e1a0a8` |
| D8 | UpdateLatencyBatch 置位时序对齐注释 | `46e1a0a8` |
| D9 | 缓存单条 16KiB 字节上限(异常 64KB 上游不再撑爆条数计量的 envelope) | `46e1a0a8` |
| H2 | MQTYPE TC 分支后台 drain(cache-warm 承诺兑现) | `560394e4` |
| H3/H5/H6 | 注释漂移改写(EnsureFullUnpack/cache_store/benchmark) | `39a34461` |
| H4 | 预打包 unpack 失败清 Data 重建真 SERVFAIL wire | `39a34461` |
| F1 | 经典 DNSCrypt UDP pad 预算 64 对齐 + 密封后大小检查 | `39a34461` |
| F2 | lrumap Len/Range RLock(MapLen -31%) | `39a34461` |
| F3 | 经典查询 header 预分配 | `39a34461` |
| F4 | spillfile Warm 锁外读块 | `39a34461` |
| S6 | spoofguard-only 部署纳入 65281 标记 | `7fb0d617` |
| S7 | TTL=0 获胜包不构成正向验证(winnerVerified) | `7fb0d617` |
| DE1 | demux detect.go OPT rdlength 偏移(P3 测试抓获) | `09bc21d3` |

### 对标采纳(08-reference-comparison.md)

| 采纳项 | 内容 | commit |
|--------|------|--------|
| REF-1 | 出站 UDP 连接 IP_RECVERR(IPv6_RECVERR)——不可达上游 ICMP 即时唤醒读,不再吃满超时 | `febd9cd7` |
| REF-6 | Linux UDP listener IP_PMTUDISC_DONT + SO_RCVBUFFORCE(隧道 PMTU 黑洞 + 突发缓冲) | `09bc21d3` |
| 拒绝: MsgOptionPackExpand | 压缩是 1400B UDP 截断预算的承载性依赖;Pack 发生在 cache-write 而非每服务,收益边际 | — |
| 未采纳(记录为后续) | REF-2 per-upstream 被动健康追踪、REF-3 Anonymized DNSCrypt relay、REF-4 PKTINFO 回包源钉死、REF-5 证书钉扎、REF-7 转发自环检测、REF-8 ODoH、REF-9 热重载、REF-10 dnstap/Prometheus | 见报告落地建议 |

### 依赖浮动(commit 7974576d)

- miekg/dns v0.6.129→v0.6.134:自动受益;`MsgOptionPackExpand` 评估后不采纳;msg.Z→Flags 重命名无本库使用。
- pion/dtls v4.0.3:close_notify 前数据投递、拒绝后继续 accept、DTLS 1.3 加固系列——自动受益。
- quic-go v0.65.1-dev:send-stream reset 泄漏修复、http3 Server.Close 死锁修复、帧排序器两级化(4096)——自动受益。
- gmsm v0.45.3 / compress v1.20.5(zstd/s2 边界修复)/ x-crypto v0.59 等——自动受益。
- **已知代价**:fork Pack/Unpack 路径 +2 allocs/+96B(worktree 隔离证明纯依赖来源,非本库改动;0-alloc 直发契约不受影响)。

## E2E 门禁(全过)

14 协议专用口 14/14;共享口 7/7;MQTYPE forward(A 可见+AAAA warm)/直连 recursive 合并/FORMERR;递归真网(cloudflare DNSSEC + baidu CNAME 链);无 EDNS TCP 缓存命中(预打包直发,0ms);12 协议压测 QPS 19-49k(udp/quic/https/http3/http-tlcp/dnscrypt×2 fail=0;tcp/tls/dtls/tlcp/dtlcp 的非零 fail 在修复前二进制上同签名复现——环境负载噪声,非回归);内存同型轮次收敛(73152→73232→73280kB,增量 <0.1% 递减);race 全绿;lint 0 警告。
