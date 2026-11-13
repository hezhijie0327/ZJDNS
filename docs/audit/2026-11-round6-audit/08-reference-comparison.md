# ZJDNS 对标分析：dnscrypt-proxy / encrypted-dns-server / coredns

分析日期：2026-11-14。对标仓库位于 `/tmp/zjdns-refs/`（dnscrypt-proxy、encrypted-dns-server、coredns）。
每条借鉴点均已先在 ZJDNS 源码中 grep 核实"确实没有"再收录；ZJDNS 已具备的能力见文末附录，不再重复建议。

评级口径：**高** = 直接影响吞吐/正确性/安全且落地路径清晰；**中** = 明确收益但工程量或适用面有限；**低** = 锦上添花。

---

## REF-1 【高】连接态 UDP socket 设置 IP_RECVERR / IPV6_RECVERR —— ICMP 错误即时唤醒读超时

- **来源**：coredns `plugin/pkg/proxy/recverr_linux.go`
- **它们怎么做**：`net.Dialer.Control` 里对 `udp4/udp6` socket 设置 `IP_RECVERR`/`IPV6_RECVERR`。注释引用 Linux `net/ipv4/udp.c __udp4_lib_err`：不带该选项时，connected UDP socket 只投递 port-unreachable 一类 ICMP 错误，host/network-unreachable 会被内核直接丢弃 —— 对不可达上游的读会干等到完整超时。设置后 ICMP 错误一到达，`Read` 立刻以 `ECONNREFUSED/ENETUNREACH/EHOSTUNREACH` 失败。
- **ZJDNS 现状**：`server/upstream/pool/udp_conn.go` —— UDPPool 的每个连接正是一条 **connected UDP socket**（`net.Dial("udp")` + `.Read(buf)`，多查询流水线复用），全库唯一的 setsockopt 只有 KTLS 与 `SO_REUSEPORT`（`server/protocol/shared/reuseport_unix.go`）。递归 walk 与转发查询都走这个池：一个路由不可达的权威 NS / 上游目前要吃满整个 query timeout 才判死，且被延迟排序缓存反复重新尝试。
- **价值**：高。上游/权威不可达的发现时间从秒级（超时）降到 ICMP RTT（毫秒级），直接改善递归路径对失效 NS 的收敛速度、转发路径的错误兜底时延。仅 Linux，需 build tag，一处 Dial Control 覆盖 UDP 池全部 socket。
- **落地建议**：在 `server/upstream/pool/udp.go` 的 UDP 拨号处加 `net.Dialer{Control: recvErrControl}`（`//go:build linux` 文件，其余平台 no-op）；读循环里把 `os.IsPermission/ENETUNREACH/EHOSTUNREACH/ECONNREFUSED` 映射为"立即失败"错误类别，让上层按"该地址本次不可达"处理（继续等其它竞态上游，而非重读）。注意：一条 socket 收到 ICMP 会 fail 该 socket 上所有 in-flight 查询 —— 语义正确（同一上游同时不可达），池下次 Acquire 重建。

## REF-2 【高】上游被动健康追踪：连续失败计数 + 探活恢复（maxfails 模型）

- **来源**：coredns `plugin/pkg/proxy/health.go` + `plugin/forward/forward.go`（`maxfails`）
- **它们怎么做**：每个上游一个原子失败计数：正常查询出错时 `incrementFails()`；`Down(maxfails)` 为真时把该上游从轮转里剔除；同时每 `hcInterval`（500ms）跑一次带外健康检查（NS/HINFO ping，per-transport：UDP/TCP/DoT/DoH/DoQ 各有 checker），成功即 `resetFails()` 恢复。转发还提供 `failfastUnhealthyUpstreams` 等 knob。
- **ZJDNS 现状**：`server/resolver/forward.go` —— 转发与递归都是 errgroup 全量竞态 + first-win，**没有任何 per-upstream 失败状态**（grep `maxFail|unhealthy|consecutive` 无结果）。一个死上游会：a) 每个查询都白白发一票；b) fallback 门控（500ms）因"还有 primary 没退出"而拖慢；c) 递归的 NS 批次里死地址反复被延迟排序重启。已有的 RFC 9520 失败缓存（`server/resolver/failure_cache.go`）是 **per-question** 去重，不解决 per-upstream 的持续浪费。
- **价值**：高。多上游转发部署下死上游的影响从"每个查询都付超时代价"降为"一次探活周期的代价"；也保护上游故障时不被客户端重试放大。
- **落地建议**：在 `internal/latency` 的 per-IP 表里加一个 `fails atomic.Uint32`（复用现有 LRU 表，零新结构）：`ExecuteQuery` 返回错误时 +1、成功清零；超过阈值（如 coredns 默认 2，可放 `config/defaults_dns.go`）时从竞态批次里跳过，仅每 N 秒放行一条探活查询（或走 warmup 的 `WarmUpConnections` 通道）直到成功。递归 NS 批次与转发批次共用同一判定。

## REF-3 【中高】Anonymized DNSCrypt Relay（服务端转发 + 客户端经 relay 路由）

- **来源**：encrypted-dns-server `src/anonymized_dns.rs`（服务端 relay）；dnscrypt-proxy `dnscrypt-proxy/proxy.go:639 prepareForRelay`（客户端）
- **它们怎么做**（eds 服务端）：UDP listener 识别 `0xff*8 0x00 0x00` relay magic → 载荷前 16B 目标 IPv6（v4-mapped 折叠）+ 2B 端口 + 原封不动的 DNSCrypt 密文；校验：目标必须是 global 单播、不在黑名单、端口在允许集（默认仅 443，可选 ≥1024）、**不得 relay 到自身**、密文不得再以 relay magic 开头（防环）、长度 ≥ magic+DNS header。用一次性 socket 转发，回包丢弃 `response_len > encrypted_packet_len` 的（**anti-amplification**：回给客户端的字节永不大于请求），证书响应额外做 1000 条 / 600s 的 relayed-cert 缓存。客户端侧（dnscrypt-proxy）把目标 IP:port 前置进查询即可经由任意 relay。
- **ZJDNS 现状**：完全没有 —— 全库无 relay magic / relay 处理（grep `anonymized|relay` 仅命中 stamp 解码：`config/load.go:154` 对 `ProtoDNSCryptRelay/ProtoODoHRelay` "no direct config protocol"）。ZJDNS 的 DNSCrypt 客户端只能直连上游（有 SOCKS5，但 SOCKS5 ≠ DNSCrypt relay，relay 不解密、不依赖 TCP）。
- **价值**：中高。这是公共 DNSCrypt 生态的隐私标配（客户端 IP 对目标解析器隐藏，relay 看不到明文）；ZJDNS 已实现 DNSCrypt v2 + PQ，补 relay 后可同时作为 relay 节点和"经 relay 出站"的客户端，与项目隐私定位一致。
- **落地建议**：分两步独立落地。a) **服务端 relay**（较大）：`server/protocol/dnscrypt/udp.go` 增加 relay 分支，配置项 `anonymized_dns{enabled, allowed_ports, blacklist}`，一次性 socket 转发 + 反放大 + relayed-cert 缓存；b) **客户端经 relay**：`server/upstream/dnscrypt` 在 `prepareQuery` 后按 per-upstream `relay` 地址前置 18B 头，响应侧无需改动（响应不经 relay 原路返回，直连客户端）。b) 先做，改动小、收益直接。

## REF-4 【中】UDP 回包源地址钉死：IP_PKTINFO/IPV6_PKTINFO OOB 透传

- **来源**：dnscrypt-proxy `dnscrypt-proxy/proxy.go:478 udpReplyConn` + `udpListener`
- **它们怎么做**：用 `ReadMsgUDP(buf, oob)` 打开 `ipv4/ipv6.FlagDst`，从 OOB 里解析收到包的**目的地址**；回包时构造 `ControlMessage{Src: dst}` 传给 `WriteMsgUDP` —— 多宿主/策略路由下，回包源 IP 一定等于客户端发包的目的 IP。
- **ZJDNS 现状**：`server/protocol/plain/udp.go:242-245` —— `WriteMsgUDP(b, nil, addr)`，OOB 恒为 nil；读路径 `ReadFromUDP` 不取 OOB。绑定通配地址（0.0.0.0/[::]）时回包源由内核按路由选择，策略路由/VRF/多上行链路部署下可能选错源，客户端（尤其做源校验的 stub）丢包。`dns.Session` 已有 `OOB` 字段（fork 已支持透传），管道是现成的。
- **价值**：中。普通单宿主部署无感；多宿主/容器/VRF 环境是正确性问题。UDP 与共享 demux（QUIC+DTLS+DTLCP 的回包路径在 `server/protocol/shared/`）都适用。
- **落地建议**：`ListenConfig.Control` 里设置 `IP_PKTINFO/IPV6_PKTINFO`；`readLoop` 换 `ReadMsgUDP` 取 OOB 存入 `udpDatagram`/`Session.OOB`；写回时把 `FlagDst` 解析出的地址编成 `Src` control message。注意 demux 的 `PacketBufPool` 管道需多带一个 OOB 引用（OOO buffer 本身也要池化，避免每包 alloc）。

## REF-5 【中】DoH/DoT/DoQ 上游 TLS 证书 SHA256 钉扎（cert_hashes）

- **来源**：dnscrypt-proxy `dnscrypt-proxy/cert_hashes.go` + `xtransport.go`（`VerifyConnection` 回调，~L407）
- **它们怎么做**：`tls.Config.VerifyConnection` 里对握手完成的连接取叶子证书（含 SAN IP 列表），与配置的一组 SHA256 比对，不匹配即失败 —— 绕开 WebPKI 信任链，对"自签/私有 CA"上游提供 TOFU 式身份校验；sdns:// stamp 的 `CertHash` 字段原生携带。
- **ZJDNS 现状**：`server/upstream/tls/client.go:172/195` —— 上游 TLS 校验只有二元 `SkipTLSVerify`，没有证书指纹钉扎。对 hostile 网络里自建 DoH/DoT 上游（项目典型场景），要么信任公共 CA、要么裸跳过校验。
- **价值**：中。给私有上游一个免 CA 的强身份绑定，防止中间人 + CA 作恶；与 DNSCrypt 证书签名（已有）对齐的信任模型。
- **落地建议**：`UpstreamServer` 加 `cert_hashes []string`（hex sha256）；`eTLSClientConfig`/`stdTLSConfig` 的 `VerifyConnection`（两处已有回调可搭车）里，配置非空时比对 `cs.PeerCertificates[0]` 的指纹与 SAN IP 指纹。同时给 `--dnsstamp --decode` 顺带输出 stamp 内 CertHash 便于填写。

## REF-6 【中】UDP listener socket 加固：IP_PMTUDISC_DONT + 收发缓冲区 + TOS

- **来源**：dnscrypt-proxy `dnscrypt-proxy/setsockopts_linux.go`
- **它们怎么做**：UDP listener 的 `ListenConfig.Control`：`IP_MTU_DISCOVER=IP_PMTUDISC_DONT`（关 DF，允许内核分片——避免 PMTU 黑洞）、`IP_DF=0`、`SO_RCVBUFFORCE/SO_SNDBUFFORCE`（4MiB 收发缓冲，吸收突发）、`IP_TOS/IPV6_TCLASS=0x70`。TCP listener：`TCP_QUICKACK`。
- **ZJDNS 现状**：`server/protocol/plain/udp.go:77-79` 与 `shared/udp_dispatch.go:48-50` 只设 `SO_REUSEPORT`（Linux/Unix）。UDP 回包上限 1400B（RFC 9715）：以太网 1500 MTU 下 1428B 恰好放得下，但 **WireGuard(1420)/PPPoE(1492)/部分 IPv6 隧道** 路径上带 DF 会被丢弃；DNSCrypt 的 PQ 证书响应（1320B+overhead）和加密大响应更易触发。默认 `IP_PMTUDISC_WANT` 下 >MTU 的包内核设 DF。
- **价值**：中。隧道/弱网客户端的 UDP 大响应可达性（客户端会重传到 TCP，但首包失败已经是延迟惩罚）；突发下 socket 缓冲防丢。Linux-only，代价是放弃 PMTU 发现（DNS 包 ≤4096，分片可接受——dnscrypt-proxy 同样取舍）。
- **落地建议**：`server/protocol/shared/reuseport_unix.go` 同层新增 `hardenedUDPControl()`（build tag linux）：`IP_PMTUDISC_DONT` + 尝试 `SO_RCVBUFFORCE`（EPERM 则退化 `SO_RCVBUF`），套到 plain UDP 与 DNSCrypt UDP listener；可加 config 开关（默认开）。

## REF-7 【中】转发自环检测（upstream 指向自己/链路回环）

- **来源**：coredns `plugin/loop/loop.go`
- **它们怎么做**：启动时生成随机 token 域名（`<7字符随机>.<zone>`，HINFO 类型）向上游发一跳；只要该 qname 再次抵达本服务器即命中（记数，2 次后 fatal），因为随机名不可能被外部合法递归到。运维报错信息直接给出环路提示。
- **ZJDNS 现状**：无部署级自环检测（grep 仅见 CNAME 环检测 `server/resolver/cname.go:218`）。若 `upstream` 配置指向本服务（或多级回环）：每个客户端查询触发本机再入，errgroup 对 N 个上游 fan-out、每跳再 fan-out —— 深度受 per-request ctx 超时限制，但**宽度按上游数指数放大**，靠 UDP worker 池饱和丢包（`drops` 计数器）兜底，等于自我 DoS。
- **价值**：中。经典配置脚枪（127.0.0.1:53 写进 upstream、或链式 ZJDNS 互相指向），一旦命中即整机不可用；检测成本一次性、几乎为零。
- **落地建议**：`server.Server` 启动监听完成后（warmup 阶段）向每个 upstream 发一条 `loopdetect-<random>.zjdns.internal HINFO`；在 Validation middleware 之前（或 bridge 层）对该 owner 的查询直接短路记数；超阈值 Warn 并把对应 upstream 标记 REF-2 的失败态。比 coredns 的 fatal 更温和：标记 + 警告即可。

## REF-8 【中】ODoH（RFC 9230）作为上游协议

- **来源**：dnscrypt-proxy `dnscrypt-proxy/oblivious_doh.go`（HPKE 封装 query/解密 response、目标 config 解析、config 指纹 keyID）+ `serversInfo.go` 的 ODoH config 后台刷新（`beginODoHRefresh`/冷却期）
- **它们怎么做**：客户端从目标解析器拉取 ODoHConfigs（含 KEM/KDF/AEAD suite + 公钥），用 HPKE（X25519+HKDF-SHA256+AES-GCM 为主）把 DNS 查询封装成 oblivious query 发给 **relay**，relay 原样转给 target，target 只见 relay IP；响应用同一 HPKE 上下文密封回客户端。config 定期刷新（成功/失败冷却，防 target 故障时刷爆）。
- **ZJDNS 现状**：无 ODoH 查询路径（`config/load.go:154` 只认 stamp 类型，无 config protocol；`cmd/zjdns/cli` 能编解码 odoh-target/odoh-relay stamp）。上游协议族 12 种，隐私向已有 DNSCrypt+PQ/TLCP/DTLCP，但缺"对目标隐藏客户端 IP"的 DoH 形态。
- **价值**：中。补齐隐私协议矩阵的最后一块（需引入 HPKE——Go 1.24+ 标准库 `crypto/hpke` 或 circl 已在依赖树中）；属新协议，按项目版本语义是 Y（minor）。ZJDNS 已有 DoH 客户端与 SOCKS5/relay 基建（若 REF-3 先落地，relay 出站可复用）。
- **落地建议**：`protocol: "odoh"` + `odoh_target`/`odoh_relay` 两个地址；实现 config 拉取缓存（TTL + 失败冷却，抄 serversInfo 的 begin/endODoHRefresh 语义）与 HPKE 封装层，HTTP 部分直接骑现有 DoH transport。工程量约等于当年 DNSCrypt 客户端的三分之一。

## REF-9 【中低】配置热重载（SIGHUP / mtime+hash 轮询）

- **来源**：coredns `plugin/reload/reload.go`（tick 间隔内对 Corefile 做 hash，变化即重建 server 并平滑替换）；dnscrypt-proxy `hot_reload.go` + `config_watcher.go`（SIGHUP + fsnotify 双路径）
- **它们怎么做**：coredns：默认 30s 间隔对配置全文做摘要（sha512），变化后走完整 build-rebuild 流程原子替换（新 server 先起、旧 server 再停，过程中查询不丢）。dnscrypt-proxy：SIGHUP 触发 + 文件 watch。
- **ZJDNS 现状**：`server/tasks.go:218` 只处理 SIGINT/SIGTERM 优雅停机；配置修改 = 重启进程。`state_file` 已把 cache/latency/delegation/DNSCrypt 窗口持久化，重启代价已被缓解（缓存热档回灌），但监听端口上的在途查询仍会断（TCP/QUIC 连接全掉）。
- **价值**：中低。长连接协议多（DoT/DoQ/DoH/DNSCrypt/TCP），热重载的收益主要是 TCP/QUIC 连接不断与统计不清零；但 ZJDNS 配置面大（协议栈、上游、防御开关都影响连接池与 listener），全量平滑替换的工程量不小、边界情况多（socket 传递、pool 归属）。
- **落地建议**：分两档。低档：SIGHUP 时仅热更新**可原子快照的部分**（zone 规则、ruleset、ACL——它们已是 `atomic.Pointer` 快照，换指针即可）+ 拒绝其余变更并 Warn；高档（若确有需求）：coredns 式整体 rebuild。建议先做低档，标注哪些字段支持热更。

## REF-10 【低】dnstap 查询日志流 + Prometheus /metrics

- **来源**：coredns `plugin/dnstap/`（framestream over TCP/Unix，protobuf 消息级全量/采样导出）；`plugin/metrics/`（Prometheus）；eds `varz.rs`/`metrics.rs`
- **它们怎么做**：dnstap：监听侧把每条 query/response 事件以 dnstap wire 格式推给本地采集器（unbound/bind9 同款生态，有现成分析工具链）。metrics：`/metrics` 暴露 QPS/rcode/cache-hit/heap 等计数器。
- **ZJDNS 现状**：统计全部内存态（`internal/stats/journal.go`），导出只有 CHAOS TXT（`zjdns._` stats）；无 dnstap、无 Prometheus。pprof HTTP listener 已存在（`server/protocols.go:284`，可选开启，已挂 `/debug/vars`）。
- **价值**：低。单机运维现状够用；但若对外提供服务或进 K8s/集群，Prometheus 是接监控栈的事实标准，dnstap 是合规/取证场景的标准出口。两者都是"导出面"改动，不碰热路径（journal 已有 pooled RequestRecord，加个异步 sink 即可）。
- **落地建议**：`/metrics` 直接挂到现有 pprof listener 的 mux（counter 从 `stats.Journal` 原子数映射，Text format 手写避免引入 client_golang 依赖）；dnstap 做成可选 `dnstap{path, sample}` 配置，异步 channel + 丢弃策略（满则丢，绝不阻塞查询路径）。

---

## 附录：已核实 ZJDNS 已具备、本文不再建议的能力

对标过程中逐项 grep 核实，以下能力 ZJDNS 已实现（多数实现强于对标项目），列出以防重复提案：

| 对标项目的能力 | ZJDNS 对应（已核实） |
|---|---|
| eds SieveCache 缓存 client_pk→shared key（免每查询 X25519） | `server/protocol/dnscrypt/crypto.go:241` classical 路径已有 `sharedKeyCache`（lrumap，随 keySnapshot 快照）；eds 对 PQ initial 同样每次 decapsulate，无差距 |
| eds / dnscrypt-proxy 查询尺寸 EWMA 估计器 | `server/upstream/dnscrypt`（ARCHITECTURE 明确 mirror QuestionSizeEstimator，EWMA 2/31、TC 翻倍、原子无锁） |
| eds 证书轮换 24h TTL / 8h 续签 + 状态持久化 | `server/protocol/dnscrypt`：同样 24h/8h、current+previous 重叠、`persist_file.go` 恢复窗口、ticket key 定期派生 |
| **replay protection** | ZJDNS 独有：`crypto.go checkReplay`（LRU 有界窗口 + 重传宽限）；eds 反而没有 |
| coredns cache prefetch | `cache/cache.go ShouldPrefetch`（10% 阈值）+ `middleware/cache_lookup.go spawnPrefetch` + cooldown + in-flight 去重 |
| coredns cache SERVFAIL 负缓存（failttl 2s） | ZJDNS 更强：RFC 9520 失败缓存（`resolver/failure_cache.go`，指数退避 5s→5min、EDE 透传、LRU 有界） |
| coredns serve-stale / verify-stale | `middleware/cache_lookup.go`：fresh/stale/refreshCoordinator + EDE StaleAnswer（RFC 8914） |
| coredns cache RFC 8198 aggressive negative + wildcard 缓存 | `cache/nsec.go` + `StoreIfCacheable → IndexNegative/IndexWildcard`、NXDOMAIN cut `cache/nxdomain.go`（RFC 8020） |
| coredns 多核 UDP 多 socket（multisocket / SO_REUSEPORT×GOMAXPROCS） | `server/protocol/plain/udp.go`：`DefaultUDPDispatchShards` 分片 socket + 256 worker 池 |
| coredns pkg/cache 256 分片 map | `internal/lrumap` sharded LRU + clock 惰性提升（命中免写锁），优于 coredns 随机逐出 |
| dnscrypt-proxy UDP 连接池（分片、每地址上限、空闲回收） | `server/upstream/pool`：UDPPool/ConnPool/RawPool 三池，per-key/per-conn/全局三层上限 + 60s 空闲回收 + 免锁快照 |
| dnscrypt-proxy TCP/DoT 持久连接 + pipelining | ConnPool RFC 7766 pipelining（maxPipe 16） |
| dnscrypt-proxy ECS 附加 | `edns/` ECS 全套（解析/透传/清洗）+ cache key 含 ecs |
| dnscrypt-proxy 本地 DoH 的 EDNS padding | `edns/` Padding（RFC 8467） |
| dnscrypt-proxy 负载策略（P2/PN/first/random + RTT EWMA 排序） | errgroup 全量竞态 first-win + `internal/latency` per-IP 探测排序 + 500ms fallback 门控（模型不同且更强） |
| coredns dns64 / acl / RFC8482 ANY / bufsize | `middleware/dns64.go` / `acl.go` / `any.go` / RFC 9715 1400B 截断 |
| coredns TLS session resumption | eTLS/quic-go session cache + DoQ 0-RTT token store（含 0-RTT 拒绝后 reset） |
| Go 侧 TCP_NODELAY | Go runtime 对 TCP 默认 no-delay（上游侧另有显式设置） |

## 明确不采纳（与 ZJDNS 设计约束冲突）

- **eds `rate_limiter.rs` / `connection_slots.rs`（per-IP 限速/连接槽）**：AGENTS.md 明示反模式（"No rate limiting or per-IP connection limits"），ZJDNS 以 worker 池饱和丢弃为过载兜底。
- **dnscrypt-proxy 动态超时（负载四阶收缩）**：ZJDNS 竞态 + 丢弃模型已有界，收益边际。
- **dnscrypt-proxy Alt-Svc h3 自动升级 + 负缓存**：ZJDNS 上游协议由运维显式指定（doH/doH3 分开配置），无自动升级需求。
- **dnscrypt-proxy cachedIPs（DoH 主机名解析缓存/多 IP 重试）**：ZJDNS 上游 URL 全部 IP 直连（config.example），无 bootstrap 循环依赖问题。
