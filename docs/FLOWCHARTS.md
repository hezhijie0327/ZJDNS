# ZJDNS 架构流程图

> 本文件与代码逐条核对（2026-08），所有流程图描述的实现细节（常量、分支、门条件）均可回溯到源码。
> 约定：`Zone`/`DNS64` 中间件为条件挂载（有规则/配置时才在链上）。

## 目录

- [整体架构](#整体架构)
- [服务生命周期](#服务生命周期)
- [快照持久化](#快照持久化)
- [中间件管道](#中间件管道)
- [MQTYPE (RFC 10029)](#mqtype-rfc-10029)
- [缓存查询流程](#缓存查询流程)
- [递归解析流程](#递归解析流程)
- [DNSSEC 验证链](#dnssec-验证链)
- [EDNS 处理流程](#edns-处理流程)
- [DNS 污染检测（四层防御）](#dns-污染检测四层防御)
- [TC→TCP 自动回退](#tctcp-自动回退)
- [Zone 规则评估](#zone-规则评估)
- [Singleflight 查询去重](#singleflight-查询去重)
- [DNS64 合成](#dns64-合成)
- [规则集引擎](#规则集引擎)
- [延迟探测](#延迟探测)
- [连接池与协议协商](#连接池与协议协商)
- [SOCKS5 代理路径](#socks5-代理路径)
- [协议对照：标准加密 ↔ 国密](#协议对照标准加密-国密)
- [DNSCrypt 密钥管理](#dnscrypt-密钥管理)
- [DNSCrypt 加密流程](#dnscrypt-加密流程)
- [同步统计记录](#同步统计记录)

## 整体架构

```mermaid
graph LR
    C[Clients] --> L
    subgraph ZJDNS
        L[Listeners<br/>UDP · TCP · DoT · DoH · DoH3<br/>DoQ · DTLS · TLCP · DTLCP<br/>DNSCrypt] --> MW[Middleware Chain<br/>Response · EDNS · MQTYPE · CacheStore<br/>Validation · Zone · Any<br/>CacheLookup · DNS64<br/>Resolution]
        MW --> RES[Resolver<br/>Forwarding · Recursive<br/>QNAME Minimisation · DNSSEC<br/>Delegation Cache]
        RES --> UP[Upstream Pool<br/>TCP Pipeline · QUIC Pool<br/>SOCKS5 Proxy]
    end
    UP --> U[Upstream DNS]
    classDef ext fill:#e2e8f0,stroke:#64748b,color:#1e293b
    classDef listen fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef resolve fill:#d1fae5,stroke:#10b981,color:#064e3b
    class C,U ext
    class L listen
    class MW proc
    class RES,UP resolve
```

## 服务生命周期

```mermaid
graph TD
    START[New Server] --> LOADCONF[Load Config<br/>+ Validate]
    LOADCONF --> INIT[In-memory Init<br/>cache.New → load cache snapshot<br/>→ load latency snapshot<br/>→ zone.New → EDNS<br/>→ Zone/Ruleset → QueryClient<br/>→ Resolver → load delegation snapshot]
    INIT --> WARM[warmUpConnections]
    WARM --> INITMW[Assemble Middleware Chain<br/>10 Layers<br/>Zone/DNS64 条件挂载]
    INITMW --> STARTPROTO[Start Protocol Listeners<br/>UDP TCP DoT DoH DoH3<br/>DoQ DTLS TLCP DTLCP<br/>DNSCrypt + pprof]
    STARTPROTO --> BG[Start Background Tasks<br/>Cookie Rotate · ECS Refresh<br/>Prefetch Cleanup · TCP WriteMu Sweep<br/>UDP Pool Reap · Snapshot Maintenance<br/>Signal Handling]
    BG --> RUNNING[Running<br/>accept queries]
    RUNNING --> SIG{Signal?}
    SIG -->|SIGINT/SIGTERM| SHUTDOWN[Mark Closed<br/>Cancel Context<br/>Stop Protocol Listeners + pprof]
    SHUTDOWN --> WAITBG[Wait Background Groups<br/>Save snapshots: cache · latency · delegation]
    WAITBG --> EXIT[Exit]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef running fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef exit fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class START start
    class LOADCONF,INIT,WARM,INITMW,STARTPROTO,BG,SHUTDOWN,WAITBG proc
    class RUNNING running
    class EXIT exit
```

> 后台任务共 7 项（`server/tasks.go`）：Cookie 密钥轮换（24h）、ECS 公网 IP 刷新（15min）、
> prefetch 节流清理、TCP writeMu 分片注册表 sweep（5min）、UDP 连接池死连接回收、
> 快照周期保存（5min）、信号处理。统计**不是**后台任务——同步内存计数（见「同步统计记录」）。

## 快照持久化

三个 store（cache / latency / delegation）在配置 `state_file` 时持久化；默认路径为空 =
不持久化（重启冷启动）。DNSCrypt 证书状态独立持久化（`dnscryptstate`）。

```mermaid
graph TD
    STARTUP[启动] --> GATE{任一 state_file 配置?}
    GATE -->|是| LOAD[启动加载<br/>cache + latency + delegation]
    GATE -->|否| COLD[冷启动<br/>无周期保存任务]
    RUNNING[Running] --> TICKER{5min 周期}
    TICKER -->|fire| SAVE[锁内收集快照<br/>锁外序列化 + temp+rename 原子写]
    SAVE --> RUNNING
    SHUTDOWN[关闭] --> SAVEF[再保存一次]
    SAVEF --> DONE
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    class STARTUP,RUNNING,SHUTDOWN start
    class LOAD,COLD,SAVE,SAVEF proc
    class DONE ok
```

## 中间件管道

```mermaid
graph LR
    Q[Query] --> R[Response<br/>EDNS · Cookie · EDE<br/>Pre-packed fast path]
    R --> E[EDNS<br/>Full unpack · ECS<br/>Cookie · Padding]
    E --> MQ[MQTYPE<br/>RFC 10029 合并 · FORMERR<br/>所有模式]
    MQ --> CS[CacheStore<br/>Write · Request Log]
    CS --> V[Validation<br/>Domain · Label · Type<br/>Opcode · QCLASS · NXNAME/XFR]
    V --> Z[Zone<br/>Rules · Wildcard<br/>Bypass · Loopback Gate]
    Z --> A[Any<br/>RFC 8482 HINFO]
    A --> CL[CacheLookup<br/>Fresh → Serve<br/>Stale → Refresh]
    CL --> D64[DNS64<br/>AAAA Synthesis]
    D64 --> RE[Resolution<br/>Upstream · Recursive<br/>Singleflight]
    classDef mw fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q mw
    class R,E,MQ,CS,V,Z,A,CL,D64,RE mw
```

> 执行顺序（外层→内层）：`Response → EDNS → MQTYPE → CacheStore → Validation → Zone → Any →
> CacheLookup → DNS64 → Resolution`（`middleware/chain.go`）。`Zone` 仅当配置了 zone 规则、
> `DNS64` 仅当配置了 DNS64 时挂载。`MQTYPE` 位于 CacheStore 外侧（post 阶段在 CacheStore
> 构建主响应之后合并）、EDNS 内侧（pre 阶段可见已解析的 Pseudo 选项）。

### MQTYPE (RFC 10029)

**出站（ZJDNS 作为 MQTYPE 客户端）**：

```mermaid
graph TD
    A1["查询 QTYPE=Q<br/>上游配置 mqtype=[T1 T2]"] --> A2{附加 MQQUERY<br/>配置 − Q 非空?}
    A2 -->|否| A3[普通查询]
    A2 -->|是| A4[附加 MQQUERY Tx]
    A4 --> A5{响应含 MQRESPONSE?}
    A5 -->|否| A6[权威不支持<br/>fallback 独立查询 §3.5]
    A5 -->|是| A7{§3.5 验证<br/>重复/主类型重复?}
    A7 -->|无效| A8[忽略捆绑数据]
    A7 -->|有效| A9[warm cache<br/>Tx 记录 + RRSIG]
    A9 --> A10[从客户端响应剥离 Tx<br/>只留主类型回答]
    classDef cl fill:#d1fae5,stroke:#10b981,color:#064e3b
    class A1,A2,A3,A4,A5,A6,A7,A8,A9,A10 cl
```

**入站（ZJDNS 作为 MQTYPE 服务端）**：

```mermaid
graph TD
    S1[客户端查询带 MQQUERY] --> S2{§3.3 八条校验}
    S2 -->|不合法| S3[FORMERR]
    S2 -->|合法| S4[主响应先行<br/>RCODE/AA/AD 定调]
    S4 --> S5{主响应 TC?}
    S5 -->|是| S6[不处理 QTx<br/>返回空 MQTYPE-Response]
    S5 -->|否| S7[逐 QTx 解析<br/>单 flight · 5s 超时]
    S7 --> S8{RCODE/标志与主响应一致?}
    S8 -->|否| S9[排除该 QTx<br/>不入合并与列表]
    S8 -->|是| S10{尺寸预算足够?}
    S10 -->|否| S11[排除 QTx<br/>合并不触发 TC]
    S10 -->|是| S12[合并 + 去重<br/>入 MQTYPE-Response 列表]
    S12 --> S13[返回合并响应<br/>空列表也必返]
    classDef sv fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class S1,S2,S3,S4,S5,S6,S7,S8,S9,S10,S11,S12,S13 sv
```

> 配置：`upstream[*].mqtype`（数字 QTYPE 列表，如 `[1, 28]`；加载期校验：data type、
> 非元类型、去重、≤4 个 §4 QTx cap）。forward 与 `protocol: recursive` 均适用。
> 不实现：zonecut DS+NS 合并（RFC A.3 记录的失败场景）、NS walk 串行化短路。

### 缓存命中直发（pre-packed）

```mermaid
graph TD
    HIT[CacheLookup 命中<br/>entry.ResponseWire + TTLOffsets] --> BP[buildFromPrePacked<br/>按 offset 表就地改写 TTL]
    BP --> GATE{Response 快路径门<br/>Data 非空 · 无 EDNS 需求<br/>非 debug · 无 DNSSEC 证据}
    GATE -->|yes| PATCH[仅 patch ID + RD<br/>Data 直发 · 零分配 ≈14ns]
    GATE -->|no| UNP[Unpack → EDNS 应用 → Pack]
    UNP --> SEND[bridge / 协议层发送]
    PATCH --> SEND
    classDef hit fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class HIT hit
    class BP,GATE,PATCH,UNP,SEND proc
```

> 门条件（`middleware/response.go`）：`!shouldAddEDNS && !IsDebug && !WireHasDNSSEC(Data)`。
> zone 合成的响应 `Data == nil`，天然不走该路径，无需显式门判断。

### TCP 写入分片（16 shard 注册表）

```mermaid
graph TD
    TCP[TCP 请求] --> SHARD[FNV-1a 选 shard]
    SHARD --> LOCK[shard.mu<br/>lookup-or-create + refs.Add]
    LOCK --> CAP[capacity 信号量<br/>RFC 7766 管道上限 16]
    CAP -->|saturated| SF[SERVFAIL<br/>writeMu 串行化]
    CAP -->|ok| GORO[goroutine: handler → pack → writeMu → write]
    GORO --> DONE["refs.Add(-1)"]
    SF --> DONE
    SWEEP["每 5min sweep<br/>refs==0 且 lastAccess > 2min<br/>→ 删除 entry"]
    DONE --> SWEEP
    classDef tcp fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef fail fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class TCP tcp
    class SHARD,LOCK,CAP,GORO,DONE,SWEEP proc
    class SF fail
```

### UDP 响应截断（RFC 9715 R3）

```mermaid
graph TD
    RESP[Response] --> SIZE{"len > min(max(客户端 EDNS, 512), 1400)?"}
    SIZE -->|是| TRUNC[truncateWire 就地截断<br/>TC=1 · 零分配<br/>保留 header/question/尾部 OPT]
    SIZE -->|否| SEND[发送]
    TRUNC --> SEND
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class RESP io
    class SIZE,TRUNC,SEND proc
```

## 缓存查询流程

```mermaid
graph TD
    Q[Query] --> ECS[ECS 候选<br/>固定顺序：最具体→最不具体<br/>≤5 候选 · 首命中即返回]
    ECS --> SQL[lrumap lookup<br/>key = qname qtype qclass<br/>ecs_addr ecs_prefix dnssec]
    SQL -->|not found| MISS[Cache Miss<br/>→ Resolution]
    SQL -->|found| WIRE[提取 pre-packed wire<br/>读 offset 表 · 边界校验]
    WIRE --> ZSTD{"> 256B?<br/>zstd 压缩"}
    ZSTD -->|yes| DECOMP[池化解压<br/>owned 拷贝]
    ZSTD -->|no| CLONE[克隆 wire<br/>避免共享切片 TTL 互踩]
    DECOMP --> LAT{hasLatencyData?}
    CLONE --> LAT
    LAT -->|yes| UNPACK[Unpack → 按延迟排序<br/>→ rebuildResponseWire]
    LAT -->|no| FRESH{TTL Expired?}
    UNPACK --> FRESH
    FRESH -->|No| HIT[Fresh Hit → Return<br/>TTLOffsets 由调用方 Release]
    FRESH -->|Yes| STALE[Stale Hit<br/>EDE 3]
    HIT --> PF{Should Prefetch?<br/>剩余 TTL ≤ 10%<br/>+ 3s 节流}
    PF -->|Yes| BG[后台刷新<br/>Serve Fresh + Update]
    PF -->|No| RETURN[Return]
    STALE --> PREFER{preferStale?}
    PREFER -->|Yes| STALEBG[立即 Serve Stale<br/>+ 后台刷新]
    PREFER -->|No| FGBG[前台刷新 600ms 预算<br/>超时回退 Serve Stale]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef hit fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef miss fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class Q start
    class ECS,SQL,WIRE,ZSTD,DECOMP,CLONE,LAT,UNPACK,FRESH,PF,BG,PREFER,STALEBG,FGBG proc
    class HIT,STALE,RETURN hit
    class MISS miss
```

> ECS 候选 = 精确前缀 + 固定 fallback 链（IPv4 /24→/16→/8→/0，IPv6 /56→/48→/32→/0），
> 第一个命中即返回（等价于旧 SQL `max(ecs_prefix)`）。命中路径无 Unpack/Pack 往返。

## 递归解析流程

```mermaid
graph TD
    Q[Query] --> CACHE{Cache Hit?}
    CACHE -->|Fresh| SERVE[Serve from Cache]
    CACHE -->|Stale| STALE[Serve Stale + Refresh]
    CACHE -->|Miss| DELCACHE{Delegation Cache Hit?}
    DELCACHE -->|Hit| SKIPROOT[Skip to Zone NS<br/>DNSKEY 仍 fresh 拉取]
    DELCACHE -->|Miss| ROOT[Root Hints → TLD → Auth]
    ROOT --> QMIN[QNAME Minimisation<br/>RFC 9156 §2.3 · max 10 iterations<br/>1-4 逐一标签 · 5-10 按比例]
    QMIN --> NXDOMAIN{NXDOMAIN?}
    NXDOMAIN -->|是| JUMP[跳过剩余最小化<br/>全名查询]
    NXDOMAIN -->|否| NS[Query NS Records]
    JUMP --> NS
    NS --> ADDR[Resolve NS Addresses<br/>Latency-Sorted]
    ADDR --> PROBE[Concurrent Query<br/>First-NOERROR Wins]
    PROBE -->|Success| VALIDATE[DNSSEC Validation<br/>+ Poisonguard 逐跳检测]
    PROBE -->|NXDOMAIN| FALLBACK[Secondary Fallback]
    PROBE -->|FORMERR| RETRY[EDNS-Free Retry<br/>RFC 6891 Sec 6.2.2]
    PROBE -->|Poisoned| TCPRESTART[整条走查<br/>经 TCP 重启]
    VALIDATE --> CNAME{CNAME?}
    CNAME -->|Yes| FOLLOW[Follow CNAME Chain<br/>max 16 hops]
    FOLLOW --> QMIN
    CNAME -->|No| STORE[Cache + Return]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef result fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef fallback fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q start
    class CACHE,ROOT,QMIN,NXDOMAIN,JUMP,NS,ADDR,PROBE,VALIDATE,CNAME,FOLLOW,RETRY,FALLBACK,SKIPROOT,DELCACHE proc
    class SERVE,STALE,STORE result
    class TCPRESTART fallback
```

> CNAME 链超过 16 hops 时返回已收集的部分链并告警（非 SERVFAIL）。委派缓存命中只替换
> 起始 NS 集，后续每跳仍过完整 Poisonguard 探测。

## DNSSEC 验证链

```mermaid
graph TD
    Q[Recursive Query] --> HINT[Root Hints]
    HINT --> ROOT[Query Root NS]
    ROOT --> ROOTKSK[Root KSK<br/>Trust Anchor · 自签名交叉校验]
    ROOTKSK --> DS{父区有 DS?}
    DS -->|Yes| TLD[DS 匹配 DNSKEY<br/>SEP 位非必需]
    DS -->|No| NODS[Authenticated no-DS 否认<br/>NSEC/NSEC3 验证]
    NODS -->|通过| INSEC[Insecure 委派<br/>继续走查]
    NODS -->|失败| BOGUS[Bogus]
    TLD --> KEYFAIL{DNSKEY 匹配失败?<br/>offline KSK}
    KEYFAIL -->|是| CDS{CDS/CDNSKEY 回退<br/>RFC 7344}
    CDS -->|匹配| TLD
    CDS -->|否| BOGUS
    KEYFAIL -->|否| AUTH[Authoritative DNSKEY]
    AUTH --> RRSIG{RRSIG Valid?}
    RRSIG -->|Yes| VALID[AD=1 · NOERROR]
    RRSIG -->|No| BOGUS
    BOGUS --> ENFORCE{dnssec_enforce?}
    ENFORCE -->|是| SERVFAIL[SERVFAIL + EDE 6]
    ENFORCE -->|否| PASSIVE[按 insecure 处理<br/>不带 AD]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef chain fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef fail fill:#fee2e2,stroke:#ef4444,color:#991b1b
    classDef insecure fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class Q start
    class HINT,ROOT,ROOTKSK,DS,NODS,TLD,KEYFAIL,CDS,AUTH,RRSIG,ENFORCE chain
    class VALID ok
    class BOGUS,SERVFAIL fail
    class INSEC,PASSIVE insecure
```

> 委派无 DS 时走**验证过的 no-DS 否认**（NSEC/NSEC3）判定 insecure，而不是直接 bogus；
> CDS/CDNSKEY（RFC 7344）仅在 DS→DNSKEY 匹配失败（离线 KSK 部署）时尝试。
> Bogus → SERVFAIL 仅当 `dnssec_enforce` 开启。

## EDNS 处理流程

```mermaid
graph TD
    Q[Incoming Query] --> PARSE[Parse EDNS Options<br/>from OPT Pseudo-Section]
    PARSE --> ECS[ECS<br/>Client Subnet Extraction<br/>RFC 7871]
    PARSE --> COOKIE[COOKIE<br/>Client + Server Cookie<br/>RFC 9018]
    PARSE --> PADDING[PADDING<br/>Block-based Padding<br/>RFC 8467]
    ECS --> ECSDB{ECS Config?}
    ECSDB -->|Static| USESTATIC[Use Configured Subnet]
    ECSDB -->|Auto| USEAUTO[Auto-Detect Public IP<br/>Background Refresh 15min]
    ECSDB -->|None| NOECS[No ECS]
    COOKIE --> CKVALID{Server Cookie Valid?}
    CKVALID -->|Yes| CKSERVE[Return Cookie]
    CKVALID -->|No| CKGEN[Generate New Cookie<br/>SipHash-2-4 + Timestamp<br/>24h Secret Rotation<br/>BADCOOKIE 23]
    PADDING --> PADREQ[Pad Request 128B]
    PADDING --> PADRESP[Pad Response 468B<br/>Secure Transports Only]
    ECS --> ECSVER[响应侧回显校验<br/>family/prefix/地址不匹配<br/>→ SERVFAIL（防投毒）]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q,PARSE start
    class ECS,COOKIE,PADDING,ECSDB,CKVALID,CKGEN,CKSERVE,PADREQ,PADRESP,USESTATIC,USEAUTO,NOECS,ECSVER proc
```

> Cookie 生命周期（RFC 9018 §4.3）：Server Cookie 有效期 1h、续期阈值 30min、未来容忍 5min；
> MAC 计算 IPv4 4 字节 / IPv6 16 字节，Reserved 字节计入 hash（防地址族替换攻击）。

## DNS 污染检测（四层防御）

所有防御机制均配置在 `UpstreamServer` 上，同时支持转发和递归模式。

### 上行查询路径（转发 + 递归通用）

```mermaid
graph TD
    Q[Outbound Query] --> UDP{Transport}
    Q --> TCP
    UDP -->|UDP| HG[HopGuard<br/>IP TTL Fingerprint]
    HG -->|TTL in +-2| SG[Spoofguard<br/>Multi-Read Loop]
    HG -->|TTL mismatch| REJECT[Reject<br/>Silent Drop]
    SG -->|Fast signal<br/>AN>=2 / NS>0 / AD=1| ACCEPT[Immediate Accept]
    SG -->|EDNS 候选| ACCEPT2[Collect<br/>Richness 决胜]
    SG -->|裸单答案 A/AAAA| CONFIRM[Re-query 确认<br/>≤3 轮相同答案 → 服务]
    CONFIRM -->|无法确认| FAIL[Query Failed]
    TCP -->|TCP| SPG[Splitguard<br/>随机 1-4B 分段<br/>TCP_NODELAY 直发]
    ACCEPT --> UP[Upstream Response]
    ACCEPT2 --> UP
    CONFIRM --> UP
    SPG --> UP
    classDef query fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef defense fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef result fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class Q query
    class HG,SG,SPG,CONFIRM defense
    class ACCEPT,ACCEPT2,UP result
    class REJECT,FAIL reject
```

### 递归逐跳检测（Poisonguard 专属）

```mermaid
graph TD
    REC[Recursive Resolution] -->|Root| RPG[Poisonguard<br/>Root: root-servers.net 任意类型<br/>`.` apex · TLD NS/DS/proofs]
    REC -->|TLD| TPG[Poisonguard<br/>TLD: 自引用 A/AAAA<br/>子域 NS/DS/proofs]
    REC -->|Auth| APG[Poisonguard<br/>Auth: VerdictUncertain]
    RPG -->|越权 A/AAAA| POISON[Poison → TCP Fallback]
    TPG -->|越权 A/AAAA| POISON
    RPG -->|Legit NS/DS| CLEAN[Clean → Continue]
    TPG -->|Legit NS/DS| CLEAN
    classDef rec fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef defense fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef poison fill:#fce7f3,stroke:#ec4899,color:#831843
    class REC rec
    class RPG,TPG,APG defense
    class CLEAN ok
    class POISON poison
```

### 四层防御机制

| 层 | 机制 | 适用模式 | 作用层 | 检测原理 |
|---|------|----------|--------|----------|
| 1 | **HopGuard** | 转发+递归 | IP 层 | UDP 上游 TTL 指纹学习，32 样本武装，拒绝偏离 ±2 的响应 |
| 2 | **SpoofGuard** | 转发+递归 | DNS 报文层 | UDP 多读循环（≤500ms），fast signal 即收、EDNS 候选决胜、裸单答案重查确认 |
| 3 | **SplitGuard** | 转发+递归 | TCP 流层 | TCP 分段发送（随机 [1,4] 字节），破坏 DPI 首包特征识别 |
| 4 | **Poisonguard** | 递归专属 | DNS 内容层 | 每跳 zone-authority 交叉验证，检测越权 A/AAAA 注入 |

### 防御机制详解

#### HopGuard（IP TTL 指纹）

```mermaid
graph TD
    Q[UDP Response Arrives] --> CAP{Capture TTL?}
    CAP -->|No| PASS[Accept]
    CAP -->|Yes| VS{State Exists?}
    VS -->|No| PASS
    VS -->|Yes| ARMED{Armed?}
    ARMED -->|No| PASS[Accept<br/>Learning Phase]
    ARMED -->|Yes| CHECK{TTL within +-2<br/>of trusted baseline?}
    CHECK -->|Yes| PASS2[Accept]
    CHECK -->|No| REJECT[Reject<br/>Silent Drop]
    PASS --> SPOOF[Spoofguard verifies<br/>DNS content is clean]
    PASS2 --> SPOOF
    SPOOF -->|Clean| FEED[Feed TTL into histogram<br/>1-in-16 拒绝采样恢复]
    FEED --> TIMER{"样本 >= 32<br/>或 >= 5min?"}
    TIMER -->|Yes| REBUILD["Rebuild trusted set<br/>×3/4 衰减 · 自适应阈值<br/>max(4, modeCount/4)"]
    REBUILD --> ARM{Trusted 集非空?}
    ARM -->|Yes| ARMED
    ARM -->|No| DISARM[Disarm<br/>重新学习]
    TIMER -->|No| DONE[Done]
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    classDef learn fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef pass fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    class PASS,PASS2,SPOOF,FEED,DONE,ARM ok
    class REJECT reject
    class TIMER,REBUILD,DISARM learn
    class Q,CAP,VS,ARMED,CHECK pass
```

> 状态存于 256 容量的 LRU（按上游键）。Windows/无 IP TTL 平台自动降级（放行 + 警告）；
> SOCKS5 代理路径无 TTL 元数据，HopGuard 自动禁用。

#### SpoofGuard（UDP 多读 + 门控）

```mermaid
graph TD
    Q[Send UDP Query] --> WAIT[Set Read Deadline<br/>Collect Window <=500ms · 100ms 轮询]
    WAIT --> READ[Read Response]
    READ --> TIMEOUT{Timeout?}
    TIMEOUT -->|Yes| CAND{Any Candidates?}
    CAND -->|No| ERR[Return Error]
    CAND -->|Yes| BEST[Pick Best Candidate]
    READ -->|Packet| HEADER{Min 12 bytes<br/>+ ID Match?}
    HEADER -->|No| READ
    HEADER -->|Yes| FAST{"Fast signal<br/>AN>=2 / NS>0 / AD=1?"}
    FAST -->|Yes| ACCEPT[Immediate Accept<br/>Stop Reading]
    FAST -->|No| EDNS{Has EDNS OPT?}
    EDNS -->|Yes| COLLECT[EDNS 候选<br/>TTL confident → 快速接受<br/>否则继续收集]
    EDNS -->|No| CNAME{CNAME 链?}
    CNAME -->|Yes| SAFE[安全 fallback]
    CNAME -->|No| AMBIG[裸单答案 A/AAAA<br/>歧义候选]
    AMBIG --> TIMEOUT
    TIMEOUT -->|仅 1 个响应| SERVE[直接服务<br/>无注入信号]
    TIMEOUT -->|>=2 个响应| REQUERY[重查确认<br/>相同答案 → 服务<br/>3 轮无匹配 → 失败]
    COLLECT --> READ
    ACCEPT --> DONE[Return Response]
    BEST --> DONE
    SAFE --> DONE
    SERVE --> DONE
    REQUERY --> DONE
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    class ACCEPT,DONE,SERVE ok
    class ERR,REQUERY reject
    class FAST,EDNS,CNAME,AMBIG,COLLECT,BEST,REQUERY proc
    class Q,WAIT,READ,UNPACK io
```

> 无 EDNS 的裸单答案 A/AAAA 不再直接拒绝——收集为歧义候选，仅 1 个响应时直接服务，
> ≥2 个响应（注入信号）时重查确认（`DefaultSpoofguardConfirmRounds = 3`）。EDNS 响应是
> 合法候选（GFW 裸响应无 EDNS）。决胜：EDNS 优先 → answer 数多者胜 → 随机 tie-break。

#### SplitGuard（TCP 分段发送）

```mermaid
graph LR
    Q[DNS over TCP Query] --> PACK[Pack DNS Message<br/>2-byte Length Prefix + Body]
    PACK --> RAND[每段随机大小 1-4B]
    RAND --> LOOP{Loop until<br/>all bytes sent}
    LOOP -->|remaining > seg| SEND[Write 随机长度段]
    SEND --> LOOP
    LOOP -->|last chunk| LAST[Write remaining bytes]
    LAST --> WAIT[Await Response]
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q,WAIT io
    class PACK,RAND,LOOP,SEND,LAST proc
```

> 首段含 2 字节长度前缀；`TCP_NODELAY` 关闭 Nagle 保证小段立发。无时间抖动——DPI 对抗
> 靠段大小随机性（每段独立 [1, segSize=4]），TCP 重组对服务器透明。

#### Poisonguard（递归 Zone-Authority 交叉验证）

```mermaid
graph TD
    Q[Recursive Response<br/>from Delegation Hop] --> EXTRACT[Extract Answer RRs<br/>matching query name]
    EXTRACT --> SIG{RRSIG 匹配存在?}
    SIG -->|Yes| CLEAN[VerdictClean<br/>DNSSEC 签名不可伪造]
    SIG -->|No| CLASSIFY[classify zone name rrtype]
    CLASSIFY --> ROOT{zone == .?}
    ROOT -->|Yes| CR[classifyRoot]
    CR --> ISROOT{name is<br/>root-servers.net?<br/>或 apex .}
    ISROOT -->|Yes| CLEAN
    ISROOT -->|No| ISTLD{NS/DS/proofs<br/>and name is TLD?}
    ISTLD -->|Yes| CLEAN
    ISTLD -->|No| POISON[VerdictPoisoned]
    ROOT -->|No| TLD{isTLD zone?}
    TLD -->|Yes| CT[classifyTLD]
    CT --> SAME{name == zone?<br/>自引用}
    SAME -->|Yes| CLEAN
    SAME -->|No| SUBDEL{子域 NS/DS/proofs?}
    SUBDEL -->|Yes| CLEAN
    SUBDEL -->|No| POISON
    TLD -->|No| UNCERTAIN[VerdictUncertain<br/>Authoritative: cannot<br/>distinguish by content alone]
    POISON --> TCPFALL[TLD probe 或检测<br/>→ 当前层 TCP<br/>poisonSeen → CNAME 后续也 TCP]
    CLEAN --> CONTINUE[Continue Resolution]
    UNCERTAIN --> CONTINUE
    classDef clean fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef poison fill:#fce7f3,stroke:#ec4899,color:#831843
    classDef uncertain fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef proc fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    class CLEAN,CONTINUE clean
    class POISON,TCPFALL poison
    class UNCERTAIN uncertain
    class Q,EXTRACT,SIG,CLASSIFY,ROOT,CR,ISROOT,ISTLD,TLD,CT,SAME,SUBDEL proc
```

> TLD probe：完整 qname（RD=0, UDP）发给 TLD server（2s 超时），返回 A/AAAA 即判中毒。
> 委派缓存命中非 TLD zone 时跳过 probe（无 tldServers）；命中 TLD zone 时 probe 仍执行。
> proofs = RRSIG/NSEC/NSEC3。

## TC→TCP 自动回退

```mermaid
graph TD
    Q[Outbound Query] --> TYPE{Protocol}
    TYPE -->|Plain UDP| UDPEXEC[UDP Exchange]
    UDPEXEC --> UDPCHECK{TC=1 or Error?}
    UDPCHECK -->|No| DONEP[Return]
    UDPCHECK -->|Yes| PLAINTCP[Plain TCP Retry<br/>same server + proxy]
    TYPE -->|DTLS| DTLS[DTLS Exchange<br/>incl. SOCKS5 proxy]
    DTLS --> DTLSCK{Failed?}
    DTLSCK -->|No| DONED[Return]
    DTLSCK -->|Yes| DOTFALL[DoT Fallback<br/>same server + proxy]
    TYPE -->|DTLCP| DTLCPEX[DTLCP Exchange<br/>incl. SOCKS5 proxy]
    DTLCPEX --> DTLCPCK{Failed?}
    DTLCPCK -->|No| DONEL[Return]
    DTLCPCK -->|Yes| TLCPFALL[TLCP Fallback<br/>same server + proxy]
    TYPE -->|DNSCrypt UDP| DCRYPT[DNSCrypt UDP<br/>incl. SOCKS5 proxy]
    DCRYPT --> DCCK{TC=1 or Error?}
    DCCK -->|No| DONEC[Return]
    DCCK -->|Yes| DCTCP[DNSCrypt TCP Retry<br/>same server + proxy]
    TYPE -->|Recursive<br/>Poisonguard| POISON[Poisonguard detects<br/>Injected A/AAAA]
    POISON --> RECTCP[TCP Fallback<br/>bypass GFW via encrypted TCP]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef fallback fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef poison fill:#fce7f3,stroke:#ec4899,color:#831843
    class Q start
    class DONEP,DONED,DONEL,DONEC ok
    class PLAINTCP,DOTFALL,TLCPFALL,DCTCP fallback
    class RECTCP poison
```

## Zone 规则评估

```mermaid
graph TD
    Q[Query] --> BYPASS{Bypass Rules<br/>Match?}
    BYPASS -->|Yes| NEXT[Skip Zone -> Next]
    BYPASS -->|No| EVAL[Evaluate<br/>qname + qtype + qclass<br/>+ client tags + client IP]
    EVAL -->|No Match| NOMATCH[No Match -> Next]
    EVAL -->|Match| DESTRUCT{破坏性 CHAOS 端点?<br/>zjdns.*.clear}
    DESTRUCT -->|是且非回环| REFUSE[REFUSED<br/>SECURITY 日志]
    DESTRUCT -->|否/回环| RCODE{Rcode == 0?}
    RCODE -->|非 0| BLOCK[构建 RCODE 响应<br/>NXDOMAIN/SERVFAIL/REFUSED…<br/>+ EDE 4]
    RCODE -->|0| RECORDS{含 Answer/Authority<br/>/Additional 记录?}
    RECORDS -->|No| PASSTHROUGH[纯透传<br/>不重写 QNAME]
    RECORDS -->|Yes| SYNTH[构建合成响应<br/>AA=1 · TTL 扣除<br/>通配符 owner 改写<br/>RFC 1034 §4.3.3]
    BLOCK --> SHORTCUT[Short-circuit Pipeline<br/>qctx.Res = synthetic]
    SYNTH --> SHORTCUT
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef match fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef nomatch fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class Q start
    class BYPASS,EVAL,DESTRUCT,REFUSE,RCODE,BLOCK,RECORDS,SYNTH proc
    class SHORTCUT match
    class NOMATCH,NEXT,PASSTHROUGH nomatch
```

> 无记录规则（Rcode=0 且无 RR）为**纯透传**——旧的 QNAME 重写分支是死代码，已移除。
> 破坏性 CHAOS 端点（`zjdns.cache.clear` 等）仅限回环地址。

## Singleflight 查询去重

```mermaid
graph TD
    Q[Concurrent Identical Queries] --> JOIN[Build PendingKey<br/>qname+qtype+qclass<br/>+ecs_addr+ecs_prefix<br/>+dnssec_ok]
    JOIN --> LRU[LRU Map 10000 entries<br/>LoadOrStore key->pendingCall]
    LRU -->|First Caller<br/>Leader| EXEC[Execute Upstream Query]
    LRU -->|Subsequent<br/>Follower| WAIT[Wait on done channel<br/>with 60s timeout]
    EXEC --> RESULT[Get Result]
    RESULT --> CLONE[Deep Clone RRs<br/>Answer+Authority+Additional]
    CLONE --> DONE[Store result<br/>Close done channel]
    DONE --> RETL[Return to Leader]
    WAIT -->|Leader finishes| SHARED[Receive Shared Result]
    WAIT -->|Timeout 60s| TIMEOUT[Return Timeout Error<br/>→ SERVFAIL]
    SHARED --> RETF[Return to Follower]
    LRU -->|Eviction| EVICT[OnEvict: ErrEvicted<br/>+ close done channel<br/>→ SERVFAIL for waiters]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef leader fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef follower fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef err fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class Q,JOIN start
    class EXEC,RESULT,CLONE,DONE,RETL leader
    class LRU,WAIT,SHARED,RETF follower
    class TIMEOUT,EVICT err
```

## DNS64 合成

```mermaid
graph TD
    Q[AAAA Query] --> RESOLVE[Resolve AAAA]
    RESOLVE --> HASAAAA{Has AAAA?}
    HASAAAA -->|Yes| RETAAAA[Return AAAA]
    HASAAAA -->|No| RESA[二次 A 查询<br/>先查响应缓存<br/>+ singleflight 去重]
    RESA --> HASA{Has A?}
    HASA -->|No| RETNO[Return Empty]
    HASA -->|Yes| SYNTH[Embed IPv4 into<br/>NAT64 Prefix<br/>RFC 6052 Sec 2.2]
    SYNTH --> TTL["TTL 上限 min(A, SOA, 600s)<br/>合成 AAAA 不带 AD"]
    TTL --> RETSYNTH[Return Synthetic AAAA]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef out fill:#d1fae5,stroke:#10b981,color:#064e3b
    class Q start
    class RESOLVE,RESA,SYNTH,TTL proc
    class RETAAAA,RETSYNTH,RETNO out
```

> 前缀 `64:ff9b::/96`（well-known），支持 /32,/40,/48,/56,/64,/96 嵌入布局（RFC 6052 Figure 1）。

## 规则集引擎

```mermaid
graph LR
    subgraph Load
        CFG[Config Rules] --> DOM[Domain Rules<br/>TLD+1 Suffix]
        CFG --> IP[IP CIDR Rules<br/>Binary Radix Trie]
    end
    subgraph Match
        Q[Query] --> DOMQ[Domain Lookup<br/>in-memory suffix map]
        Q --> IPQ[IP Lookup<br/>O-128 Trie Walk]
        DOMQ --> TAGS[Collect Tags]
        IPQ --> TAGS
    end
    TAGS --> USE{Usage}
    USE -->|Upstream| ROUTE[Route to Matching Server]
    USE -->|Zone| FILTER[Filter Zone Rules<br/>by Client Tags]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef out fill:#d1fae5,stroke:#10b981,color:#064e3b
    class CFG,Q start
    class DOM,IP,DOMQ,IPQ,TAGS,USE proc
    class ROUTE,FILTER out
```

## 延迟探测

```mermaid
graph TD
    QUERY[Cache Hit<br/>with A/AAAA Records] --> EXTRACT[Extract All IPs<br/>from Answer Section<br/>跳过 loopback/private/link-local]
    EXTRACT --> BATCH[Batch lookup<br/>in-memory latency map]
    BATCH -->|All Cached| SORT[Sort Records<br/>by Latency ASC]
    BATCH -->|Some Missing| PROBE[Background Probe<br/>per-IP concurrent]

    PROBE --> STEPS[按配置顺序执行探测步骤<br/>首个成功即返回<br/>elapsed from start]
    STEPS --> ICMP[ICMP Ping<br/>privileged raw socket]
    STEPS --> TCP[TCP Connect<br/>configurable port]
    STEPS --> UDP[UDP Send + Read<br/>single-byte datagram]
    STEPS --> HTTP[HTTP HEAD<br/>port 80]
    STEPS --> HTTPS[HTTPS HEAD<br/>port 443 · TLS]
    STEPS --> HTTP3[HTTP3 HEAD<br/>port 443 · QUIC]
    STEPS --> DNS[DNS Query<br/>UDP:53 · ID match]
    STEPS --> DNSTCP[DNS Query<br/>TCP:53 · length-prefixed]

    ICMP --> SUCC{任一成功?}
    TCP --> SUCC
    UDP --> SUCC
    HTTP --> SUCC
    HTTPS --> SUCC
    HTTP3 --> SUCC
    DNS --> SUCC
    DNSTCP --> SUCC
    SUCC -->|是| LAT[取首个成功步骤耗时]
    SUCC -->|否| MAX[MaxInt64<br/>视为不可达]
    LAT --> SMOOTH[EWMA 平滑<br/>无偏整数 EWMA · α=1/2<br/>首次探测直接存储]
    SMOOTH --> STORE[Store latency map<br/>Per-IP, shared across domains]
    MAX --> STORE
    STORE --> SORT
    SMOOTH -.->|下一轮探测<br/>≥60s 后（min interval）| PROBE

    SORT --> RETURN[Return Sorted Answer<br/>Fastest IP First]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef proto fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef out fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class QUERY start
    class EXTRACT,BATCH,PROBE,STEPS,SUCC,LAT,MAX,SMOOTH,STORE,SORT proc
    class ICMP,TCP,UDP,DNS,DNSTCP,HTTP,HTTPS,HTTP3 proto
    class RETURN out
```

> 聚合语义：按配置顺序执行各探测步骤，**首个成功步骤的累计耗时**即该 IP 的延迟
> （不是各步骤最小值）。缓存命中时 `sortAnswerByLatency` 按延迟升序重排 A/AAAA。
>
> **NS/Root 探测**（`ProbeNSAddrs`）：固定两步 `dns:53 → dns-tcp:53`，不读配置。
> 发送真实 DNS 查询（root A），任意响应（NOERROR/NXDOMAIN/REFUSED/SERVFAIL）即成功，
> 按 RFC 5452 §4.2 校验 QR 位与消息 ID。**无 ping 步骤**——链式首胜下多数公共 NS
> 的 ICMP 响应会短路真实 DNS 测量。
>
> **SRTT 平滑**（`UpdateLatency`）：写入前用无偏整数 EWMA 合并历史值
> `srtt = ((N-1)·srtt + rtt) / N`，`DefaultLatencyProbeSmoothFactor = 2`（α=1/2）——
> 抗单点抖动，链式首胜的瞬时 RTT 不再直接污染排序。首次探测 / 过期条目（3 天）直接
> 存储；探测失败不写，保留旧平滑值。

## 连接池与协议协商

```mermaid
graph LR
    subgraph Client
        Q[Query] --> ROUTE{Route}
        ROUTE -->|UDP| SPOOF{SpoofGuard?}
        SPOOF -->|Yes| MULTI[Multi-Read<br/>EDNS Gate + Richness]
        SPOOF -->|No| UDP[UDP Exchange]
        ROUTE -->|TCP| POOL[TCP Connection Pool<br/>RFC 7766 Pipelining]
        POOL -->|SplitGuard| SEG[Segmented Write<br/>1-4 byte chunks]
        POOL -->|Normal| TCP[TCP Exchange]
        ROUTE -->|TLS| DOT[DoT Pool<br/>TLS 1.3 · 0-RTT · Session Resume]
        ROUTE -->|QUIC| DOQ[DoQ Pool<br/>0-RTT · Address Validation]
        ROUTE -->|HTTPS| DOH[DoH<br/>HTTP/2 · TLS 1.3]
        ROUTE -->|HTTP3| DOH3[DoH3<br/>HTTP/3 · QUIC]
        ROUTE -->|DTLS| DTLS[DTLS<br/>DTLS 1.3 · PMTU Truncate]
        ROUTE -->|DNSCrypt| DCRYPT[DNSCrypt<br/>X-Wing PQ · XChaCha20]
        ROUTE -->|TLCP| TLCP[TLCP DoT<br/>SM2/SM3/SM4 · Session Cache]
        ROUTE -->|HTTP-TLCP| TLCPDOH[TLCP DoH<br/>SM2/SM3/SM4 · HTTP/2]
        ROUTE -->|DTLCP| DTLCP[DTLCP<br/>SM2/SM3/SM4 · PMTU Truncate]
    end
    MULTI --> UP[Upstream]
    UDP --> UP
    SEG --> UP
    TCP --> UP
    DOT --> UP
    DOQ --> UP
    DOH --> UP
    DOH3 --> UP
    DTLS --> UP
    DCRYPT --> UP
    TLCP --> UP
    TLCPDOH --> UP
    DTLCP --> UP
    classDef query fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef route fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef proto fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef gm fill:#f3e8ff,stroke:#a855f7,color:#4c1d95
    classDef ext fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class Q query
    class ROUTE,SPOOF route
    class MULTI,UDP,POOL,SEG,TCP,DOT,DOQ,DOH,DOH3,DTLS,DCRYPT proto
    class TLCP,TLCPDOH,DTLCP gm
    class UP ext
```

> 四种池类型（`server/upstream/pool/`）：TCP/DoT/DTLS/TLCP/DTLCP 走
> **ConnPool**、UDP/DNSCrypt-UDP 走 **UDPPool**、DNSCrypt-TCP 走 **RawPool**
> （长度前缀帧复用，不解析 DNS，nonce 前缀路由）、DoQ 走 **QUIC 连接池**、
> DoH/DoH3/HTTP-TLCP 走 HTTP transport 缓存。
>
> **统一三层上限**（每池实例）：per-key 4 连接 × per-conn 16 在途 × **全局 128
> live 连接**（`DefaultMaxPoolTotalConns`）。超限时 `dialAndAdd` 触发
> `evictOne` 驱逐：死连接 → 空闲 LRU → 任意 LRU（`lastUsed` 时间戳，close
> 在锁外）。空闲回收 UDP 30s / TCP 60s。服务端并发上限统一派生自
> `DefaultServerGoroutineLimit`（256），QUIC 连接准入 128。

## SOCKS5 代理路径

```mermaid
graph LR
    Q[Query] --> PROXY{Proxy?}
    PROXY -->|No| POOL[Pooled Direct<br/>key=addr]
    PROXY -->|Yes| POOLP[Pooled Proxied<br/>key=addr&#124;proxy]
    POOLP -->|TCP family| TCPR[Relay TCP<br/>Socks Handshake<br/>一次/连接]
    POOLP -->|UDP family| UDPR[UDP ASSOCIATE<br/>relay 绑定<br/>一次/socket]
    POOL --> UP[Upstream]
    TCPR --> UP
    UDPR --> UP
    classDef query fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ext fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class Q query
    class PROXY,POOL,POOLP,TCPR,UDPR proc
    class UP ext
```

> 全部 12 协议客户端支持 SOCKS5：代理连接与直连共用池机制，key 含代理
> 标识（`addr|proxy`），dialFunc 建立 SOCKS5 ASSOCIATE/TCP relay —— 握手
> 每 socket 一次而非每查询。证书获取（UDP+TCP）同样走代理池化。裸拨号
> 仅保留为池不可用时的回退。**guard 兼容性**：spoofguard/splitguard/
> poisonguard 完全支持（内容/TCP 层机制与传输无关；poisonguard 经
> `recursiveProxyURL` 走递归代理链）；hopguard 降级（SOCKS5 relay 不带 IP
> TTL 元数据，警告 + 无 TTL 模式，由 spoofguard 兜底内容防护）。

## 协议对照：标准加密 ↔ 国密

```mermaid
graph TD
    subgraph Standard[标准加密体系]
        TLS[TLS 1.3<br/>ECDSA + AES-GCM + SHA-256] -->|TCP 加密| DOT[DoT RFC 7858]
        TLS -->|TCP + HTTP| DOH[DoH RFC 8484]
        TLS -->|UDP 适配| DTLS[DTLS 1.2/1.3 RFC 8094]
        DTLS -->|UDP 加密| DOD[DoD DNS over DTLS]
    end
    subgraph GM[国密体系 GB/T 38636 · GM/T 0128]
        TLCP[TLCP<br/>SM2 + SM4-GCM + SM3] -->|TCP 加密| TLCPDOT[TLCP DoT]
        TLCP -->|TCP + HTTP| TLCPDOH[TLCP DoH]
        TLCP -->|UDP 适配| DTLCP[DTLCP GM/T 0128]
        DTLCP -->|UDP 加密| DTLCPDOD[DTLCP DoD]
    end

    TLS -.->|加密原语替换<br/>ECDSA→SM2<br/>AES-GCM→SM4-GCM<br/>SHA-256→SM3| TLCP
    DTLS -.->|加密原语替换<br/>DTLS→DTLCP| DTLCP

    classDef std fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef gm fill:#f3e8ff,stroke:#a855f7,color:#4c1d95
    classDef proto fill:#d1fae5,stroke:#10b981,color:#064e3b
    class TLS,DTLS std
    class TLCP,DTLCP gm
    class DOT,DOH,DOD,TLCPDOT,TLCPDOH,DTLCPDOD proto
```

## DNSCrypt 密钥管理

```mermaid
graph TD
    START[Server Start] --> GEN[Generate Initial Cert Pair<br/>Classical + PQ<br/>Ed25519 Signing Key]
    GEN --> TICKET["Derive Ticket Key<br/>SHA-256(DNSCrypt-PQ-ticket-key-v1 + signing key)<br/>从不轮换"]
    TICKET --> SERVE[Begin Serving]
    SERVE --> RENEW{8h Ticker}
    RENEW -->|fire| UPDATE[updateKeys<br/>铸造新证书对<br/>prepend newest first]
    UPDATE --> PURGE[Purge Expired Keys<br/>30s ticker<br/>仅按 NotAfter 判定<br/>无 overlap grace]
    PURGE --> RESETCACHE[Reset Shared Key Cache<br/>旧 X25519 密钥失效]
    RESETCACHE --> SERVE
    SERVE --> PERSIST[状态持久化<br/>dnscryptstate · 重启补铸<br/>config key 变更 → 丢弃状态]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    class START start
    class GEN,TICKET,RENEW,UPDATE,PURGE,RESETCACHE,PERSIST proc
    class SERVE ok
```

> 证书 TTL 24h、轮换 ticker 8h（8h < 24h 自然形成当前+前一个的重叠窗口）。ticket key
> **不随证书轮换**（ticket 由客户端缓存，密钥漂移会使恢复失败）。

## DNSCrypt 加密流程

单一流程图覆盖三种会话模式（Classical / PQ 初始 / PQ 恢复），共享填充、加解密与响应路径：

```mermaid
graph TD
    C[Client] --> MODE{会话模式}
    MODE -->|Classical| GENKEY[Generate Ephemeral<br/>X25519 Key Pair<br/>或复用 cached key pair]
    MODE -->|PQ 初始| CERT[Fetch PQ Cert<br/>1320B via TXT query<br/>Ed25519 验签]
    MODE -->|PQ 恢复| RESUME[Build Resumed Query<br/>PQResumeMagic 8B<br/>Ticket + ClientNonce 12B]
    GENKEY --> CLQUERY[Build Query<br/>ClientMagic 8B<br/>ClientPk 32B<br/>ClientNonce 12B]
    GENKEY --> CLKEY[SharedKey = X25519<br/>ClientSk x ResolverPk]
    CERT --> ENCAP[X-Wing Encapsulate<br/>ResolverPk 1216B<br/>→ Ciphertext 1120B<br/>→ SharedSecret 32B]
    ENCAP --> HKDF[HKDF-SHA256 Derive<br/>cert-context + ciphertext]
    HKDF --> PQQUERY[Build PQ Query<br/>ClientMagic 8B<br/>Ciphertext 1120B<br/>ClientNonce 12B]
    CLQUERY --> PAD
    CLKEY --> PAD
    RESUME --> PAD
    PQQUERY --> PAD
    PAD["ISO/IEC 7816-4 Padding<br/>Classical: 目标 minQueryLen<br/>初始 512 · TC 翻倍 ≤4096<br/>EWMA 收缩 ≥512（均值低于预算一半时减半）<br/>PQ: 初始 ≥64B · 恢复 max(minQueryLen, 256)<br/>7 次重试后 TCP 回退"]
    PAD --> ENCRYPT[XChaCha20-Poly1305 Encrypt<br/>Nonce = ClientNonce + Zeroes 12B]
    ENCRYPT --> SEND[Send to Resolver]

    SEND --> SRECV[Resolver Receives]
    SRECV --> SMAGIC{ClientMagic<br/>Match Cert?}
    SMAGIC -->|No| REJECT[Silent Drop]
    SMAGIC -->|Yes| SDECRYPT{查询类型}
    SDECRYPT -->|Classical| SDH[Compute SharedKey<br/>X25519 ClientPk x ResolverSk<br/>SharedKeyCache 2048 LRU]
    SDECRYPT -->|PQ 初始| SDECAP[X-Wing Decapsulate<br/>Ciphertext x ResolverSk<br/>→ SharedSecret 32B]
    SDECRYPT -->|PQ 恢复| SOPEN[Open Ticket<br/>验证 cert-context<br/>Derive SharedKey]
    SDH --> SUNPAD[Decrypt + Verify<br/>+ Unpad]
    SDECAP --> SKDF[HKDF-SHA256 Derive<br/>SharedKey]
    SKDF --> SUNPAD
    SOPEN --> SUNPAD
    SUNPAD --> SPROCESS[Process DNS Query]

    SPROCESS --> SRESP[Build DNS Response]
    SRESP --> SPAD[Deterministic Padding<br/>SHA-256 SharedKey+ClientNonce<br/>Multiple of 64 bytes]
    SPAD --> SENCRYPT[Encrypt Response<br/>ResolverMagic 8B<br/>Nonce 24B + Poly1305 Tag]
    SENCRYPT --> SBUDGET{UDP Budget?}
    SBUDGET -->|OK| TICKET{Include<br/>Resumption Ticket?}
    SBUDGET -->|响应超预算| STRUNCATE[Truncate + Set TC]
    TICKET -->|Yes · 仅 PQ| BUILDCTL[Build Control Block<br/>PQDR Magic 4B + Version 1B<br/>TicketLifetime 4B + TicketLen 2B<br/>+ Sealed Ticket]
    BUILDCTL --> CTLBUDGET{票能装进<br/>预算?}
    CTLBUDGET -->|Yes| SSEND[Send to Client]
    CTLBUDGET -->|No| WITHHOLD[Withhold Ticket<br/>Send Response 无 TC]
    TICKET -->|No| SSEND

    SSEND --> CLIENT[PQ: Client Stores Ticket<br/>for Resumption · 600s 有效]
    CLIENT --> RESUME

    classDef client fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef server fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef ticket fill:#f3e8ff,stroke:#a855f7,color:#4c1d95
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class C,MODE,GENKEY,CLQUERY,CLKEY,CERT,ENCAP,HKDF,PQQUERY,RESUME,PAD,ENCRYPT,SEND,CLIENT client
    class SRECV,SMAGIC,SDECRYPT,SDH,SDECAP,SOPEN,SKDF,SUNPAD,SPROCESS,SRESP,SPAD,SENCRYPT,SBUDGET,SSEND server
    class TICKET,BUILDCTL,CTLBUDGET,WITHHOLD ticket
    class REJECT,STRUNCATE reject
```

> PQ ClientMagic = SHA-256(pq_public_key) 前 8 字节（首 7 字节全零或等于 PQResumeMagic 时
> 翻转首字节，避开 QUIC 首字节范围）。ticket 由 `ticketKey` 用 XChaCha20-Poly1305 密封，
> 明文 86B：resume-secret(32) + es-version(2) + client-magic(8) + serial(4) + ts-end(4) +
> expiry(4) + profile-ext-hash(32)。

## 同步统计记录

```mermaid
graph LR
    REQ[RecordRequest] -->|同步 · 请求路径内| ATOMIC[原子计数器<br/>total · hit · miss<br/>rcode 计数]
    ATOMIC --> TOPK[非命中事件<br/>per-RCODE top-N 域名<br/>topk.Map 有界]
    TOPK --> DONE[Done<br/>无 channel · 无后台 goroutine<br/>重启归零]
    QUERY[zjdns.stats CHAOS] --> SNAP["读取内存快照<br/>O(1) 计数 + top-N 排序"]
    SNAP --> TXT[TXT 输出<br/>overview / hit / rcode / top-rcodeN]
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef done fill:#d1fae5,stroke:#10b981,color:#064e3b
    class REQ,QUERY io
    class ATOMIC,TOPK,SNAP,TXT proc
    class DONE done
```

> 统计为纯同步内存实现（`cache/statsjournal.go`）：原子计数器 + mutex 保护的 topk journal，
> 无缓冲 channel、无批量刷新、无过载丢弃。清空端点 `zjdns.stats.clear` / `zjdns.querylog.clear`
> 仅限回环地址。
