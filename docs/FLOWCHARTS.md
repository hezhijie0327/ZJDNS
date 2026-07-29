# ZJDNS 架构流程图

## 整体架构

```mermaid
graph LR
    C[Clients] --> L
    subgraph ZJDNS
        L[Listeners<br/>UDP · TCP · DoT · DoH · DoH3<br/>DoQ · DTLS · TLCP · DTLCP<br/>DNSCrypt] --> MW[Middleware Chain<br/>Response · CacheStore · Validation<br/>Zone · EDNS · CacheLookup<br/>PTR · DNS64 · Resolution]
        MW --> RES[Resolver<br/>Forwarding · Recursive<br/>QNAME Minimisation · DNSSEC]
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
    LOADCONF --> INITDB[Open BadgerDB<br/>KV Store]
    INITDB --> INITMW[Build Middleware Chain<br/>9 Layers]
    INITMW --> INITHANDLER[Create Handler<br/>+ Resolver + Zone + Ruleset]
    INITHANDLER --> STARTPROTO[Start Protocol Listeners<br/>UDP TCP DoT DoH DoH3<br/>DoQ DTLS TLCP DTLCP<br/>DNSCrypt]
    STARTPROTO --> BG[Start Background Tasks<br/>ECS Refresh · Cookie Rotate<br/>TCP WriteMu Sweep]
    BG --> RUNNING[Running<br/>accept queries]
    RUNNING --> SIG{Signal?}
    SIG -->|SIGINT/SIGTERM| SHUTDOWN[Mark Handler Closed<br/>Cancel Context<br/>Stop Protocol Listeners]
    SHUTDOWN --> WAITBG[Wait Background Tasks<br/>Drain AsyncStatsWriter · Close DB]
    WAITBG --> EXIT[Exit]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef running fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef exit fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class START start
    class LOADCONF,INITDB,INITMW,INITHANDLER,STARTPROTO,BG,SHUTDOWN,WAITBG proc
    class RUNNING running
    class EXIT exit
```

## 中间件管道

```mermaid
graph LR
    Q[Query] --> R[Response<br/>EDNS · Cookie · EDE]
    R --> CS[CacheStore<br/>Write · Request Log]
    CS --> V[Validation<br/>Domain · Label · Type<br/>Opcode · QCLASS]
    V --> Z[Zone<br/>Rules · Wildcard<br/>Bypass]
    Z --> E[EDNS<br/>ECS · Cookie<br/>Padding]
    E --> CL[CacheLookup<br/>Fresh → Serve<br/>Stale → Refresh]
    CL --> PT[PTR<br/>Reverse Lookup]
    PT --> D64[DNS64<br/>AAAA Synthesis]
    D64 --> RE[Resolution<br/>Upstream · Recursive<br/>Singleflight]
    classDef mw fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q mw
    class R,CS,V,Z,E,CL,PT,D64,RE mw
```

## 缓存查询流程

```mermaid
graph TD
    Q[Query] --> ECSCAND[Build ECS Fallback Candidates<br/>addr/prefix granularities<br/>+ empty-ECS for non-ECS entries]
    ECSCAND --> LOOP{Loop candidates}
    LOOP -->|next| QUERY[BadgerDB Key Lookup<br/>qname+qtype+qclass+ecs]
    QUERY -->|found| UNPACK[dns.Msg Unpack]
    QUERY -->|not found| LOOP
    QUERY -->|error| MISS[Cache Miss]
    LOOP -->|exhausted| MISS
    DECOMP --> UNPACK[Unpack dns.Msg]
    UNPACK --> SORT[Sort A/AAAA by<br/>IP Latency Probe]
    SORT --> EXPIRED{TTL Expired?}
    EXPIRED -->|No| HIT[Fresh Hit → Return]
    EXPIRED -->|Yes| STALE[Stale Hit]
    STALE --> PREFETCH{Should Prefetch?}
    PREFETCH -->|Yes| BG[Background Refresh<br/>Serve Stale + Update Cache]
    PREFETCH -->|No| RETURN[Serve Stale]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef hit fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef miss fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class Q start
    class ECSCAND,LOOP,QUERY,DECOMP,UNPACK,SORT,EXPIRED,PREFETCH,BG proc
    class HIT hit
    class MISS,RETURN,STALE miss
```

## 递归解析流程

```mermaid
graph TD
    Q[Query] --> CACHE{Cache Hit?}
    CACHE -->|Fresh| SERVE[Serve from Cache]
    CACHE -->|Stale| STALE[Serve Stale + Refresh]
    CACHE -->|Miss| ROOT[Root Hints → TLD → Auth]
    ROOT --> QMIN[QNAME Minimisation<br/>RFC 9156 · max 16 steps]
    QMIN --> NS[Query NS Records]
    NS --> ADDR[Resolve NS Addresses<br/>Latency-Sorted]
    ADDR --> PROBE[Concurrent Query<br/>First-NOERROR Wins]
    PROBE -->|Success| VALIDATE[DNSSEC Validation]
    PROBE -->|NXDOMAIN| FALLBACK[Secondary Fallback]
    PROBE -->|FORMERR| RETRY[EDNS-Free Retry<br/>RFC 6891 Sec 6.2.2]
    VALIDATE --> CNAME{CNAME?}
    CNAME -->|Yes| FOLLOW[Follow CNAME Chain<br/>max 16 hops]
    FOLLOW --> QMIN
    CNAME -->|No| STORE[Cache + Return]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef result fill:#d1fae5,stroke:#10b981,color:#064e3b
    class Q start
    class CACHE,ROOT,QMIN,NS,ADDR,PROBE,VALIDATE,CNAME,FOLLOW,RETRY,FALLBACK proc
    class SERVE,STALE,STORE result
```

## DNSSEC 验证链

```mermaid
graph TD
    Q[Recursive Query] --> HINT[Root Hints]
    HINT --> ROOT[Query Root NS]
    ROOT --> ROOTKSK[Root KSK<br/>Trust Anchor]
    ROOTKSK --> DS{DS Match?}
    DS -->|Yes| TLD[TLD DNSKEY Verified]
    DS -->|No| CDS{CDS Fallback?<br/>RFC 7344}
    CDS -->|Match| TLD
    CDS -->|No| BOGUS[Bogus → SERVFAIL]
    TLD --> AUTH[Authoritative DNSKEY]
    AUTH --> RRSIG{RRSIG Valid?}
    RRSIG -->|Yes| VALID[AD=1 · NOERROR]
    RRSIG -->|No| BOGUS
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef chain fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef fail fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class Q start
    class HINT,ROOT,ROOTKSK,DS,CDS,TLD,AUTH,RRSIG chain
    class VALID ok
    class BOGUS fail
```

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
    CKVALID -->|No| CKGEN[Generate New Cookie<br/>SipHash-2-4 + Timestamp<br/>24h Secret Rotation]
    PADDING --> PADREQ[Pad Request 128B]
    PADDING --> PADRESP[Pad Response 468B<br/>Secure Transports Only]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q,PARSE start
    class ECS,COOKIE,PADDING,ECSDB,CKVALID,CKGEN,CKSERVE,PADREQ,PADRESP,USESTATIC,USEAUTO,NOECS proc
```

## DNS 污染检测（四层防御）

所有防御机制均配置在 `UpstreamServer` 上，同时支持转发和递归模式。

### 上行查询路径（转发 + 递归通用）

```mermaid
graph TD
    Q[Outbound Query] --> UDP{Transport}
    Q --> TCP
    UDP -->|UDP| HG[HopGuard<br/>IP TTL Fingerprint]
    HG -->|TTL in +-2| SG[Spoofguard<br/>Multi-Read Loop]
    HG -->|TTL mismatch| REJECT[Reject]
    SG -->|AR=0+NOERROR+EDNS| REJECT
    SG -->|AN>=2 or NS>0 or AD=1| ACCEPT[Accept]
    SG -->|Ambiguous| COLLECT[Collect <=500ms]
    COLLECT --> PICK[Pick Richest]
    TCP -->|TCP| SPG[Splitguard<br/>Random 1-4 Byte Segments]
    ACCEPT --> UP[Upstream Response]
    PICK --> UP
    SPG --> UP
    classDef query fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef defense fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef result fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class Q query
    class HG,SG,SPG defense
    class ACCEPT,PICK,UP result
    class REJECT reject
```

### 递归逐跳检测（Poisonguard 专属）

```mermaid
graph TD
    REC[Recursive Resolution] -->|Root| RPG[Poisonguard<br/>Root: Only NS/DS for TLD]
    REC -->|TLD| TPG[Poisonguard<br/>TLD: Only NS/DS sub-delegation]
    REC -->|Auth| APG[Poisonguard<br/>Auth: VerdictUncertain]
    RPG -->|Injected A/AAAA| POISON[Poison → TCP Fallback]
    TPG -->|Injected A/AAAA| POISON
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
| 1 | **HopGuard** | 转发+递归 | IP 层 | UDP 上游 TTL 指纹学习，32样本武装，拒绝偏离 +-2 的响应 |
| 2 | **SpoofGuard** | 转发+递归 | DNS 报文层 | UDP 多读循环，EDNS 门控 + richness 优选 |
| 3 | **SplitGuard** | 转发+递归 | TCP 流层 | TCP 分段发送（1-4字节），破坏 DPI 首包特征识别 |
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
    SPOOF -->|Clean| FEED[Feed TTL into histogram]
    FEED --> SAMPLES{Samples >= 32?}
    SAMPLES -->|Yes| REBUILD[Rebuild trusted set<br/>from histogram peaks]
    REBUILD --> ARM[Arm detector]
    SAMPLES -->|No| DONE[Done]
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    classDef learn fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef pass fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    class PASS,PASS2,SPOOF,FEED,DONE,ARM ok
    class REJECT reject
    class SAMPLES,REBUILD,ARM learn
    class Q,CAP,VS,ARMED,CHECK pass
```

#### SpoofGuard（UDP 多读 + EDNS 门控）

```mermaid
graph TD
    Q[Send UDP Query] --> WAIT[Set Read Deadline<br/>Collect Window <=500ms]
    WAIT --> READ[Read Response]
    READ --> TIMEOUT{Timeout?}
    TIMEOUT -->|Yes| NOCAND{Any Candidates?}
    NOCAND -->|No| ERR[Return Error]
    NOCAND -->|Yes| BEST[Pick Best Candidate]
    READ -->|Packet| HEADER{Min 12 bytes?}
    HEADER -->|No| READ
    HEADER -->|Yes| IDMATCH{ID Match?}
    IDMATCH -->|No| READ
    IDMATCH -->|Yes| UNPACK[Unpack DNS Response]
    UNPACK --> EDNS{Has EDNS OPT?}
    EDNS -->|No| NONEDNS{AN>=2 or NS>0<br/>or CNAME chain?}
    NONEDNS -->|No| REJECT[Reject<br/>GFW signature: AR=0 + NOERROR<br/>without EDNS]
    NONEDNS -->|Yes| KEEP[Keep as fallback]
    KEEP --> READ
    EDNS -->|Yes| RICH{AN>=2 or NS>0<br/>or AD=1?}
    RICH -->|Yes| ACCEPT[Immediate Accept<br/>Stop Reading]
    RICH -->|No| COLLECT[Collect Candidate<br/>Continue Reading]
    COLLECT --> READ
    ACCEPT --> DONE[Return Response]
    BEST --> DONE
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    class ACCEPT,DONE ok
    class REJECT,ERR reject
    class EDNS,RICH,NONEDNS,COLLECT,KEEP,BEST proc
    class Q,WAIT,READ,UNPACK io
```

#### SplitGuard（TCP 分段发送）

```mermaid
graph LR
    Q[DNS over TCP Query] --> PACK[Pack DNS Message<br/>2-byte Length Prefix + Body]
    PACK --> RAND[Random Segment Size<br/>1 to 4 bytes]
    RAND --> LOOP{Loop until<br/>all bytes sent}
    LOOP -->|remaining > segSize| SEND[Write segSize bytes]
    SEND --> JITTER[Random Jitter<br/>1-5ms]
    JITTER --> LOOP
    LOOP -->|last chunk| LAST[Write remaining bytes]
    LAST --> WAIT[Await Response]
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    class Q,WAIT io
    class PACK,RAND,LOOP,SEND,JITTER,LAST proc
```

#### Poisonguard（递归 Zone-Authority 交叉验证）

```mermaid
graph TD
    Q[Recursive Response<br/>from Delegation Hop] --> EXTRACT[Extract Answer RRs<br/>matching query name]
    EXTRACT --> CLASSIFY[classify zone name rrtype]
    CLASSIFY --> ROOT{zone == .?}
    ROOT -->|Yes| CR[classifyRoot]
    CR --> ISROOT{name is<br/>root-servers.net.?}
    ISROOT -->|Yes| CLEAN[VerdictClean]
    ISROOT -->|No| ISTLD{rrtype is NS/DS<br/>and name is TLD?}
    ISTLD -->|Yes| CLEAN
    ISTLD -->|No| POISON[VerdictPoisoned]
    ROOT -->|No| TLD{isTLD zone?}
    TLD -->|Yes| CT[classifyTLD]
    CT --> SAME{name == zone?}
    SAME -->|Yes| CLEAN
    SAME -->|No| POISON
    TLD -->|No| UNCERTAIN[VerdictUncertain<br/>Authoritative: cannot<br/>distinguish by content alone]
    POISON --> TCPFALL[Trigger TCP Fallback<br/>bypass GFW via encrypted TCP]
    CLEAN --> CONTINUE[Continue Resolution]
    UNCERTAIN --> CONTINUE
    classDef clean fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef poison fill:#fce7f3,stroke:#ec4899,color:#831843
    classDef uncertain fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef proc fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    class CLEAN,CONTINUE clean
    class POISON,TCPFALL poison
    class UNCERTAIN uncertain
    class Q,EXTRACT,CLASSIFY,ROOT,CR,ISROOT,ISTLD,TLD,CT,SAME proc
```

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
    BYPASS -->|No| LOAD[Load Rules from BadgerDB<br/>Exact + Wildcard + File]
    LOAD --> MATCH[Intersect with<br/>Client Match Tags<br/>CIDR + Domain]
    MATCH -->|No Match| NOMATCH[No Match -> Next]
    MATCH -->|Match| SCORE[Score by Tag Priority]
    SCORE --> TYPE{Response Type}
    TYPE -->|ANSWER| BUILDANS[Build Answer Section<br/>A/AAAA/CNAME/TXT...]
    TYPE -->|RCODE| BUILDRC[Return RCODE Only<br/>NXDOMAIN/SERVFAIL...]
    BUILDANS --> REWRITE{Rewrite QNAME?}
    REWRITE -->|Yes| SETNAME[Set OriginalName<br/>Rewrite for Resolution]
    REWRITE -->|No| SHORTCUT[Short-circuit Pipeline<br/>qctx.Res = synthetic]
    BUILDRC --> SHORTCUT
    SETNAME --> SHORTCUT
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef match fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef nomatch fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class Q start
    class BYPASS,LOAD,MATCH,SCORE,TYPE,BUILDANS,BUILDRC,REWRITE,SETNAME proc
    class SHORTCUT match
    class NOMATCH,NEXT nomatch
```

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
    WAIT -->|Timeout 60s| TIMEOUT[Return Timeout Error]
    SHARED --> RETF[Return to Follower]
    LRU -->|Eviction| EVICT[OnEvict: close done<br/>channel with nil result<br/>-> SERVFAIL for waiters]
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
    HASAAAA -->|No| RESA[Resolve A Record]
    RESA --> HASA{Has A?}
    HASA -->|No| RETNO[Return Empty]
    HASA -->|Yes| SYNTH[Embed IPv4 into<br/>NAT64 Prefix<br/>RFC 6052 Sec 2.2]
    SYNTH --> RETSYNTH[Return Synthetic AAAA]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef out fill:#d1fae5,stroke:#10b981,color:#064e3b
    class Q start
    class RESOLVE,RESA,SYNTH proc
    class RETAAAA,RETSYNTH,RETNO out
```

## 规则集引擎

```mermaid
graph LR
    subgraph Load
        CFG[Config Rules] --> DOM[Domain Rules<br/>TLD+1 Suffix]
        CFG --> IP[IP CIDR Rules<br/>Binary Radix Trie]
    end
    subgraph Match
        Q[Query] --> DOMQ[Domain Lookup<br/>BadgerDB Prefix Scan]
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
    QUERY[Cache Hit<br/>with A/AAAA Records] --> EXTRACT[Extract All IPs<br/>from Answer Section]
    EXTRACT --> BATCH[Batch BadgerDB Lookup<br/>e:ip: prefix scan]
    BATCH -->|All Cached| SORT[Sort Records<br/>by Latency ASC]
    BATCH -->|Some Missing| PROBE[Background Probe<br/>per-IP concurrent]

    PROBE --> STEPS[Probe Steps<br/>configurable order]
    STEPS --> ICMP[ICMP Ping<br/>privileged raw socket]
    STEPS --> TCP[TCP Connect<br/>configurable port]
    STEPS --> UDP[UDP Send + Read<br/>DNS probe query]
    STEPS --> HTTP[HTTP HEAD<br/>port 80]
    STEPS --> HTTPS[HTTPS HEAD<br/>port 443 · TLS]
    STEPS --> HTTP3[HTTP3 HEAD<br/>port 443 · QUIC]

    ICMP --> AGG[Take Minimum<br/>of All Steps]
    TCP --> AGG
    UDP --> AGG
    HTTP --> AGG
    HTTPS --> AGG
    HTTP3 --> AGG

    AGG --> STORE[Store in ip_latency<br/>Per-IP, shared across domains]
    STORE --> SORT

    SORT --> RETURN[Return Sorted Answer<br/>Fastest IP First]
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef proto fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef out fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class QUERY start
    class EXTRACT,BATCH,PROBE,STEPS,AGG,STORE,SORT proc
    class ICMP,TCP,UDP,HTTP,HTTPS,HTTP3 proto
    class RETURN out
```

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
        ROUTE -->|DTLS| DTLS[DTLS<br/>DTLS 1.2+ · PMTU Truncate]
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

## SOCKS5 代理路径

```mermaid
graph LR
    Q[Query] --> PROXY{Proxy?}
    PROXY -->|No| DIRECT[Direct Dial]
    PROXY -->|Yes| AUTH{Auth?}
    AUTH -->|No| NOAUTH[TCP Connect<br/>+ UDP Associate]
    AUTH -->|User/Pass| UPAUTH[TCP Connect<br/>+ Auth Negotiation<br/>+ UDP Associate]
    NOAUTH --> UP[Upstream]
    UPAUTH --> UP
    DIRECT --> UP
    classDef query fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ext fill:#e2e8f0,stroke:#64748b,color:#1e293b
    class Q query
    class PROXY,AUTH,NOAUTH,UPAUTH,DIRECT proc
    class UP ext
```

## 协议对照：标准加密 ↔ 国密

```mermaid
graph TD
    subgraph Standard[标准加密体系]
        TLS[TLS 1.3<br/>ECDSA + AES-GCM + SHA-256] -->|TCP 加密| DOT[DoT RFC 7858]
        TLS -->|TCP + HTTP| DOH[DoH RFC 8484]
        TLS -->|UDP 适配| DTLS[DTLS 1.2 RFC 8094]
        DTLS -->|UDP 加密| DOD[DoD DNS over DTLS]
    end
    subgraph GM[国密体系 GB/T 38636 · GM/T 0128]
        TLCP[TLCP<br/>SM2 + SM4-GCM + SM3] -->|TCP 加密| TLCPDOT[TLCP DoT]
        TLCP -->|TCP + HTTP| TLCPDOH[TLCP DoH]
        TLCP -->|UDP 适配| DTLCP[DTLCP GM/T 0128]
        DTLCP -->|UDP 加密| DTLCPDOD[DTLCP DoD]
    end

    TLS -.->|加密原语替换<br/>ECDSA→SM2<br/>AES-GCM→SM4-GCM<br/>SHA-256→SM3| TLCP
    DTLS -.->|加密原语替换<br/>DTLS 1.2→DTLCP| DTLCP

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
    GEN --> TICKET[Derive Ticket Key<br/>from Signing Key<br/>for PQ Resumption]
    TICKET --> SERVE[Begin Serving]
    SERVE --> TIMER{24h Ticker}
    TIMER -->|Fire| ROTATE[rotateKeys]
    ROTATE --> NEWCERT[Generate New Cert Pair<br/>Classical + PQ]
    NEWCERT --> PREPEND[Prepend to keys list<br/>newest first]
    PREPEND --> PURGE[Purge Expired Keys<br/>TTL + Overlap window]
    PURGE --> RESETCACHE[Reset Shared Key Cache<br/>old X25519 keys invalid]
    RESETCACHE --> SERVE
    classDef start fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef ok fill:#d1fae5,stroke:#10b981,color:#064e3b
    class START start
    class GEN,TICKET,ROTATE,NEWCERT,PREPEND,PURGE,RESETCACHE proc
    class SERVE ok
```

## DNSCrypt 加密流程

### Classical（X25519 + XChaCha20-Poly1305）

```mermaid
graph TD
    C[Client] --> GENKEY[Generate Ephemeral<br/>X25519 Key Pair]
    GENKEY --> QUERY[Build Query<br/>ClientMagic 8B<br/>ClientPk 32B<br/>ClientNonce 12B]
    QUERY --> PAD[ISO/IEC 7816-4 Padding<br/>Target 256B for UDP<br/>Random 1-256B for TCP]
    PAD --> ENCRYPT[XChaCha20-Poly1305 Encrypt<br/>Key = SharedKey from X25519<br/>Nonce = ClientNonce + Zeroes 12B]
    ENCRYPT --> SEND[Send to Resolver]

    SEND --> SRECV[Resolver Receives]
    SRECV --> SMAGIC{ClientMagic<br/>Match Cert?}
    SMAGIC -->|No| REJECT[Silent Drop]
    SMAGIC -->|Yes| SDH[Compute SharedKey<br/>X25519 ClientPk x ResolverSk]
    SDH --> SCHECK[Cached in<br/>SharedKeyCache?]
    SCHECK -->|Hit| SUSE[Use Cached Key]
    SCHECK -->|Miss| SCOMPUTE[Compute + Cache]
    SUSE --> SDECRYPT[Decrypt + Verify Poly1305]
    SCOMPUTE --> SDECRYPT
    SDECRYPT --> SUNPAD[Unpad]
    SUNPAD --> SPROCESS[Process DNS Query]

    SPROCESS --> SRESP[Build DNS Response]
    SRESP --> SPAD[Deterministic Padding<br/>SHA-256 SharedKey+ClientNonce<br/>Multiple of 64 bytes]
    SPAD --> SENCRYPT[Encrypt Response<br/>ResolverMagic 8B<br/>Nonce 24B<br/>Poly1305 Tag]
    SENCRYPT --> SBUDGET{UDP Budget?}
    SBUDGET -->|OK| SSEND[Send to Client]
    SBUDGET -->|Exceeded| STRUNCATE[Truncate + Set TC]

    classDef client fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef server fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class C,GENKEY,QUERY,PAD,ENCRYPT,SEND client
    class SRECV,SDH,SCHECK,SUSE,SCOMPUTE,SDECRYPT,SUNPAD,SPROCESS,SRESP,SPAD,SENCRYPT,SSEND server
    class REJECT,STRUNCATE reject
```

### Post-Quantum（X-Wing KEM）

```mermaid
graph TD
    C[Client] --> CERT[Fetch PQ Cert<br/>1320B via TXT query]
    CERT --> ENCAP[X-Wing Encapsulate<br/>ResolverPk 1216B<br/>→ Ciphertext 1120B<br/>→ SharedSecret 32B]
    ENCAP --> HKDF[HKDF-SHA256 Derive<br/>SharedKey from SharedSecret<br/>cert-context + ciphertext]
    HKDF --> QUERY[Build PQ Query<br/>ClientMagic 8B<br/>Ciphertext 1120B<br/>ClientNonce 12B]
    QUERY --> PAD[ISO/IEC 7816-4 Padding<br/>Target 64B min<br/>Ciphertext provides<br/>anti-amplification]
    PAD --> ENCRYPT[XChaCha20-Poly1305 Encrypt]
    ENCRYPT --> SEND[Send to Resolver]

    SEND --> SRECV[Resolver Receives]
    SRECV --> SMAGIC{ClientMagic<br/>Match PQ Cert?}
    SMAGIC -->|No| REJECT[Silent Drop]
    SMAGIC -->|Yes| SDECAP[X-Wing Decapsulate<br/>Ciphertext x ResolverSk<br/>→ SharedSecret 32B]
    SDECAP --> SHKDF[HKDF-SHA256 Derive<br/>SharedKey]
    SHKDF --> SDECRYPT[Decrypt + Verify]
    SDECRYPT --> SPROCESS[Process DNS Query]

    SPROCESS --> TICKET{Include<br/>Resumption Ticket?}
    TICKET -->|Yes| BUILDCTL[Build Control Block<br/>PQDR Magic 4B<br/>TicketLifetime 4B<br/>Sealed Ticket]
    BUILDCTL --> CTLBUDGET{UDP Budget OK?}
    CTLBUDGET -->|Yes| SENDRESP[Send Response with Ticket]
    CTLBUDGET -->|No| WITHHOLD[Withhold Ticket<br/>Send Response + TC]
    TICKET -->|No| SENDRESP

    SENDRESP --> CLIENT[Client Stores Ticket<br/>for Resumption]
    CLIENT --> RESUME[Future Query:<br/>PQResumeMagic 8B<br/>Ticket + ClientNonce<br/>Encrypted Query]
    RESUME --> RESOLVER[Resolver Opens Ticket<br/>Validates cert-context<br/>Derives SharedKey]
    RESOLVER --> SPROCESS

    classDef client fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef server fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef ticket fill:#f3e8ff,stroke:#a855f7,color:#4c1d95
    classDef reject fill:#fee2e2,stroke:#ef4444,color:#991b1b
    class C,CERT,ENCAP,HKDF,QUERY,PAD,ENCRYPT,SEND,CLIENT,RESUME client
    class SRECV,SDECAP,SHKDF,SDECRYPT,SPROCESS,SENDRESP,RESOLVER server
    class TICKET,BUILDCTL,CTLBUDGET,WITHHOLD ticket
    class REJECT reject
```

## 异步统计写入

```mermaid
graph LR
    REQ[RecordRequest] -->|Non-blocking| CH[Buffered Channel<br/>cap 64]
    CH -->|default: drop| DROP[Drop under overload]
    CH -->|send| BG[Background Goroutine<br/>batch accumulate]
    BG --> TICKER{100ms Ticker<br/>or batch full 64}
    TICKER -->|Fire| FLUSH[Aggregate in Memory<br/>WriteBatch Flush]
    FLUSH --> BG
    CLOSE[Close] --> DRAIN[Drain channel]
    DRAIN --> FLUSHLAST[Final Flush]
    FLUSHLAST --> DONE[Exit]
    classDef io fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
    classDef proc fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef done fill:#d1fae5,stroke:#10b981,color:#064e3b
    class REQ,CLOSE io
    class CH,DROP,BG,TICKER,FLUSH,DRAIN,FLUSHLAST proc
    class DONE done
```

