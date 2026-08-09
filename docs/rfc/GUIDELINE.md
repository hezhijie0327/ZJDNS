# RFC 精华指南

每个 RFC 的核心协议要点提炼，供开发者快速理解规范要求而无需阅读 RFC 全文。

格式：**概述 → 常量 → 关键要求 → 协议流程 → 我们的实现**

### 状态图例

Section 标题栏位格式：`[RFC NNNN: 状态]` `合规标记`

| 标记 | RFC 状态 | 说明 |
|------|----------|------|
| `[Standard]` | Internet Standard (STD) | 正式互联网标准 |
| `[Internet Standard]` | Internet Standard (STD) | 正式互联网标准 |
| `[Proposed Standard]` | Standards Track | 标准轨道提案 |
| `[Best Current Practice]` | BCP | 当前最佳实践 |
| `[Informational]` | Informational | 信息性文档 |
| `[Experimental]` | Experimental | 实验性协议 |
| `[Historic]` | Historic | 已废弃/被取代 |

| 标记 | 合规状态 | 说明 |
|------|----------|------|
| ✅ | 合规 | 已完整实现 |
| ⚠️ | 部分合规 | 已知差距，见条目详情 |
| ⚪ | 参考 | 不适用（非递归解析器职责）或仅供参考 |
| ❌ | 不合规 | 要求未实现（当前无此项） |

### 统计摘要

| 状态 | 数量 |
|------|------|
| Internet Standard / Standard | 3 (RFC 768, 1034, 1035) |
| Proposed Standard | 74 |
| Best Current Practice | 3 (RFC 2929, 6895, 8499) |
| Informational | 10 |
| Experimental | 8 |
| Historic | 6 |
| Internet-Draft | 3 (DNS Stamp, DNSCrypt, DELEG) |
| 国密标准 | 1 (TLCP/DTLCP) |
| **总计** | **108 RFC 条目 / 96 章节**（含 2065/2537、4033/4034/4035 等合并段；90 个 RFC 编号章节 + 6 个非 RFC 章节：DELEG / DNS Stamp / DNSCrypt / SOCKS5 / TLCP / 已知偏离） |

| 合规 | 数量 |
|------|------|
| ✅ 合规 | 68 |
| ⚠️ 部分合规 | 4 (RFC 5001, 5011/9077, 8198, 9567) |
| ⚪ 参考 | 18 |

---

## RFC 768 — User Datagram Protocol  `[RFC 768: Standard (STD 6)]`  ✅

**DNS 的 UDP 传输基础（端口 53、最大 512 字节消息、无连接语义）。**

- UDP 头 8 字节；IPv4 最小 MTU 68、IPv6 最小 MTU 1280
- 512 字节限制 → EDNS(0)（RFC 6891）扩展

### 我们的实现

- 全链路 UDP 支持（服务端 + 上游客户端），EDNS 载荷 1232 ✓

---

## RFC 1034 — DNS 概念与设施  `[RFC 1034: Internet Standard (STD 13)]`  ✅

**域名系统（DNS）的概念基础：命名空间、资源记录、名称服务器、解析器算法。**

### 关键常量

- 域名最大长度: **255** 字节（线格式）、**253** 字符（表示格式）
- 标签最大长度: **63** 字符
- 标签类型: 标准（高 2 位 = 00）、压缩指针（= 11）
- SOA 字段: SERIAL（32 位）、REFRESH、RETRY、EXPIRE、MINIMUM（均秒）

### 关键要求

- **MUST**: 标签大小写不敏感比较（ASCII，高零位）
- **MUST**: 压缩指针的标签必须能在任意消息位置出现（所有实现必须能解析）
- **MUST**: CNAME 记录与同标签其他记录互斥
- **MUST**: NS/MX RData 不能是别名（CNAME）
- **MUST**: DNS Header 的 Z 标志（保留位）必须为 0
- **SHOULD**: UDP 重传间隔最低 2–5 秒

### 关键概念

- **区域切割（Zone Cut）**: 父域 NS 记录委托到子域权威服务器，glue 记录位于 Additional Section
- **泛域名（Wildcard）**: `*.example.com` 匹配下层标签但不匹配自身；显式数据抑制泛域名；委托取消泛域名
- **CNAME 处理**: CNAME 存在时不得有其他 RR；解析器跟随 CNAME 链（循环检测）
- **否定回答缓存**（§4.3.4）: 权威 SOA 放入 Authority Section；SOA MINIMUM 控制否定 TTL

### 解析器算法（§5.3.3）

1. 查找本地缓存/主机信息
2. 查找最佳 NS 服务器
3. 按需向 NS 发送查询
4. 分析响应（回答/委托/CNAME/错误）

### 我们的实现

- 递归解析器实现完整的 §5.3.3 算法（`server/resolver/recursive.go`）
- `zonecut.go`：区域切割检测与 glue 记录处理
- CNAME 链处理在 `cname.go` 带循环检测

## RFC 1035 — DNS 实现规范  `[RFC 1035: Internet Standard (STD 13)]`  ✅

**域名系统（DNS）的线格式、消息结构、传输协议和查询语义。**

### 关键常量

- DNS 端口: **53** (UDP + TCP)
- 域名最大长度: **255** 字节（线格式）= 253 字符（表示格式，去掉长度前缀和根终止符）
- 标签最大长度: **63** 字符
- UDP 消息最大: **512** 字节（无 EDNS）

### 关键要求

- **MUST**: UDP 和 TCP 均使用端口 53
- **MUST**: TCP 消息以 2 字节大端长度前缀开头
- **MUST**: 支持 TCP 连接复用（同一连接多查询）
- **MUST**: 截断（TC）响应触发 TCP 重试
- TCP 空闲超时建议约 **2 分钟**

### 我们的实现

- `config.MaxDNSMessageSize = 65535`（TCP 最大消息）
- `config.MaxDomainLength = 253`
- TCP 管线化：`server/upstream/pool/tcp.go`（RFC 7766 增强）

---

## RFC 1348 — NSAP Records（已废弃）  `[RFC 1348: Historic (Obsoleted by RFC 1706)]`  ⚪

**NSAP RR（22）：OSI NSAP 地址的 DNS 发布（后被 RFC 1706 取代并从标准中移除）。**

### 我们的实现

- ⚪ 历史参考

---

## RFC 1876 — LOC Record  `[RFC 1876: Experimental]`  ✅

**LOC RR（29）：地理定位（纬度/经度/高度/精度）。**

### 我们的实现

- miekg/dns 类型支持；zone 规则可配置 ✓

---

## RFC 1995 — Incremental Zone Transfer (IXFR)  `[RFC 1995: Proposed Standard]`  ⚪

**增量区域传输：仅传输变化的 RRset（SOA SERIAL 比较）。**

### 我们的实现

- ⚪ 参考：ZJDNS 不做区域传输（非权威）；ANY/AXFR/IXFR 查询被拒绝（REFUSED）✓

---

## RFC 1996 — DNS NOTIFY  `[RFC 1996: Proposed Standard]`  ⚪

**区域变更提示：主服务器通知辅助服务器"区域变了"，辅助再发起 SOA 查询/传输。**

### 我们的实现

- ⚪ 参考：非权威/辅助场景，ZJDNS 无此职责

---

## RFC 2065 / 2537 / 3110 / 3445 — DNSSEC 历史与旧算法  `[RFC 2065: Historic (Obsoleted by RFC 4033–4035) | RFC 2537: Historic (Obsoleted by RFC 3110) | RFC 3110: Historic (Obsoleted) | RFC 3445: Historic (Obsoleted by RFC 4033–4035)]`  ⚪ ⚪ ⚪ ⚪

**历史参考：**
- 2065: DNSSEC 原始规范（被 2535 取代）
- 2537: RSA/MD5 KEY/SIG（算法 1，已废弃）
- 3110: RSA/SHA-1 SIG 与 KEY（算法 5，已废弃）
- 3445: 限制 KEY RR 作用域（仅静态/动态更新标识，后被 4034 DNSKEY 取代）

### 我们的实现

- ⚪ 历史参考：现代 DNSSEC 见 RFC 4033/4034/4035、5702、6605、8080 条目

---

## RFC 2136 — Dynamic Updates in the DNS (DNS UPDATE)  `[RFC 2136: Proposed Standard]`  ⚪

**DNS 动态更新协议（UPDATE 消息、Prerequisite 与 Update 段、SOA 序列号递增）。**

### 关键点

- OPCODE=5；Prerequisite（依赖检查）与 Update（添加/删除/替换）段
- 更新须经授权（TSIG/源地址）；SOA SERIAL 由主服务器维护

### 我们的实现

- ⚪ 参考：ZJDNS 非权威服务器，不提供动态更新；Validation 中间件拒绝非 QUERY opcode（NOTIMP）✓

---

## RFC 2181 — DNS 规范澄清  `[RFC 2181: Proposed Standard]`  ✅

**对 RFC 1034/1035 的关键澄清：RRsets、TC 位语义、TTL 一致性、缓存信任等级。**

### 关键要求

- **MUST**: 同标签、同类、同类型的所有 RR 组成一个 RRSet，查询返回完整的 RRSet
- **MUST**: RRSet 内所有 RR 的 TTL 必须一致（不一致视为错误，取最小值）
- **MUST**: 服务器绝不将缓存 RR 与响应合并形成 RRSet
- **MUST**: 源地址选择：UDP 响应的源 IP 必须匹配查询的目标 IP
- **MUST**: NS/MX RData 不能是别名（CNAME）
- **MUST NOT**: Additional/Authority Section 中非权威数据不可缓存为回答

### TC 位语义（§9）

- TC **仅**在必须的完整 RRSet 放不下时设置
- **不应**因 Additional Section 数据放不下而设 TC
- TC 设置时可保留部分 RRSet；接收者应忽略并改用 TCP

### 缓存信任等级（§5.4.1）

1. 主区域文件数据
2. 区域传输（AXFR/IXFR）
3. 权威 Answer Section
4. 权威 Authority Section
5. Glue 数据
6. 非权威 Answer Section
7. 权威响应的 Additional Section / 非权威的 Authority Section
8. 额外信息（最低信任）

### TTL 限制（§8）

- TTL 为无符号 32 位（最大 2^31 − 1）
- MSB 置位的 TTL 值应视为 0
- 实现可以强制上限

### 我们的实现

- TC 语义：`server/bridge.go:153` 严格遵循 §9
- RRSet 验证：`dnssec/crypto.go` 遵循 §5
- 源地址选择：Go `net` 包默认行为

## RFC 2671 — Extension Mechanisms for DNS (EDNS0)  `[RFC 2671: Historic (Obsoleted by RFC 6891)]`  ⚪

**EDNS(0) 原始规范（被 RFC 6891 取代）：OPT 伪记录、UDP 载荷扩展、扩展 RCODE。**

### 我们的实现

- 已实现（RFC 6891 条目）；本条目为历史参考

---

## RFC 2782 — SRV Record  `[RFC 2782: Proposed Standard]`  ✅

**SRV RR（33）：服务定位（`_service._proto.name` → 目标 + 端口 + 权重/优先级）。**

### 关键点

- RDATA: priority、weight、port、target；权重 0 表示无负载均衡偏好
- 客户端按 priority 升序、weight 随机选择

### 我们的实现

- miekg/dns 类型支持；zone 规则可配置 ✓

---

## RFC 2845 / 4635 — TSIG  `[RFC 2845: Proposed Standard | RFC 4635: Proposed Standard]`  ⚪ ⚪

**TSIG（250）：事务签名（HMAC-SHA* 的共享密钥认证，4635 定义 HMAC-SHA1/224/256/384/512 算法标识）。**

### 关键点

- 签名覆盖消息 + TSIG 变量（时间戳、MAC 等）；时间戳防重放（±300s 窗口）
- 用于动态更新、区域传输、缓存投毒防护

### 我们的实现

- ⚪ 参考：ZJDNS 上游查询/客户端不启用 TSIG（RFC 8945 提及但无部署需求）；miekg/dns 类型支持

---

## RFC 2915 / 3401 / 3402 / 3403 — NAPTR 与 DDDS  `[RFC 2915: Proposed Standard (Obsoleted by RFC 3401–3403) | RFC 3401: Informational | RFC 3402: Proposed Standard | RFC 3403: Proposed Standard]`  ⚪ ✅ ✅ ✅

**NAPTR RR（35）+ DDDS 框架三部曲：字符串重写规则驱动的服务解析（ENUM、SIP 等）。**

- NAPTR RDATA: order、preference、flags（"s"/"a"）、service、regexp、replacement
- DDDS 算法：迭代应用重写规则直到 terminal 规则；RFC 3403 定义 DNS 作为 DDDS 数据库的编码

### 我们的实现

- miekg/dns 类型支持；zone 规则可配置 ✓

---

## RFC 2929 / 6895 — DNS IANA Considerations  `[RFC 2929: Best Current Practice (BCP 42) | RFC 6895: Best Current Practice (BCP 182)]`  ⚪ ⚪

**DNS 参数注册表管理：类型/类/操作码/RCODE 的分配政策与保留。**

### 我们的实现

- ⚪ 参考：类型/选项号与 miekg/dns 一致

---

## RFC 3123 — APL Record  `[RFC 3123: Experimental]`  ✅

**APL RR（42）：地址前缀列表（IPv4/IPv6 CIDR + 否定标记）。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 3225 — DO bit (DNSSEC OK)  `[RFC 3225: Proposed Standard]`  ✅

**EDNS0 扩展位（DO）：客户端声明理解 DNSSEC 记录；无 DO 的响应不应包含 DNSSEC 记录。**

### 关键要求

- 响应方 SHOULD 在响应 OPT 中回显 DO 位（RFC 3225 最初语义，后由 RFC 6840 §5.9 调整）
- DO=0 客户端不应收到 RRSIG/NSEC/NSEC3/DNSKEY/DS

### 我们的实现

- `msg.Security`（DO 位）解析/设置 ✓；缓存按 dnssec_ok 键隔离 DO=0/1 内容；DO=0 命中过滤 DNSSEC 证明 ✓

---

## RFC 3596 — AAAA Record  `[RFC 3596: Proposed Standard]`  ✅

**AAAA RR（28）：IPv6 地址。更新 RFC 1886。**

### 我们的实现

- 全链路支持（含 DNS64 合成）✓

---

## RFC 3597 — Handling of Unknown DNS RR Types  `[RFC 3597: Proposed Standard]`  ✅

**未知 RR 类型的通用表示（TYPE=\<any\>、`\#` 格式的 RDATA 十六进制编码），允许 DNS 软件在不更新代码的情况下处理新 RR 类型。**

### 关键点

- 未知类型用 `\# <length> <hex>` 表示 RDATA
- DNS 软件 MUST 能解析和转发未知类型，不得因未知类型拒绝消息

### 我们的实现

- miekg/dns 完整支持 RFC 3597 未知类型表示；ZJDNS 透传所有未知类型 ✓

---

## RFC 4025 — IPSECKEY Record  `[RFC 4025: Proposed Standard]`  ✅

**IPSECKEY RR（45）：存储 IPsec 网关信息与密钥材料。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 4033/4034/4035 — DNSSEC  `[RFC 4033: Proposed Standard | RFC 4034: Proposed Standard | RFC 4035: Proposed Standard]`  ✅ ✅ ✅

**DNS 安全扩展，通过数字签名保证 DNS 数据的完整性和真实性。**

### 信任链

```
DNSKEY (自签名) → DS (父域授权) → DNSKEY (子域) → RRSIG (签名验证)
```

### 关键要求

- **MUST**: RRSIG 有效期手动验证（`dnssec/crypto.go` — RFC 4034 §3.1.5）
- **MUST**: 信任锚从 DNSKEY RRset 加载，支持过期检测

### 我们的实现

- `server/resolver/dnssec/` 完整实现：签名验证、信任链、NSEC/NSEC3 否定回答
- `dnssec_chain.go`：逐级 DS/DNSKEY/RRSIG 验证
- `trust_anchor.go`：lazy-loaded 根信任锚（静态，未实现 RFC 5011 自动化）

---

## RFC 4255 — SSHFP Record  `[RFC 4255: Proposed Standard]`  ✅

**SSHFP RR（44）：SSH 主机密钥指纹，SSH 证书验证用。**

### 我们的实现

- miekg/dns 类型支持；zone 规则可配置 ✓

---

## RFC 4343 — DNS Case Insensitivity Clarification  `[RFC 4343: Proposed Standard]`  ✅

**澄清 DNS 名称大小写不敏感的确切语义：比较时 ASCII 字母的高零位（0x20 位）必须被忽略，但其他位精确匹配。**

### 关键要求

- **MUST**: 名称比较时清除 ASCII 字母的第 5 位（0x20），其他所有位精确匹配
- **MUST**: 响应中 QNAME 的大小写 MUST 原样回显（不能标准化），但比较时大小写不敏感
- 更新 RFC 1034/1035/2181

### 我们的实现

- Go `strings.EqualFold` + miekg/dns `dns.Equal()` 严格执行 DNS 大小写规则 ✓

---

## RFC 4408 — Sender Policy Framework (SPF)  `[RFC 4408: Experimental]`  ✅

**SPF RR（99）：邮件发件人授权验证（后被 RFC 7208 TXT 取代，类型不再推荐使用）。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 4509 — SHA-256 in DS RRs  `[RFC 4509: Proposed Standard]`  ✅

\*\*DNSSEC DS 摘要 MUST 支持 SHA-256（更新 RFC 4034）。\*\*

### 我们的实现

- `dnssec/crypto.go` 验证器支持 DS 摘要类型 2（SHA-256）✓

---

## RFC 4592 — The Role of Wildcards in the DNS  `[RFC 4592: Proposed Standard]`  ✅

**泛域名（`*.example.com`）语义的权威澄清：匹配规则、与显式数据的优先级、委托取消。**

### 关键点

- 泛域名不匹配自身（`*.example.com` 不匹配 `example.com`）
- 显式数据抑制泛域名；委托取消泛域名；ENT（空非终端）匹配泛域名
- CNAME 泛域名链的语义

### 我们的实现

- zone 规则支持 `*.` 通配符条目（`zone/zone.go`），`maxWildcardLabels` 批量查询；`restoreDomain` 处理通配符改写后的名字还原

---

## RFC 4701 — DHCID Record  `[RFC 4701: Proposed Standard]`  ✅

**DHCID RR（49）：DHCP 客户端身份标识，用于 FQDN 更新冲突检测。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 4892 — Requirements for a Mechanism Identifying a Name Server Instance  `[RFC 4892: Informational]`  ✅

**NSID 的需求文档（`id.server`/`hostname.bind` CHAOS 查询作为临时方案），RFC 5001 的动机。**

### 我们的实现

- CHAOS 类查询已放行（Validation 中间件允许 ClassCHAOS），内省支持在 handler 层 ✓

---

## RFC 5001 — DNS Name Server Identifier (NSID)  `[RFC 5001: Proposed Standard]`  ⚠️

**EDNS0 选项（OPTION-CODE 3）：响应中携带服务器实例标识，用于 anycast/负载均衡环境识别应答者。**

- 载荷为服务器自选的字节串（通常含主机名）
- 请求方在查询中带空 NSID 选项，响应方回填

### 我们的实现

- ⚠ 未实现。备选：`id.server` CHAOS 查询已有等价内省信息，NSID 可后补

---

## RFC 5011/9077 — Trust Anchor 自动化  `[RFC 5011: Proposed Standard | RFC 9077: Proposed Standard]`  ⚠️ ⚠️

**DNSSEC 信任锚的自动化管理（RFC 9077 更新 5011）。**

- ⚠ **已知差距**：§4 状态机（Add Hold-Down 30 天 + 事件驱动）是实现大功能。当前 `named.root` 静态加载已满足基本需求，REVOKE 位检查已实现

---

## RFC 5077 — TLS Session Resumption (Session Tickets)  `[RFC 5077: Proposed Standard]`  ✅

**通过 Session Ticket 恢复 TLS 会话，避免完整握手（减少 1 RTT）。**

### 关键常量

- Ticket 由服务端加密（仅服务端可解密）
- Ticket lifetime 建议 ≤ 24h

### 我们的实现

- `DefaultTLSSessionCacheSize = 128`
- `DefaultDTLSSessionCacheSize = 128`
- TLCP/DTLCP 各自独立的 session cache
- DNSCrypt PQ ticket 会话恢复（类似概念，独立实现）

---

## RFC 5155 — NSEC3（哈希认证的否定存在证明）  `[RFC 5155: Proposed Standard]`  ✅

**NSEC3 替代 NSEC 提供否定存在证明，同时防止区域枚举（zone walking）。**

### 关键常量

| 参数               | 值                                         | 说明                                     |
| ------------------ | ------------------------------------------ | ---------------------------------------- |
| NSEC3 RR TYPE      | **50**                                     | Hashed Authenticated Denial of Existence |
| NSEC3PARAM RR TYPE | **51**                                     | 区域顶端的参数信号                       |
| 哈希算法           | **1**（SHA-1）                             | 唯一标准算法                             |
| DNSKEY 算法别名    | **6**（DSA-NSEC3）、**7**（RSASHA1-NSEC3） | 表示区域使用 NSEC3                       |

### 迭代上限（§10.3）

| 密钥大小 | 最大迭代次数 |
| -------- | ------------ |
| 1024 位  | **150**      |
| 2048 位  | **500**      |
| 4096 位  | **2500**     |

### 哈希计算（§5）

```
IH(salt, x, 0) = H(x || salt)
IH(salt, x, k) = H(IH(salt, x, k-1) || salt), k > 0
Owner Name = Base32(IH(salt, canonical_name, iterations)).zone
```

### Opt-Out（§6）

- Opt-Out NSEC3 RR 不对其所覆盖的不安全委托做出存在/不存在的断言
- 设置 Opt-Out 后 AD 位 **MUST NOT** 设置（§9.2）

### 验证器算法（§8）

- **MUST**: 忽略未知哈希类型的 NSEC3（§8.1）
- **MUST**: 忽略 Flags 非 0/1 的 NSEC3（§8.2）
- 最近可证明包围体（Closest Encloser）证明需要至多 2 个 NSEC3 RR
- Name Error 需要至多 3 个 NSEC3（最近包围体证明 + 覆盖泛域名）
- No Data (DS)：若无匹配 NSEC3，需要最近可证明包围体证明（Opt-Out 位覆盖）

### 我们的实现

- `DefaultMaxNSEC3Iterations = 150`（对应 1024 位密钥）
- `dnssec/nsec.go`：NSEC3 验证逻辑

---

## RFC 5205 — HIP Record  `[RFC 5205: Experimental]`  ✅

**HIP RR（55）：Host Identity Protocol 的 DNS 扩展（HIT、RVS 服务器）。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 5702 — SHA-2 in DNSSEC  `[RFC 5702: Proposed Standard]`  ✅

**SHA-256/SHA-512 的 DNSSEC 支持：算法 8（RSASHA256）/10（RSASHA512）、DS 摘要 2（SHA-256）/4（SHA-384）。**

### 我们的实现

- `dnssec/crypto.go` 验证器支持 RSASHA256(8)/RSASHA512(10) + SHA-256 DS ✓

---

## RFC 5936 — Zone Transfer Protocol (AXFR)  `[RFC 5936: Proposed Standard]`  ⚪

**完整区域传输协议：序列化传输整个 zone（SOA 起始与结束）。**

### 我们的实现

- ⚪ 参考：AXFR 查询被拒绝（REFUSED）；加密传输变体见 RFC 9103 条目

---

## RFC 5966 — DNS Transport over TCP  `[RFC 5966: Historic (Obsoleted by RFC 7766)]`  ⚪

**TCP 传输要求（RFC 7766 的前身与基础）：所有实现 MUST 同时支持 UDP 与 TCP。**

- TCP 帧 = 2 字节长度前缀 + 消息
- 支持连接复用；解析器不应因 TCP 开销回避 TCP 重试
- 截断（TC）响应 MUST 触发 TCP 重试

### 我们的实现

- 已实现（与 RFC 7766 条目合并）：TCP 管线化连接池、TC → TCP 自动重试 ✓

---

## RFC 6052/6147 — DNS64  `[RFC 6052: Proposed Standard | RFC 6147: Proposed Standard]`  ✅ ✅

**IPv6-only 客户端访问 IPv4-only 服务器的 NAT64 过渡技术。**

### 关键常量

- Well-Known Prefix: **`64:ff9b::/96`**（RFC 6052 §2.1）

### 协议流程

```
客户端查询 AAAA → 无 AAAA 记录
  → 查询 A 记录（IPv4 地址）
  → 合成 AAAA = Prefix + IPv4
  → 返回合成 AAAA
```

### 我们的实现

- `config.DefaultDNS64Prefix = "64:ff9b::/96"` ✓
- `middleware/dns64.go`：AAAA 合成逻辑

---

## RFC 6125 — TLS 证书名验证  `[RFC 6125: Proposed Standard]`  ✅

**TLS 客户端如何验证服务端证书中的标识名（SAN/CN）。**

### 关键要求

- **MUST**: 验证 `subjectAltName` (SAN) dNSName
- **MUST NOT**: 仅依赖 CN（Common Name）
- 支持通配符：`*.example.com` 匹配 `foo.example.com`

### 我们的实现

- Go `crypto/tls` 库默认执行 RFC 6125 验证
- `ServerName` 字段设置 TLS SNI + 证书验证 ✓

---

## RFC 6604/6840/7344 — DNSSEC 补充  `[RFC 6604: Proposed Standard | RFC 6840: Proposed Standard | RFC 7344: Informational]`  ✅ ✅ ✅

**对 DNSSEC 的澄清和自动化更新。**

| RFC      | 关键点                      | 引用位置             |
| -------- | --------------------------- | -------------------- |
| RFC 6604 | NXDOMAIN 可包含 CNAME/DNAME | `nameserver.go:124`   |
| RFC 6840 | §4.1 祖先委托排除           | `dnssec/nsec.go:139`  |
| RFC 7344 | CDS/CDNSKEY 自动化信任锚    | `dnssec_chain.go`    |

---

## RFC 6605 — ECDSA P-256 for DNSSEC  `[RFC 6605: Proposed Standard]`  ✅

**算法 13（ECDSAP256SHA256）：DNSSEC 椭圆曲线签名（含 GOST 与 P-384 的讨论）。**

### 我们的实现

- 验证器支持 ECDSAP256SHA256(13) ✓（cloudflare 等主流 zone 默认算法）

---

## RFC 6672 — DNAME  `[RFC 6672: Proposed Standard]`  ✅

**将整个子树重定向到另一个域名的 DNS RR 类型（类似 CNAME 但对整个 zone）。**

### 协议行为

- `x.example.com DNAME y.example.net` → `x.example.com` 的查询被重写为 `x.example.net`
- DNAME 不重写 QNAME 本身，而是对查询名做后缀替换
- **MUST**: DNAME 只出现在应答的 authority section（不在 answer section）
- DNAME 与 CNAME 同时存在时，CNAME 优先

### 我们的实现

- `nameserver.go:91`：在 NXDOMAIN 响应中处理 `*dns.CNAME` 和 `*dns.DNAME` 记录 ✓

---

## RFC 6725 — DNSKEY Algorithm IANA Registry Updates  `[RFC 6725: Proposed Standard]`  ⚪

**DNSKEY 算法注册表状态整理（划分 MUST/MAY 支持等）。**

### 我们的实现

- ⚪ 参考：算法支持状态与验证器一致

---

## RFC 6742 — ILNP Records  `[RFC 6742: Experimental]`  ✅

**ILNP RR 家族（NID=104、L32=105、L64=106、LP=107）：Identifier-Locator Network Protocol 的 DNS 编码。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 6761 — 特殊域名  `[RFC 6761: Proposed Standard]`  ⚠️

**DNS 中具有特殊含义、不应全局解析的域名。**

### 关键域名

| 域名                  | 用途             |
| --------------------- | ---------------- |
| `localhost.`          | 回环地址         |
| `.local`              | mDNS 本地链路    |
| `.onion`              | Tor 隐藏服务     |
| `test.` / `invalid.`  | 测试 / 无效域名  |
| `10.in-addr.arpa.` 等 | 私有地址反向区域 |

### 我们的实现

- ⚠️ 部分满足：特殊域名按普通名字正常解析/缓存，但 RFC 6761 §6.3/§6.4 要求缓存解析器 SHOULD NOT 转发 localhost/test 查询（应本地应答）；ZJDNS 无 localhost 特判，直接转发上游（行为缺口，SHOULD 级）
- 不做本地拦截——本地过滤属于策略选择，可由 zone 规则实现

---

## RFC 6840 — DNSSEC 澄清与更新  `[RFC 6840: Proposed Standard]`  ✅

**对 RFC 4033–4035 和 5155 的关键澄清，提升 MUST/SHOULD 级别。**

### 算法要求（§2）

- 验证器 **MUST** 支持 NSEC + NSEC3（若支持算法 6/7）
- 验证器 **MUST** 支持 RSASHA256（8）+ RSASHA512（10）+ SHA-256 DS（2）

### BAD Cache（§3.1）

- 从 RFC 4035 的 MAY 提升为 **SHOULD**（安全感知解析器应实现 BAD cache）

### 祖先委托 NSEC/NSEC3（§4.1）

- 祖先域的 NSEC/NSEC3（NS=1、SOA=0、签名者短于 Owner Name）**MUST NOT** 用于证明子域不存在

### CNAME 位检查（§4.3）

- 验证 NOERROR/NODATA 时 **MUST** 检查匹配 NSEC/NSEC3 的 CNAME 位
- 未检查将被攻击者剥离 CNAME 伪装成 NODATA

### 不安全委托证明（§4.4）

- **MUST** 验证 NSEC/NSEC3 的 NS 位存在，或被 Opt-Out NSEC3 覆盖

### CD/AD 位（§5.8–5.9）

- 上游查询 **SHOULD** 每个都设置 **CD 位**（无论传入 CD 位）
- 仅在请求含 **DO 或 AD 位**时设置 AD 位

### 多 RRSIG（§5.4）

- **SHOULD** 接受任意一个有效 RRSIG；仅在所有 RRSIG 都失败时 Bogus

### 我们的实现

- 祖先委托限制：`dnssec/nsec.go` 检查 NS/SOA 位
- CNAME 位检查：验证逻辑中包含

---

## RFC 6844 / 8659 — Certification Authority Authorization (CAA)  `[RFC 6844: Proposed Standard | RFC 8659: Proposed Standard]`  ✅ ✅

**CAA RR（257）：域名所有者声明允许的 CA 列表，控制证书签发。**

### 关键点

- RDATA: `flags` + `tag`（issue/issuewild/iodef）+ `value`
- 签发方 MUST 检查 CAA；递归解析器在应答中透传即可

### 我们的实现

- miekg/dns 支持 CAA 类型；zone 规则可配置 CAA 记录 ✓

---

## RFC 6891 — EDNS(0)  `[RFC 6891: Proposed Standard]`  ✅

**DNS 的扩展机制，支持更大的 UDP 负载、额外的 OPT 选项。**

### 关键常量

- UDP 最小负载: **512** 字节（向后兼容）
- 推荐 UDP 最大: **4096** 字节（适合 DNSSEC 签名响应）
- DNS Flag Day 2020 推荐: **1232** 字节（避免 IPv6 分片）

### 协议要求

- **MUST**: 不支持 EDNS 版本的响应 → BADVERS（RFC 6891 §6.1.3）
- **MUST**: 响应方 UDPSize 反映自身最大负载能力
- 发送方 UDPSize 过大导致响应被截断时，应回退到较小值

### 我们的实现

- 标准查询: `pool.UDPBufferSize = 1232`
- 递归查询: `pool.RecursiveUDPBufferSize = 4096`（DNSSEC 链需要更大空间）
- `edns/edns.go:ApplyToMessage()` 在响应中设置 UDPSize

---

## RFC 6944 — DNSSEC DNSKEY Algorithm Status  `[RFC 6944: Proposed Standard]`  ⚪

**算法状态（撤销/废弃/可选）：RSAMD5、RSASHA1、DSA 等的 MUST/MAY 清单。**

### 我们的实现

- ⚪ 参考：验证器按 4035/6840 要求支持主流算法

---

## RFC 6975 — Algorithm Understanding in DNSSEC  `[RFC 6975: Proposed Standard]`  ✅

**EDNS0 选项 DAU（5）/DHU（6）/N3U（7）：解析器向权威宣告支持的签名/摘要/NSEC3 哈希算法。**

### 我们的实现

- ✓ 上游查询携带 DAU={8,10,13,14,15}（ED448 刻意排除——验证器无 ED448 支持）、DHU={1,2,4}、N3U={1}（`edns/edns.go:ApplyToMessage`，仅请求方向）

---

## RFC 7043 — EUI48/EUI64 Records  `[RFC 7043: Informational]`  ✅

**EUI48（108）/EUI64（109）RR：IEEE EUI 标识符（MAC 地址）的 DNS 发布。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 7314 — EDNS EXPIRE Option  `[RFC 7314: Experimental]`  ⚪

**EDNS0 选项（OPTION-CODE 9）：辅助服务器通告其 SOA EXPIRE 状态，主服务器可据此调整通知策略。**

### 我们的实现

- ⚪ 参考：辅助/传输场景，ZJDNS 非权威

---

## RFC 7477 — Child-to-Parent Synchronization (CSYNC)  `[RFC 7477: Proposed Standard]`  ⚪

**CSYNC RR（62）：子区向父区宣告应同步的记录（NS/DS 等），父区代理据此更新。**

### 我们的实现

- ⚪ 参考：父区管理场景；miekg/dns 类型支持

---

## RFC 7553 — URI Record  `[RFC 7553: Informational]`  ✅

**URI RR（256）：URI 元数据发布（带优先级/权重）。**

### 我们的实现

- miekg/dns 类型支持 ✓

---

## RFC 7719 / 8499 — DNS Terminology  `[RFC 7719: Informational (Obsoleted by RFC 8499) | RFC 8499: Best Current Practice (BCP 219)]`  ✅ ✅

**DNS 术语标准参考（8499 更新 7719）。** ✓

---

## RFC 7766 — DNS over TCP  `[RFC 7766: Proposed Standard]`  ✅

**DNS TCP 传输的实现要求，更新 RFC 1035。**

### 关键要求

- **MUST**: 支持 TCP 查询管线化（不等响应即可发送后续查询）
- **RECOMMENDED**: 支持并行准备响应并乱序发送（客户端 **MUST** 能处理乱序响应，用 Message ID 匹配）
- **MUST NOT**: 客户端不得复用同一 TCP 连接上正在进行的查询的 DNS Message ID
- 服务端空闲超时 **RECOMMENDED** 在秒级（RFC 不指定具体值，建议至少几秒）
- 连接复用优于每条查询新建连接

### 协议流程

```
Client → [2字节长度][DNS消息] → Server
Client → [2字节长度][DNS消息] → Server  (管线化，不等响应)
Client ← [2字节长度][DNS响应] ← Server  (按序)
```

### 我们的实现

- ConnPool 管线化连接池：`server/upstream/pool/tcp.go`
- `DefaultTCPPoolIdleTimeout = 60s`（客户端侧，减少重连）

---

## RFC 7828 — EDNS TCP Keepalive  `[RFC 7828: Proposed Standard]`  ✅

**EDNS0 选项，协商 TCP/DoT 连接的保活超时。**

### 关键常量

- 超时单位: **100ms**（值 × 100ms = 实际超时）
- 仅在 TCP 服务端响应中添加

### 我们的实现

- ⚠️ `edns/edns.go:ApplyToMessage()` 支持 tcpKeepaliveTimeout 参数，但 `qctx.TCPKeepalive` 从未被赋值——实际从不发出该选项

---

## RFC 7858 — DNS over TLS (DoT)  `[RFC 7858: Proposed Standard]`  ✅

**通过 TLS 加密传输 DNS 查询，防止窃听和篡改。**

### 关键常量

- 端口: **853**
- ALPN: **`"dot"`**
- 消息帧: 2 字节长度前缀（同 TCP）

### 协议流程

```
Client → TLS 握手 (ALPN="dot") → Server
Client ⇄ [2字节长度][DNS消息] ⇄ Server  (TLS 加密通道内)
连接关闭 → TLS close_notify
```

### 我们的实现

- `DefaultTLSPort = "853"`
- 服务端：`server/protocol/tls/tls.go`
- 客户端：`server/upstream/tls/tls.go`（管线化连接池）

---

## RFC 7871 — EDNS Client Subnet (ECS)  `[RFC 7871: Informational]`  ✅

**允许递归解析器向权威服务器传递客户端子网信息（用于 CDN 定位）。**

### 关键常量

| 参数          | RFC 推荐        | 我们的值 |
| ------------- | --------------- | -------- |
| IPv4 前缀长度 | **/24**         | `/24` ✓  |
| IPv6 前缀长度 | **/56**         | `/56` ✓  |
| SCOPE 默认    | **0**（不可用） | `0` ✓    |

### 关键要求

- **MUST**: ECS 选项仅用于递归→权威方向（不发送给客户端）
- **SHOULD**: IPv6 使用 /56（允许站点内子网聚合）
- SCOPE=0 表示"响应未应用 ECS"

### 我们的实现

- `edns/ecs.go`: `DefaultECSv4Len=24`, `DefaultECSv6Len=56`, `DefaultECSScope=0`
- ECS 选项格式: FAMILY(2) + SOURCE PREFIX-LENGTH(1) + SCOPE PREFIX-LENGTH(1) + ADDRESS(变长)
- 缓存按 ECS 地址最长前缀匹配分桶；Additional/Authority Section 记录不绑定网络
- Birthday Attack 缓解：响应 ECS 必须回显查询的 FAMILY/ADDRESS/SOURCE PREFIX（`VerifyECSResponse`，不匹配 → SERVFAIL，防投毒）
- ⚠️ REFUSED 时去除 ECS 重试：**未实现**（RFC 7871 建议项，暂无部署需求）

---

## RFC 7873/9018 — DNS Cookies  `[RFC 7873: Proposed Standard | RFC 9018: Proposed Standard]`  ✅ ✅

**轻量级无状态 DNS 事务认证机制，防止放大攻击和缓存投毒。**

### 关键常量（RFC 9018）

| 参数            | 值            | 说明                    |
| --------------- | ------------- | ----------------------- |
| Client Cookie   | **8** 字节    | 客户端生成（随机数）    |
| Server Cookie   | **8–32** 字节 | 服务端 SipHash-2-4 生成 |
| Secret 轮换间隔 | **30 分钟**   | 定期更换防止长期泄露    |
| Cookie 有效期   | **1 小时**    | 超过后客户端需更新      |
| 续期阈值        | **30 分钟**   | 提前提示客户端续期      |
| 未来容忍        | **5 分钟**    | 容忍时钟偏差            |

### 协议流程（RFC 9018 §4.3）

```
客户端首次查询 → Client Cookie (8B 随机)
服务端 → BADCOOKIE + 有效 Server Cookie
客户端后续查询 → Client Cookie + Server Cookie
服务端验证 → CookieValid / CookieValidRenew / CookieExpired / CookieFuture
```

### 序列号运算（RFC 1982）

- 使用 32 位序列号空间
- 比较：在 2^31 窗口内判定先后
- 减法：模运算避免溢出

### 我们的实现

- `edns/cookie.go`: `compare1982()`, `subtract1982()` 实现序列号运算 ✓
- `DefaultCookieSecretRotationInterval = 24h`（RFC 7873 §7.1 默认 1 天）✓
- Cookie 生命周期常量：1h/30min/5min（硬编码，匹配 RFC 9018 §4.3）✓
- `buildBadCookieResponse()`：使用 `RcodeBadCookie(23)` ✓
- ✓ `rfc9018MAC()`：IPv4 使用 4 字节，IPv6 使用 16 字节（RFC 9018 §4.4 防替换攻击）
- ✓ Reserved bytes：接收值包含在 hash 计算中（生成时为零，验证时用接收值）

---

## RFC 7958 — DNSSEC Trust Anchor Publication  `[RFC 7958: Informational]`  ✅

**根信任锚（root-anchors.xml）的发布格式与获取方式（ICANN 发布、RFC 8145 信任锚传送）。**

### 我们的实现

- 根信任锚静态加载（`named.root`/`root-anchors.xml`）✓；RFC 5011 自动化未实现（见 5011/9077 条目）

---

## RFC 8080 — EdDSA for DNSSEC  `[RFC 8080: Proposed Standard]`  ✅

**算法 15（ED25519）/16（ED448）：EdDSA 签名，DNSSEC 的最优现代算法。**

### 我们的实现

- 验证器支持 ED25519(15)/ED448(16) ✓

---

## RFC 8094 — DNS over DTLS  `[RFC 8094: Experimental]`  ✅

**通过 DTLS（UDP 上的 TLS）加密传输 DNS。**

### 关键常量

- 端口: **853**
- 空闲超时: 建议 **几秒到几十秒**（无硬性值）
- 消息帧: **DTLS 记录本身提供分帧**，无需额外长度前缀

### 关键要求

- **MUST**: 空闲超时后发送 DTLS fatal alert 并销毁 DTLS 状态
- DTLS 1.2+ 必须支持
- DTLS 记录层已提供数据报边界，不需要内层长度前缀
- 响应过大（>PMTU）：服务器 **MUST** 设置 TC 位并返回截断响应
- **客户端识别到 DTLS 超时/失败后应回退到 DoT**（§5）：大响应超过 PMTU 时服务器设 TC，客户端在 Strict 模式下 MUST 回退到 DoT

### 协议流程

```
Client → DTLS 握手 (UDP) → Server
Client ⇄ DTLS 记录 [DNS消息] ⇄ Server  (UDP 数据报)
空闲超时 → Server 发送 fatal alert → 关闭
```

### 我们的实现

- 端口 **8853**（非标准，避免与 DoT 853 冲突）
- `DefaultDTLSIdleTimeout = 30s`
- ✓ 空闲超时正确处理：timeout → return（关闭连接，发送 fatal alert）
- ✓ DTLS 失败时自动 fallback 到 DoT（RFC 8094 §3.3 PMTU 场景）

---

## RFC 8198 — Aggressive NSEC Caching  `[RFC 8198: Proposed Standard]`  ⚠️

**利用缓存的 NSEC/NSEC3 范围推导否定回答。**

- ⚠ **已知差距**：miekg/dns 提供 NSEC/NSEC3 数据但不提供覆盖判断。需自行实现范围比较 + RRSIG 附带 + 通配符处理。之前尝试过但边界条件问题多，暂不实现

---

## RFC 8310 — DoT/DTLS Privacy Profiles  `[RFC 8310: Proposed Standard]`  ✅

**定义了 Strict 和 Opportunistic 两种隐私配置模式。**

### 两种 Profile

| 要求       | Strict                | Opportunistic      |
| ---------- | --------------------- | ------------------ |
| 加密       | MUST                  | SHOULD             |
| 证书验证   | MUST (SPKI pin 或 CA) | MAY                |
| 回退到明文 | MUST NOT              | 允许（加密失败后） |
| 认证域名   | MUST                  | MAY                |

### 关键要求

- **MUST**: 实现 Raw Public Keys (RFC 7250)
- **SHOULD**: 实现 TLS False Start (RFC 7918)
- **SHOULD**: 实现 Cached Info Extension (RFC 7924)
- **MUST**: TLS 1.2+，禁用压缩，支持会话复用

### 我们的实现

- ✓ `PrivacyProfile` 配置字段：`"strict"`（默认，PKIX 验证）和 `"opportunistic"`（允许 `SkipTLSVerify`）
- ✓ 默认为 Strict Privacy（RFC 8310 §6）：TLS + PKIX 证书验证
- TLS 1.3 服务端 / TLS 1.2+ 客户端 ✓
- 会话缓存已实现 ✓

---

## RFC 8427 — Representing DNS Messages in JSON  `[RFC 8427: Informational]`  ⚪

**DNS 消息（或其组成部分）的通用 JSON 表示格式，用于数据交换（查询日志、被动 DNS、消息组装）。**

### 关键成员（均可选，profile 可自定义必需项）

- 消息级: `ID`、`QR`、`Opcode`、`AA/TC/RD/RA/AD/CD`、`RCODE`、`QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT`（整数）、`QNAME/QTYPE/QCLASS`、`QTYPEname/QCLASSname`、`questionRRs/answerRRs/authorityRRs/additionalRRs`（数组）
- 记录级: `NAME`、`TYPE`、`CLASS`、`TTL`、`RDLENGTH`、`RDATAHEX`（base16）、`rrSet`（列表）、`compressedNAME`（isCompressed/length）
- 常用 RDATA 具名成员: `rdataA`、`rdataAAAA`、`rdataCNAME/DNAME/NS/PTR`、`rdataTXT`，及 `rdataCDNSKEY/rdataDNSKEY/rdataMX/rdataNSEC/rdataNSEC3/rdataRRSIG/rdataSRV/rdataTLSA` 等（RFC 显示格式的字符串）
- 原始字节: `messageOctetsHEX/headerOctetsHEX/questionOctetsHEX/answerOctetsHEX/authorityOctetsHEX/additionalOctetsHEX`、`rrOctetsHEX`
- 附加: `dateString`（RFC 3339）、`dateSeconds`（可小数）、`comment`
- 查询-响应配对: `{"queryMessage": {...}, "responseMessage": {...}}`
- 流式: JSON Text Sequences（RFC 7464）

### 关键要求

- 名称限制在 U+0000–U+007F；`HEX` 后缀成员用大写 base16；名称一律非压缩表示
- 同一数据允许多种成员重复表示（可能不一致——读者不得假设一致性）
- 明确允许描述畸形消息（用于攻击日志分析）
- Media Type: `application/dns+json`

### 我们的实现

- ⚪ **参考级**：纯数据交换格式，无协议交互，ZJDNS 无明确的集成面（Google 的 `/json` DoH 格式非此标准）。miekg/dns 已提供 `dns.MarshalJSON/UnmarshalJSON` + `dnsjson` 子包，需要时可调用

---

## RFC 8446 — TLS 1.3  `[RFC 8446: Proposed Standard]`  ✅

**TLS 协议的当前版本，废弃不安全的旧算法，强制前向安全性。**

### 关键要点

- 移除 RSA 密钥交换、RC4、3DES、CBC 模式
- 仅保留 AEAD 密码套件（AES-GCM、Chacha20-Poly1305）
- 0-RTT 握手（通过 `pre_shared_key` 扩展）
- 强制 Perfect Forward Secrecy

### 我们的实现

- 服务端：`MinVersion = eTLS.VersionTLS13` ✓
- 客户端：`MinVersion = eTLS.VersionTLS12`（允许 TLS 1.2 兼容）

---

## RFC 8467/7830 — EDNS Padding  `[RFC 8467: Experimental | RFC 7830: Proposed Standard]`  ✅ ✅

**DNS 响应的填充策略，防止流量分析推断查询内容。**

### 关键常量

| 参数       | 值                | 说明                  |
| ---------- | ----------------- | --------------------- |
| 请求块大小 | **128**           | 查询填充到 128 的倍数 |
| 响应块大小 | **468**           | 响应填充到 468 的倍数 |
| 客户端退出 | `+nopadding` 标记 | 通过 OPT 选项禁用填充 |

### 我们的实现

- `DefaultPaddingRequestBlockSize = 128` ✓
- `DefaultPaddingResponseBlockSize = 468` ✓
- `edns/padding.go:HasPaddingOption()` 检测客户端退出请求 ✓

---

## RFC 8482 — Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY  `[RFC 8482: Proposed Standard]`  ✅

**对 ANY 查询返回最小化响应（空 ANSWER + HINFO 或最小记录），避免 ANY 被滥用放大。**

### 关键要求

- 权威对 ANY 查询：可以返回最小响应（HINFO）替代完整区域数据
- 解析器不必转发 ANY（RFC 8482 建议权威直接响应）

### 我们的实现

- ✓ ANY 查询由 Any 中间件（`middleware/any.go`，位于 Zone 之后）应答 `HINFO "RFC8482" ""`（TTL 3600）；zone 规则优先
- ✓ NXNAME(128) 查询在 Validation 中间件拒绝（FORMERR + EDE 30，RFC 9824 §3.5 MUST），不转发

---

## RFC 8484 — DNS over HTTPS (DoH)  `[RFC 8484: Proposed Standard]`  ✅

**通过 HTTPS 传输 DNS 查询。**

### 关键常量

- 端口: **443**
- Content-Type: **`application/dns-message`**
- 路径: **`/dns-query`**（推荐但非强制）
- 方法: **POST** + GET（服务端 **MUST** 两者都实现；GET 使用 Base64url 无填充编码）
- DoH 使用 **UDP 线格式**（无 2 字节长度前缀），与 DoT 的 TCP 线格式不同
- **MUST**: DoH 服务器忽略 DNS 请求中的 EDNS UDP 负载大小
- 最大消息: **65535** 字节（RFC 8484 §6）

### 协议流程

```
POST /dns-query HTTP/2
Content-Type: application/dns-message
Accept: application/dns-message
Body: [DNS 线格式消息]

→ 200 OK
Content-Type: application/dns-message
Body: [DNS 线格式消息]
```

### 我们的实现

- `DefaultHTTPSPort = "443"`，`DefaultHTTP3Port = "443"`
- `DefaultQueryPath = "/dns-query"`
- `DefaultDOHMaxRequestSize = 8192`
- 服务端：`server/protocol/tls/https.go`（HTTP/2+HTTP/3）
- 客户端：`server/upstream/tls/https.go`（连接池 + 会话复用）

---

## RFC 8499 — DNS Terminology  `[RFC 8499: Best Current Practice (BCP 219)]`  ✅

**DNS 标准术语参考。** ✓

---

## RFC 8767 — Serving Stale Data  `[RFC 8767: Proposed Standard]`  ✅

**通过提供过期缓存数据来提高 DNS 可用性（当权威服务器不可达时）。**

### 关键常量

- TTL 上限（入站记录）: **SHOULD ≤ 604,800 秒（7 天）** — §4
- Stale 保留期: 建议 **1–3 天** — §6
- 客户端等待超时: **SHOULD 短于查询超时** — §5.2

### 协议流程

```
查询到达 → 缓存命中（已过期）
  → 后台刷新（异步查询权威）
  → 立即返回过期数据（stale-while-revalidate）
  → 刷新成功 → 更新缓存
  → 刷新失败 → 保留过期数据直到超过 stale 保留期
```

### 我们的实现

- `DefaultStaleMaxAge = 3 * 86400`（3 天，匹配 RFC 8767 §6 建议 1–3 天）
- `DefaultServeExpiredClientTimeout = 600ms`
- ✓ 入站记录 TTL 上限 `DefaultMaxCacheableTTL = 7 * 86400`（`minTTL()` 中 clamp）

---

## RFC 8777 — AMTRELAY Record  `[RFC 8777: Proposed Standard]`  ✅

**AMTRELAY RR（260）：AMT（Automatic Multicast Tunneling）中继发现，更新 RFC 7450。反向 IP zone 发布。**

### 我们的实现

- miekg/dns 类型声明（未实现 pack/unpack）；ZJDNS 仅透传 ✓

---

## RFC 8914 — Extended DNS Errors (EDE)  `[RFC 8914: Proposed Standard]`  ✅

**在 DNS 响应中携带额外的错误信息（如 DNSSEC 验证失败原因）。**

### 关键 EDE 码（OPTION-CODE=15，INFO-CODE 为 16 位）

| 码  | 含义                         | 使用                           |
| --- | ---------------------------- | ------------------------------ |
| 0   | Other                        | 通用                           |
| 1   | Unsupported DNSKEY Algorithm | 不支持的 DNSSEC 算法           |
| 3   | Stale Answer                 | stale-while-revalidate         |
| 6   | DNSSEC Bogus                 | 签名验证失败                   |
| 7   | Signature Expired            | RRSIG 过期                     |
| 9   | DNSKEY Missing               | 缺少密钥                       |
| 15  | Blocked                      | 被策略阻止                     |
| 17  | Filtered                     | 被过滤                         |
| 18  | Prohibited                   | 被禁止（如未授权 XFR）         |
| 20  | Not Authoritative            | 非权威回答                     |
| 21  | Not Supported                | 不支持（如 XoT 上非 XFR 查询） |
| 22  | No Reachable Authority       | 权威不可达                     |
| 23  | Network Error                | 网络错误                       |
| 24  | Invalid Data                 | 无效数据                       |

### 协议要求

- **MUST NOT**: EDE 不能改变 RCODE 的处理逻辑
- 空间紧张时 **SHOULD** 先丢弃 EDE 选项再丢弃其他数据
- EDE 是未认证的诊断信息，不能仅依赖 EDE 做安全决策

### 我们的实现

- `handler/response.go`：透传 EDE 到客户端
- `middleware/cache_lookup.go`：stale 响应附加 EDE 3

---

## RFC 8976 — Message Digest for DNS Zones (ZONEMD)  `[RFC 8976: Proposed Standard]`  ✅

**ZONEMD RR（63）：区域数据静态摘要（SHA-384 等），防区域数据篡改（配合 DNSSEC 或独立）。**

### 关键点

- RDATA: serial、scheme、hash algorithm、digest
- 验证器/辅助服务器可校验区域传输完整性

### 我们的实现

- miekg/dns 类型支持；解析器不校验（权威/辅助侧特性）✓

---

## RFC 9000 — QUIC  `[RFC 9000: Proposed Standard]`  ✅

**UDP 上的多路复用安全传输协议（QUIC v1）。**

### 关键常量

- 空闲超时: **30s**（默认）
- Keep-Alive: **20s**（防中间盒超时）
- 地址验证 Token 缓存: 128 条目（LRU）

### 我们的实现

- `DefaultQUICServerIdleTimeout = 30s` ✓
- `DefaultQUICClientIdleTimeout = 60s`
- `DefaultQUICKeepAlive = 20s` ✓
- `DefaultQUICAddrCacheTTL = 30min`
- 地址验证器：`server/protocol/tls/addr_validator.go` — LRU cache, 128 entries ✓

---

## RFC 9443 — Multiplexing Scheme Updates for QUIC  `[RFC 9443: Proposed Standard]`  ✅

**QUIC 与其他 UDP 协议共享接收 socket 的首字节分路规则（更新 RFC 7983/5764）。**

- 首字节范围：0-3 STUN、20-63 DTLS、64-127 TURN/QUIC（源端口消歧）、128-191 RTP、192-255 QUIC
- 与 QUIC v2（RFC 9369）兼容；不得发送 `grease_quic_bit`（RFC 9287）
- 引用：`internal/dnscryptcrypto/pq.go` — DNSCrypt PQ client-magic 避开 QUIC 首字节范围（RFC 9443 §2）

---

## RFC 9103 — DNS Zone Transfer over TLS (XoT)  `[RFC 9103: Proposed Standard]`  ⚪

**通过 TLS 加密 AXFR/IXFR 区域传输，更新 RFC 1995/5936/7766。**

### 关键常量

- 端口: **853**（同 DoT）
- ALPN: **`"dot"`**

### 关键要求

- **MUST**: 仅使用 **TLS 1.3+**
- **MUST**: ALPN `"dot"` 在 TLS 握手中
- **MUST**: 客户端通过 Strict Privacy + ADN 认证服务器
- **MUST**: 服务端验证客户端（mTLS 或 IP ACL + TSIG/SIG(0)）
- **MUST**: 单连接支持多个并发 IXFR/AXFR
- **MUST**: 最后一个 AXoT 响应的 SOA 与第一个相同
- **MUST**: Secondary 容忍填充过的 AXoT 响应（包括"空"填充）
- **MUST**: 整个传输组 XoT 策略一致
- **SHOULD**: XoT 连接上对非 XFR 流量返回 REFUSED + EDE 21
- **SHOULD**: 使用 edns-tcp-keepalive 维持持久连接

### 我们的实现

- XoT 是 zone transfer 加密机制，非通用 DoT 运维指南
- ZJDNS 不实现 zone transfer（不是权威服务器），此 RFC 仅供参考

---

## RFC 9114 — HTTP/3  `[RFC 9114: Proposed Standard]`  ✅

**QUIC 上的 HTTP 协议，DoH3 的基础传输层。**

### 关键点

- HTTP/3 使用 QUIC 流替代 TCP 连接
- DoH3：`POST /dns-query` + `application/dns-message`

### 我们的实现

- `server/protocol/tls/http3.go`：quic-go/http3 实现 ✓

---

## RFC 9156 — QNAME Minimisation  `[RFC 9156: Proposed Standard]`  ✅

**通过逐步暴露查询名的最小标签数来增强 DNS 隐私。**

### 关键常量

- 最大迭代数 `MAX_MINIMISE_COUNT`: 推荐 **10**
- 逐一标签阶段 `MINIMISE_ONE_LAB`: 推荐 **4**

### 算法（§2.3）

```
第 1–4 次迭代: 每次多加 1 个标签（逐一暴露）
第 5–10 次迭代: 按比例分配剩余标签
  perStep = labelsLeft / remainingSteps
  remainder = labelsLeft % remainingSteps
  最后 remainder 次迭代各多加 1 个标签
超过 10 次: 暴露全部剩余标签
```

### 我们的实现

- `DefaultQnameMinimiseCount = 10`，`DefaultMinimiseOneLabel = 4` ✓
- `qname_minimise.go:labelsToAdd()` 精确实现比例分配算法 ✓

---

## RFC 9250 — DNS over QUIC (DoQ)  `[RFC 9250: Proposed Standard]`  ✅

**通过 QUIC 传输 DNS，利用 QUIC 的 0-RTT 和多路复用能力。**

### 关键常量

- 端口: **853**
- ALPN: **`"doq"`**
- 流映射: **每个查询一个双向流**

### 关键要求

- **MUST**: DNS Message ID 设为 **0**
- **MUST**: 发送 STREAM FIN 标记查询结束
- **MUST NOT**: 在 DoQ 连接上发送 edns-tcp-keepalive (RFC 7828)
- **MUST**: 每流一个查询（多查询 → `DOQ_PROTOCOL_ERROR`）
- **MUST**: 非零 Message ID → `DOQ_PROTOCOL_ERROR`

### 协议流程

```
Client → QUIC 握手 (ALPN="doq") → Server
Client → STREAM[0]: [2字节长度][DNS消息(ID=0)] → FIN → Server
Client ← STREAM[0]: [2字节长度][DNS响应(ID=0)] ← Server
```

### 我们的实现

- `DefaultQUICPort = "853"`，ALPN `"doq"` ✓
- 客户端：`server/upstream/tls/quic.go` — 正确设置 `msg.ID = 0`
- ✓ 服务端验证 Message ID = 0（非零 → `DOQ_PROTOCOL_ERROR`）
- ✓ 全部 7 个 DoQ 错误码已定义（`QUICCode*`）

---

## RFC 9460 — Service Binding and Parameter Specification (SVCB and HTTPS)  `[RFC 9460: Proposed Standard]`  ✅

**SVCB（64）/HTTPS（65）RR：服务绑定 + 参数（alpn、port、ech、dohpath…），替代 SRV 的更优方案。**

### 关键点

- `Priority`（0 = alias mode）、`TargetName`、`SvcParams`（key=value 列表）
- AliasMode 与 ServiceMode 的解析规则；HTTPS = SVCB 的子集语义
- DoH/DoT 端点发现（9461/9462）、ECH 配置传递

### 我们的实现

- 上游查询/zone 规则可配置 SVCB/HTTPS 记录（miekg/dns 类型）；DDR 场景使用 `dohpath` 等参数 ✓

---

## RFC 9461 — Service Binding Mapping for DNS Servers (SVCB for DNS)  `[RFC 9461: Proposed Standard]`  ✅

**SVCB/HTTPS 记录在 DNS 服务器发现上的映射：如何用 SVCB 参数描述 DoH/DoT/DoQ 端点。**

- 定义 `alpn`、`port`、`dohpath` 等参数在 DNS 服务场景的语义（与 9462 DDR 配合）
- DoQ 的 `alpn="doq"`、DoT 的 `alpn="dot"`

### 我们的实现

- 与 9462 一并支持（DDR 的 SVCB 应答）✓

---

## RFC 9462 — Discovery of Designated Resolvers (DDR)  `[RFC 9462: Proposed Standard]`  ✅

**客户端通过 `_dns.resolver.arpa` 的 SVCB/HTTPS 记录发现加密 DNS 解析器（DoH/DoT/DoQ）。**

### 关键点

- QNAME: `_dns.resolver.arpa`（Special-Use，不递归解析）
- SVCB 参数: `alpn`、`port`、`dohpath`、`ech`；服务端应答须 AA=1 且不转发
- 加密传输必须验证（TLS 证书/ECH），防降级攻击
- 定义 `resolver.arpa` 作为解析器信息查询点（与 RFC 9606 RESINFO 配合）

### 我们的实现

- 已实现（`config/ddr.go`）：DoH/DoT 端点经 SVCB 公布；9606 RESINFO 计划在其上延伸

---

## RFC 9567 — DNS Error Reporting  `[RFC 9567: Proposed Standard]`  ⚠️

**通过 EDNS0 Report-Channel 选项（OPTION-CODE 0x12）+ 构造的 QNAME，把验证失败/错误上报给权威运营者。**

### 协议流程

```
权威响应 → 携带 EDNS0 Report-Channel 选项（agent domain，非请求触发）
验证失败 → 解析器构造报告查询:
  QNAME = "_er.<QTYPE>.<失败QNAME>.<EDE码>._er.<agent-domain>"
  QTYPE = TXT
监控 agent 收到 → 解析出 (zone, qtype, qname, EDE 码) → 通知运营者修复
```

- agent domain 为空/根时权威 MUST NOT 携带该选项
- 报告查询可被缓存（同一问题每 TTL 一条报告）
- RDATA 内容无规范（无指导）

### 我们的实现

- ⚠ **未实现**。ZJDNS 作为验证型递归解析器可选实现上报端（DNSSEC 验证失败 → 发送报告查询）；需要权威配合才有实际价值。miekg/dns 提供 `REPORTING` 选项（`CodeREPORTING=0x12`）

---

## RFC 9606 — DNS Resolver Information (RESINFO)  `[RFC 9606: Proposed Standard]`  ✅

**新 RR 类型 RESINFO（261），让 DNS 客户端查询递归解析器的能力信息（隐私/过滤/透明策略），用于解析器选择。**

### 检索方式

- QNAME = 认证域名（ADN, DDR/DNR 发现）或 Special-Use 名 **`resolver.arpa`**（RFC 9462）
- 客户端 **MUST** 设 RD=0；响应 AA=1 才可接受（解析器本地应答，**不递归**）
- RRset 必须恰好一条记录；无效记录客户端静默忽略
- 解析器家族（anycast/共享 ADN）应暴露一致的 RESINFO

### 格式与键（IANA 注册，未知键忽略；`temp-` 前缀供本地用）

| 键 | 含义 |
|----|------|
| `qnamemin` | 支持 QNAME 最小化（RFC 9156）；无 `=` 时为布尔属性 |
| `exterr` | 可返回的 EDE 码列表：单个、`-` 区间、`,` 分隔 |
| `infourl` | https 诊断信息 URL（仅 text/html，IT 人员用） |

示例: `resolver.example.net. 7200 IN RESINFO qnamemin exterr=15-17 infourl=https://resolver.example.com/guide`

### 我们的实现

- ✓ `config/resinfo.go`：随 DDR 一起发布（`ddr.infourl` 可选）——DDR 开启时注入 `resolver.arpa`（+ DDR 域名）的 RESINFO zone 规则，本地应答
- 键: `qnamemin`（✓ 9156 已实现）、`exterr=3,6,7,9,15,16,17,18,21,22,23,24,30`、可选 `infourl`（`ddr.infourl` 配置）

---

## RFC 9660 — DNS Zone Version (ZONEVERSION)  `[RFC 9660: Proposed Standard]`  ⚪

**EDNS0 选项（OPTION-CODE 0x13）：权威服务器在响应中原子性地携带区域版本（SOA SERIAL），类似 NSID 的诊断用途。**

### 格式

- 载荷: `Labels(1) + Type(1) + Version(变长)`；Type 0 = SOA-SERIAL（唯一定义类型），Version 为 4 字节大端序列号
- 用于 anycast/多后端区域诊断：版本与答案原子返回

### 我们的实现

- ⚪ 仅供参考（权威侧特性）。ZJDNS 非权威服务器，无 SOA 序列号可报。miekg/dns 提供 `ZONEVERSION` 选项（`CodeZONEVERSION=0x13`）

---

## RFC 9715 — IP Fragmentation Avoidance in DNS over UDP  `[RFC 9715: Informational]`  ✅

**避免 DNS/UDP 报文 IP 分片的推荐做法（Informational，原拟 BCP）。**

### 关键要求

- **R1**: UDP 响应方不应使用 IPv6 分片
- **R2**: 响应方应配置系统防止 UDP 响应分片（BSD 用 DF 位；Linux 的 IP_MTU_DISCOVER 对 UDP 有害——主流实现用 `IP_PMTUDISC_OMIT`）
- **R3**: 响应报文大小 ≤ min(请求方 EDNS 载荷、接口 MTU、网络 MTU、**推荐上限 1400**)
- **R4**: EMSGSIZE 时重建 ≤PMTU 的响应或设 TC 位
- **R5**: 请求方 EDNS 载荷 ≤ min(接口 MTU、网络 MTU、**1400**)，允许更小
- **R6**: 请求方应在防火墙丢弃**分片**的 DNS/UDP 响应（非零 FO 或 MF=1；IPv6 Fragment Header）
- **R7**: 重复 UDP 超时后回退到替代传输（TCP）

### 背景与常量

- 最小 IPv6 MTU 1280 → 减去 IPv4/IPv6+UDP 头部 → Flag Day 2020 推荐请求方 **1232**
- RFC 4035 要求 DNSSEC 感知服务器支持 ≥1220 字节
- 主流实现（BIND/Unbound/Knot/PowerDNS）默认 1232，`max-udp-size` 上限 1232–4096
- 分片攻击根源：UDP 端口 + DNS ID 各 16 位熵，且都在首片——RFC 8900 系统性脆弱性

### 我们的实现

- 请求端（上游）: `pool.UDPBufferSize = 1232` ✓（≤1400，符合 R5）；递归路径 `RecursiveUDPBufferSize = 4096`（DNSSEC 链需要，偏离 R5——有意的权衡，见"已知偏离"）
- 响应端 ✓: `bridge.go` 按 `min(客户端 EDNS, DefaultMaxUDPResponseSize=1400)` 截断（R3）——超限设 TC 位 + TCP 重试，避免 IP 分片
- 待评估: R6 分片丢弃（防火墙/系统层，非应用可做）

---

## RFC 9824 — Compact Denial of Existence in DNSSEC  `[RFC 9824: Proposed Standard]`  ✅

**紧凑否认证明（Compact Answers，更新 4034/4035）：权威对不存在的名字返回 NODATA + 单条匹配 QNAME 的 NSEC/NSEC3（bitmap 含 NXNAME 信号），替代 NXDOMAIN——响应更小、在线签名开销更低、防 zone 枚举。**

### 关键点

- 不存在名字: NODATA + 动态构造 NSEC（owner=QNAME，Next Domain=QNAME 的字典序后继即加 `\000` 前缀标签，bitmap 仅 RRSIG/NSEC/**NXNAME(128)**）；NSEC3 时 bitmap 仅 NXNAME
- 不存在类型: NODATA + 匹配 NSEC（bitmap 列出该名字现有类型）
- 通配符匹配: 答案 RRSIG 的 label count 等于查询名 label 数（精确匹配证明），省略 closer-match NSEC
- 未签名委托: NSEC 的 Next Domain = owner 首标签 + `\000`（不得落入委托子域）
- **NXNAME 是 Meta-TYPE**: 显式查询 → 权威 MUST 返回 FORMERR；解析器 MUST NOT 转发/迭代
- 解析器无强制处理；可选实现 §5.1 "Signaled Response Code Restoration"：检测 bitmap 的 NXNAME 位 → 把紧凑 NODATA 恢复为 NXDOMAIN 语义
- 协商: EDNS OPT 的 **CO 位**（Compact Answers OK）——解析器设置后权威才返回紧凑答案

### 我们的实现

- ✓ 上游查询设 CO 位（`edns/edns.go:ApplyToMessage` 请求方向，miekg 已接入 OPT）
- ✓ 验证器 §5.1: `dnssec.HasCompactNXNAME` 检测 NSEC/NSEC3 bitmap 的 NXNAME 位 → 递归路径（`recursive.go`，仅在 NSEC 证明验证通过后）与转发路径（`forward.go`）均恢复 NXDOMAIN rcode
- ✓ Validation 中间件拒绝 NXNAME(128) 显式查询（FORMERR + EDE 30，RFC 9824 §3.5 MUST；AXFR/IXFR 仍 REFUSED）
- ✓ 附带修复: NXDOMAIN rcode 贯通 miss 路径与缓存 wire（`cache.Set` 新增 rcode 参数）——此前 NXDOMAIN 恒被服务为 NODATA
  4. 核对现有 `matchesNSECDenial` 对紧凑 NODATA（owner=QNAME 匹配）的处理 ✓ 已兼容

---

## RFC 9859 — DNS Synchronization (DSYNC RR)  `[RFC 9859: Proposed Standard]`  ⚪

**扩展 DNS NOTIFY 的触发机制：新 RR 类型 DSYNC（66），父区→子区（或反之）的 NS/DS 更新通知，含 DNSSEC 启动（bootstrapping）。**

### 关键点

- DSYNC 是**通知**，不改变动作本身（接收方自行执行预定义动作及其安全检查）
- 初始通知类型: 父区 NS/DS 记录更新（`notify_types` 位图）
- 发现接收端点: DSYNC 记录发布接收方信息

### 我们的实现

- ⚪ 仅供参考（区同步/父区通知，非递归解析器职责）。miekg/dns 提供 `DSYNC` 类型（66）

---

## RFC 10029 — Multiple QTYPEs in a Single DNS Query (MQTYPE-Query/Response)  `[RFC 10029: Proposed Standard]`  ⚪

**EDNS0 选项 MQTYPE-Query（20）/MQTYPE-Response（21）：客户端在查询中附加 QTYPE 列表，服务端把多类型响应合并进单个回复。**

### 我们的决定

⚠️ **不实现。** 经过完整实现后又全部移除，原因：

- **服务端合并无实际收益**: ZJDNS 的客户端不发 MQTYPE-Query；即使支持，合并逻辑增加的复杂度（缓存穿透、RCODE/flags 一致性、预算管理、RR 去重）远超省下的 RTT
- **转发透传多余**: 客户端不发 MQTYPE-Query 时透传零作用；更糟的是 MQTYPE 中间件本身已能做合并（转发模式跳过逻辑反而绕过了自身能力）
- **递归→权威无收益**: 权威多数不实现 MQTYPE；DS+NS 合并被 referral Authority section 里已有的 NS 记录覆盖，MQTYPE-Query(TypeNS) 纯属冗余
- **ZJDNS↔ZJDNS 场景不需要**: 两个实例间不需要 MQTYPE 来减少 RTT——缓存预热已有同等效果

---

## DELEG RR (draft-dnsop-deleg-00)

**提议的新委托 RR 类型（Provisional 65432/65433），在 NS 之外携带委托子域的能力与额外信息（可扩展）。**

### 关键点

- 头部新增 **DELEG OK 位**（`_DE = 1<<13`，miekg 已接入 `Msg.Delegation`）
- 状态: draft rev-00，类型未正式分配（65432/65433 为临时值）——协议可能变化
- 递归解析器的委托处理（zonecut）未来需理解 DELEG 引用

### 我们的实现

- ⚪ 观望：类型未分配、草案未稳定，暂不接入 zonecut/委托逻辑。miekg/dns 提供 `DELEG`/`DELEGPARAM` 类型与 `deleg` 子包

---

## DNS Stamp (draft-denis-dns-stamps-02)

**DNS 服务器地址的标准化 URI 编码格式（`sdns://`）。**

### 8 种协议类型

| ID   | 协议               | 传输    |
| ---- | ------------------ | ------- |
| 0x00 | Plain DNS          | UDP/TCP |
| 0x01 | DNSCrypt           | UDP/TCP |
| 0x02 | DoH                | HTTPS   |
| 0x03 | DoT                | TLS     |
| 0x04 | DoQ                | QUIC    |
| 0x05 | Plain DNS (DNSSEC) | UDP/TCP |
| 0x06 | DoH (no ECS)       | HTTPS   |
| 0x07 | DoH3               | HTTP/3  |

### Stamp 格式

```
sdns://<base64(BinaryStamp)>
BinaryStamp = [protocol:1][props:8][addr_len:1][addr:N][hashes...][path...]
```

### 我们的实现

- `internal/stamp/parse.go`: 全部 8 种协议解析 ✓
- `internal/stamp/encode.go`: 编码 ✓
- CLI: `--dnsstamp --decode/--encode` ✓

---

## DNSCrypt (draft-denis-dprive-dnscrypt-11)

**非 IETF 标准的 DNS 加密协议，支持后量子密码学（X-Wing PQ/T KEM）。**

### 关键常量

- 默认端口: **8443**（§5.2 SHOULD 443 — 与 dnscrypt-proxy 社区一致）
- Client Magic: 8 字节；Classical=X25519 PK 前 8B, PQ=SHA-256(X-Wing PK)[:8]
- UDP 查询最小: **512** 字节（§5.4.1 MAY，与 dnscrypt-proxy 对齐）
- 证书轮换: **8h** ticker（§8 MUST ≤24h —— 8h < 24h 有效期形成重叠窗口）
- 证书有效期: 24h（8h 轮换 → 最多 3 份证书同时有效）
- 查询上限: **4096** 字节（§5.2 MUST）
- TCP 响应上限: **4096** 字节（§5.4.7 MUST）

### 两种加密构造

| 类型      | 密钥封装    | AEAD               | 证书大小 |
| --------- | ----------- | ------------------ | -------- |
| Classical | X25519      | XChacha20-Poly1305 | 124B     |
| PQ        | X-Wing PQ/T | XChacha20-Poly1305 | 1320B    |

### 协议流程

```
1. 客户端 → DNS TXT 查询获取证书（Ed25519 签名）
2. 客户端 → 加密查询（Classical 或 PQ）
3. 服务端 → 加密响应
4. PQ 模式：首次查询后获得 ticket，后续查询可复用（类似 TLS 会话恢复）
```

### 新增 §5.4.5 确定性响应填充

- 填充长度: SHA-256(sharedKey || clientNonce)[0] → 1-256 字节
- 64 字节对齐（预算允许时）
- 防止重传查询产生不同的填充长度（可链接信号）
- 与 encrypted-dns-server 的 SipHash 方案功能等价

### 新增 §5.4.6-5.4.7 响应处理

- **UDP**: 加密响应 ≤ 查询大小（反放大）。超预算 → 截断 DNS 响应 + TC，禁止静默丢弃
- **TCP**: 无 UDP 反放大限制，但加密响应 < 4096 字节
- TCP 每次连接只处理一个查询后关闭（§5.4.4）

### 防放大（§5.5 / §11.3）

- UDP 证书响应 MUST NOT 大于请求
- PQ 证书省略时 → 设置 TC=true，保留 Classical 证书
- 客户端收到 TC → TCP 重试获取完整证书集

### 客户端优化

- **EWMA 自适应 sizing**: 跟踪响应大小，逐步下调 minQueryLen（对齐 dnscrypt-proxy）
- **TC 翻倍升级**: 收到 TC 时 minQueryLen *= 2（O(log n) 收敛）
- **临时密钥**: `ephemeral_keys: true` 启用每查询新 X25519 密钥对（前向安全）
- **PQ 降级保护**: `pqdnscrypt: true` 时拒绝 Classical 回退（§11.9 MUST）
- **服务端共享密钥缓存**: client_pk → shared_key LRU 缓存（§8 SHOULD）

### 我们的实现

- `DefaultDNSCryptPort = "8443"` ✓
- XWingPQ + XChacha20Poly1305 两种构造 ✓
- 8h 轮换 / 24h 证书有效期 ✓
- PQ Ticket 会话恢复 ✓
- §5.4.5 确定性响应填充 ✓
- §5.4.6 TC 截断（不静默丢弃）✓
- §5.4.7 TCP 4096 字节限制 ✓
- 证书 TC + Classical 保留 ✓
- EWMA 自适应 sizing ✗（`ewmaQuerySize` 为死代码，未实现；minQueryLen 仅 TC 翻倍升级）
- 临时密钥 ✓
- PQ 降级保护 ✓
- §8 共享密钥缓存（2048-entry LRU）✓
- 弱密钥检查 ✓
- 18/19 参考实现对齐（EWMA 未实现）

---

## SOCKS5 (RFC 1928/1929)

**TCP/UDP 代理协议，用于通过防火墙/代理访问上游 DNS 服务器。**

### 协议流程

```
Client → GREETING [0x05, 1, 0x00|0x02] → Server
Client ← METHOD [0x05, 0x00|0x02] ← Server
(if auth)
Client → AUTH [0x01, user_len, user, pass_len, pass] → Server
Client ← AUTH_RESP [0x01, 0x00] ← Server
Client → CONNECT [0x05, 0x01, 0x00, addr_type, addr, port] → Server
Client ← CONNECT_RESP [0x05, 0x00, 0x00, addr_type, addr, port] ← Server
Client ⇄ 数据透传 ⇄ Target
```

### 关键要求

- 支持 TCP CONNECT（RFC 1928）
- 支持 UDP ASSOCIATE（§6）— 用于 UDP DNS 代理
- 支持用户名/密码认证（RFC 1929）

### 我们的实现

- `server/upstream/socks5/`: TCP + UDP ASSOCIATE + 认证 ✓

---

## TLCP/DTLCP — 国密标准

**中国国家标准：基于 SM2/SM3/SM4 的 TLS/DTLS 等价协议。**

### 标准引用

| 标准            | 内容                            |
| --------------- | ------------------------------- |
| GB/T 38636-2020 | TLCP 协议规范                   |
| GM/T 0024-2014  | SSL VPN 技术规范（SM 密码套件） |
| GM/T 0128-2023  | DTLCP（DTLS over SM）           |

### 关键常量

| 端口     | 值   | 说明                   |
| -------- | ---- | ---------------------- |
| TLCP DoT | 9853 | 自定义（非 IANA 注册） |
| TLCP DoH | 9443 | 自定义                 |
| DTLCP    | 9853 | 自定义                 |

### 帧格式

- DoT/DTLCP 均使用 2 字节长度前缀（继承自 RFC 8094/1035 模式）

### 已知限制

- gotlcp 库不支持 `net.Listen("udp")`：使用 `net.ListenUDP` + 自定义 listener
- DTLCP 同样受 PMTU 限制（UDP），失败时自动 fallback 到 TLCP
- 共享 UDP socket 同一时间仅一个连接（gotlcp 限制）
- 证书：SM2 密钥对（签名+加密）与 TLCP 共用

### 我们的实现

- `server/protocol/tlcp/`：DoT + DoH + DTLCP 服务端
- `server/upstream/tlcp/`：DoT + DoH + DTLCP 客户端
- `gotlcp` 库提供 SM2/SM3/SM4 密码学基础

---

## 已知偏离与设计权衡

| 偏离                                 | RFC           | 影响              | 原因                                          |
| ------------------------------------ | ------------- | ----------------- | --------------------------------------------- |
| DTLS 端口 8853 非 853                | RFC 8094      | 低 — 生态广泛使用 | 避免与 DoT(853) 冲突                          |
| DNSCrypt 查询缺少 ResolverMagic 前缀 | DNSCrypt §5.2 | 低 — 服务端用 ClientMagic 识别，查询中冗余 | 与 dnscrypt-proxy 一致；响应仍包含 ResolverMagic |
| 递归上游查询 EDNS 载荷 4096 超 R5 推荐 1400 | RFC 9715 | 中 — 可能招致分片 | DNSSEC 签名引用/证明常超 1232，4096 是递归解析的实际需要；客户端侧仍用 1232 |
