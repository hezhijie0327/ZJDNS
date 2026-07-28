# RFC 精华指南

每个 RFC 的核心协议要点提炼，供开发者快速理解规范要求而无需阅读 RFC 全文。

格式：**概述 → 常量 → 关键要求 → 协议流程 → 我们的实现**

---

## RFC 1034 — DNS 概念与设施

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

## RFC 2181 — DNS 规范澄清

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

## RFC 1035 — DNS 实现规范

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

## RFC 6891 — EDNS(0)

**DNS 的扩展机制，支持更大的 UDP 负载、额外的 OPT 选项。**

### 关键常量

- UDP 最小负载: **512** 字节（向后兼容）
- 推荐 UDP 最大: **4096** 字节（适合 DNSSEC 签名响应）
- DNS Flag Day 2020 推荐: **1232** 字节（避免 IPv6 分片）

### 协议要求

- **MUST**: 不支持 EDNS 版本的响应 → FORMERR
- **MUST**: 响应方 UDPSize 反映自身最大负载能力
- 发送方 UDPSize 过大导致响应被截断时，应回退到较小值

### 我们的实现

- 标准查询: `pool.UDPBufferSize = 1232`
- 递归查询: `pool.RecursiveUDPBufferSize = 4096`（DNSSEC 链需要更大空间）
- `edns/edns.go:ApplyToMessage()` 在响应中设置 UDPSize

---

## RFC 7766 — DNS over TCP

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

## RFC 8446 — TLS 1.3

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

## RFC 5077 — TLS Session Resumption (Session Tickets)

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

## RFC 6125 — TLS 证书名验证

**TLS 客户端如何验证服务端证书中的标识名（SAN/CN）。**

### 关键要求

- **MUST**: 验证 `subjectAltName` (SAN) dNSName
- **MUST NOT**: 仅依赖 CN（Common Name）
- 支持通配符：`*.example.com` 匹配 `foo.example.com`

### 我们的实现

- Go `crypto/tls` 库默认执行 RFC 6125 验证
- `ServerName` 字段设置 TLS SNI + 证书验证 ✓

---

## RFC 7858 — DNS over TLS (DoT)

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

## RFC 8094 — DNS over DTLS

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

## RFC 8484 — DNS over HTTPS (DoH)

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

## RFC 9250 — DNS over QUIC (DoQ)

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

## RFC 8767 — Serving Stale Data

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

## RFC 9156 — QNAME Minimisation

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

## RFC 7873/9018 — DNS Cookies

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

## RFC 7871 — EDNS Client Subnet (ECS)

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
- Birthday Attack 缓解：响应 ECS 必须回显查询的 FAMILY/ADDRESS/SOURCE PREFIX（不匹配 → 丢弃）
- 收到 REFUSED 时 MUST 去除 ECS 重试

---

## RFC 8467/7830 — EDNS Padding

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

## RFC 9000 — QUIC

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

## RFC 8310 — DoT/DTLS Privacy Profiles

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

## RFC 9103 — DNS Zone Transfer over TLS (XoT)

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

## RFC 4033/4034/4035 — DNSSEC

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

## RFC 6840 — DNSSEC 澄清与更新

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

## RFC 4509 — SHA-256 in DS RRs

\*\*DNSSEC DS 摘要 MUST 支持 SHA-256（更新 RFC 4---

## RFC 5155 — NSEC3（哈希认证的否定存在证明）

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

## RFC 5011/9077 — Trust Anchor 自动化

**DNSSEC 信任锚的自动化管理（RFC 9077 更新 5011）。**

- ⚠ **已知差距**：§4 状态机（Add Hold-Down 30 天 + 事件驱动）是实现大功能。当前 `named.root` 静态加载已满足基本需求，REVOKE 位检查已实现

---

## RFC 8198 — Aggressive NSEC Caching

**利用缓存的 NSEC/NSEC3 范围推导否定回答。**

- ⚠ **已知差距**：miekg/dns 提供 NSEC/NSEC3 数据但不提供覆盖判断。需自行实现范围比较 + RRSIG 附带 + 通配符处理。之前尝试过但边界条件问题多，暂不实现

---

## RFC 8499 — DNS Terminology

**DNS 标准术语参考。** ✓

---

## RFC 6052/6147 — DNS64

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

## RFC 6604/6840/7344 — DNSSEC 补充

**对 DNSSEC 的澄清和自动化更新。**

| RFC      | 关键点                      | 引用位置             |
| -------- | --------------------------- | -------------------- |
| RFC 6604 | NXDOMAIN 可包含 CNAME/DNAME | `nameserver.go:78`   |
| RFC 6840 | §5.3 放宽签名有效期检查     | `dnssec/nsec.go:139` |
| RFC 7344 | CDS/CDNSKEY 自动化信任锚    | `dnssec_chain.go`    |

---

## RFC 6672 — DNAME

**将整个子树重定向到另一个域名的 DNS RR 类型（类似 CNAME 但对整个 zone）。**

### 协议行为

- `x.example.com DNAME y.example.net` → `x.example.com` 的查询被重写为 `x.example.net`
- DNAME 不重写 QNAME 本身，而是对查询名做后缀替换
- **MUST**: DNAME 只出现在应答的 authority section（不在 answer section）
- DNAME 与 CNAME 同时存在时，CNAME 优先

### 我们的实现

- `nameserver.go:91`：在 NXDOMAIN 响应中处理 `*dns.CNAME` 和 `*dns.DNAME` 记录 ✓

---

## RFC 7828 — EDNS TCP Keepalive

**EDNS0 选项，协商 TCP/DoT 连接的保活超时。**

### 关键常量

- 超时单位: **100ms**（值 × 100ms = 实际超时）
- 仅在 TCP 服务端响应中添加

### 我们的实现

- `edns/edns.go:ApplyToMessage()` 支持 tcpKeepaliveTimeout 参数 ✓

---

## RFC 8914 — Extended DNS Errors (EDE)

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

## RFC 9114 — HTTP/3

**QUIC 上的 HTTP 协议，DoH3 的基础传输层。**

### 关键点

- HTTP/3 使用 QUIC 流替代 TCP 连接
- DoH3：`POST /dns-query` + `application/dns-message`

### 我们的实现

- `server/protocol/tls/http3.go`：quic-go/http3 实现 ✓

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

## DNSCrypt (draft-denis-dprive-dnscrypt-11)

**非 IETF 标准的 DNS 加密协议，支持后量子密码学（X-Wing PQ/T KEM）。**

### 关键常量

- 默认端口: **8443**（§5.2 SHOULD 443 — 与 dnscrypt-proxy 社区一致）
- Client Magic: 8 字节；Classical=X25519 PK 前 8B, PQ=SHA-256(X-Wing PK)[:8]
- UDP 查询最小: **512** 字节（§5.4.1 MAY，与 dnscrypt-proxy 对齐）
- 证书轮换: **24h**（§8 MUST ≤24h）
- 证书有效期: 48h（当前+前一个重叠）
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
- 24h 证书轮换 ✓
- PQ Ticket 会话恢复 ✓
- §5.4.5 确定性响应填充 ✓
- §5.4.6 TC 截断（不静默丢弃）✓
- §5.4.7 TCP 4096 字节限制 ✓
- 证书 TC + Classical 保留 ✓
- EWMA 自适应 sizing ✓
- 临时密钥 ✓
- PQ 降级保护 ✓
- §8 共享密钥缓存 ✓
- 弱密钥检查 ✓
- 19/19 参考实现对齐 ✓

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

## RFC 6761 — 特殊域名

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

- 未针对特殊域名做特殊处理（递归解析正常查询上游 NS）
- 低优先级：可添加本地过滤

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

## 已知偏离与设计权衡

| 偏离                                 | RFC           | 影响              | 原因                                          |
| ------------------------------------ | ------------- | ----------------- | --------------------------------------------- |
| DTLS 端口 8853 非 853                | RFC 8094      | 低 — 生态广泛使用 | 避免与 DoT(853) 冲突                          |
| DNSCrypt 查询缺少 ResolverMagic 前缀 | DNSCrypt §5.2 | 低 — 服务端用 ClientMagic 识别，查询中冗余 | 与 dnscrypt-proxy 一致；响应仍包含 ResolverMagic |
