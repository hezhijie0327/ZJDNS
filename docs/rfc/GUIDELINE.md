# RFC 精华指南

每个 RFC 的核心协议要点提炼，供开发者快速理解规范要求而无需阅读 RFC 全文。

格式：**概述 → 常量 → 关键要求 → 协议流程 → 我们的实现**

---

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
- **MUST**: 响应顺序与查询顺序一致
- 服务端空闲超时 **SHOULD** 在秒级（建议 2-60s）
- 连接复用优于每条查询新建连接

### 协议流程
```
Client → [2字节长度][DNS消息] → Server
Client → [2字节长度][DNS消息] → Server  (管线化，不等响应)
Client ← [2字节长度][DNS响应] ← Server  (按序)
```

### 我们的实现
- ConnPool 管线化连接池：`server/upstream/pool/tcp.go`
- `DefaultTCPPoolIdleTimeout = 120s`（客户端侧，减少重连）

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
- 响应过大（>PMTU）应静默丢弃

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

---

## RFC 8484 — DNS over HTTPS (DoH)

**通过 HTTPS 传输 DNS 查询。**

### 关键常量
- 端口: **443**
- Content-Type: **`application/dns-message`**
- 路径: **`/dns-query`**（推荐但非强制）
- 方法: **POST**（推荐）+ GET（可选，Base64url 编码）

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
| 参数 | 值 | 说明 |
|------|-----|------|
| Client Cookie | **8** 字节 | 客户端生成（随机数） |
| Server Cookie | **8–32** 字节 | 服务端 SipHash-2-4 生成 |
| Secret 轮换间隔 | **30 分钟** | 定期更换防止长期泄露 |
| Cookie 有效期 | **1 小时** | 超过后客户端需更新 |
| 续期阈值 | **30 分钟** | 提前提示客户端续期 |
| 未来容忍 | **5 分钟** | 容忍时钟偏差 |

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
| 参数 | RFC 推荐 | 我们的值 |
|------|---------|---------|
| IPv4 前缀长度 | **/24** | `/24` ✓ |
| IPv6 前缀长度 | **/56** | `/56` ✓ |
| SCOPE 默认 | **0**（不可用） | `0` ✓ |

### 关键要求
- **MUST**: ECS 选项仅用于递归→权威方向（不发送给客户端）
- **SHOULD**: IPv6 使用 /56（允许站点内子网聚合）
- SCOPE=0 表示"响应未应用 ECS"

### 我们的实现
- `edns/ecs.go`: `DefaultECSv4Len=24`, `DefaultECSv6Len=56`, `DefaultECSScope=0`
- ECS 透传到上游，缓存按 ECS 地址分桶

---

## RFC 8467/7830 — EDNS Padding

**DNS 响应的填充策略，防止流量分析推断查询内容。**

### 关键常量
| 参数 | 值 | 说明 |
|------|-----|------|
| 请求块大小 | **128** | 查询填充到 128 的倍数 |
| 响应块大小 | **468** | 响应填充到 468 的倍数 |
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
- 地址验证器：`server/protocol/tls/addr_validator.go`（capped at 100K）

---

## RFC 8310 — DoT/DTLS Privacy Profiles

**定义了 Strict 和 Opportunistic 两种隐私配置模式。**

### 两种 Profile

| 要求 | Strict | Opportunistic |
|------|--------|---------------|
| 加密 | MUST | SHOULD |
| 证书验证 | MUST (SPKI pin 或 CA) | MAY |
| 回退到明文 | MUST NOT | 允许（加密失败后） |
| 认证域名 | MUST | MAY |

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

## RFC 9103 — DoT 操作考虑

**DNS over TLS 的部署和操作指南（更新 RFC 7858 和 RFC 8310）。**

### 关键要点
- DNS 服务器应使用 TLS 1.3+（废弃 < 1.2）
- 推荐使用 Forward Secrecy 密码套件
- 连接应支持 keepalive 以减少握手开销
- 不推荐 DoT 与明文 DNS 之间做协议回退（降级攻击风险）

### 我们的实现
- 服务端 TLS 1.3、客户端 TLS 1.2+ ✓
- eTLS 曲线偏好配置（Forward Secrecy）✓
- DoT 连接池 + keepalive ✓
- 无明文回退 ✓

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
- NSEC3 迭代上限: **150**（RFC 5155 §10.3）→ `DefaultMaxNSEC3Iterations = 150`

### 我们的实现
- `server/resolver/dnssec/` 完整实现：签名验证、信任链、NSEC/NSEC3 否定回答
- `dnssec_chain.go`：逐级 DS/DNSKEY/RRSIG 验证
- `trust_anchor.go`：lazy-loaded 根信任锚

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

| RFC | 关键点 | 引用位置 |
|-----|--------|---------|
| RFC 6604 | NXDOMAIN 可包含 CNAME/DNAME | `nameserver.go:78` |
| RFC 6840 | §5.3 放宽签名有效期检查 | `dnssec/nsec.go:139` |
| RFC 7344 | CDS/CDNSKEY 自动化信任锚 | `dnssec_chain.go` |

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

### 关键 EDE 码
| 码 | 含义 | 使用 |
|----|------|------|
| 0 | Other | 通用 |
| 3 | Stale Answer | stale-while-revalidate |
| 6 | DNSSEC Bogus | 签名验证失败 |
| 9 | DNSKEY Missing | 缺少密钥 |
| 20 | No Reachable Authority | 权威不可达 |

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
| 标准 | 内容 |
|------|------|
| GB/T 38636-2020 | TLCP 协议规范 |
| GM/T 0024-2014 | SSL VPN 技术规范（SM 密码套件） |
| GM/T 0128-2023 | DTLCP（DTLS over SM） |

### 关键常量
| 端口 | 值 | 说明 |
|------|-----|------|
| TLCP DoT | 9853 | 自定义（非 IANA 注册） |
| TLCP DoH | 9443 | 自定义 |
| DTLCP | 9853 | 自定义 |

### 帧格式
- DoT/DTLCP 均使用 2 字节长度前缀（继承自 RFC 8094/1035 模式）

### 已知限制
- gotlcp 库不支持 `net.Listen("udp")`：使用 `net.ListenUDP` + 自定义 listener
- 共享 UDP socket 同一时间仅一个连接（gotlcp 限制）
- 证书：SM2 密钥对（签名+加密）与 TLCP 共用

### 我们的实现
- `server/protocol/tlcp/`：DoT + DoH + DTLCP 服务端
- `server/upstream/tlcp/`：DoT + DoH + DTLCP 客户端
- `gotlcp` 库提供 SM2/SM3/SM4 密码学基础

---

## DNSCrypt (draft-denis-dprive-dnscrypt-10)

**非 IETF 标准的 DNS 加密协议，支持后量子密码学（X-Wing PQ/T KEM）。**

### 关键常量
- 默认端口: **8443**
- Client Magic: 8 字节协议标识
- UDP 查询最小: **256** 字节（填充防放大）
- 证书轮换: **24h**
- 证书有效期: 48h（当前+前一个重叠）

### 两种加密构造
| 类型 | 密钥封装 | AEAD | 证书大小 |
|------|---------|------|---------|
| Classical | X25519 | XChacha20-Poly1305 | 124B |
| PQ | X-Wing PQ/T | XChacha20-Poly1305 | 1320B |

### 协议流程
```
1. 客户端 → DNS TXT 查询获取证书（Ed25519 签名）
2. 客户端 → 加密查询（Classical 或 PQ）
3. 服务端 → 加密响应
4. PQ 模式：首次查询后获得 ticket，后续查询可复用（类似 TLS 会话恢复）
```

### 防放大（§10.3）
- UDP 证书响应 MUST NOT 大于请求
- 响应过大 → 设置 TC 位 → 客户端通过 TCP 重试

### 我们的实现
- `DefaultDNSCryptPort = "8443"` ✓
- XWingPQ + XChacha20Poly1305 两种构造 ✓
- 24h 证书轮换 ✓
- PQ Ticket 会话恢复 ✓
- UDP 256 字节最小填充 ✓
- 防放大（TC 回退 TCP）✓

---

## DNS Stamp (draft-denis-dns-stamps-02)

**DNS 服务器地址的标准化 URI 编码格式（`sdns://`）。**

### 8 种协议类型
| ID | 协议 | 传输 |
|----|------|------|
| 0x00 | Plain DNS | UDP/TCP |
| 0x01 | DNSCrypt | UDP/TCP |
| 0x02 | DoH | HTTPS |
| 0x03 | DoT | TLS |
| 0x04 | DoQ | QUIC |
| 0x05 | Plain DNS (DNSSEC) | UDP/TCP |
| 0x06 | DoH (no ECS) | HTTPS |
| 0x07 | DoH3 | HTTP/3 |

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
| 域名 | 用途 |
|------|------|
| `localhost.` | 回环地址 |
| `.local` | mDNS 本地链路 |
| `.onion` | Tor 隐藏服务 |
| `test.` / `invalid.` | 测试 / 无效域名 |
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

| 偏离 | RFC | 影响 | 原因 |
|------|-----|------|------|
| DTLS 端口 8853 非 853 | RFC 8094 | 低 — 生态广泛使用 | 避免与 DoT(853) 冲突 |
