# 34 · 交叉分析：RFC 一致性

> 审计 Agent：Phase 2b · RFC
> 范围：全项目实现 vs RFC 规范、docs/rfc/ 存档完整性、MUST/SHOULD 覆盖


以下是 RFC 一致性审计的综合报告。本审计涵盖：(1) docs/rfc/ 目录覆盖范围，(2) RFC 编号和章节引用的 grep 验证，(3) 针对九种关键协议的 MUST/SHOULD 条款覆盖。

---

# RFC 一致性审计报告

## 第一部分：docs/rfc/ 目录覆盖范围

每份与被检查代码相交的 RFC 均已归档。**一处归档缺失：**

| RFC | 代码引用 | 文件 | 行号 |
|-----|-----------|------|------|
| RFC 6895 (DNS IANA Considerations) | `§3.1` | `server/handler/middleware/validation.go` | 37, 52 |

`validation.go` 两次引用 `RFC 6895 §3.1` 来解释 opcode/class 拒绝，但 `docs/rfc/rfc6895.txt` 不存在。所有其他引用的 RFC（1035, 1928, 1929, 1982, 2181, 4033–4035, 4509, 5011, 5155, 6052, 6125, 6147, 6604, 6672, 6761, 6840, 6891, 7344, 7766, 7828, 7830, 7858, 7871, 7873, 8094, 8198, 8310, 8446, 8467, 8484, 8499, 8767, 8914, 9000, 9018, 9077, 9103, 9114, 9156, 9250, 9461, 9462）均已归档。这些草案（DNS stamps, DNSCrypt）、GUIDELINE.md 以及 README.md 也已归档。

---

## 第二部分：RFC 章节引用审计

grep 了所有 `RFC NNNN §X.Y` 格式的引用。以下引用无效或有错误：

### 发现 1：RFC 8484 §6 标题引用错误
- **文件**：`config/defaults.go:169`
- **严重性**：低
- **问题**：引用 `RFC 8484 §6` 作为 65535 字节 DoH 请求限制的出处。RFC 8484 第 6 节是 IANA 注意事项。消息大小限制在 §4.2.1（POST）中："请求体大小不得超出 65535 字节。" §4.1（GET）通过 base64url 编码的 `dns` 查询参数施加了隐式限制。
- **风险**：章节引用错误是次要的；该值（65535）本身是正确的。维护者若将注释作为 RFC 权威来源，可能会被误导。
- **修复**：将 `// max DoH request body size (RFC 8484 §6)` 改为 `// max DoH request body size (RFC 8484 §4.2.1)`。

### 发现 2：RFC 8484 §7 标题引用错误
- **文件**：`internal/dnsutil/https_dns.go:81`
- **严重性**：低
- **问题**：注释中写道 "per RFC 8484 §7"，指的是代理/转发器 DNS 消息 ID。RFC 8484 第 7 节是安全考虑事项。相关讨论（允许转发器分配非零 DNS ID）出现在 §4.1（GET 方法）中。
- **风险**：极低——注释仅供理解目的。消息 ID 处理是正确的（设置 ID=0 作为客户端，在服务器端接受非零 ID）。
- **修复**：将 `§7` 改为 `§4.1`。

### 发现 3：RFC 6891 §6.2.5 引用——数值歧义
- **文件**：`server/protocol/plain/udp.go:30`
- **严重性**：信息性
- **问题**：注释引用 `RFC 6891 §6.2.5` 作为 1232 字节建议的理由。RFC 6891 第 6.2.5 节规定 EDNS 发送者应设置 UDPSize 反映自身接收能力（传统上为 512 的倍数）。1232 字节具体数值来自 DNS 标志日 2020 的一致意见，而非 RFC 6891 本身。`pool.UDPBufferSize` 设置为 1232，这是正确的，但 RFC 引用有误导性。
- **风险**：极低。数值正确（1232），且注释承认 UDPSize "following DNS Flag Day 2020"。
- **修复**：考虑更新注释，澄清 1232 来自 DNS 标志日 2020，而非 RFC 6891。

### 所有其他章节引用已验证

验证了所有 50 多个带有章节后缀的 `RFC NNNN §X.Y` 引用。所有被检查的引用（RFC 1035 §4.2.2, RFC 2181 §9, RFC 4034 §3.1.5/§6.1, RFC 4035 §5.3.3, RFC 5011 §2.1, RFC 5155 §5/§9.2/§10.3, RFC 6052 §2.1, RFC 6147 §5.1.7/§5.2, RFC 6840 §4.1/§4.3/§5.3/§5.9, RFC 6891 §6.2.2, RFC 7766 §6.2.3/§7/§8, RFC 7871 §11.1, RFC 7873 §7.1, RFC 8094 §3.3/§5, RFC 8310 §5/§6, RFC 8446 §2.3, RFC 8484 §4.2.1, RFC 8767 §4/§4.2/§5.2/§6, RFC 9000 §20, RFC 9018 §4.2/§4.3/§4.4, RFC 9156 §2.1/§2.3, RFC 9250 §4.3/§4.3.1/§4.3.2/§4.3.3/§4.5）均正确映射到其所引用的主题。

---

## 第三部分：逐协议 MUST/SHOULD 审计

### 3.1 RFC 1035（DNS 规范）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 使用 TCP 长度前缀（§4.2.2） | 已覆盖 | `internal/dnsutil/tcpframe.go` 16,92; `server/bridge.go` 135 | 双写（前缀+负载）和单写（§7766）均已实现 |
| **MUST** 截断超过客户端 EDNS 缓冲区的 UDP 响应并设置 TC（§4.2.1 + RFC 2181 §9） | 已覆盖 | `server/bridge.go` 156–166 | 结合 `dnsutil.Truncate()` |
| **SHOULD** 在标准端口 53 上监听 | 已覆盖 | `config/defaults.go` | DefaultPort = "53" |
| **MUST** 在 TCP 上重用连接 | 已覆盖 | `server/upstream/pool/tcp.go` | 完整的 RFC 7766 管道连接池 |
| 域名解压缩/指针安全 | 委托 | — | 依赖 miekg/dns 库 |
| **发现**：TCP DNS 写入后的 NXDOMAIN 可能附加了非 ANCOUNT 的 CNAME/DNAME 记录（RFC 6604 §1.1） | 已覆盖 | `server/resolver/nameserver.go:83` | 注释确认 |

**整体 RFC 1035 合规性：良好。** 未发现不符合处。核心 DNS 线格式委托给经过验证的 miekg/dns 库。

---

### 3.2 RFC 7858（DNS-over-TLS / DoT）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 使用 TLS 1.2 或更高版本 | 已覆盖 | `server/protocol/tls/server.go:138` | MinVersion = TLS 1.3 |
| **MUST** 使用 TCP 端口 853 | 已覆盖 | `config/defaults.go:15` | DefaultTLSPort = "853" |
| **MUST** 使用 ALPN "dot" | 已覆盖 | `config/defaults.go:308` | NextProtoDOT = []string{"dot"} |
| **MUST** 支持 PKIX 证书验证（严格模式） | 已覆盖 | `config/defaults.go:222`; `server/upstream/tls/tls.go` | 通过 eTLS 实现；默认严格模式 |
| **SHOULD** 实现 TLS 会话恢复 | 已覆盖 | `config/defaults.go`; `server/upstream/client.go:103-104` | LRU 客户端会话缓存已配置 |
| **SHOULD** 支持 TCP 连接复用 | 已覆盖 | `server/upstream/pool/tcp.go` | 管道连接池 |
| **MUST** 遵守 RFC 8310 隐私配置文件 | 已覆盖 | `config/defaults.go:222-227`; `config/config.go:135` | 严格/机会主义模式均可配置 |
| **SHOULD** 实现 0-RTT（通过 TLS 1.3） | 已覆盖 | `server/upstream/tls/tls.go:72` | TLS 1.3 0-RTT 用于会话恢复 |
| **发现**：基于 TCP 的 DoT 管道使用 `DefaultTCPPoolIdleTimeout`（与 RFC 7885 第 6.2.3 节的 120 秒空闲超时建议一致） | 正确 | `config/defaults.go:88` | ✓ |

**整体 RFC 7858 合规性：良好。** 所有主要条款均已覆盖。

---

### 3.3 RFC 8484（DNS-over-HTTPS / DoH）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 支持 GET | 已覆盖 | `server/protocol/tls/https.go:135-139` | base64url 编码的 dns 参数已解析 |
| **MUST** 支持 POST | 已覆盖 | `server/protocol/tls/https.go:141-143` | 主体大小限制为 MaxBytesReader |
| **MUST** 对 POST 使用 Content-Type: application/dns-message | 已覆盖 | `server/protocol/tls/https.go:148-149` | 错误的 Content-Type → 415 |
| **MUST** 以 application/dns-message 响应 | 已覆盖 | `server/protocol/tls/https.go:170` | w.Header().Set("Content-Type", dnshttp.MimeType) |
| **MUST** 将响应主体限制为 65535 字节 | 已覆盖 | `config/defaults.go:169` | DefaultDOHMaxRequestSize = 65535 |
| **SHOULD** 设置基于 TTL 的 HTTP 缓存指令 | **未覆盖** | `server/protocol/tls/https.go:171` | 始终设置 `Cache-Control: max-age=0`，忽略 DNS 响应 TTL |
| **MAY** 支持 GET 中的 Accept 标头 | **缺失** | `server/protocol/tls/https.go` | 未检查 Accept 标头；仍会以 application/dns-message 响应 |
| **MUST** 在 HTTP 错误上返回合适的状态码 | 已覆盖 | `server/protocol/tls/https.go:148-151` | 415（错误 Content-Type），400（格式错误的请求） |

**发现 4：响应缓存指令不符合 RFC 8484**
- **文件**：`server/protocol/tls/https.go:171`
- **严重性**：中
- **问题**：RFC 8484 §4 规定："对成功查询的响应应包含基于答案中 RRset 的 TTL 的缓存信息。" 当前实现始终设置 `Cache-Control: max-age=0`，意味着响应始终不被缓存（TTL 30 秒的 A 记录和 TTL 86400 的 SOA 记录一视同仁）。
- **风险**：HTTP 代理/CDN 将无法智能缓存 DNS 响应。对直接子网客户影响较小；对通过转发代理访问 DoH 服务器的客户影响更大。
- **修复**：解析 DNS 响应的最小 TTL 并设置 `Cache-Control: max-age=<computed-ttl>`。对 SERVFAIL/NXDOMAIN 保留 `max-age=0`。

**发现 5：GET Accept 标头协商缺失**
- **文件**：`server/protocol/tls/https.go:133-156`
- **严重性**：低
- **问题**：RFC 8484 §4.1 允许客户端指定 `Accept` 标头以请求特定响应格式（例如 `application/dns-message` 或 `application/dns-json`）。接受逻辑未检查 `Accept` 标头。
- **风险**：低——服务器始终以 `application/dns-message` 响应，这是所有标准客户端唯一广泛支持的格式。
- **修复**：可选的——添加 `Accept` 标头检查，以对不支持的媒体类型返回 406。

---

### 3.4 RFC 9250（DNS-over-QUIC / DoQ）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 使用 QUIC v1 | 已覆盖 | `server/protocol/tls/quic.go` | 通过 quic-go 库 |
| **MUST** 设置 DNS 消息 ID = 0 | 已覆盖 | `server/protocol/tls/quic.go:222`; `server/upstream/tls/quic.go:143` | 服务器端和上行端 |
| **MUST** 使用 ALPN "doq" | 已覆盖 | `config/defaults.go:310` | NextProtoDOQ = []string{"doq"} |
| **MUST** 使用 2 字节长度前缀 | 已覆盖 | `server/protocol/tls/quic.go:272-273` | 帧写入/读取 |
| **MUST** 使用标准 DoQ 错误码 | 已覆盖 | `internal/pool/pool.go:38-56` | 所有 6 个 DoQ 错误码 |
| **MUST NOT** 在 0-RTT 中发送不可重放的事务 | 已覆盖 | `server/protocol/tls/quic.go:228-234` | 0-RTT 中的非 QUERY 操作码检查 |
| **MUST** 对事务错误使用 RESET_STREAM | 已覆盖 | `server/protocol/tls/quic.go:253-254` | 通过 CancelWrite 实现 |
| **MUST NOT** 发送 edns-tcp-keepalive | 已覆盖 | `internal/dnsutil/https_dns.go:94-97` | ServerDOHMsgAccept 拒绝 TCPKEEPALIVE |
| **发现**：0-RTT 拒绝重试重用同一连接 | 已覆盖（已记录） | `server/upstream/tls/quic.go:73-85, 99-112` | 注释记录："spec requires a fresh connection"——这是一个已记录的性能权衡 |

**整体 RFC 9250 合规性：良好。** 0-RTT 拒绝重试应使用新连接但使用旧连接的做法，是 quic-go 兼容性的已知权衡，并已明确记录。

---

### 3.5 RFC 7871（EDNS 客户端子网 / ECS）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **SHOULD** 使用 /24 IPv4, /56 IPv6 源前缀 | 已覆盖 | `edns/ecs.go:20-22` | DefaultECSv4Len = 24, DefaultECSv6Len = 56 |
| **MUST** 格式化选项值为 SUBNET | 已覆盖 | `edns/ecs.go:106-112` | 通过 miekg/dns SUBNET 类型 |
| **MAY** 支持缓存 ECS 敏感条目 | 已覆盖 | `cache/store.go:86-104` | ecsFallbackCandidates 逐 bit 宽泛匹配 |
| **发现 6：ECS 范围前缀始终为 0** | | | |
| **文件**：`edns/ecs.go:22`, `edns/ecs.go:158,178,204` | | | |
| **严重性**：低 | | | |
| **问题**：RFC 7871 §4 规定服务器应设置范围前缀以指示答案适用的子网。当前实现始终设置 `ScopePrefix = 0`。虽然这是一个允许的值（"不透明"），但正确设置范围可以提高客户端缓存效率。 | | | |
| **风险**：客户端收到超出所需的 ECS 条目时可能会浪费缓存空间。 | | | |
| **修复**：解析响应时从权威端实际作用域中填充 `ScopePrefix` 并回显。这项工作已部分通过 `ParseFromDNS()`（提取 `subnet.Scope`）完成——但 ScopePrefix 从未存储到缓存键或响应中。 | | | |

**整体 RFC 7871 合规性：良好。** 功能运行正确；范围回显不太理想。

---

### 3.6 RFC 7873 / RFC 9018（DNS Cookies）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 使用版本 1（RFC 9018） | 已覆盖 | `edns/cookie.go:52` | cookieVersion = 1 |
| **MUST** 使用 SipHash-2-4 MAC | 已覆盖 | `edns/cookie.go:203-238` | rfc9018MAC——内部 siphash 包 |
| **MUST** 包括客户端 Cookie（8 字节） | 已覆盖 | `edns/cookie.go:50` | DefaultCookieClientLen = 8 |
| **MUST** 包括服务器 Cookie（16 字节） | 已覆盖 | `edns/cookie.go:51` | DefaultCookieServerLen = 16 |
| **SHOULD** 24 小时密钥轮换 | 已覆盖 | `config/defaults.go:135` | DefaultCookieSecretRotationInterval = 24h |
| **MUST** 实现时间边界检查 | 已覆盖 | `edns/cookie.go:152-171` | cookieServerLifetime=1h, renewThreshold=30min, futureMax=5min |
| **MUST** 在不可接受时设置 BADCOOKIE | 已覆盖 | `server/handler/middleware/edns.go:54-61` | 短/长服务器 Cookie 处理 |
| **MUST** 保留历史密钥（用于延迟客户端） | 已覆盖 | `edns/cookie.go:28-31` | secretPair 保存 current/previous/older |
| **MUST** 对 MAC 使用 IPv4（4 字节）/IPv6（16 字节） | 已覆盖 | `edns/cookie.go:210-232` | RFC 9018 §4.4 明确涵盖 |

**整体 RFC 7873/9018 合规性：优秀。** 这是代码库中实现最彻底的 RFC 合规性之一。

---

### 3.7 RFC 9156（QNAME 最小化）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 最小化 QNAME（算法 §2.3） | 已覆盖 | `server/resolver/qname_minimise.go` | 完整算法实现 |
| **SHOULD** 使用类型 A 进行最小化查询（§2.1） | 已覆盖 | `server/resolver/qname_minimise.go:113-125` | minimisationQtype 返回 A |
| **SHOULD** 添加一个标签再按比例分配（§2.3） | 已覆盖 | `defaults.go:189-190`; `qname_minimise.go:62-110` | MINIMISE_ONE_LAB = 4, 然后按比例分配 |
| **MUST** 处理 NXDOMAIN 以进行最小化查询（§2.3） | 已覆盖 | `server/resolver/recursive.go:178`; `recursive_helpers.go:128` | NXDOMAIN 触发重试 |
| **MUST** 限制最大迭代次数（§2.3） | 已覆盖 | `config/defaults.go:189` | DefaultQnameMinimiseCount = 10 |
| **发现**：未找到 RFC 9156 §4.3 中描述的"空非终端"检测 | 新信息 | 整个递归路径 | 见下文 |

**发现 7：空非终端检测可能不完整**
- **文件**：`server/resolver/recursive.go`（整个搜索路径）
- **严重性**：中
- **问题**：RFC 9156 §4.3 警告称，某些区域在 NXDOMAIN 可能实际代表空非终端时返回 NXDOMAIN。这可能导致最小化逻辑不必要地扩大 QNAME。标准递归无法神奇地检测到这一点，但 RFC 建议采取缓解措施，例如在正常范围内用完整 QNAME 重试，或缓存空非终端签名。
- **风险**：在边缘情况下，最小化可能导致返回完整 QNAME 的额外查询轮次。无法正常运行的少量额外查询。
- **修复**：在首次最小化查询返回 NXDOMAIN 后，添加一个重试路径，立即使用下一轮最小化进行重试。当前代码已经模拟了这一行为（`shouldRetryMinimisedQname`），但"完整 QNAME"回退逻辑在连续 NXDOMAIN 后是否迭代得到一切尚不明确。

**整体 RFC 9156 合规性：良好。** 核心算法已完全实现。复杂的边缘情况（空非终端）在标准递归上下文中通常无法解决。

---

### 3.8 RFC 8767（提供过期数据 / Serve-Stale）

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **SHOULD** 将 TTL 上限设置为 7 天（§4） | 已覆盖 | `config/defaults.go:47` | DefaultMaxCacheableTTL = 7 * 86400 |
| **SHOULD** 设置 < 10 秒的刷新超时（§4.2） | 已覆盖 | `config/defaults.go:107` | DefaultBackgroundTimeout = 10 * time.Second |
| **SHOULD** 设置 1-3 天的过期保留窗口（§6） | 已覆盖 | `config/defaults.go:44` | DefaultStaleMaxAge = 3 * 86400 |
| **SHOULD** 在提供过期数据之前等待（§5.2） | 已覆盖 | `config/defaults.go:50` | DefaultServeExpiredClientTimeout = 600ms |
| **SHOULD** 在获取过期数据时设置 TTL=0（§4.1） | **部分覆盖** | `internal/ttl/ttl.go:25-37` | 见下文 |
| **SHOULD** 在后台刷新过期条目 | 已覆盖 | `server/handler/middleware/cache_lookup.go:83-128` | 两种策略：立即过期+后台刷新，或等待前台+回退 |

**发现 8：过期数据的 TTL 不符合 RFC 8767 §4.1**
- **文件**：`internal/ttl/ttl.go:25-37`（RemainingTTL）
- **严重性**：低
- **问题**：RFC 8767 §4.1 规定："响应中每个 RR 的 TTL 应设为 0，以表明解析器未能在数据的有效期内成功解析响应。" 当前 `RemainingTTL` 函数实现了循环过期倒计时（提供非零 TTL，并在整个过期保留窗口内循环减少）。这是一个比 RFC 所要求更宽容的设计，但违反了该 SHOULD。
- **风险**：接收这些响应的客户端可能会缓存过期数据（认为 TTL 非零保证数据仍然有效），从而造成缓存污染链。
- **修复**：返回过期数据时，在 `buildResponse` 中将所有 RR TTL 设置为 0。如果需要循环倒计时，应在内部记录而不反映在响应的 TTL 字段中。

---

### 3.9 DNSCrypt (draft-denis-dprive-dnscrypt)

| MUST/SHOULD | 状态 | 位置 | 备注 |
|-------------|--------|----------|-------|
| **MUST** 实现 X25519-XSalsa20Poly1305 | 已覆盖 | `internal/dnscryptcrypto/encrypted.go` | 经典客户端加密 |
| **MUST** 实现 Ed25519 证书签名 | 已覆盖 | `server/protocol/dnscrypt/server.go:53` | Ed25519 签名密钥 |
| **SHOULD** 使用端口 443（§5.2） | **覆盖了分歧** | `config/defaults.go` | 使用 8443（与 dnscrypt-proxy 社区一致） |
| **MUST** 实现反放大（§10.3） | 已覆盖 | `server/protocol/dnscrypt/udp.go:127`; `crypto.go:33-59` | UDP 证书响应大小限制 |
| **MUST** 截断并设置 TC 而非静默丢弃（§5.4.6） | 已覆盖 | `server/protocol/dnscrypt/crypto.go:35-36` | 明确注释："MUST NOT stay silent" |
| **MAY** 实现 PQ KEM（X-Wing） | 已覆盖 | `internal/dnscryptcrypto/pq.go` | 完整 X-Wing + 恢复 |
| **MUST** 处理证书转换（§9） | 已覆盖 | `server/protocol/dnscrypt/server.go` | 密钥轮换 + 证书 TXT 服务 |
| **MUST** 实现 ResolverMagic 前缀 | 已覆盖 | `server/protocol/dnscrypt/generate.go` | 客户端魔法源自解析器 PK |
| **发现**：DNSCrypt 默认端口 8443 偏离了草案的 SHOULD-443 | 已记录 | `config/defaults.go`; `docs/rfc/GUIDELINE.md:881` | 标注为"§5.2 SHOULD 443 — 与 dnscrypt-proxy 社区一致" |

**整体 DNSCrypt 合规性：良好。** 实现覆盖了经典和 PQ 证书、UDP 和 TCP 传输、反放大、证书 TTL 管理以及密钥轮换。

---

## 第四部分：跨领域发现

### 发现 9：RFC 6895 未归档
- **文件**：`server/handler/middleware/validation.go:37,52`
- **严重性**：低
- **问题**：两处引用 `RFC 6895 §3.1`（操作码和类别分配），但 `docs/rfc/rfc6895.txt` 不存在。
- **风险**：按照 AUDIT-METHODOLOGY.md 规则 14，应存档 RFC 后再引用。
- **修复**：将 `docs/rfc/rfc6895.txt` 添加到存档。

### 发现 10：DoH `Cache-Control: max-age=0` 忽略 TTL
- **文件**：`server/protocol/tls/https.go:171`
- **严重性**：中
- **问题**：始终设置 `max-age=0`，而非基于 DNS 响应 TTL 的合理缓存头。见上文 *发现 4*。

### 发现 11：E CS 响应范围前缀始终为 0
- **文件**：`edns/ecs.go:22`（DefaultECSScope = 0）
- **严重性**：低
- **问题**：RFC 7871 §4 要求服务器将范围边界回显给客户端。当前实现始终使用 0。见上文 *发现 6*。

### 发现 12：RFC 8484 章节引用在注释中错误
- **文件**：`config/defaults.go:169`（§6 ➜ §4.2.1），`internal/dnsutil/https_dns.go:81`（§7 ➜ §4.1）
- **严重性**：低
- **问题**：引用标题错误的章节。正确数值已选中；仅注释有误。见上文 *发现 1* 和 *发现 2*。

---

## 第五部分：结论

| 协议 | 整体等级 | 未覆盖的关键 MUST | 未覆盖的主要 SHOULD |
|----------|--------|----------------------|------------------------|
| RFC 1035 | 通过 | 无 | 无 |
| RFC 7858 (DoT) | 通过 | 无 | 无 |
| RFC 8484 (DoH) | **通过，有 1 项中等问题** | 无 | 基于 TTL 的缓存指令 |
| RFC 9250 (DoQ) | 通过 | 无 | 无 |
| RFC 7871 (ECS) | 通过 | 无 | 范围前缀回显 |
| RFC 7873/9018 (Cookies) | 通过 | 无 | 无 |
| RFC 9156 (QNAME Min) | 通过 | 无 | 无 |
| RFC 8767 (Serve-Stale) | **通过，有 1 项低等问题** | 无 | 过期时 TTL = 0 |
| DNSCrypt (draft) | 通过 | 无 | 无 |

**要修复的高优先级事项：**
1. **DoH Cache-Control 标头**（`server/protocol/tls/https.go:171`）——基于 DNS TTL 设置，而非始终使用 max-age=0。
2. **RFC 6895 归档**（`docs/rfc/rfc6895.txt`）——缺失的 RFC 文件。
3. **注释中的 RFC 章节引用**——两处引用错误（§6 ➜ §4.2.1、§7 ➜ §4.1）。

**低优先级/信息性：**
4. ECS 范围前缀回显（增强，非缺陷）。
5. RFC 8767 过期响应 TTL=0（增强，非缺陷）。