# 33 · 交叉分析：常量提取

> 审计 Agent：Phase 2b · Constants
> 范围：全项目魔法数字扫描、RFC 推荐值对比、跨包重复常量


# 常量审计报告

## 1. 数字字面量审计（3+ 位应提取为命名常量的值）

### 严重：应提取为命名常量

| # | 文件:行 | 值 | 问题 | 风险 | 修复建议 |
|---|---------|-----|------|------|---------|
| 1 | `cache/async_writer.go:155`、`cache/stats.go:101` | 86400 | 两处内联使用 `now / 86400` 计算天数，但 `config/defaults.go` 已用 `86400`（如 `DefaultStaleMaxAge = 3 * 86400` 和 `DefaultMaxCacheableTTL = 7 * 86400`），`internal/dns64/dns64.go` 也有 `maxSynTTL = 600`。未统一为命名常量 | 值含义不清晰；若需修改秒/天转换，需全文搜索 | 提取 `SecondsPerDay = 86400` 至 `config/defaults.go` 或 `internal/dnsutil`，所有内联 86400 引用替换之 |
| 2 | `server/upstream/socks5/socks5.go:363` | 65535 | 端口验证内联 `port > 65535`，而 `config/defaults.go:184` 已定义 `MaxPortNumber = 65535` | 未来端口上限变更需改多处 | 引用 `config.MaxPortNumber` |
| 3 | `server/upstream/socks5/socks5.go:243` | 255 | SOCKS5 用户名/密码长度检查内联 `len(d.username) > 255`，而 `config/defaults.go:300` 已定义 `SOCKS5MaxAuthLen = 255` | RFC 1929 长度上限硬编码 | 引用 `config.SOCKS5MaxAuthLen` |

### 中等：建议提取为命名常量

| # | 文件:行 | 值 | 问题 | 风险 | 修复建议 |
|---|---------|-----|------|------|---------|
| 4 | `database/db.go:60` | 1000 | `bdb.GetSequence(..., 1000)` 带宽值内联，无注释说明为何是 1000 | 难以理解调优依据 | 提取 `DefaultEntrySeqBandwidth = 1000` 至 `database/db.go` 或 `config/defaults.go` |
| 5 | `server/protocol/dnscrypt/server.go:555,570` | 255、254 | `const maxChunk = 255` 和 `(len(escaped) + 254) / 255` 定义在函数体内 | 仅在该函数内使用，但定义过于局部 | 提取至文件级常量，注释标注为 DNSCrypt TCP chunk 分割 |
| 6 | `server/upstream/socks5/udp.go:286,358` | 1500 | SOCKS5 UDP MTU 检查内联 `if totalLen <= 1500`，而 `socks5.go:57` 已定义 `socks5WriteBufSize = 1500` | 同包已有命名常量，UDp.go 未引用 | 引用 `socks5WriteBufSize` 或提取公共 MTU 常量 |
| 7 | `internal/dnsutil/dnsutil.go:181` | 128 | `buf.Grow(128)` 预分配内联 | 128 作为典型行大小的依据不可见 | 提取命名常量并加注释 |
| 8 | `internal/stamp/encode.go:36` | 128 | `make([]byte, 0, 128)` 初始缓冲区大小内联 | 同上 | 提取命名常量 |

### 低等：边界值应引用已有常量

| # | 文件:行 | 值 | 问题 | 风险 | 修复建议 |
|---|---------|-----|------|------|---------|
| 9 | `config/validate.go:224` | 65535 | `port > 65535` 应引用 `config.MaxPortNumber` | 代码一致性 | 替换为 `config.MaxPortNumber` |
| 10 | `cache/store.go:325`、`config/ecs.go:40` | 128 | `bits := 128` 表示 IPv6 地址位数 | 128 作为地址位数的含义不明显 | 提取 `IPv6BitsLen = 128` 至公共包 |
| 11 | `server/upstream/plain/udp.go:488` | 2 | `rand.IntN(2)` 随机二选一 | 值 2 的含义（二进制选择）不明显 | 可提取 `binaryTieBreak = 2` |

---

## 2. config/defaults.go 常量值与 RFC/IETF 标准对比

| 常量 | 值 | RFC 引用 | RFC 推荐值 | 一致？ | 备注 |
|------|-----|----------|-----------|--------|------|
| `DefaultTLSPort` | "853" | RFC 7858 | 853 | ✓ | |
| `DefaultQUICPort` | "853" | RFC 9250 | 853 | ✓ | |
| `DefaultHTTPSPort` | "443" | RFC 8484 | 443 | ✓ | |
| `DefaultHTTP3Port` | "443" | DoH3 | 443 | ✓ | |
| `DefaultDTLSPort` | **"8853"** | RFC 8094 | **853** | **X 偏离** | 注释承认 RFC 要求 853，但自称"8853 广泛部署"。实际 IANA 未记录 8853 为 DNS-DTLS。这是 GB/T 或国产协议使用的端口，注释应明确说明 |
| `DefaultStaleMaxAge` | 259200 (3d) | RFC 8767 §6 | 1-3 天推荐 | ✓ | 取上限值 |
| `DefaultMaxCacheableTTL` | 604800 (7d) | RFC 8767 §4 | SHOULD cap 604800 | ✓ | |
| `DefaultDNSQueryTimeout` | 9s | RFC 8767 §4.2 | <10 秒 | ✓ | |
| `DefaultServeExpiredClientTimeout` | 600ms | RFC 8767 §5.2 | 无具体值 | N/A | 自选值，合理 |
| `DefaultQUICServerIdleTimeout` | 30s | RFC 9000 | 推荐 30s 防超时 | ✓ | |
| `DefaultTCPIdleTimeout` | **120s** | RFC 7766 §6.2.3 | **"几秒"量级** | **X 偏离** | 注释引用 §6.2.3，但该节建议服务器空闲超时"on the order of seconds"（几秒量级），120s 远超此范围。值可能出于操作需求，但 RFC 引用不准 |
| `DefaultCookieSecretRotationInterval` | 24h | RFC 7873 §7.1 | 默认 1 天，不超过 26h | ✓ | |
| `DefaultDOHMaxRequestSize` | 65535 | RFC 8484 §6 | 最大 65535 | ✓ | |
| `DefaultQnameMinimiseCount` | 10 | RFC 9156 §2.3 | 示例值 10 | ✓ | |
| `DefaultMinimiseOneLabel` | 4 | RFC 9156 §2.3 | "好值" 4 | ✓ | |
| `DefaultPaddingRequestBlockSize` | 128 | RFC 8467 | NDSS-PADDING 中使用的值 | ✓ | |
| `DefaultPaddingResponseBlockSize` | 468 | RFC 8467 | NDSS-PADDING 中使用的值 | ✓ | |
| `DefaultDNS64Prefix` | "64:ff9b::/96" | RFC 6052 §2.1 | 规定前缀 | ✓ | |
| `DefaultMaxNSEC3Iterations` | **150** | RFC 5155 §10.3 | **取决于密钥大小：1024→150, 2048→500, 4096→2500** | **△ 保守** | 固定 150 适用于 1024-bit RSA，对更大密钥偏保守。注释只说 "RFC 5155 §10.3" 但未说明选 150 的理由 |
| `DefaultPMTU` | 1280 | RFC 8094 §5 | SHOULD assume 1280 | ✓ | |
| `SOCKS5MaxAuthLen` | 255 | RFC 1929 §3 | 最多 255 | ✓ | |
| `DefaultQUICAddrCacheSize` | **128** | 注释说 "RFC 9000" | **RFC 9000 未规定具体缓存大小** | **X 注释误导** | RFC 9000 讨论地址验证令牌但未规定 LRU 缓存大小应为 128。注释暗示 RFC 要求此值，实为自选 |
| `DefaultTCPIdleTimeout` | 120s | RFC 7766 §6.2.3 | "几秒量级" | **X** | 见上文 |
| `DefaultPrefetchThresholdPercent` | 10 | — (无 RFC 引用) | — | N/A | 常见值，但注释无依据 |

### RFC 偏离汇总

| 严重度 | 问题 | 说明 |
|--------|------|------|
| **中等** | `DefaultDTLSPort = "8853"` | RFC 8094 规定 853，代码用 8853。若出于合规原因（如国内替代），注释应写明具体标准编号，而非含糊的"widely deployed" |
| **中等** | `DefaultTCPIdleTimeout = 120s` 引用 RFC 7766 §6.2.3 | RFC 建议"几秒量级"，120s 差两个数量级。如果运营商原因保留 120s，应更正注释（如"local policy: 120s to accommodate slow-provisioning resolvers"） |
| **低等** | `DefaultMaxNSEC3Iterations = 150` | 仅覆盖 1024-bit RSA 场景。注释应说明为何取最小值而非依赖密钥大小 |
| **低等** | `DefaultQUICAddrCacheSize = 128` 注释写 "RFC 9000" | RFC 9000 未规定该值，注释应改为 "implementation-chosen LRU capacity" |

---

## 3. 跨包重复定义常量

| # | 值 | 定义位置 | 问题 | 严重度 | 建议 |
|---|-----|---------|------|--------|------|
| 1 | 10000 | `config/defaults.go:36` (`DefaultMaxCacheEntries`)、`internal/pending/pending.go:31` (`maxPending`)、`server/handler/pending.go:51` (`pendingRequestCapacity`) | 三个独立 10000 含义不同（缓存条目数 vs 待处理请求数），但值恰好相同。若需调优，各自独立修改 | 低（巧合而非逻辑重复） | 可保留现状，但建议 `pending.go` 添加注释说明 10000 与 cache 的 10000 无关系 |
| 2 | 4096 | `config/defaults.go:282` (`DefaultDNSCryptUDPSize`)、`internal/dnscryptcrypto/proto.go:24` (`MaxDNSUDPPacketSize`)、`internal/pool/pool.go:29` (`RecursiveUDPBufferSize`)、`server/protocol/tls/server.go:83` (`TLSConnBufferSize`) | 四个包独立定义 4096（DNS UDP 最大载荷），`TLSConnBufferSize` 实际上是对 TLS 读缓冲区的初始分配 | 中 | `TLSConnBufferSize` 与 UDP 载荷不同——TLS 缓冲区大小应由管道流控决定而非 UDP MTU。建议将 `TLSConnBufferSize` 重命名并注释其不同用途，或引用公共常量 |
| 3 | 8192 | `internal/dnsutil/dnsutil.go:44` (`defaultPanicStackBufSize`)、`internal/pool/pool.go:30` (`SecureBufferSize`)、`server/upstream/socks5/socks5.go:58` (`socks5ReadBufSize`) | 三个 8192 各自追求的不同目的（栈转储缓冲区、安全连接缓冲区、SOCKS5 读缓冲区） | 低 | 含义不同，可保留现状 |
| 4 | 1500 | `internal/latency/probes.go:25` (`probeICMPReadBufSize`)、`server/upstream/socks5/socks5.go:57` (`socks5WriteBufSize`)、`server/upstream/socks5/udp.go:286,358` (内联) | ICMP 探针缓冲区、SOCKS5 写缓冲区都用 1500（标准以太网 MTU） | 中 | 提取公共常量 `StandardMTU = 1500` 至 `internal/dnsutil`，所有 1500 引用使用之 |
| 5 | 128 | `server/protocol/tlcp/certs.go:36`、`server/protocol/tls/certs.go:31` | 两个证书生成函数分别计算 `1 << 128` 作为序列号上限 | 中 | 完全相同逻辑重复。若 TLS 和 TLCP 证书逻辑独立可接受，但应提取常量如 `certSerialBits = 128` |
| 6 | 53 / 853 / 443 | `config/defaults.go` (string)、`cmd/zjdns/cli/probe.go` (int)、`internal/stamp/stamp.go` (int) | 端口号跨包重复定义，string 与 int 类型不一致 | 低 | `config/defaults.go` 中端口为 string（用于配置解析），其他包为 int（用于计算逻辑）。这种类型不匹配是设计选择，但 `stamp.go` 可引用 `config.DefaultProbePortDNS` 而非定义自己的 `DefaultDNSPort` |
| 7 | 30 * time.Second | 6 处（QUIC、TCP keepalive、DTLS、递归超时、后台关闭、根下载） | 概念不同但值相同 | 低 | 纯巧合，各自有不同语义，无需合并 |

---

## 4. time.Duration 常量单位注释检查

### config/defaults.go 中缺少单位/用途注释的常量

| 常量 | 行号 | 当前注释 | 问题 |
|------|------|---------|------|
| `DefaultPrefetchThrottleInterval` | 51 | **无** | 缺少用途说明。注释应解释"prefetch throttle"的触发条件和间隔意义 |
| `DefaultPoisonProbeTimeout` | 71 | **无** | 缺少超时溢出时的行为说明（如"比 DNS 查询超时短，确保防污染探测不阻塞管道"） |
| `DefaultECSRefreshInterval` | 136 | **无** | 缺少 refresh 的含义（是全量刷新还是增量？触发条件是啥？） |
| `DefaultLatencyProbeTimeout` | 230 | **无** | 缺少探测超时的容忍度说明 |
| `DefaultDNSCryptCertificateTTL` | 280 | **无** | 缺少证书 TTL 的含义（是服务器用还是客户端缓存用？） |
| `DefaultDNSCryptCertificateCacheTTL` | 283 | **无** | 同上 |
| `DefaultDNSCryptReadTimeout` | 284 | **无** | 缺少超时场景（读什么？单消息还是整个握手？） |
| `DefaultDNSCryptPQTicketLifetime` | 286 | **无** | 缺少 ticket 的生命周期安全考虑（与 `DefaultDNSCryptCertificateTTL` 的关系？） |
| `DefaultDNSCryptKeyOverlap` | 287 | **无** | 缺少 overlap 的含义（新旧密钥同时有效的时间窗口？） |

### 其他包中缺少注释的 time.Duration 常量

| 文件 | 常量 | 注释 |
|------|------|------|
| `edns/cookie.go:59-61` | `cookieServerLifetime`、`cookieRenewThreshold`、`cookieFutureMax` | 均有 RFC 7873 引用 ✓ |
| `internal/dnsutil/keepalive.go:18` | `defaultTCPKeepAlivePeriod = 30 * time.Second` | **无注释**——重复 `config.DefaultTCPKeepAlivePeriod` 但缺乏参考说明 |
| `internal/dnsutil/download.go:14` | `downloadTimeout = 30 * time.Second` | 有 "matches config.DefaultRootDownloadTimeout" 注释 ✓ |
| `internal/ipdetect/ipdetect.go:20-21` | 两个 timeout | 有 "matches config.DefaultIPDetect*" 注释 ✓ |

---

## 汇总

| 类别 | 严重 | 中 | 低 | 总计 |
|------|------|----|-----|------|
| 数字字面量 → 命名常量 | 3 | 5 | 3 | 11 |
| RFC 合规偏离 | 0 | 2 | 2 | 4 |
| 跨包重复常量 | 0 | 3 | 4 | 7 |
| Duration 注释缺失 | 0 | 4 | 5 | 9 |

**最高优先级修复：**
1. `DefaultDTLSPort = "8853"` — 要么改回 RFC 853 要么更新注释引用实际遵循的标准
2. `DefaultTCPIdleTimeout = 120s` 引用 RFC 7766 §6.2.3 注释不实
3. 三处 `86400` 内联使用应提取为 `SecondsPerDay` 命名常量
4. `Server/upstream/socks5/socks5.go:363` 和 `config/validate.go:224` 中的 `65535` 应引用 `config.MaxPortNumber`