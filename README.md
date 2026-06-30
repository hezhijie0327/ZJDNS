# ZJDNS Server

🚀 高性能递归 DNS 解析服务器，基于 Go 语言开发。支持 LRU 内存缓存（落盘持久化）、DNSSEC 验证、ECS、DoT/DoQ/DoH/DoH3 等高级功能。

> ⚠️ **警告**
> 本项目尚未在生产环境中得到充分验证。请勿在生产环境中使用。

---

## 🌟 核心特性

### 🔧 DNS 解析核心

- **递归 DNS 解析**：完整递归查询算法，从 13 组根服务器逐步解析至 TLD 和权威服务器
- **上游 DNS 转发**：主/备上游并发查询 + 首胜策略（First-Win），上游优先，失败时备路结果立即可用
- **混合模式**：可同时配置上游 DNS 和内置递归解析器（`builtin_recursive`）
- **SOCKS5 代理**：每上游可选 SOCKS5 代理（TCP CONNECT + UDP ASSOCIATE），规避 DNS 屏蔽/劫持，所有协议 + 递归模式全覆盖
- **TCP/DoT/DoQ 连接池**：TCP/DoT RFC 7766 查询流水线 + DoQ QUIC 原生 stream 复用，连接失败回退单次连接
- **CNAME 链解析**：多级 CNAME 追踪，防循环（最大 16 级）
- **A/AAAA 延迟探测**：统一引擎 + 多协议（ping/tcp/udp/http/https/http3）速度检测，按最快顺序重排，去重缓存避免重复探测，UDP 支持任意端口通用检测
- **DNS 重写**：精确域名匹配 + 客户端 IP 过滤 + 自定义响应码

### 🛡️ 安全与防御

- **CIDR 过滤**：基于标签的 IP 过滤，支持文件/内联规则，IPv4 位运算优化匹配
- **DNS 劫持防护**：根/TLD 越权响应检测，UDP→TCP 自动回退
- **DNSSEC 密码学验证**：递归模式完整信任链（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 已验证否定验证（RFC 5155），上游模式 AD 标志信任，`dnssec_enforce` 开关控制 bogus 响应拒绝，EDE 错误码传播
- **ECS 支持**：EDNS 客户端子网，支持 auto/auto_v4/auto_v6 自动检测
- **DNS Cookie**：HMAC-SHA256 服务端 Cookie，密钥无缝轮换，入口早期验证 (RFC 7873)
- **扩展 DNS 错误 (EDE)**：24 种 EDE 代码，DNSSEC 失败自动映射（EDE 6/9/10）
- **路径安全**：`filepath.Clean` + 绝对路径解析 + 符号链接拒绝 + 危险目录拦截

### 🔐 安全传输协议

| 协议                       | 端口 | 说明             |
| -------------------------- | ---- | ---------------- |
| **DoT** (DNS over TLS)     | 853  | TLS 1.3 加密     |
| **DoQ** (DNS over QUIC)    | 853  | QUIC 协议，0-RTT |
| **DoH** (DNS over HTTPS)   | 443  | HTTP/2 加密      |
| **DoH3** (DNS over HTTP/3) | 443  | HTTP/3 加密      |
| **DNSCrypt** (DNS Encryption) | 8443 | DNSCrypt v2 加密 |

- **内核 TLS 卸载 (KTLS)**：TCP TLS（DoT/DoH）支持 Linux 内核 TLS 卸载，零拷贝加解密，不支持时静默回退用户态。服务端 TX/RX 可通过 `server.tls.ktls.kernel_tx` / `kernel_rx` 独立控制
- **统一证书管理**：自签名 ECDSA P-384 CA，动态签发
- **DNS 填充 (RFC 7830)**：安全连接填充至 468 字节
- **DNSCrypt v2**：`github.com/AdguardTeam/dnscrypt`，支持 XSalsa20-Poly1305 / XChacha20-Poly1305，UDP + TCP 双通道，Ed25519 证书签名，密钥可配置或自动生成（`-generate-dnscrypt-keys` 预生成）
- **DDR 自动发现 (RFC 9461/9462)**：SVCB 记录自动生成

### 💾 缓存系统

- **固定容量**：`size` 指定缓存上限（字节），默认 4 MB
- **LRU 内存缓存**：RLock 读取（零读争用），atomic 访问时间淘汰，TTL 下限保护（10s）
- **磁盘持久化**：gob 快照，启动恢复，定期落盘 (默认 30s)，原子写入
- **过期缓存服务 (RFC 8767)**：上游不可用时返回过期缓存（最大 30 天）
- **预取机制**：TTL 剩余 ≤40% 时后台刷新
- **ECS 感知缓存**：基于客户端子网分区
- **PTR 反查优化**：IP→域名索引，O(1) 反查

### ⚡ 性能优化

- **锁无关统计**：全部计数器使用 `atomic.Uint64`，热路径无 mutex
- **无锁 RNG**：`math/rand/v2.IntN()` 替代自定义 mutex RNG
- **对象池**：`sync.Pool` 复用 `dns.Msg` 和 `[]byte`
- **CIDR IPv4 位运算**：uint32 掩码匹配，避免 `net.IPNet.Contains`
- **延迟探测去重**：FNV hash 缓存探测结果，TTL 控制避免高 QPS 下重复探测
- **HTTP 探测连接池**：按 (端口, TLS, HTTP3) 缓存客户端，避免重复 TLS 握手
- **TCP/DoT 流水线**：单连接 16 路并发查询，reader goroutine 按 DNS ID 分发响应
- **连接池**：TCP/DoT/DoQ 每上游 4 连接上限，容量背压，死连接自动驱逐重建
- **并发查询**：errgroup + 自适应并发限制 + 首胜即取消
- **正则编译一次**：IP 检测 regex 包级编译

### 📊 统计与监控

- 请求计数器（按协议：UDP、TCP、DoT、DoQ、DoH、DoH3、DNSCrypt）
- 缓存命中率、重写次数、劫持检测、过期响应、预取次数
- JSON 日志输出 + 定期重置（`log_level` 可配：error/warn/info/debug）
- **pprof**：`http://127.0.0.1:6060/debug/pprof/`

---

## 📜 支持的 RFC 标准

| RFC                                                     | 标准名称                                   | 实现功能                                 |
| ------------------------------------------------------- | ------------------------------------------ | ---------------------------------------- |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html) | SOCKS Protocol Version 5                   | SOCKS5 代理客户端                        |
| [RFC 3597](https://www.rfc-editor.org/rfc/rfc3597.html) | Handling Unknown DNS RR Types              | 未知记录类型回退                         |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html) | DNS Security Introduction and Requirements | DNSSEC 基础                              |
| [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034.html) | Resource Records for DNSSEC                | RRSIG/NSEC/DNSKEY/DS 类型                |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html) | Protocol Modifications for DNSSEC          | 信任链 + AD/CD 标志                      |
| [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155.html) | NSEC3 Hashed Authenticated Denial          | NSEC3 已验证否定 + RRSIG 验证            |
| [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766.html) | DNS Transport over TCP                     | TCP/DoT 连接复用 + 查询流水线 + 乱序响应 |
| [RFC 7830](https://www.rfc-editor.org/rfc/rfc7830.html) | EDNS(0) Padding                            | DNS 响应填充                             |
| [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html) | DNS over TLS (DoT)                         | TLS 加密传输                             |
| [RFC 7871](https://www.rfc-editor.org/rfc/rfc7871.html) | EDNS Client Subnet (ECS)                   | 客户端子网                               |
| [RFC 7873](https://www.rfc-editor.org/rfc/rfc7873.html) | DNS Cookies                                | Cookie 机制                              |
| [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) | DNS over HTTPS (DoH)                       | HTTPS 加密传输                           |
| [RFC 8767](https://www.rfc-editor.org/rfc/rfc8767.html) | Serving Stale DNS Answers                  | 过期缓存服务                             |
| [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914.html) | Extended DNS Errors (EDE)                  | 扩展错误码                               |
| [RFC 9018](https://www.rfc-editor.org/rfc/rfc9018.html) | DNS Cookies for TLS                        | TLS Cookie                               |
| [RFC 9250](https://www.rfc-editor.org/rfc/rfc9250.html) | DNS over QUIC (DoQ)                        | QUIC 加密传输                            |
| [RFC 9461](https://www.rfc-editor.org/rfc/rfc9461.html) | SVCB/HTTPS RR for DNS                      | DDR SVCB 记录                            |
| [RFC 9462](https://www.rfc-editor.org/rfc/rfc9462.html) | Discovery of Designated Resolvers          | DDR 自动发现                             |
| [DNSCrypt](https://dnscrypt.info/protocol)               | DNSCrypt v2 Protocol                       | DNSCrypt 加密传输                        |

---

## 🏗️ 包结构

```
zjdns/
├── main.go / version.go           # Entry point + ldflags variables
├── cli/                           # CLI helper functions
├── internal/
│   ├── log/                       # Logger, TimeCache
│   ├── pool/                      # sync.Pool (MessagePool, BufferPool)
│   ├── dnsutil/                   # DNS utilities (NormalizeDomain, HandlePanic)
│   ├── ipdetect/                  # Public IP detection for ECS
│   └── latency/                   # Unified latency probe engine
├── config/                        # Configuration (types, loader, defaults)
├── edns/                          # EDNS(0) extensions (ECS, Cookie, EDE, Padding)
├── cache/                         # LRU memory cache + disk persistence
├── cidr/                          # CIDR IP filtering
├── rewrite/                       # Domain rewrite rules
├── stats/                         # Lock-free atomic metrics
└── server/                        # Core server
    ├── client/                    # Outbound query client (UDP, TCP, DoT, DoQ, DoH, DoH3, SOCKS5)
    │   └── pool/                  # TCP/DoT/QUIC connection pools
    ├── resolver/                  # Recursive + upstream DNS resolution
    ├── dnscrypt/                  # DNSCrypt v2 server wrapper (AdGuardTeam/dnscrypt)
    ├── security/                  # DNSSEC + hijack detection
    ├── tls/                       # Secure transport listeners (DoT, DoQ, DoH, DoH3)
    └── latency/                   # Client-facing latency probe adapter
```

---

## 📋 使用示例

### 生成配置

```bash
./zjdns -generate-config > config.json
```

### 启动服务器

```bash
./zjdns -config config.json   # 指定配置
./zjdns                        # 默认配置（纯递归 + 内存缓存）
./zjdns -version                              # 版本信息
./zjdns -generate-dnscrypt-keys example.com    # 生成 DNSCrypt 密钥对
```

### 测试解析

```bash
dig @127.0.0.1 -p 53 example.com              # UDP
dig @127.0.0.1 -p 53 example.com +tcp          # TCP
kdig @127.0.0.1 -p 853 example.com +tls        # DoT
kdig @127.0.0.1 -p 853 example.com +quic       # DoQ
kdig @127.0.0.1 -p 443 example.com +https      # DoH
# DNSCrypt 需要使用 dnscrypt-proxy 或兼容客户端
```

### DNSSEC 验证

```bash
# 测试 bogus 委托（应返回 SERVFAIL + EDE 6）
kdig dnssec-failed.org a +dnssec @127.0.0.1

# 测试有效 DNSSEC（应返回 NOERROR + AD 标志）
kdig cloudflare.com a +dnssec @127.0.0.1
```

### 性能监控

```bash
curl http://127.0.0.1:6060/debug/pprof/heap    # 内存分析
curl http://127.0.0.1:6060/debug/pprof/profile # CPU 分析
```

---

## 🛠️ 开发

### 构建

```bash
go build -o zjdns

# 带版本信息
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns

# Docker
docker build -t zjdns .
```

### 代码质量

```bash
golangci-lint run && golangci-lint fmt
```

---

## 📝 许可证

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
