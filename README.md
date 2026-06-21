# ZJDNS Server

🚀 高性能递归 DNS 解析服务器，基于 Go 语言开发。支持 LRU 内存缓存（落盘持久化）、DNSSEC 验证、ECS、DoT/DoQ/DoH/DoH3、速率限制等高级功能。

> ⚠️ **警告**
> 本项目尚未在生产环境中得到充分验证。请勿在生产环境中使用。

---

## 🌟 核心特性

### 🔧 DNS 解析核心

- **递归 DNS 解析**：完整递归查询算法，从 13 组根服务器逐步解析至 TLD 和权威服务器
- **上游 DNS 转发**：多上游并发查询 + 首胜策略（First-Win），降低延迟
- **混合模式**：可同时配置上游 DNS 和内置递归解析器（`builtin_recursive`）
- **TCP/DoT/DoQ 连接池**：TCP/DoT RFC 7766 查询流水线 + DoQ QUIC 原生 stream 复用，fallback 单次连接
- **智能协议协商**：UDP 截断自动回退 TCP
- **CNAME 链解析**：多级 CNAME 追踪，防循环（最大 16 级）
- **A/AAAA 延迟探测**：后台多协议（ping/tcp/udp/http/https/http3）速度检测，按最快顺序重排
- **DNS 重写**：精确域名匹配 + 客户端 IP 过滤 + 自定义响应码

### 🛡️ 安全与防御

- **速率限制**：全协议 per-IP token bucket，自动清理空闲客户端
- **CIDR 过滤**：基于标签的 IP 过滤，支持文件/内联规则，IPv4 位运算优化匹配
- **DNS 劫持防护**：根/TLD 越权响应检测，UDP→TCP 自动回退
- **DNSSEC 密码学验证**：递归模式完整信任链（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 认证拒绝验证（RFC 5155），上游模式 AD 标志信任，`dnssec_enforce` 开关控制 bogus 响应拒绝，EDE 错误码传播
- **ECS 支持**：EDNS 客户端子网，支持 auto/auto_v4/auto_v6 自动检测
- **DNS Cookie**：HMAC-SHA256 服务端 Cookie，密钥无缝轮换
- **扩展 DNS 错误 (EDE)**：24 种 EDE 代码，DNSSEC 失败自动映射（EDE 6/9/10）
- **路径安全**：`filepath.Clean` + 绝对路径解析 + 符号链接拒绝 + 危险目录拦截

### 🔐 安全传输协议

| 协议                       | 端口 | 说明             |
| -------------------------- | ---- | ---------------- |
| **DoT** (DNS over TLS)     | 853  | TLS 1.3 加密     |
| **DoQ** (DNS over QUIC)    | 853  | QUIC 协议，0-RTT |
| **DoH** (DNS over HTTPS)   | 443  | HTTP/2 加密      |
| **DoH3** (DNS over HTTP/3) | 443  | HTTP/3 加密      |

- **统一证书管理**：自签名 ECDSA P-384 CA，动态签发
- **DNS 填充 (RFC 7830)**：安全连接填充至 468 字节
- **DDR 自动发现 (RFC 9461/9462)**：SVCB 记录自动生成

### 💾 缓存系统

- **自适应容量**：`size=0` 时自动按系统内存 5% 分配（≈1KB/条目），也可手动指定
- **LRU 内存缓存**：RLock 读取（零读争用），atomic 访问时间淘汰，TTL 下限保护（10s）
- **磁盘持久化**：gob 快照，启动恢复，定时落盘，原子写入
- **过期缓存服务 (RFC 8767)**：上游不可用时返回过期缓存（最大 45 天）
- **预取机制**：TTL 剩余 ≤25% 时后台刷新
- **ECS 感知缓存**：基于客户端子网分区
- **PTR 反查优化**：IP→域名索引，O(1) 反查

### ⚡ 性能优化

- **锁无关统计**：16 个计数器全部 `atomic.Uint64`，热路径无 mutex
- **无锁 RNG**：`math/rand/v2.IntN()` 替代自定义 mutex RNG
- **对象池**：`sync.Pool` 复用 `dns.Msg` 和 `[]byte`
- **CIDR IPv4 位运算**：uint32 掩码匹配，避免 `net.IPNet.Contains`
- **TCP/DoT 流水线**：单连接 16 路并发查询，reader goroutine 按 DNS ID 分发响应
- **连接池**：TCP/DoT/DoQ 每上游 4 连接上限，容量背压，死连接自动驱逐重建
- **并发查询**：errgroup + 自适应并发限制 + 首胜即取消
- **正则编译一次**：IP 检测 regex 包级编译

### 📊 统计与监控

- 请求计数器（按协议：UDP、TCP、DoT、DoQ、DoH、DoH3）
- 缓存命中率、重写次数、劫持检测、过期响应、预取次数
- JSON 日志输出 + 定期重置（`log_level` 可配：error/warn/info/debug）
- **pprof**：`http://127.0.0.1:6060/debug/pprof/`

---

## 📜 支持的 RFC 标准

| RFC                                                     | 标准名称                                   | 实现功能                                 |
| ------------------------------------------------------- | ------------------------------------------ | ---------------------------------------- |
| [RFC 3597](https://www.rfc-editor.org/rfc/rfc3597.html) | Handling Unknown DNS RR Types              | 未知记录类型回退                         |
| [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html) | DNS Security Introduction and Requirements | DNSSEC 基础                              |
| [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034.html) | Resource Records for DNSSEC                | RRSIG/NSEC/DNSKEY/DS 类型                |
| [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html) | Protocol Modifications for DNSSEC          | 信任链 + AD/CD 标志                      |
| [RFC 5155](https://www.rfc-editor.org/rfc/rfc5155.html) | NSEC3 Hashed Authenticated Denial          | NSEC3 认证拒绝 + RRSIG 验证              |
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

---

## 🏗️ 包结构

```
zjdns/
├── main.go                          # 入口
├── version.go                       # ldflags 变量
├── internal/
│   ├── log/log.go                   # 日志 (Error/Warn/Info/Debug)
│   ├── pool/pool.go                 # MessagePool, BufferPool
│   ├── dnsutil/dnsutil.go           # 工具函数
│   ├── ipdetect/ipdetect.go         # 公网 IP 检测
│   └── sysmem/sysmem.go             # 系统内存检测
├── config/config.go                 # 配置类型 + 加载 + 验证 + DDR
├── edns/                            # EDNS(0) 扩展 (5 文件)
│   ├── edns.go                      # Handler, ApplyToMessage
│   ├── ecs.go                       # ECS 选项
│   ├── cookie.go                    # Cookie 生成/验证
│   ├── ede.go                       # EDE 错误码
│   └── padding.go                   # RFC 7830 填充
├── cache/                           # 缓存系统 (3 文件)
│   ├── cache.go                     # Store 接口, CacheEntry, 工具函数
│   ├── memory.go                    # MemoryCache, LRU 淘汰, PTR 索引
│   └── persist.go                   # 磁盘快照
├── cidr/cidr.go                     # Filter — IP 过滤
├── rewrite/rewrite.go               # Evaluator — 域名重写
├── stats/stats.go                   # Collector — 原子指标
└── server/                          # 核心服务
    ├── server.go                    # Server 生命周期
    ├── server_handlers.go           # 查询管道
    ├── client/                      # 出站查询 (7 文件 + pool/ 子包)
    │   ├── client.go                # Client, ExecuteQuery
    │   ├── tcp.go, dot.go, doq.go, doh.go, doh3.go, doh_request.go
    │   └── pool/                     # 连接池子包
    │       ├── tcp.go               # RFC 7766 TCP/DoT 连接池
    │       └── quic.go               # QUIC 连接池
    ├── resolver/                    # 解析策略 (7 文件)
    │   ├── resolver.go              # Resolver, 首胜+
    │   ├── upstream.go              # 上游并发查询
    │   ├── recursive.go             # 递归 walk
    │   ├── cname.go                 # CNAME 链
    │   ├── dnssec_chain.go          # DNSSEC 信任链
    │   ├── nameserver.go            # NS 并发查询
    │   └── zonecut.go               # 区域切割检测
    ├── tls/                         # 安全传输 (4 文件)
    │   ├── tls.go                   # Server, 证书
    │   ├── dot.go, doq.go, doh.go
    ├── security/                    # 安全 (4 文件)
    │   ├── security.go              # Guard
    │   ├── dnssec.go                # DNSSEC 记录存在检查
    │   ├── dnssec_crypto.go         # 完整密码学 DNSSEC 验证
    │   └── hijack.go                # 劫持检测
    ├── latency/probe.go             # 延迟探测
    └── ratelimit/ratelimit.go       # 速率限制
```

---

## 🔍 DNS 查询流程

```
1. Server.processDNSQuery() — 入口
2. rewrite.Evaluator.Evaluate() — 重写规则匹配
3. edns.Handler — 解析 ECS/Cookie/EDE
4. cache.Store.Get() — 命中 → CIDR 过滤 → 响应
5. resolver.Resolver.Query() — 上游(首胜) 或 递归
6. security.Guard — DNSSEC 验证 + 劫持检测
7. cidr.Filter.MatchIP() — 过滤 A/AAAA IP
8. 写入缓存 → 延迟探测 → 返回响应
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
./zjdns -version               # 版本信息
```

### 测试解析

```bash
dig @127.0.0.1 -p 53 example.com              # UDP
dig @127.0.0.1 -p 53 example.com +tcp          # TCP
kdig @127.0.0.1 -p 853 example.com +tls        # DoT
kdig @127.0.0.1 -p 853 example.com +quic       # DoQ
kdig @127.0.0.1 -p 443 example.com +https      # DoH
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

## 🙏 致谢

- [miekg/dns](https://github.com/miekg/dns) — Go DNS 库
- [quic-go/quic-go](https://github.com/quic-go/quic-go) — QUIC 协议实现
