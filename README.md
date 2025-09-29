# ZJDNS Server

🚀 高性能递归 DNS 解析服务器，基于 Go 语言开发，支持 Redis 缓存、DNSSEC 验证、ECS、DoT/DoQ 等高级功能。

> ⚠️ **警告**
> 本项目为 Vibe Coding 产物，代码结构复杂且未经充分生产环境验证，请勿用于生产环境

## ✨ 功能特点

### 🔧 核心功能

- **递归 DNS 解析**：完整实现 DNS 递归查询算法，从根服务器开始逐级解析
- **智能协议协商**：同时支持 UDP 和 TCP 协议，**当 UDP 响应被截断或超过缓冲区大小时，自动回退到 TCP 协议**，确保大响应数据的完整传输
- **CNAME 链解析**：智能处理 CNAME 记录链，防止循环引用，支持多级 CNAME 解析
- **并发查询**：高性能并发处理，支持连接池管理
- **DNS 重写功能**：支持精确匹配的域名重写规则，可实现域名过滤和重定向；支持自定义响应码（如 NXDOMAIN、SERVFAIL 等）和 DNS 记录（如 A、AAAA、CNAME 等）的返回
- **混合模式**：可同时配置上游 DNS 服务器和递归解析器，实现灵活的查询策略
- **网络质量感知排序**：对解析结果进行网络延迟测试并按质量排序，优先返回网络质量最佳的结果

### 🛡️ 安全与防御特性

- **DNS 劫持预防**：主动检测并智能应对来自根服务器的越权响应。
  - **第一步**：当检测到根服务器直接返回非根域名的最终记录时，判定为 DNS 劫持。
  - **第二步**：**自动切换到 TCP 协议进行重试**，以绕过常见的 UDP 污染。
  - **第三步**：如果 TCP 查询结果**依然**被劫持，则彻底拒绝该响应，从源头上防止污染。
- **DNSSEC 验证**：完整的 DNSSEC 支持和验证，可设置服务器强制验证，支持 AD 标志传递
- **ECS 支持**：EDNS Client Subnet，提供地理位置感知的解析，支持`auto`、`auto_v4`、`auto_v6`自动检测或手动 CIDR 配置
- **递归深度保护**：防止恶意递归查询攻击，可配置最大递归深度
- **IP 过滤**：基于 CIDR 的 IP 过滤功能，可区分可信 IP 和非可信 IP，实现精细化流量控制
- **内存安全**：采用对象池管理，修复潜在内存泄漏，提升长时间运行稳定性

### 🔐 安全传输协议

- **DNS over TLS (DoT)**：支持标准的 DNS over TLS 协议 (RFC 7818)，在端口`853`上提供加密的 DNS 查询，防止中间人窃听和篡改。
- **DNS over QUIC (DoQ)**：支持前沿的 DNS over QUIC 协议，利用 QUIC 协议的 0-RTT、多路复用和连接迁移等特性，提供更低延迟和更高可靠性的加密 DNS 服务。
- **DNS over HTTPS (DoH/DoH3)**：同时支持 HTTP/2 和 HTTP/3 的 DoH 服务，在端口`443`上提供基于 HTTPS 的 DNS 查询。
- **统一证书管理**：DoT、DoQ 和 DoH 共享同一套 TLS 证书配置，简化部署。
- **连接复用与保活**：为安全连接实现连接复用和 TCP Keep-Alive，提升性能和稳定性。

### 📦 DNS Padding

- **RFC 7830 标准支持**：实现 DNS Padding 功能，通过在 EDNS0 中添加填充字节，使 DNS 响应数据包大小标准化，有效对抗基于流量大小的指纹识别和审查。
- **智能块大小填充**：采用推荐的 128 字节块大小进行填充，平衡隐私保护和带宽效率。
- **按需启用**：可通过配置文件灵活开启或关闭此功能，**仅对安全连接（DoT/DoQ/DoH）生效**。

### 📍 DDR (Discovery of Designated Resolvers) 功能

- **自动发现支持**：支持 RFC [9461](https://www.rfc-editor.org/rfc/rfc9461.html)/[9462](https://www.rfc-editor.org/rfc/rfc9461.html) DNS SVCB 记录，用于自动发现安全 DNS 服务器
- **SVCB 记录生成**：自动生成 DoT、DoH、DoQ 的 SVCB 记录，支持 IPv4 和 IPv6 提示
- **灵活配置**：通过配置文件指定 DDR 域名和对应的 IP 地址，支持 IPv4 和 IPv6 双栈配置
- **智能响应**：当收到 `_dns.resolver.arpa` `_dns.dns.example.org` `_non_53_port._dns.dns.example.org` 的 SVCB 查询时，自动返回配置的加密 DNS 服务信息

### 🚀 网络质量测试 (SpeedTest)

- **多协议支持**：支持 ICMP、TCP 和 UDP 等多种协议进行网络质量测试
- **灵活配置**：可配置不同的测试端口和超时时间，适应不同网络环境
- **智能排序**：根据测试结果对 DNS 解析结果进行延迟排序，优先返回网络质量最佳的结果
- **缓存机制**：内置测试结果缓存，避免重复测试，提高响应速度
- **并发处理**：支持并发测试多个 IP 地址，提高测试效率

### 💾 缓存系统

- **双模式运行**：
  - **无缓存模式**：适合测试环境，零配置启动，纯递归解析
  - **Redis 缓存模式**：生产环境推荐，支持分布式部署，数据持久化
- **智能 TTL 管理**：灵活的 TTL 策略，支持最小/最大 TTL 限制
- **过期缓存服务 (Serve Stale)**：在上游服务器不可用时，提供过期缓存服务，极大提高系统可用性
- **预取机制**：后台自动刷新即将过期的缓存，减少用户等待时间
- **ECS 感知缓存**：基于客户端地理位置（EDNS Client Subnet）的缓存分区，提供精准的本地化解析
- **访问节流**：对缓存的访问时间更新操作进行节流，减轻 Redis 压力

### 🕵️ 请求追踪系统

- **全链路追踪**：为每个 DNS 请求生成唯一 ID，详细记录处理过程中的每一步操作和耗时。
- **智能日志**：在`DEBUG`级别下，输出带时间戳的请求处理步骤，极大简化调试和性能分析。
- **摘要报告**：在`INFO`级别下，输出请求处理摘要，包括缓存命中状态、总耗时、使用的上游服务器等关键信息。

## 🏗️ 系统架构

```mermaid
graph TD
    A[DNS Client] --> B[ZJDNS Server]
    subgraph ZJDNS_Server ["ZJDNS Server 内部架构"]
        direction TB
        B --> C[请求处理器 Request Handler]
        C --> D[DNS重写器 DNS Rewriter]
        C --> E[缓存管理器 Cache Manager]
        C --> F[连接池 Connection Pool]
        C --> G[查询引擎 Query Engine]

        E --> H[(Redis)]
        F --> I[安全连接池 Secure Conn Pool]
        F --> J[UDP/TCP 连接池]

        G --> K[上游服务器管理器 Upstream Manager]
        G --> L[递归解析器 Recursive Resolver]
        G --> M[DNSSEC验证器 DNSSEC Validator]
        G --> N[IP过滤器 IP Filter]
        G --> O[劫持预防器 Hijack Prevention]
        G --> P[ECS管理器 ECS Manager]
        G --> Q[Padding管理器 Padding Manager]
        G --> R[网络质量测试器 Speed Tester]

        I --> S[DoT/TLS 服务器]
        I --> T[DoQ/QUIC 服务器]
        I --> U[DoH/HTTP3 服务器]

        L --> V[根服务器 Root Servers]
    end
    K --> W[上游DNS服务器]
    L --> W
```

## 📁 项目文件结构

```bash
zjdns/
    ├── main.go                 # 程序入口点
    ├── config.go               # 配置文件解析和管理
    ├── dns_server.go           # DNS服务器主逻辑
    ├── dns_client.go           # DNS客户端实现
    ├── dns_rewriter.go         # DNS重写规则处理
    ├── dns_hijack.go           # DNS劫持检测与防护
    ├── upstream_manager.go     # 上游服务器管理
    ├── securedns_manager.go    # 安全DNS管理器（DoT/DoQ/DoH）
    ├── securedns_client.go     # 安全DNS客户端实现
    ├── securedns_error.go      # 安全DNS错误处理
    ├── edns_manager.go         # EDNS支持管理（包括ECS和Padding）
    ├── cache_null.go           # 空缓存实现（无缓存模式）
    ├── cache_redis.go          # Redis缓存实现
    ├── connection_manager.go   # 连接池管理
    ├── ip_filter.go            # IP过滤器
    ├── ip_speedtest.go         # 网络质量测试功能
    ├── task_manager.go         # 任务管理器（缓存预取等后台任务）
    ├── resource_manager.go     # 资源管理器
    ├── logging.go              # 日志系统
    ├── utils.go                # 工具函数
    ├── constants.go            # 常量定义
    ├── types.go                # 类型定义
    ├── Dockerfile              # Docker镜像构建文件
    └── README.md               # 项目说明文档
```

## 📋 使用示例

### 生成示例配置文件

```bash
./zjdns -generate-config > config.json
```

### 启动服务器

```bash
# 使用默认配置（纯递归模式，无缓存）
./zjdns

# 使用配置文件启动（推荐）
./zjdns -config config.json
```

## 📝 许可证

本项目采用 MIT 许可证，详见 [LICENSE](LICENSE) 文件。

## 🛠️ 开发工具

### golangci-lint

在提交代码前，请使用 [golangci-lint](https://golangci-lint.run/) 进行代码检查。

安装 golangci-lint：

```bash
brew install golangci-lint
```

运行检查：

```bash
golangci-lint run
```

运行代码格式化：

```bash
golangci-lint fmt
```

提交代码前请确保 golangci-lint 检查通过，以保证代码质量和一致性。

## 🙏 致谢

感谢以下开源项目：

- [miekg/dns](https://github.com/miekg/dns) - Go DNS 库
- [redis/go-redis](https://github.com/redis/go-redis) - Redis Go 客户端
- [quic-go/quic-go](https://github.com/quic-go/quic-go) - QUIC 协议实现
- [bluele/gcache](https://github.com/bluele/gcache) - Go 通用缓存库
