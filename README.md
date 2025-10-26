# ZJDNS Server

🚀 高性能递归 DNS 解析服务器，基于 Go 语言开发，支持 Redis 缓存、DNSSEC 验证、ECS、DoT/DoQ/DoH 等高级功能。

- 🚀 High-performance recursive DNS resolution server written in Go, supporting Redis caching, DNSSEC validation, ECS, DoT/DoQ/DoH and other advanced features.

---

## ⚠️ 免责声明 | Disclaimer

> ⚠️ **警告 | Warning**
> 这个项目是一个 Vibe Coding 产品，具有复杂的代码结构，尚未在生产环境中得到充分验证。请不要在生产环境中使用。
>
> This project is a Vibe Coding product with complex code structure and hasn't been thoroughly verified in production environments. Please do not use it in production.

---

## 🌟 核心特性 | Core Features

### 🔧 DNS 解析核心 | DNS Resolution Core

- **递归 DNS 解析**：完整的 DNS 递归查询算法实现，从根服务器开始逐步解析

  - **Recursive DNS Resolution**: Complete implementation of DNS recursive query algorithm, resolving step by step from root servers

- **智能根服务器管理**：自动管理 13 个 IPv4 和 13 个 IPv6 根服务器，基于实时网络延迟测试动态排序，优先选择最优服务器进行查询

  - **Smart Root Server Management**: Automatically manages 13 IPv4 and 13 IPv6 root servers, dynamically sorts based on real-time network latency testing, prioritizing optimal servers for queries

- **智能协议协商**：支持 UDP 和 TCP 协议，当 UDP 响应被截断或超过缓冲区大小时**自动回退到 TCP 协议**，确保大数据响应的完整传输

  - **Intelligent Protocol Negotiation**: Supports both UDP and TCP protocols, **automatically falls back to TCP protocol when UDP responses are truncated or exceed buffer size**, ensuring complete transmission of large response data

- **CNAME 链解析**：智能处理 CNAME 记录链，防止循环引用，支持多级 CNAME 解析

  - **CNAME Chain Resolution**: Intelligently handles CNAME record chains, prevents circular references, supports multi-level CNAME resolution

- **并发查询**：高性能并发处理，具备连接池管理

  - **Concurrent Queries**: High-performance concurrent processing with connection pool management

- **DNS 重写功能**：支持精确匹配域名重写规则，实现域名过滤和重定向；支持自定义响应码（如 NXDOMAIN、SERVFAIL 等）和 DNS 记录（如 A、AAAA、CNAME 等）返回

  - **DNS Rewrite Functionality**: Supports exact match domain rewrite rules, enabling domain filtering and redirection; supports custom response codes (such as NXDOMAIN, SERVFAIL, etc.) and DNS records (such as A, AAAA, CNAME, etc.) return

- **混合模式**：可同时配置上游 DNS 服务器和递归解析器，实现灵活的查询策略

  - **Hybrid Mode**: Can configure both upstream DNS servers and recursive resolvers simultaneously, enabling flexible query strategies

- **网络质量感知排序**：对解析结果进行网络延迟测试并按质量排序，优先选择网络质量最好的结果
  - **Network Quality-Aware Sorting**: Performs network latency testing on resolution results and sorts by quality, prioritizing results with the best network quality

### 🛡️ 安全与防御 | Security and Defense

- **CIDR 过滤**：基于 CIDR 规则的智能 IP 地址过滤，支持精确的结果控制。

  - **CIDR Filtering**: Intelligent IP address filtering based on CIDR rules, supporting precise result control.
  - **文件配置**：通过外部文件定义 CIDR 规则，支持动态加载和管理。
  - **File Configuration**: Define CIDR rules through external files, supporting dynamic loading and management.
  - **标签匹配**：使用标签系统将上游服务器与过滤规则关联，实现灵活的策略配置。
  - **Label Matching**: Use label system to associate upstream servers with filtering rules, enabling flexible policy configuration.
  - **记录过滤**：智能过滤 A 和 AAAA 记录，只允许符合 CIDR 规则的 IP 结果通过。
  - **Record Filtering**: Intelligently filter A and AAAA records, only allowing IP results that comply with CIDR rules to pass through.
  - **拒绝策略**：当任何记录被过滤时，返回 REFUSED 响应，确保严格的访问控制。
  - **Rejection Policy**: When any record is filtered, returns REFUSED response, ensuring strict access control.

- **DNS 劫持防护**：主动检测并智能响应根服务器的越权响应。

  - **DNS Hijacking Prevention**: Proactively detects and intelligently responds to overreaching responses from root servers.
  - **步骤 1**：当检测到根服务器直接为非根域名返回最终记录时，判定为 DNS 劫持。
  - **Step 1**: When detecting that root servers directly return final records for non-root domains, it's determined as DNS hijacking.
  - **步骤 2**：**自动切换到 TCP 协议重试**以绕过常见的 UDP 污染。
  - **Step 2**: **Automatically switches to TCP protocol for retry** to bypass common UDP pollution.
  - **步骤 3**：如果 TCP 查询结果**仍然**被劫持，完全拒绝该响应，从源头防止污染。
  - **Step 3**: If TCP query results are **still** hijacked, completely reject the response, preventing pollution from the source.

- **DNSSEC 验证**：完整的 DNSSEC 支持和验证，可设置服务器强制验证，支持 AD 标志传播

  - **DNSSEC Validation**: Complete DNSSEC support and validation, can set server mandatory validation, supports AD flag propagation

- **ECS 支持**：EDNS 客户端子网，提供地理位置感知解析，支持 `auto`、`auto_v4`、`auto_v6` 自动检测或手动 CIDR 配置

  - **ECS Support**: EDNS Client Subnet, providing geolocation-aware resolution, supports `auto`, `auto_v4`, `auto_v6` auto-detection or manual CIDR configuration

- **递归深度保护**：防止恶意递归查询攻击，可配置最大递归深度
  - **Recursion Depth Protection**: Prevents malicious recursive query attacks, configurable maximum recursion depth

### 🔐 安全传输协议 | Secure Transport Protocols

- **DNS over TLS (DoT)**：支持标准 DNS over TLS 协议 (RFC 7818)，在端口 `853` 上提供加密 DNS 查询，防止窃听和篡改。

  - **DNS over TLS (DoT)**: Supports standard DNS over TLS protocol (RFC 7818), providing encrypted DNS queries on port `853`, preventing eavesdropping and tampering.

- **DNS over QUIC (DoQ)**：支持前沿的 DNS over QUIC 协议，利用 QUIC 协议的 0-RTT、多路复用和连接迁移特性，提供更低延迟和更高可靠性的加密 DNS 服务。

  - **DNS over QUIC (DoQ)**: Supports cutting-edge DNS over QUIC protocol, leveraging QUIC protocol's 0-RTT, multiplexing, and connection migration features to provide lower latency and higher reliability encrypted DNS services.

- **DNS over HTTPS (DoH/DoH3)**：同时支持 HTTP/2 和 HTTP/3 DoH 服务，在端口 `443` 上提供基于 HTTPS 的 DNS 查询。

  - **DNS over HTTPS (DoH/DoH3)**: Simultaneously supports HTTP/2 and HTTP/3 DoH services, providing HTTPS-based DNS queries on port `443`.

- **统一证书管理**：DoT、DoQ 和 DoH 共享相同的 TLS 证书配置，简化部署。

  - **Unified Certificate Management**: DoT, DoQ, and DoH share the same TLS certificate configuration, simplifying deployment.

- **自签名 CA 支持**：内置自签名 CA 功能，可为域名动态签名 TLS 证书，简化开发环境配置。

  - **Self-signed CA Support**: Built-in self-signed CA functionality, can dynamically sign TLS certificates for domains, simplifying development environment configuration.

- **调试证书自动生成**：在开发或调试模式下自动生成自签名 TLS 证书，无需外部证书文件。

  - **Debug Certificate Auto-generation**: Automatically generates self-signed TLS certificates in development or debug mode, no external certificate files required.

- **增强的 TLS 日志**：提供详细的 TLS 握手和证书验证日志，便于问题诊断和安全监控。
  - **Enhanced TLS Logging**: Provides detailed TLS handshake and certificate validation logs, facilitating problem diagnosis and security monitoring.

### 🔧 TLS 证书管理 | TLS Certificate Management

- **自签名根 CA**：内置自签名根证书颁发机构，支持为任何域名签名 TLS 证书。

  - **Self-signed Root CA**: Built-in self-signed root certificate authority, supports signing TLS certificates for any domain.

- **动态证书签发**：可根据配置的域名动态生成有效的 TLS 证书，无需外部证书文件。

  - **Dynamic Certificate Issuance**: Can dynamically generate valid TLS certificates based on configured domains, no external certificate files required.

- **开发调试支持**：在开发环境中自动生成临时证书，简化配置过程。

  - **Development Debug Support**: Automatically generates temporary certificates in development environments, simplifying the configuration process.

- **EC 密钥支持**：支持 ECDSA 私钥的生成、序列化和加载，提供更现代的加密算法。

  - **EC Key Support**: Supports generation, serialization, and loading of ECDSA private keys, providing more modern encryption algorithms.

- **证书验证日志**：详细的 TLS 证书验证过程日志，包括证书链验证、有效期检查等。
  - **Certificate Validation Logs**: Detailed TLS certificate validation process logs, including certificate chain validation, validity period checks, etc.

### 📦 DNS 填充 | DNS Padding

- **RFC 7830 标准支持**：实现 DNS 填充功能，通过在 EDNS0 中添加填充字节来标准化 DNS 响应包大小，有效对抗基于流量大小的指纹识别和审查。

  - **RFC 7830 Standard Support**: Implements DNS Padding functionality, standardizing DNS response packet sizes by adding padding bytes in EDNS0, effectively combating fingerprinting and censorship based on traffic size.

- **智能块大小填充**：填充到推荐的 468 字节，平衡隐私保护和带宽效率。

  - **Smart Block Size Padding**: Pads to recommended 468 bytes, balancing privacy protection and bandwidth efficiency.

- **按需启用**：可通过配置文件灵活启用或禁用，**仅对安全连接（DoT/DoQ/DoH）生效**。
  - **On-demand Enablement**: Can be flexibly enabled or disabled through configuration file, **only effective for secure connections (DoT/DoQ/DoH)**.

### 📍 DDR 功能 | DDR (Discovery of Designated Resolvers) Functionality

- **自动发现支持**：支持 RFC [9461](https://www.rfc-editor.org/rfc/rfc9461.html)/[9462](https://www.rfc-editor.org/rfc/rfc9462.html) DNS SVCB 记录，用于自动发现安全 DNS 服务器

  - **Auto-discovery Support**: Supports RFC [9461](https://www.rfc-editor.org/rfc/rfc9461.html)/[9462](https://www.rfc-editor.org/rfc/rfc9462.html) DNS SVCB records for automatic discovery of secure DNS servers

- **SVCB 记录生成**：自动为 DoT、DoH、DoQ 生成 SVCB 记录，支持 IPv4 和 IPv6 提示

  - **SVCB Record Generation**: Automatically generates SVCB records for DoT, DoH, DoQ, supporting IPv4 and IPv6 hints

- **灵活配置**：通过配置文件指定 DDR 域名和对应的 IP 地址，支持 IPv4 和 IPv6 双栈配置

  - **Flexible Configuration**: Specify DDR domain names and corresponding IP addresses through configuration file, supporting IPv4 and IPv6 dual-stack configuration

- **智能响应**：当接收到 `_dns.resolver.arpa`、`_dns.dns.example.org`、`_non_53_port._dns.dns.example.org` 的 SVCB 查询时，自动返回配置的加密 DNS 服务信息
  - **Intelligent Response**: When receiving SVCB queries for `_dns.resolver.arpa`, `_dns.dns.example.org`, `_non_53_port._dns.dns.example.org`, automatically returns configured encrypted DNS service information

### 🚀 网络质量测试 | Network Quality Testing (SpeedTest)

- **多协议支持**：支持 ICMP、TCP、UDP 等多种协议进行网络质量测试

  - **Multi-protocol Support**: Supports various protocols including ICMP, TCP, and UDP for network quality testing

- **灵活配置**：可配置不同的测试端口和超时值，适应不同的网络环境

  - **Flexible Configuration**: Configurable different test ports and timeout values, adapting to different network environments

- **智能排序**：根据测试结果按延迟对 DNS 解析结果进行排序，优先选择网络质量最好的结果

  - **Intelligent Sorting**: Sorts DNS resolution results by latency based on test results, prioritizing results with the best network quality

- **缓存机制**：内置测试结果缓存，避免重复测试，提高响应速度

  - **Caching Mechanism**: Built-in test result caching, avoiding duplicate tests and improving response speed

- **并发处理**：支持多个 IP 地址的并发测试，提高测试效率
  - **Concurrent Processing**: Supports concurrent testing of multiple IP addresses, improving test efficiency

### 💾 缓存系统 | Cache System

- **双模式运行**：

  - **无缓存模式**：适用于测试环境，零配置启动，纯递归解析
  - **Redis 缓存模式**：推荐生产环境使用，支持分布式部署，数据持久化
  - **Dual Mode Operation**:
  - **No Cache Mode**: Suitable for testing environments, zero-configuration startup, pure recursive resolution
  - **Redis Cache Mode**: Recommended for production environments, supports distributed deployment, data persistence

- **智能 TTL 管理**：灵活的 TTL 策略，支持最小/最大 TTL 限制

  - **Intelligent TTL Management**: Flexible TTL strategies, supports minimum/maximum TTL limits

- **过期缓存服务**：当上游服务器不可用时提供过期缓存服务，大大提高系统可用性

  - **Stale Cache Serving**: Provides stale cache service when upstream servers are unavailable, greatly improving system availability

- **预取机制**：后台自动刷新即将过期的缓存，减少用户等待时间

  - **Prefetch Mechanism**: Background automatic refresh of soon-to-expire cache, reducing user waiting time

- **ECS 感知缓存**：基于客户端地理位置（EDNS Client Subnet）的缓存分区，提供精确的本地化解析

  - **ECS-aware Caching**: Cache partitioning based on client geographic location (EDNS Client Subnet), providing precise localized resolution

- **访问限流**：限制缓存访问时间更新操作，减少 Redis 压力
  - **Access Throttling**: Throttles cache access time update operations, reducing Redis pressure

### 🕵️ 请求跟踪系统 | Request Tracking System

- **全链路追踪**：为每个 DNS 请求生成唯一 ID，详细记录处理过程中的每个步骤和耗时。

  - **Full-chain Tracing**: Generates unique ID for each DNS request, detailed recording of each step and time consumption during processing.

- **智能日志**：在 `DEBUG` 级别输出带时间戳的请求处理步骤，大大简化调试和性能分析。

  - **Intelligent Logging**: At `DEBUG` level, outputs timestamped request processing steps, greatly simplifying debugging and performance analysis.

- **摘要报告**：在 `INFO` 级别输出请求处理摘要，包括缓存命中状态、总时间、使用的上游服务器等关键信息。
  - **Summary Report**: At `INFO` level, outputs request processing summary, including cache hit status, total time, upstream servers used, and other key information.

### 🧠 内存管理与优化 | Memory Management & Optimization

- **工作池任务管理**：优化的 TaskManager，具有固定工作池和任务队列，防止 goroutine 爆炸并减少内存开销。

  - **Worker Pool Task Management**: Optimized TaskManager with fixed worker pool and task queue, preventing goroutine explosion and reducing memory overhead.

- **智能消息池化**：增强的 DNS 消息池，具有大小限制（1000 条消息）、切片容量控制（50）和适当的清理以防止内存膨胀。

  - **Smart Message Pooling**: Enhanced DNS message pool with size limits (1000 messages), slice capacity controls (50), and proper cleanup to prevent memory bloat.

- **受控查询并发**：限制并发查询（MaxSingleQuery: 5），采用首胜策略，减少资源使用并提高响应时间。

  - **Controlled Query Concurrency**: Limited concurrent queries (MaxSingleQuery: 5) with first-winner strategy, reducing resource usage and improving response times.

- **实时内存监控**：每 30 秒持续跟踪内存使用情况，当内存超过 500MB 时自动触发 GC。

  - **Real-time Memory Monitoring**: Continuous memory usage tracking every 30 seconds with automatic GC triggering when memory exceeds 500MB.

- **资源生命周期管理**：在关闭期间适当清理所有资源，防止内存泄漏。

  - **Resource Lifecycle Management**: Proper cleanup of all resources during shutdown to prevent memory leaks.

- **Goroutine 优化**：在关键路径上直接使用 goroutine 而不是 TaskManager，减少上下文切换开销。
  - **Goroutine Optimization**: Direct goroutine usage for critical paths instead of TaskManager, reducing context switching overhead.

### ⚡ 高级连接池 | Advanced Connection Pooling

- **协议特定连接池**：为不同协议维护专门的连接池（HTTP/2、HTTP/3、QUIC、TLS）

  - **Protocol-specific Connection Pools**: Maintain dedicated connection pools for different protocols (HTTP/2, HTTP/3, QUIC, TLS)

- **连接复用**：智能复用持久连接，减少连接建立开销

  - **Connection Reuse**: Intelligently reuse persistent connections, reducing connection establishment overhead

- **会话缓存**：TLS 会话缓存加速后续连接建立

  - **Session Caching**: TLS session caching accelerates subsequent connection establishment

- **连接生命周期管理**：自动清理空闲连接，防止资源泄漏
  - **Connection Lifecycle Management**: Automatic cleanup of idle connections prevents resource leaks

### 🔧 根服务器管理 | Root Server Management

- **动态服务器发现**：自动发现和管理根服务器列表

  - **Dynamic Server Discovery**: Automatically discover and manage root server lists

- **延迟排序**：基于实时网络测试对根服务器进行排序

  - **Latency-based Sorting**: Sort root servers based on real-time network testing

- **故障转移**：自动切换到响应更好的根服务器

  - **Failover**: Automatically switch to better responding root servers

- **性能监控**：持续监控根服务器性能指标
  - **Performance Monitoring**: Continuous monitoring of root server performance metrics

---

## 🏗️ 系统架构 | System Architecture

ZJDNS 采用模块化、分层设计，核心组件职责清晰、松耦合，支持高并发和多安全协议。架构强调内存效率和资源优化，具备智能任务管理和实时监控。总体架构如下：

```mermaid
graph TB
    subgraph "客户端层 | Client Layer"
        A[DNS 客户端<br><i>DNS Client</i>]
    end

    subgraph "核心服务层 | Core Service Layer"
        B[DNSServer<br><i>服务器核心</i>]
        C[ConfigManager<br><i>配置管理</i>]
        E[CacheManager<br><i>缓存接口</i>]
        F[QueryManager<br><i>查询管理器</i>]
        G[UpstreamHandler<br><i>上游处理器</i>]
    end

    subgraph "协议处理层 | Protocol Processing Layer"
        H[UDPServer<br><i>UDP:53</i>]
        I[TCPServer<br><i>TCP:53</i>]
        J[DoTHandler<br><i>DoT:853</i>]
        K[DoQHandler<br><i>DoQ:853</i>]
        L[DoHHandler<br><i>DoH:443</i>]
    end

    subgraph "DNS 处理引擎 | DNS Processing Engine"
        M[RecursiveResolver<br><i>递归解析器</i>]
        N[CNAMEHandler<br><i>CNAME处理器</i>]
        O[ResponseValidator<br><i>响应验证器</i>]
        P[QueryClient<br><i>查询客户端</i>]
    end

    subgraph "安全与增强层 | Security & Enhancement Layer"
        Q[SecurityManager<br><i>安全管理器</i>]
        R[EDNSManager<br><i>EDNS管理器</i>]
        S[DNSSECValidator<br><i>DNSSEC验证器</i>]
        T[HijackPrevention<br><i>劫持防护</i>]
        U[CIDRManager<br><i>CIDR过滤</i>]
        V[RewriteManager<br><i>DNS重写</i>]
        W[SpeedTestManager<br><i>网络测试</i>]
    end

    subgraph "缓存系统 | Cache System"
        X[RedisCache<br><i>Redis缓存</i>]
        Y[NullCache<br><i>无缓存模式</i>]
        Z[Prefetch Mechanism<br><i>缓存预取</i>]
        AA[ServeStale<br><i>过期缓存服务</i>]
    end

    subgraph "基础设施层 | Infrastructure Layer"
        BB[RequestTracker<br><i>请求跟踪</i>]
        DD[TLSManager<br><i>TLS证书管理</i>]
        EE[RootServerManager<br><i>根服务器管理</i>]
        FF[IPDetector<br><i>IP检测器</i>]
        GG[LogManager<br><i>日志管理</i>]
        LL[ConnPool<br><i>高级连接池</i>]
    end

    subgraph "背景任务组 | Background Task Groups"
        MM[Background Group<br><i>背景任务</i>]
        NN[Cache Refresh Group<br><i>缓存刷新</i>]
        OO[Shutdown Coordinator<br><i>关闭协调</i>]
    end

    subgraph "外部服务 | External Services"
        KK[Root Servers<br><i>根服务器</i>]
        MM2[Upstream DNS<br><i>上游DNS</i>]
        NN2[Redis Cluster<br><i>Redis集群</i>]
        OO2[Self-signed CA<br><i>自签名CA</i>]
        PP[TLS Certificates<br><i>TLS证书</i>]
    end

    %% Main connections
    A -->|DNS 查询| H
    A -->|DNS 查询| I
    A -->|安全查询| J
    A -->|安全查询| K
    A -->|安全查询| L

    H --> B
    I --> B
    J --> B
    K --> B
    L --> B

    B --> M
    B --> N
    B --> O
    B --> P

    M --> Q
    M --> R
    M --> S
    M --> T
    M --> U
    M --> V
    M --> W

    P --> EE
    P --> LL
    B --> X
    B --> Y
    X --> Z
    X --> AA

    B --> BB
    B --> DD
    B --> FF
    B --> GG

    B --> MM
    B --> NN
    B --> OO

    %% External connections
    EE --> KK
    G --> MM2
    X --> NN2
    DD --> OO2
    DD --> PP
    J --> PP
    K --> PP
    L --> PP

    %% Style definitions
    classDef client fill:#3498db,stroke:#2980b9,color:#fff
    classDef core fill:#2ecc71,stroke:#27ae60,color:#fff,font-weight:bold
    classDef protocol fill:#e67e22,stroke:#d35400,color:#fff
    classDef engine fill:#9b59b6,stroke:#8e44ad,color:#fff
    classDef security fill:#e74c3c,stroke:#c0392b,color:#fff
    classDef cache fill:#f39c12,stroke:#d68910,color:#fff
    classDef infra fill:#34495e,stroke:#2c3e50,color:#fff
    classDef external fill:#95a5a6,stroke:#7f8c8d,color:#fff
    classDef background fill:#16a085,stroke:#138d75,color:#fff

    class A client
    class B,C,E,F,G core
    class H,I,J,K,L protocol
    class M,N,O,P engine
    class Q,R,S,T,U,V,W security
    class X,Y,Z,AA cache
    class BB,DD,EE,FF,GG,LL infra
    class KK,MM2,NN2,OO2,PP external
    class MM,NN,OO background
```

---

## 🔍 DNS 查询流程 | DNS Query Process

### 完整查询流程 | Complete Query Flow

以下图表和步骤说明了 DNS 查询如何在 ZJDNS 中从客户端请求到最终响应的完整流程：

The following diagram and steps illustrate how a DNS query flows through ZJDNS from client request to final response:

```mermaid
sequenceDiagram
    participant C as DNS 客户端<br><i>DNS Client</i>
    participant S as DNSServer
    participant RT as RequestTracker
    participant CM as CacheManager
    participant QR as QueryManager
    participant RR as RecursiveResolver
    participant HP as HijackPrevention
    participant QC as QueryClient
    participant ST as SpeedTestManager
    participant RSM as RootServerManager
    participant RS as 根服务器<br><i>Root Servers</i>
    participant US as 上游DNS<br><i>Upstream DNS</i>
    participant CIDR as CIDRManager
    participant R as Redis缓存<br><i>Redis Cache</i>

    Note over C,R: 客户端查询 example.com<br><i>Client queries for example.com</i>

    C->>S: DNS 查询 (UDP/TCP/DoT/DoQ/DoH)<br><i>DNS Query</i>
    S->>RT: 创建请求跟踪<br><i>Create Request Tracker</i>
    S->>S: 解析和验证请求<br><i>Parse & Validate Request</i>
    S->>CIDR: 检查客户端IP过滤<br><i>Check Client IP Filter</i>

    alt 客户端IP被过滤
        CIDR-->>S: 返回REFUSED<br><i>Return REFUSED</i>
        S-->>C: DNS 错误响应<br><i>DNS Error Response</i>
    else 客户端IP允许
        S->>S: 应用重写规则<br><i>Apply Rewrite Rules</i>
        S->>S: 处理ECS选项<br><i>Handle ECS Options</i>
        S->>CM: 检查缓存<br><i>Check Cache</i>

        alt 缓存命中 (新鲜)<br><i>Cache Hit (Fresh)</i>
            CM-->>S: 返回缓存响应<br><i>Return Cached Response</i>
            S->>S: 应用安全规则<br><i>Apply Security Rules</i>
            S->>CIDR: 过滤响应IP<br><i>Filter Response IPs</i>
            S->>RT: 记录处理时间<br><i>Record Processing Time</i>
            S-->>C: DNS 响应<br><i>DNS Response</i>
        else 缓存命中 (过期) 或 缓存未命中<br><i>Cache Hit (Stale) or Cache Miss</i>
            S->>QR: 开始查询流程<br><i>Start Query Process</i>
            QR->>RR: 递归解析<br><i>Recursive Resolution</i>

            RR->>RSM: 获取最优根服务器<br><i>Get Optimal Root Servers</i>
            RSM-->>RR: 返回延迟排序的根服务器<br><i>Return Latency-sorted Root Servers</i>

            RR->>HP: 检查DNS劫持<br><i>Check DNS Hijacking</i>
            HP->>QC: 查询根服务器<br><i>Query Root Servers</i>
            QC->>ST: 测试网络质量<br><i>Test Network Quality</i>
            ST-->>QC: 返回最佳服务器<br><i>Return Best Server</i>
            QC->>RS: UDP查询<br><i>UDP Query</i>
            RS-->>QC: 返回响应<br><i>Return Response</i>
            QC-->>HP: 响应结果<br><i>Response Result</i>

            alt 检测到DNS劫持 (根服务器直接返回最终记录)<br><i>DNS Hijacking Detected (Root server returns final records directly)</i>
                HP->>QC: 自动切换TCP重试<br><i>Auto-switch to TCP retry</i>
                QC->>RS: TCP查询<br><i>TCP Query</i>
                RS-->>QC: TCP响应<br><i>TCP Response</i>
                QC-->>HP: TCP响应结果<br><i>TCP Response Result</i>

                alt TCP查询仍被劫持<br><i>TCP Query Still Hijacked</i>
                    HP-->>RR: 完全拒绝响应<br><i>Completely Reject Response</i>
                    RR-->>QR: 劫持错误<br><i>Hijacking Error</i>
                    QR-->>S: 劫持检测失败<br><i>Hijacking Detection Failed</i>
                    S-->>C: DNS 错误响应<br><i>DNS Error Response</i>
                else TCP查询正常<br><i>TCP Query Normal</i>
                    HP-->>RR: TCP正常响应<br><i>TCP Normal Response</i>
                    RR->>QC: 继续查询TLD服务器<br><i>Continue Query TLD Servers</i>
                    QC-->>RR: 返回权威引用<br><i>Referral to Authoritative</i>
                    RR->>QC: 查询权威服务器<br><i>Query Authoritative</i>
                    QC-->>RR: 最终响应<br><i>Final Response</i>
                end
            else 正常响应 (TLD引用)<br><i>Normal Response (TLD Referral)</i>
                HP-->>RR: 正常TLD引用<br><i>Normal TLD Referral</i>
                RR->>QC: 查询TLD服务器<br><i>Query TLD Servers</i>
                QC-->>RR: 返回权威引用<br><i>Referral to Authoritative</i>
                RR->>QC: 查询权威服务器<br><i>Query Authoritative</i>
                QC-->>RR: 最终响应<br><i>Final Response</i>
            end

            alt 查询成功<br><i>Query Success</i>
                RR-->>QR: 有效响应<br><i>Valid Response</i>
                QR->>CIDR: 过滤响应IP<br><i>Filter Response IPs</i>

                alt 有IP通过过滤
                    CIDR-->>QR: 过滤后的响应<br><i>Filtered Response</i>
                    QR->>CM: 存储到缓存<br><i>Store in Cache</i>
                    QR-->>S: 查询结果<br><i>Query Result</i>
                    S->>S: 应用安全规则<br><i>Apply Security Rules</i>
                    S->>RT: 记录处理时间<br><i>Record Processing Time</i>
                    S-->>C: DNS 响应<br><i>DNS Response</i>
                else 所有IP被过滤
                    CIDR-->>QR: 返回REFUSED<br><i>Return REFUSED</i>
                    QR-->>S: 拒绝结果<br><i>Rejected Result</i>
                    S-->>C: DNS 拒绝响应<br><i>DNS REFUSED Response</i>
                end
            else 查询超时/错误<br><i>Query Timeout/Error</i>
                RR-->>QR: 错误<br><i>Error</i>
                QR->>CM: 尝试过期缓存<br><i>Try Stale Cache</i>
                alt 过期缓存可用<br><i>Stale Available</i>
                    CM-->>QR: 过期响应<br><i>Stale Response</i>
                    QR-->>S: 过期结果<br><i>Stale Result</i>
                    S-->>C: 过期响应<br><i>Stale Response</i>
                else 无过期缓存<br><i>No Stale</i>
                    QR-->>S: 错误响应<br><i>Error Response</i>
                    S-->>C: DNS 错误<br><i>DNS Error</i>
                end
            end
        end
    end
```

---

## 📋 使用示例 | Usage Examples

### 生成示例配置文件 | Generate Example Configuration File

```bash
./zjdns -generate-config > config.json
```

### 启动服务器 | Start Server

```bash
# 使用默认配置（纯递归模式，无缓存）
# Use default configuration (pure recursive mode, no cache)
./zjdns

# 使用配置文件启动（推荐）
# Start with configuration file (recommended)
./zjdns -config config.json
```

### 测试 DNS 解析 | Test DNS Resolution

```bash
# 传统DNS测试
# Traditional DNS test
kdig @127.0.0.1 -p 53 example.com

# DoT测试
# DoT test
kdig @127.0.0.1 -p 853 example.com +tls

# DoQ测试
# DoQ test
kdig @127.0.0.1 -p 853 example.com +quic

# DoH测试
# DoH test
kdig @127.0.0.1 -p 443 example.com +https
```

### 性能监控 | Performance Monitoring

```bash
# 启用pprof性能分析
# Enable pprof performance analysis
curl http://127.0.0.1:6060/debug/pprof/

# 查看内存使用情况
# View memory usage
curl http://127.0.0.1:6060/debug/pprof/heap
```

---

## 🛠️ 开发工具 | Development Tools

### golangci-lint

提交代码前，请使用 [golangci-lint](https://golangci-lint.run/) 进行代码检查。

安装 golangci-lint：

Install golangci-lint:

```bash
brew install golangci-lint
```

运行检查和代码格式化：

Run checks & code formatting:

```bash
golangci-lint run && golangci-lint fmt
```

请确保 golangci-lint 检查通过后再提交代码，以保持代码质量和一致性。

Please ensure golangci-lint checks pass before committing code to maintain code quality and consistency.

### 构建和测试 | Build and Test

```bash
# 构建二进制文件
# Build binary
go build -o zjdns

# 生成配置示例
# Generate config example
./zjdns -generate-config
```

---

## 📝 许可证 | License

本项目采用 MIT 许可证。详情请参见 [LICENSE](LICENSE) 文件。

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙏 致谢 | Acknowledgments

感谢以下开源项目：

Thanks to the following open source projects:

- [miekg/dns](https://github.com/miekg/dns) - Go DNS library
- [redis/go-redis](https://github.com/redis/go-redis) - Redis Go client
- [quic-go/quic-go](https://github.com/quic-go/quic-go) - QUIC protocol implementation
