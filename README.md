# ZJDNS

```
███████╗     ██╗██████╗ ███╗   ██╗███████╗
╚══███╔╝     ██║██╔══██╗████╗  ██║██╔════╝
  ███╔╝      ██║██║  ██║██╔██╗ ██║███████╗
 ███╔╝  ██   ██║██║  ██║██║╚██╗██║╚════██║
███████╗╚█████╔╝██████╔╝██║ ╚████║███████║
╚══════╝ ╚════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

[![Version](https://img.shields.io/badge/Version-3.4.25-informational)](https://github.com/hezhijie0327/ZJDNS/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success)](https://golangci-lint.run/)

高性能递归 DNS 服务器，内置 DNS 劫持/投毒防护、SQLite 缓存、DNSSEC、全协议加密传输 (TLS/QUIC/HTTPS/HTTP3/DTLS)、(PQ)DNSCrypt、TLCP/DTLCP 国密传输及 KTLS 内核卸载。

## 快速开始

```bash
# 构建
go build -o zjdns ./cmd/zjdns

# 纯递归模式（内存缓存）
./zjdns

# 指定配置文件
./zjdns --config config.json

# 生成示例配置
./zjdns --generate-config

# 生成 DNSCrypt 密钥及配置（输出完整 JSON，可直接用作配置文件）
./zjdns --generate-config --dnscrypt --provider example.com [--addr <host:port>]

# DNS Stamp 工具
./zjdns --dnsstamp --decode "sdns://..."          # 将 sdns:// 戳记解码为上游 JSON 配置
./zjdns --dnsstamp --encode --proto doh           # 从字段编码为 sdns:// 戳记
    --stamp-addr 9.9.9.9 --provider-name dns.quad9.net:443 --path /dns-query

# 执行 SQL 查询
./zjdns --sql cache.db "SELECT * FROM zone_entries"

# 探测上游服务器能力
./zjdns --probe --pipeline    tcp://8.8.8.8      # 测试 RFC 7766 查询流水线
./zjdns --probe --conn-reuse  tls://1.1.1.1       # 测试 RFC 1035 连接复用
./zjdns --probe --idle-timeout tls://1.1.1.1       # 测量服务器空闲超时
```

```bash
# DNS 查询测试
dig @127.0.0.1 -p 53 example.com                 # UDP
dig @127.0.0.1 -p 53 example.com +tcp             # TCP
kdig @127.0.0.1 -p 853 example.com +tls           # TLS
kdig @127.0.0.1 -p 853 example.com +quic          # QUIC
kdig @127.0.0.1 -p 443 example.com +https         # HTTPS

# 验证 DNSCrypt 证书握手
dig @127.0.0.1 -p 8443 2.dnscrypt-cert.example.com TXT   # 获取 DNSCrypt 证书
```

## 核心特性

### 统一数据库

基于 SQLite WAL 模式的统一关系型数据库（`database/`），九表设计，所有子系统共享同一 DB 连接：

| 表 | 说明 |
|----|------|
| `version` | 数据库版本号（单行，启动时同步至应用版本） |
| `entries` | DNS 响应缓存（复合 UNIQUE，zstd 压缩 BLOB，级联驱逐） |
| `ptr_map` | PTR 反向映射（IP→域名，WITHOUT ROWID，ON DELETE CASCADE） |
| `query_stats` | 每日聚合统计（stat_day + result + protocol + rcode + dnssec + hijack + fallback，滑动窗口 ~500 行） |
| `query_log` | 请求审计日志（qname 去规范化存储，仅非 hit 事件） |
| `ip_latency` | 延迟探测结果（IP 为键，所有域名共享同 IP 行） |
| `ruleset_entries` | 规则集条目（tag + type + value，WITHOUT ROWID） |
| `zone_entries` | 区域规则匹配（WITHOUT ROWID，is_wildcard 前置 PK） |

- **Wire format 加速**：`msg_wire` BLOB 存储 zstd 压缩的 DNS 响应，`Get()` 解压缩 + `Msg.Unpack()` 一步还原，缓存命中 ~0.5ms
- **延迟驱动排序**：A/AAAA 记录按 `ip_latency` 探测结果排序（最快优先），同一 CDN IP 多域名共享延迟数据
- **滑动窗口统计**：所有请求写入 `query_stats`（按天分桶聚合），`Stats()` 单表扫描。非 hit 事件同时写入 `query_log` 作为审计日志。滑动窗口长度由 `DefaultQueryJournalRetention` 控制
- **统计/日志独立**：`FlushDB("stats")` 清空 `query_stats`，`FlushDB("querylog")` 清空 `query_log`，互不影响
- **驱逐策略**：TTL 惰性过期 + 条数上限最旧淘汰，`ON DELETE CASCADE` 清理 `ptr_map`；无 FK 表（`ip_latency`、`query_log`）通过 `DefaultStaleMaxAge` 时间窗口清理
- **写入优化**：`Set()` 的 CPU 密集步骤（TTL 计算、zstd 压缩）在 `writeMu` 外执行；驱逐在 `writeMu` 内运行以防止 TOCTOU

### DNS 解析

- **递归解析**：从 IANA 根服务器（根提示 + 延迟排序缓存）逐步解析至 TLD 和权威服务器，完整 DNSSEC 信任链。根提示文件 `named.root` 和 DNSSEC 信任锚文件 `root-anchors.xml` 默认从配置文件同目录加载（无配置文件时从二进制同目录加载），文件缺失时自动从 IANA/InterNIC 下载
- **上游转发**：主/备服务器并发查询（`errgroup` + 首胜策略），上游优先
- **混合模式**：上游 DNS 与 `builtin_recursive` 可同时配置，并发竞争
### 规则集与上游分流

`ruleset` 统一了 IP（CIDR）和域名（后缀）匹配，产出标签（tag）。`UpstreamServer.match` 用标签做解析前分流和解析后 IP 过滤。

```json
{
  "ruleset": [
    { "tag": "google", "type": "domain", "rule": ["google.com", "*.youtube.com"] },
    { "tag": "cn",     "type": "domain", "file": "china-domains.txt" },
    { "tag": "corp",   "type": "ip",     "rule": ["10.0.0.0/8"] }
  ],
  "upstream": [
    { "address": "8.8.8.8:53",     "match": ["google"] },
    { "address": "114.114.114.114:53", "match": ["cn"] },
    { "address": "10.0.0.1:53",    "match": ["corp"] }
  ]
}
```

- `type: "domain"` — 域名后缀匹配（`google.com` 匹配自身及所有子域，`*.youtube.com` 只匹配子域），TLD+1 查找，规则存储在 SQLite `ruleset_entries` 表中
- `type: "ip"` — CIDR 匹配，SQLite 加载 CIDR 规则 + Go `net.IPNet.Contains` 校验
- `file` — 每行一个条目，按 `type` 解析；`#` 注释
- `match` 有两层作用：
  - **查询前**：域名标签匹配 → 选择上游（如 `"match": ["google"]` 将 google 相关域名路由到该上游）
  - **查询后**：IP 标签匹配 → 过滤响应中的 A/AAAA 记录（如 `"match": ["!block-ip"]` 滤除特定 IP 段）
  - 支持 `!` 取反：`["google", "!block-ip"]` 表示匹配 google 标签但不含被屏蔽 IP

- **SOCKS5 代理**：每上游可选代理（TCP CONNECT + UDP ASSOCIATE，RFC 1928/1929）
- **连接池**：TCP/TLS RFC 7766 查询流水线 + QUIC 原生流复用，按需拨号入池
- **CNAME 追踪**：多级追踪（最大 16 级），防循环检测
- **按接口绑定**：所有监听器按网卡 IP 逐一绑定，端口冲突自动跳过
- **延迟探测**：ICMP/TCP/UDP/HTTP/HTTPS/HTTP3 统一引擎，异步写入 `ip_latency`
- **`no_cache` 开关**：按上游/回退服务器禁用缓存，不信任的上游响应不会污染本地缓存

### 上游服务器配置

`upstream` 和 `fallback` 均使用 `UpstreamServer` 结构，字段如下：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `address` | string | ✓ | 服务器地址。`host:port`、`https://host:port/path`、`builtin_recursive` 或 `sdns://` DNS 戳记（支持所有协议，自动推导 `protocol` / `server_name` / `public_key`） |
| `protocol` | string | | 传输协议：`udp`(默认)/`tcp`/`tls`/`quic`/`https`/`http3`/`dtls`/`dnscrypt`/`dnscrypt-tcp`/`tlcp`/`http-tlcp`/`dtlcp`。使用 `sdns://` 时可省略，自动从戳记推导 |
| `server_name` | string | TLS/DNSCrypt | TLS SNI 主机名；非戳记 DNSCrypt 时用作 provider name。使用 `sdns://` 时自动填充 |
| `skip_tls_verify` | bool | | 跳过 TLS 证书验证 |
| `no_cache` | bool | | 禁止缓存该上游的响应（默认 `false`=正常缓存） |
| `match` | []string | | 规则集标签：查询前域名路由 + 查询后 IP 过滤（`!tag` 取反） |
| `proxy` | string | | SOCKS5 代理：`socks5://[user:pass@]host:port` |
| `public_key` | string | DNSCrypt | 解析器 Ed25519 公钥（hex），非戳记 DNSCrypt 必填 |
| `pqdnscrypt` | bool | DNSCrypt | 优先使用后量子证书（默认 `true`，与官方 dnscrypt-proxy 行为一致），设为 `false` 强制经典 XChacha20 |

### 安全

- **DNSSEC**：完整密码学信任链（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 已验证否定（RFC 5155）
- **QNAME 最小化**：RFC 9156，默认启用，计数器推进 + 按比例暴露标签
- **劫持防护**：根/TLD 越权响应检测（`Detector.Validate`）→ UDP→TCP 自动回退绕过 GFW 中间盒注入
- **DNS Cookie**：SipHash-2-4（RFC 9018），服务器密钥每 30 分钟轮换，保留 2 个历史密钥避免慢客户端 BADCOOKIE，有效 Cookie 原样回显避免重算
- **DNS64**（RFC 6147）：AAAA 无记录时自动从 A 记录合成（默认前缀 `64:ff9b::/96`），纯 IPv6/NAT64 网络必备
- **并发查询去重**（singleflight）：同 key 的并发缓存 miss 合并为一次上游查询，leader 完成广播给所有 follower，消除缓存投毒竞争窗口
- **规则集**：统一的 IP + 域名标签匹配引擎，上游可按标签分流、Zone 可按标签过滤
- **EDNS Padding**：随机填充字节（`crypto/rand`）替代确定性零填充，增强流量分析抵抗
- **安全传输**：DNSCrypt v2（经典 XChacha20-Poly1305 + 后量子 X-Wing KEM 双证书同时启用，UDP/TCP 双协议，UDP→TCP 自动回退、PQ 票据续期减少重复 KEM 开销）、TLS (RFC 7858/8310)、QUIC (RFC 9250)、HTTPS (RFC 8484)、HTTP3 (RFC 9114)、DTLS (RFC 8094)，TLS 1.3 + KTLS 可选卸载

### KTLS 内核卸载

将 TLS 加解密从 CPU 卸载至 Linux 内核（`af_alg` + `setsockopt(TCP_ULP)`），降低 CPU 占用。仅适用 TLS/HTTPS（TCP），QUIC 不适用。非 Linux 静默回退。

**启用**：

```bash
# 加载内核模块
modprobe tls
```

```json
{ "server": { "features": { "ktls": { "kernel_tx": true, "kernel_rx": false } } } }
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `kernel_tx` | `false` | TX 卸载，通常安全 |
| `kernel_rx` | `false` | RX 卸载，需内核 ≥ 5.3 + 兼容网卡驱动 |

> `"bad record MAC"` 错误 → 关闭 `kernel_rx`。客户端上游 TLS/HTTPS 连接自动复用服务端 KTLS 配置。

### 国密 TLCP (实验性)

基于 `Trisia/gotlcp` (纯 Go 实现，GB/T 38636-2020) 支持 TLCP 传输层加密。客户端支持 `tlcp` 和 `http-tlcp` 两种上游协议；服务端支持独立 TLCP 监听器，同时提供 TLS 和 HTTPS 服务。

> **注意**：DNSPod 的 `sm2.doh.pub` 证书（`*.doh.pub`，签发链：DNSPod TLS SM2 CA G2 → TrustAsia Global SM2 Root CA G2）已于 **2024-06-06** 过期，测试时需 `skip_tls_verify: true`。

**服务端配置**（独立于 TLS，需要 SM2 双证书）：

```json
{
  "server": {
    "protocol": { "tlcp": "8530", "http_tlcp": { "port": "4430" } },
    "certificate": { "domain": "example.com", "tlcp": { "self_signed": true } }
  }
}
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `protocol.tlcp` | `""` | TLCP TLS 端口（为空则不启用） |
| `protocol.http_tlcp.port` | `""` | TLCP HTTPS 端口 |
| `protocol.http_tlcp.endpoint` | `"/dns-query"` | TLCP HTTPS 路径 |
| `certificate.tlcp.sign_cert_file` / `sign_key_file` | — | SM2 签名证书和私钥 |
| `certificate.tlcp.enc_cert_file` / `enc_key_file` | — | SM2 加密证书和私钥 |
| `certificate.tlcp.self_signed` | `false` | 自动生成 SM2 自签名双证书 |
| `certificate.domain` | — | **必填**（安全协议启用时），服务器域名 |

**客户端配置**：

```json
{
  "upstream": [
    { "address": "https://127.0.0.1:4430/dns-query", "protocol": "http-tlcp", "server_name": "ZJDNS TLCP", "skip_tls_verify": true }
  ]
}
```

TLCP 密码套件（默认全部启用）：`ECC_SM4_GCM_SM3`、`ECC_SM4_CBC_SM3`、`ECDHE_SM4_GCM_SM3`、`ECDHE_SM4_CBC_SM3`，密钥交换曲线 SM2。

### 国密 DTLCP (实验性)

基于 `Trisia/gotlcp/dtlcp` (GM/T 0128-2023) 支持 DNS-over-DTLCP 加密传输。客户端通过 `dtlcp` 协议向上游发起 SM2/SM3/SM4 加密的 DNS 查询；服务端支持 DTLCP 监听器。

> **已知限制**：`gotlcp` 库两个主要公开 API 在 UDP 上不可用：
> - `dtlcp.Listen("udp", ...)` → `net.Listen` 不支持 UDP → ZJDNS 使用 `acceptDTLCP()` 适配函数替代
> - `dtlcp.Dial("udp", ...)` → connected socket 与库内部 `WriteTo` 冲突 → ZJDNS 使用 `dialDTLCP()` 适配函数替代
>
> 详见 `CLAUDE.md` §DTLCP。

**服务端配置**（复用 SM2 双证书，与 TLCP TLS/HTTPS 共用）：

```json
{
  "server": {
    "protocol": { "dtlcp": "8542" },
    "certificate": { "domain": "example.com", "tlcp": { "self_signed": true } }
  }
}
```

| 字段 | 默认 | 说明 |
|------|------|------|
| `protocol.dtlcp` | `""` | DTLCP 端口（为空则不启用） |

**客户端配置**：

```json
{
  "upstream": [
    { "address": "127.0.0.1:8542", "protocol": "dtlcp", "server_name": "example.com", "skip_tls_verify": true }
  ]
}
```

> **注意**：DTLCP 使用与 DTLS (RFC 8094) 相同的 2 字节长度前缀 + DNS 载荷帧格式，仅底层加密层替换为 SM2/SM3/SM4。

### 可观测性

- **运行时查询**：`dig zjdns.stats CH TXT` 缓存统计（10 条 TXT 记录：概览、缓存命中、异常、响应码、劫持/回退、明文协议、加密协议、DNSCrypt、TLCP、DNSSEC）
- **缓存管理**：`dig zjdns.db.clear CH TXT` 全清 / `.db.clear.cache` 清缓存 / `.db.clear.stats` 清零统计 / `.db.clear.latency` 清延迟 / `.db.clear.zone` 清区域规则 / `.db.clear.ruleset` 清规则集，仅限本地回环
- **组件级日志**：`log_level` 支持 `level:COMP1,COMP2` 语法（如 `debug:UPSTREAM,SECURITY`），23 个日志前缀
- **CLI 分析工具**：`zjdns --sql <db> <query>` 只读查询（`PRAGMA query_only=ON`），加 `--rw` 读写（含确认提示）
- **Schema 迁移**：增量版本号 `version`，老库自动升级；旧迁移导出 `.sql` 文件可手动执行
- **pprof**：标准 Go 性能分析端点

### DNS Zone

匹配键为 `(QNAME, QTYPE, QCLASS)`，返回完整的 ANSWER + AUTHORITY + ADDITIONAL + RCODE。支持 JSON 内联规则和 zone file 批量导入，两者等价。

**JSON 内联**：

```json
"zone": {
  "rules": [
    { "name": "blocked.com", "rcode": 3 },
    { "name": "static.example.com", "answer": [
        {"type": 1, "content": "10.0.0.1", "ttl": 300},
        {"type": 28, "content": "::1", "ttl": 3600}
    ]},
    { "name": "*.cdn.example.com", "match": ["corp-net", "!guest"],
      "answer": [{"type": 1, "content": "10.0.0.1", "ttl": 300}] },
    { "name": "example.com",
      "answer":     [{"type": 1, "content": "10.0.0.1", "ttl": 300}],
      "authority":  [{"type": 6, "content": "ns1.example.com. admin.example.com. 1 3600 900 86400 3600", "ttl": 3600}],
      "additional": [{"type": 1, "name": "ns1.example.com", "content": "10.0.0.2", "ttl": 3600}] },
    { "file": "hosts.zone" }
  ],
  "bypass_tags": ["gateway"]
}
```

**Zone 文件**（域名头 + 记录行，`#` 注释，与上面等价）：

```zone
.blocked.com rcode=3

.static.example.com
  1  10.0.0.1  300
  28  ::1  3600

*.cdn.example.com match=corp-net,!guest
  1  10.0.0.1  300

.example.com
  1  10.0.0.1  300
  6  "ns1.example.com. admin.example.com. 1 3600 900 86400 3600"  3600  section=authority
  1  10.0.0.2  3600  name=ns1.example.com  section=additional
```

记录行 key=value 选项：`class=N`（默认 1=IN）、`name=STR`（RR owner 覆盖）、`section=authority|additional`（默认 answer）。

`bypass_tags` 指定跳过所有 zone 规则的 CIDR 标签（如网关设备），配合 `ruleset` 段的 `tag` 使用。

## 配置示例

```json
{
  "server": {
    "log_level": "info",
    "protocol": {
      "udp": "53",
      "tcp": "53",
      "tls": "853",
      "quic": "853",
      "https": { "port": "443" },
      "http3": { "port": "443" },
      "dnscrypt": "8443"
    },
    "certificate": {
      "domain": "example.com",
      "tls": { "self_signed": true }
    },
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "database": {
        "db_path": "/var/lib/zjdns/cache.db",
        "mmap_size_mb": 64,
        "cache_size_mb": 32
      },
      "cache": {
        "max_entries": 10000,
        "prefer_stale": true
      },
      "latency_probe": [
        { "protocol": "ping", "timeout": 200 },
        { "protocol": "tcp", "port": 443, "timeout": 200 }
      ]
    }
  },
  "upstream": [
    { "address": "builtin_recursive" },
    { "address": "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe..." },
    { "address": "sdns://AgMAAAAAAAAABzkuOS45LjkgKhX11qy..." }
  ]
}
```

`log_level` 支持组件过滤：`debug:UPSTREAM,RECURSION` 仅输出指定组件 Debug 日志。

### 缓存调优

SQLite 缓存通过两层内存协同工作：

| 参数 | 占用 | 说明 |
|------|------|------|
| `max_entries` | 磁盘 | 缓存条目数上限。1 万条 ≈ 20MB，5 万条 ≈ 100MB |
| `mmap_size_mb` | 虚拟内存 | 将数据库文件映射到进程地址空间，OS 按需换页。建议 ≥ 数据库文件大小 |
| `cache_size_mb` | 物理内存 | SQLite 内部 page cache，缓存 b-tree 节点和热门数据 |
| `db_path` | 磁盘路径 | 数据库文件位置；空串 = 纯内存模式（进程重启数据丢失） |

**总物理内存 ≈ cache_size_mb + OS buffer cache 热点部分**（通常 10-50MB）。

**调优建议：**

| 场景 | 条目数 | 磁盘 | 虚拟内存 | 物理内存 | 配置 |
|------|--------|------|---------|---------|------|
| 低内存 | 1000 | ~2MB | 16MB | ~10MB | `mmap_size_mb: 16, cache_size_mb: 8, max_entries: 1000` |
| 家庭 | 1 万 | ~20MB | 64MB | ~36MB | `mmap_size_mb: 64, cache_size_mb: 32` |
| 高负载 | 5 万 | ~100MB | 128MB | ~50MB | `mmap_size_mb: 128, cache_size_mb: 32` |
| 保守 | 5 万 | ~100MB | 64MB | ~30MB | `mmap_size_mb: 64, cache_size_mb: 8` |

- **`mmap_size_mb`**：设太小会退化到 `read()` I/O。设太大浪费虚拟地址空间（64 位系统无所谓）。建议 ≥ 数据库文件大小。
- **`cache_size_mb`**：DNS 查询符合 Zipf 分布（少数热门域名占大部分请求），不需要覆盖全库。8MB 足够缓存 b-tree 内部节点 + 热门叶子页。
- **`db_path`**：空串 = 纯内存模式（进程重启数据丢失）。

```json
// 默认值
"cache": { "max_entries": 10000, "mmap_size_mb": 64, "cache_size_mb": 32 }

// 低内存场景（树莓派/容器）
"cache": { "max_entries": 1000, "mmap_size_mb": 16, "cache_size_mb": 8 }

// 高负载场景
"cache": { "max_entries": 50000, "mmap_size_mb": 128, "cache_size_mb": 32 }

// 保守场景（低内存设备）
"cache": { "max_entries": 50000, "mmap_size_mb": 64, "cache_size_mb": 8 }
```

## 数据库查询

```bash
# 方式一：sqlite3 直接查询
sqlite3 /var/lib/zjdns/cache.db "SELECT COUNT(*) FROM entries"

# 方式二：内置 analyze（对齐表格输出）
./zjdns --sql /var/lib/zjdns/cache.db "SELECT timestamp, qname, result, rcode, response_ms FROM query_log ORDER BY timestamp DESC LIMIT 10"
```

### 常用查询

```sql
-- 请求概览（单表聚合，无需 UNION）
SELECT result, SUM(query_count) AS total
FROM query_stats GROUP BY result ORDER BY total DESC;

-- 缓存命中率
SELECT result, SUM(query_count) AS total
FROM query_stats WHERE result IN ('hit', 'miss', 'stale')
GROUP BY result ORDER BY total DESC;

-- 各上游服务器的请求量（仅非命中请求）
SELECT server, COUNT(*) AS requests, ROUND(AVG(response_ms), 1) AS avg_ms
FROM query_log WHERE server != '' GROUP BY server ORDER BY requests DESC;

-- rcode 分布（单表聚合）
SELECT rcode, SUM(query_count) AS total
FROM query_stats GROUP BY rcode ORDER BY total DESC;

-- 被劫持的查询
SELECT qname, qtype, server, response_ms
FROM query_log WHERE hijack = 1 ORDER BY timestamp DESC;

-- 慢查询（>1s）
SELECT qname, qtype, server, rcode, response_ms
FROM query_log WHERE response_ms > 1000 ORDER BY response_ms DESC;

-- 协议分布（单表聚合）
SELECT protocol, SUM(query_count) AS total
FROM query_stats GROUP BY protocol ORDER BY total DESC;

-- DNSSEC 状态分布
SELECT dnssec, SUM(query_count) AS total
FROM query_stats WHERE dnssec != '' GROUP BY dnssec ORDER BY total DESC;

-- 延迟最低的 IP
SELECT qtype, rdata_ip, latency_ms FROM ip_latency
ORDER BY latency_ms ASC;

-- PTR 反查（某 IP 对应的所有域名）
SELECT DISTINCT pm.name FROM ptr_map pm
JOIN entries e ON pm.entry_id = e.id
WHERE pm.rdata_ip = '104.20.23.154' AND e.expires_at + 2592000 >= unixepoch();

-- 某域名的请求历史（审计日志）
SELECT timestamp, protocol, result, rcode, response_ms, server, hijack
FROM query_log WHERE qname = 'www.google.com.'
ORDER BY timestamp DESC LIMIT 20;

-- 某域名的缓存命中统计（按协议/rcode 聚合）
SELECT protocol, rcode, SUM(query_count) AS hits
FROM query_stats WHERE result = 'hit'
GROUP BY protocol, rcode ORDER BY hits DESC;
```

## 支持的标准

| RFC / 草案 | 标准 | 实现 |
|------------|------|------|
| [1928](https://www.rfc-editor.org/info/rfc1928) / [1929](https://www.rfc-editor.org/info/rfc1929) | SOCKS5 | TCP CONNECT + UDP ASSOCIATE |
| [4033](https://www.rfc-editor.org/info/rfc4033) / [4034](https://www.rfc-editor.org/info/rfc4034) / [4035](https://www.rfc-editor.org/info/rfc4035) | DNSSEC | 信任链验证 + RRSIG |
| [5155](https://www.rfc-editor.org/info/rfc5155) | NSEC3 | 已验证否定（DoS 防护：迭代次数上限 150） |
| [6052](https://www.rfc-editor.org/info/rfc6052) | IPv6 Addressing of IPv4/IPv6 Translators | NAT64 前缀 64:ff9b::/96 |
| [6147](https://www.rfc-editor.org/info/rfc6147) | DNS64 | AAAA 合成（IPv6-only/NAT64 网络） |
| [6840](https://www.rfc-editor.org/info/rfc6840) | DNSSEC Clarifications | 特殊标签处理（Digest 类型、NXT 等） |
| [6891](https://www.rfc-editor.org/info/rfc6891) | EDNS(0) | FORMERR 自动回退无 EDNS 重试 |
| [7766](https://www.rfc-editor.org/info/rfc7766) | DNS over TCP | 连接池复用 + 流水线（最多 16 路并发） |
| [7828](https://www.rfc-editor.org/info/rfc7828) | EDNS TCP Keepalive | 长连接空闲超时协商 |
| [7830](https://www.rfc-editor.org/info/rfc7830) / [8467](https://www.rfc-editor.org/info/rfc8467) | EDNS Padding | 查询 128B / 响应 468B（TLS/QUIC/HTTPS 加密链接专用） |
| [7858](https://www.rfc-editor.org/info/rfc7858) / [8310](https://www.rfc-editor.org/info/rfc8310) | DNS over TLS | TLS 1.3 + Strict/Opportunistic 隐私配置文件 |
| [7871](https://www.rfc-editor.org/info/rfc7871) | EDNS Client Subnet | ECS 子网隐私控制 |
| [8094](https://www.rfc-editor.org/info/rfc8094) | DNS over DTLS | DTLS 1.2+ 传输层，UDP 加密 DNS |
| [8484](https://www.rfc-editor.org/info/rfc8484) | DNS over HTTPS | HTTPS (HTTP/2) |
| [8767](https://www.rfc-editor.org/info/rfc8767) | Serving Stale | 过期缓存服务 + 后台预取 |
| [8914](https://www.rfc-editor.org/info/rfc8914) | Extended DNS Errors | EDE 代码传递 |
| [9000](https://www.rfc-editor.org/info/rfc9000) | QUIC | QUIC 传输层 |
| [9018](https://www.rfc-editor.org/info/rfc9018) | DNS Cookies | SipHash-2-4 服务器 Cookie（时间戳 + 版本字段，互操作格式） |
| [9114](https://www.rfc-editor.org/info/rfc9114) | HTTP/3 | HTTP3 传输层 |
| [9156](https://www.rfc-editor.org/info/rfc9156) | QNAME Minimisation | 递归查询名最小化 |
| [9250](https://www.rfc-editor.org/info/rfc9250) | DNS over QUIC | QUIC 协议映射 |
| [9461](https://www.rfc-editor.org/info/rfc9461) / [9462](https://www.rfc-editor.org/info/rfc9462) | SVCB / DDR | 加密解析器自动发现 |
| [draft-denis-dprive-dnscrypt-10](https://datatracker.ietf.org/doc/html/draft-denis-dprive-dnscrypt-10) | DNSCrypt v2 | XChacha20 AEAD + X-Wing PQ KEM |
| [draft-denis-dns-stamps-02](https://datatracker.ietf.org/doc/html/draft-denis-dns-stamps-02) | DNS Stamp | sdns:// 戳记编解码，8 种协议类型 |
| [GB/T 38636-2020](https://std.samr.gov.cn/gb/search/gbDetailed?id=A47A713B764314ABE05397BE0A0ABB25) | TLCP (国密 SSL) | SM2/SM3/SM4 密码套件 (ECC/ECDHE_SM4_GCM/CBC_SM3)，TLS/HTTPS 传输 |
| [GM/T 0128-2023](https://std.samr.gov.cn/hb/search/stdHBDetailed?id=1BF26B7A9FF0FD76E06397BE0A0A81D8) | DTLCP (国密 DTLS) | SM2/SM3/SM4 over UDP，DTLCP 传输 |

## 关键依赖

| 库 | 用途 |
|---|------|
| [cloudflare/circl](https://github.com/cloudflare/circl) | Ed25519 签名、X25519 密钥交换、后量子 X-Wing KEM（DNSCrypt PQC） |
| [go-extension/http](https://gitlab.com/go-extension/http) | HTTPS 客户端/服务端（`net/http` 替代，原生 eTLS + KTLS） |
| [go-extension/tls](https://gitlab.com/go-extension/tls) | eTLS（`crypto/tls` 替代，KTLS 内核卸载） |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | ChaCha20-Poly1305 AEAD、HKDF 密钥派生（DNSCrypt 自定义构造） |
| [golang.org/x/sync](https://pkg.go.dev/golang.org/x/sync) | errgroup 并发编排（服务器 goroutine 生命周期管理） |
| [klauspost/compress](https://github.com/klauspost/compress) | zstd 压缩（缓存响应 + Zone 记录 wire format） |
| [miekg/dns](https://codeberg.org/miekg/dns) | DNS 协议编解码、UDP/TCP 传输、NSEC3 哈希、规范排序、标签遍历等原语 |
| [ncruces/go-sqlite3](https://github.com/ncruces/go-sqlite3) | 纯 Go SQLite（WASM 编译，无 CGo，统一数据库引擎） |
| [pion/dtls](https://github.com/pion/dtls) | DTLS 1.2+ 传输层（DNS-over-DTLS，RFC 8094） |
| [quic-go/quic-go](https://github.com/quic-go/quic-go) | QUIC 传输层（QUIC / HTTP3） |
| [Trisia/gotlcp](https://gitee.com/Trisia/gotlcp) | TLCP (GB/T 38636-2020) 协议栈（国密 SM2/SM3/SM4，纯 Go） |

## 开发

```bash
go fix ./... && golangci-lint run && golangci-lint fmt  # 零警告，gofumpt 格式化
sh scripts/bump-version.sh patch "description"  # 版本升级 + 迁移 SQL
sh scripts/bump-version.sh patch "desc" --no-migration  # 纯代码升级
go test ./... -short
go test -bench=. -short ./...
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns
```

## 调试

端到端协议调试配置及文档见 [`docs/debug/`](docs/debug/DEBUG.md)，覆盖场景：

- **ZJDNS ↔ ZJDNS**：UDP / TCP / TLS / HTTPS / HTTP3 / QUIC / DTLS 回环
- **ZJDNS ↔ RouteDNS**：DNS-over-DTLS (RFC 8094) 互操作
- **ZJDNS ↔ DNSCrypt-proxy**：双证书（经典 + 后量子），客户端通过 `pqdnscrypt` 选择模式
- **国密**：TLCP TLS / TLCP HTTPS (self-signed SM2) + DTLCP 回环 + DNSpod 外部上游
- **DNSSEC**：强制验证 (bogus→SERVFAIL, valid→NOERROR)
- **劫持防护**：GFW 投毒检测 + UDP→TCP 自动回退
- **上游**：AliDNS (TLS/HTTPS/QUIC/HTTP3) + Quad9 (DNSCrypt)

所有 TLS/TLCP 配置使用内置 `self_signed` 自签证书，无需外部证书生成。

## 许可证

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
