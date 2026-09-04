# ZJDNS

```
███████╗     ██╗██████╗ ███╗   ██╗███████╗
╚══███╔╝     ██║██╔══██╗████╗  ██║██╔════╝
  ███╔╝      ██║██║  ██║██╔██╗ ██║███████╗
 ███╔╝  ██   ██║██║  ██║██║╚██╗██║╚════██║
███████╗╚█████╔╝██████╔╝██║ ╚████║███████║
╚══════╝ ╚════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

[![Version](https://img.shields.io/badge/Version-4.4.3-informational)](https://github.com/hezhijie0327/ZJDNS/releases)
[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](https://go.dev/)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success)](https://golangci-lint.run/)

高性能递归 DNS 服务器，内置 DNS 防污染、纯内存缓存、DNSSEC、全协议加密传输（TLS/QUIC/HTTPS/HTTP3/DTLS/(PQ)DNSCrypt/TLCP/DTLCP）及 KTLS 内核卸载。

## 快速开始

```bash
# 构建
go build -o zjdns ./cmd/zjdns

# 默认配置 = 递归解析器（UDP/TCP 监听）
./zjdns

# 指定配置文件
./zjdns --config config.json

# 生成示例配置
./zjdns --generate-config

# 生成 DNSCrypt 配置
./zjdns --generate-config --dnscrypt --provider example.com

# 查询测试
dig @127.0.0.1 -p 53 example.com                 # UDP
dig @127.0.0.1 -p 53 example.com +tcp             # TCP
kdig @127.0.0.1 -p 853 example.com +tls           # DoT
kdig @127.0.0.1 -p 853 example.com +quic          # DoQ
kdig @127.0.0.1 -p 443 example.com +https         # DoH

# 验证 DNSCrypt
dig @127.0.0.1 -p 443 2.dnscrypt-cert.example.com TXT
```

## 核心特性

### DNS 解析
- **递归解析**：从 IANA 根服务器逐步解析至权威服务器，完整 DNSSEC 信任链（根提示 + 延迟排序缓存 + 委派缓存）
- **上游转发**：主/备服务器并发查询 + 首胜策略；支持 `protocol: "recursive"` 纯递归模式
- **CNAME 追踪**：最大 16 级，防循环检测
- **QNAME 最小化**：[RFC 9156](docs/rfc/rfc9156.txt)，默认启用
- **委派缓存**：zone-cut 委派记录（NS 名称 + DS）内存 LRU + 快照文件，后续同域子域名查询直接跳过已知层级
- **并发去重**：singleflight 合并同 key 并发 miss
- **紧凑否认**：[RFC 9824](docs/rfc/rfc9824.txt) —— 上游查询设置 CO 位，NXNAME 信号自动恢复 NXDOMAIN 语义
- **分片避免**：[RFC 9715](docs/rfc/rfc9715.txt) —— UDP 响应 1400 字节上限，超限 TC + TCP 重试
- **多类型捆绑（MQTYPE）**：[RFC 10029](docs/rfc/rfc10029.txt) —— `upstream[*].mqtype` 可配数字 QTYPE 列表（如 `[1, 28]`）；出站查询附加 MQQUERY 捆绑解析，合并记录 warm 缓存（含 DNSSEC 签名）并从客户端响应剥离；服务端支持客户端 MQQUERY 合并（§3.3 八条 FORMERR 校验、§3.4 合并预算与标志匹配）；权威不支持时自动回退独立查询

### 全协议支持
| 协议 | 端口 | 传输 | RFC |
|------|------|------|-----|
| Plain DNS | 53 | UDP/TCP | [RFC 1035](docs/rfc/rfc1035.txt) |
| DoT | 853 | TCP + TLS 1.3 | [RFC 7858](docs/rfc/rfc7858.txt) |
| DoQ | 853 | QUIC | [RFC 9250](docs/rfc/rfc9250.txt) |
| DoH / DoH3 | 443 | HTTP/2 + HTTP/3 | [RFC 8484](docs/rfc/rfc8484.txt) / [RFC 9114](docs/rfc/rfc9114.txt) |
| DTLS | 853 | UDP + DTLS 1.2+ | [RFC 8094](docs/rfc/rfc8094.txt) |
| DNSCrypt | 443 | UDP/TCP + PQ KEM | [draft-denis-dprive-dnscrypt](docs/rfc/draft-denis-dprive-dnscrypt.txt) |
| TLCP DoT | 853 | TCP + SM2/SM3/SM4 | GB/T 38636-2020 |
| TLCP DoH | 443 | HTTP + SM2/SM3/SM4 | GB/T 38636-2020 |
| DTLCP | 853 | UDP + SM2/SM3/SM4 | GM/T 0128-2023 |

### 安全
- **DNSSEC**：完整密码学信任链（DNSKEY→DS→RRSIG），NSEC/NSEC3 否定回答（[RFC 5155](docs/rfc/rfc5155.txt)），REVOKE 位检查（[RFC 5011](docs/rfc/rfc5011.txt)）
- **DNS 防污染**：hopguard（IP TTL 指纹）、spoofguard（UDP 多读）、poisonguard（越权检测）、splitguard（TCP 分段）、capsguard（DNS 0x20 大小写随机化）
- **DNS Cookie**：SipHash-2-4（[RFC 9018](docs/rfc/rfc9018.txt)），密钥 24h 轮换，保留历史密钥兼容慢客户端
- **EDNS Padding**：[RFC 8467](docs/rfc/rfc8467.txt)，请求 128/响应 468 块大小，随机填充
- **ANY 最小响应**：[RFC 8482](docs/rfc/rfc8482.txt)，QTYPE=ANY 返回 `HINFO "RFC8482"` 而非完整区域
- **DNS64**：[RFC 6147](docs/rfc/rfc6147.txt)，AAAA 无记录时从 A 合成（默认前缀 `64:ff9b::/96`）
- **SOCKS5 代理**：每上游可选（TCP CONNECT + UDP ASSOCIATE，[RFC 1928](docs/rfc/rfc1928.txt)/[RFC 1929](docs/rfc/rfc1929.txt)）
- **TLS 隐私 Profile**：[RFC 8310](docs/rfc/rfc8310.txt) Strict/Opportunistic 模式可配

### 解析器信息与发现
- **DDR**：[RFC 9462](docs/rfc/rfc9462.txt)，通过 `_dns.resolver.arpa` SVCB 记录公布加密端点
- **RESINFO**：[RFC 9606](docs/rfc/rfc9606.txt)，`resolver.arpa` 的解析器能力信息（qnamemin/exterr/infourl，随 DDR 发布）

### 缓存与数据库
纯内存存储（LRU 缓存 + 原子统计 + 快照规则，[架构参考](docs/ARCHITECTURE.md)），zstd 压缩存储，缓存命中走 pre-packed 直发路径（零分配、纳秒级）。A/AAAA 记录按延迟探测排序。原子计数器统计 + 可选文件快照持久化。懒惰过期 + 条数上限淘汰。

### 规则集
统一的 IP + 域名标签匹配引擎，上游可按标签分流、Zone 可按标签过滤：

```json
{
  "ruleset": [
    { "tag": "google", "type": "domain", "rule": ["google.com", "*.youtube.com"] },
    { "tag": "cn",     "type": "domain", "file": "china-domains.txt" },
    { "tag": "corp",   "type": "ip",     "rule": ["10.0.0.0/8"] }
  ],
  "upstream": [
    { "address": "8.8.8.8:53",         "match": ["google"] },
    { "address": "114.114.114.114:53", "match": ["cn"] },
    { "address": "10.0.0.1:53",        "match": ["corp"] }
  ]
}
```

- `type: "domain"` — 后缀匹配（含子域）；`file` 每行一条，`#` 注释
- `type: "ip"` — CIDR 匹配，二进制 radix trie O(128)
- `match` 双层作用：查询前分流 + 查询后 IP 过滤（`!tag` 取反）

### 连接池
TCP/TLS [RFC 7766](docs/rfc/rfc7766.txt) 查询管线化 + QUIC 原生流复用，按需拨号入池。5 种 Session Cache（TLS/DTLS/QUIC/TLCP/DTLCP）减少握手开销。

### KTLS 内核卸载
TLS 加解密卸载至 Linux 内核（`af_alg` + `setsockopt(TCP_ULP)`）。仅适用 TLS/HTTPS（TCP），非 Linux 静默回退。

## 配置

### 上游服务器

| 字段 | 类型 | 说明 |
|------|------|------|
| `address` | string | `host:port` / `https://host:port/path` / `sdns://` |
| `protocol` | string | 传输协议（`udp`/`tls`/`quic`/`https`/`http3`/`dtls`/`dnscrypt`/`tlcp`/`http-tlcp`/`dtlcp`/`recursive`），`sdns://` 自动推导 |
| `server_name` | string | TLS SNI / DNSCrypt provider name |
| `skip_tls_verify` | bool | 跳过 TLS 证书验证 |
| `privacy_profile` | string | `"strict"`（默认，[RFC 8310](docs/rfc/rfc8310.txt) §6）/ `"opportunistic"`（§5） |
| `skip_cache` | bool | 禁止缓存该上游响应 |
| `fallback` | bool | 兜底上游：与主上游并发查询，但主上游在 500ms 内无结果、或全部主上游提前失败退出时才采纳其响应；结果附 EDE 65280 且全链不缓存，采纳后主上游继续后台填充缓存（需至少一个非 `fallback` 上游） |
| `match` | []string | 规则集标签分流 |
| `proxy` | string | SOCKS5 代理：`socks5://[user:pass@]host:port` |
| `public_key` | string | DNSCrypt 公钥（hex） |
| `pqdnscrypt` | bool | 优先使用后量子证书（默认 `true`） |
| `ephemeral_keys` | bool | 每查询新 X25519 密钥对，前向安全（默认 `true`） |
| `poisonguard` | bool | 递归越权检测 |
| `spoofguard` | bool | UDP 多读防欺骗 |
| `splitguard` | bool | TCP 分段防 RST |
| `hopguard` | bool | IP TTL 指纹防欺骗 |
| `capsguard` | bool | DNS 0x20 问题名大小写随机化（应答须逐字节回显） |
| `mqtype` | []uint16 | [RFC 10029](docs/rfc/rfc10029.txt) 捆绑 QTYPE 列表（数字，如 `[1, 28]` = A + AAAA）——查询时附加 MQQUERY 捆绑解析，合并记录 warm 缓存并从客户端响应剥离；空 = 关闭 |

### 防污染配置示例

```json
{ "protocol": "recursive", "poisonguard": true, "spoofguard": true, "splitguard": true, "hopguard": true },
{ "address": "8.8.4.4:53", "protocol": "udp", "spoofguard": true },
{ "address": "8.8.8.8:53", "protocol": "tcp", "splitguard": true },
{ "address": "8.8.8.8:53", "protocol": "udp", "hopguard": true }
```

### 常用功能配置

```json
{
  "server": {
    "protocol": { "udp": "53", "tcp": "53", "tls": "853", "quic": "853", "https": { "port": "443", "endpoint": "/dns-query" } },
    "certificate": { "domain": "dns.example.com", "tls": { "self_signed": true } },
    "features": {
      "ecs_subnet": { "ipv4": "1.2.3.0/24", "ipv6": "2001:db8::/56" },
      "dns64": { "prefix": "64:ff9b::/96" },
      "cache": {
        "entries": { "limit": 10000, "prefer_stale": true, "state_file": "/var/lib/zjdns/zjdns.state.cache" }
      },
      "ktls": { "kernel_tx": true, "kernel_rx": false }
    }
  }
}
```

- **KTLS**：需先 `modprobe tls`，仅 Linux + TLS/HTTPS（TCP）生效，非 Linux 静默回退
- **DNS64**：纯 IPv6/NAT64 网络必备，AAAA 无记录时从 A 合成
- **ECS**：CIDR 格式指定子网（如 `"1.2.3.0/24"`），[RFC 7871](docs/rfc/rfc7871.txt) 建议 `/24`（IPv4）、`/56`（IPv6）。设为 `"auto"` 自动检测公网 IP
- **prefer_stale**：上游不可达时优先返回过期缓存（[RFC 8767](docs/rfc/rfc8767.txt)）
- **state_file**：默认**为空 = 不持久化**（纯内存，重启冷启动）；设置路径后启用快照持久化 —— 缓存/延迟/委派三个 store 各自独立开关，配置示例见上（`./zjdns.cache` 等）。DNSCrypt 的 `certificate.dnscrypt.state_file` 同理，默认空则每次重启更换证书窗口
- **self_signed**：自动生成自签名证书，跳过 `cert_file`/`key_file`

### 协议监听示例

```json
{ "server": { "protocol": {
  "udp": "53",          // 标准 DNS
  "tls": "853",         // DoT
  "quic": "853",        // DoQ（与 DoT 共享 UDP 853）
  "https": { "port": "443", "endpoint": "/dns-query" },  // DoH
  "http3": { "port": "443", "endpoint": "/dns-query" },  // DoH3（与 DoH 共享 UDP 443）
  "dtls": "853",        // DTLS（与 DoQ 共享 UDP 853）
  "dnscrypt": "443",    // DNSCrypt（与 DoH 共享 TCP 443，需 certificate.dnscrypt 配置密钥）
  "tlcp": "853",        // TLCP DoT（与 DoT 共享 TCP 853，需 certificate.tlcp 配置 SM2 证书）
  "http_tlcp": { "port": "443", "endpoint": "/dns-query" },  // TLCP DoH（与 DoH 共享 TCP 443）
  "dtlcp": "853"        // DTLCP（与 DoQ 共享 UDP 853）
} }
```

## CLI 工具

```bash
# DNS Stamp 编解码
./zjdns --dnsstamp --decode "sdns://..."              # 解码为上游 JSON
./zjdns --dnsstamp --encode --proto doh \             # 编码为 sdns://
    --stamp-addr 9.9.9.9 --provider-name dns.quad9.net:443 --path /dns-query


# 探测上游能力
./zjdns --probe --pipeline    tcp://8.8.8.8:53       # [RFC 7766](docs/rfc/rfc7766.txt) 管线化
./zjdns --probe --conn-reuse  tls://1.1.1.1:853      # [RFC 1035](docs/rfc/rfc1035.txt) 连接复用
./zjdns --probe --idle-timeout tls://1.1.1.1:853     # 空闲超时
```

## 构建与测试

```bash
go build -o zjdns ./cmd/zjdns                         # 构建
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ...    # 交叉编译
go test -short ./...                                   # 测试
go test -bench=. -short -benchtime=500ms ./...         # Benchmark
golangci-lint run && golangci-lint fmt                 # Lint
```

## 文档

| 文档 | 内容 |
|------|------|
| [AUDIT-METHODOLOGY.md](docs/AUDIT-METHODOLOGY.md) | 审计框架 |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构设计、设计决策 |
| [BENCHMARK.md](docs/benchmark/BENCHMARK.md) | Benchmark 指南 |
| [DEBUG.md](docs/debug/DEBUG.md) | 调试配置、E2E 测试 |
| [GUIDELINE.md](docs/rfc/GUIDELINE.md) | RFC 精华指南（RFC 的关键常量/协议流程/合规状态） |
| [FLOWCHARTS.md](docs/FLOWCHARTS.md) | 架构流程图（查询管道、DNS 防污染、DNSSEC、递归解析） |

## License

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
