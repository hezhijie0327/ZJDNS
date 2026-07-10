# ZJDNS

```
███████╗     ██╗██████╗ ███╗   ██╗███████╗
╚══███╔╝     ██║██╔══██╗████╗  ██║██╔════╝
  ███╔╝      ██║██║  ██║██╔██╗ ██║███████╗
 ███╔╝  ██   ██║██║  ██║██║╚██╗██║╚════██║
███████╗╚█████╔╝██████╔╝██║ ╚████║███████║
╚══════╝ ╚════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
```

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success)](https://golangci-lint.run/)

高性能递归 DNS 解析服务器，内置 SQLite 关系型缓存引擎、DNSSEC 密码学验证链、DNSCrypt/DoT/DoQ/DoH/DoH3 全协议支持，DNSCrypt 支持后量子密码学 (PQC) X-Wing KEM 及 XChacha20-Poly1305 AEAD。

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
./zjdns --generate-config --dnscrypt --provider example.com [--addr <host:port>] [--es-version xwingpq|xchacha20poly1305] [--cert-ttl 30d]

# 执行 SQL 查询
./zjdns --sql cache.db "SELECT * FROM zone_entries"
```

```bash
# DNS 查询测试
dig @127.0.0.1 -p 53 example.com                 # UDP
dig @127.0.0.1 -p 53 example.com +tcp             # TCP
kdig @127.0.0.1 -p 853 example.com +tls           # DoT
kdig @127.0.0.1 -p 853 example.com +quic          # DoQ
kdig @127.0.0.1 -p 443 example.com +https         # DoH

# 验证 DNSCrypt 证书握手
dig @127.0.0.1 -p 8443 2.dnscrypt-cert.example.com TXT   # 获取 DNSCrypt 证书
```

## 核心特性

### 统一数据库

基于 SQLite WAL 模式的统一关系型数据库（`database/`），七表设计，缓存与区域规则共享同一 DB 连接：

| 表 | 说明 |
|----|------|
| `entries` | DNS 响应缓存（8 列，UNIQUE 约束，zstd 压缩 BLOB） |
| `zone_entries` | 区域规则匹配（复合主键，O(log n) 查询，zstd 压缩 BLOB） |
| `request_log` | 请求日志（entry_id FK，miss/stale/zone/error） |
| `entry_hit_counters` | 命中计数器（entry+protocol+rcode 聚合） |
| `stats_meta` | 统计元信息（单行，记录上次清除阈值） |
| `ip_latency` | 延迟探测结果（IP 为键，所有域名共享同 IP 行） |
| `ptr_map` | PTR 反向映射（IP→域名，WITHOUT ROWID，ON DELETE CASCADE） |

- **Wire format 加速**：`msg_wire` BLOB 存储 zstd 压缩的 DNS 响应，`Get()` 解压缩 + `Msg.Unpack()` 一步还原，缓存命中 ~0.5ms
- **延迟驱动排序**：A/AAAA 记录按 `ip_latency` 探测结果排序（最快优先），同一 CDN IP 多域名共享延迟数据
- **请求日志去冗余**：`request_log` 通过 `entry_id` JOIN `entries` 获取 qname/qtype，省去冗余存储。`entry_hit_counters` 聚合缓存命中计数，避免重复 hit 行膨胀
- **统计独立**：`FlushDB("stats")` 清空 `entry_hit_counters` + 重置 `stats_meta` 阈值，`request_log` 保留可查
- **驱逐策略**：TTL 惰性过期 + 条数上限最旧淘汰，`ON DELETE CASCADE` 统一清理关联表
- **写入优化**：`Set()` 提交 INSERT 后立即释放 `writeMu`，eviction 独立事务不阻塞并发写入

### DNS 解析

- **递归解析**：从 IANA 根服务器（静态根提示 + 延迟排序缓存）逐步解析至 TLD 和权威服务器，完整 DNSSEC 信任链
- **上游转发**：主/备服务器并发查询（`errgroup` + 首胜策略），上游优先
- **混合模式**：上游 DNS 与 `builtin_recursive` 可同时配置，并发竞争
- **SOCKS5 代理**：每上游可选代理（TCP CONNECT + UDP ASSOCIATE，RFC 1928/1929）
- **连接池**：TCP/DoT RFC 7766 查询流水线 + DoQ QUIC 原生流复用，按需拨号入池
- **CNAME 追踪**：多级追踪（最大 16 级），防循环检测
- **按接口绑定**：所有监听器按网卡 IP 逐一绑定，端口冲突自动跳过
- **延迟探测**：ICMP/TCP/UDP/HTTP/HTTPS/HTTP3 统一引擎，异步写入 `ip_latency`
- **`no_cache` 开关**：按上游/回退服务器禁用缓存，不信任的上游响应不会污染本地缓存

### 上游服务器配置

`upstream` 和 `fallback` 均使用 `UpstreamServer` 结构，字段如下：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `address` | string | ✓ | 服务器地址。`host:port`、`https://host:port/path`、`builtin_recursive` 或 `sdns://` DNSCrypt 戳记 |
| `protocol` | string | | 传输协议：`udp`(默认)/`tcp`/`tls`(DoT)/`quic`(DoQ)/`https`(DoH)/`http3`(DoH3)/`dnscrypt`(DNSCrypt UDP)/`dnscrypt-tcp`(DNSCrypt TCP) |
| `server_name` | string | TLS/DNSCrypt | TLS SNI 主机名；非戳记 DNSCrypt 时用作 provider name |
| `skip_tls_verify` | bool | | 跳过 TLS 证书验证 |
| `no_cache` | bool | | 禁止缓存该上游的响应（默认 `false`=正常缓存） |
| `match` | []string | | CIDR 标签过滤（`!tag` 排除） |
| `proxy` | string | | SOCKS5 代理：`socks5://[user:pass@]host:port` |
| `public_key` | string | DNSCrypt | 解析器 Ed25519 公钥（hex），非戳记 DNSCrypt 必填 |

### 安全

- **DNSSEC**：完整密码学信任链（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 已验证否定（RFC 5155）
- **QNAME 最小化**：RFC 9156，默认启用，计数器推进 + 按比例暴露标签
- **劫持防护**：根/TLD 越权响应检测（`Detector.Validate`）→ UDP→TCP 自动回退绕过 GFW 中间盒注入
- **DNS Cookie**：HMAC-SHA256（RFC 7873），服务器密钥每 30 分钟轮换，保留 2 个历史密钥避免慢客户端 BADCOOKIE
- **并发查询去重**（singleflight）：同 key 的并发缓存 miss 合并为一次上游查询，leader 完成广播给所有 follower，消除缓存投毒竞争窗口
- **CIDR 过滤**：基于标签的 IP 匹配，支持取反（`!tag`），IPv4 预转换为 `uint32` 位运算
- **EDNS Padding**：随机填充字节（`crypto/rand`）替代确定性零填充，增强流量分析抵抗
- **安全传输**：DNSCrypt v2（XChacha20-Poly1305 AEAD + 后量子 X-Wing KEM，UDP/TCP 双协议，UDP→TCP 自动回退、PQ 票据续期减少重复 KEM 开销）、DoT (RFC 7858)、DoQ (RFC 9250)、DoH (RFC 8484)、DoH3，TLS 1.3 + KTLS 可选卸载

### 可观测性

- **运行时查询**：`dig zjdns.stats CH TXT` 缓存统计（8 条 TXT 记录：概览、成功、错误、响应码、异常、明文协议、加密协议、DNSSEC）
- **缓存管理**：`dig zjdns.db.clear CH TXT` 全清 / `.db.clear.cache` 清缓存 / `.db.clear.stats` 清零统计 / `.db.clear.latency` 清延迟数据，仅限本地回环
- **组件级日志**：`log_level` 支持 `level:COMP1,COMP2` 语法（如 `debug:UPSTREAM,SECURITY`），19 个日志前缀
- **CLI 分析工具**：`zjdns --sql <db> <query>` 直接 SQL 查询或修改数据库
- **Schema 迁移**：增量版本号 `migration_version`，老库自动升级；旧迁移导出 `.sql` 文件可手动执行
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

`bypass_tags` 指定跳过所有 zone 规则的 CIDR 标签（如网关设备），配合 `cidr` 段的 `ips` 使用。

## 配置示例

```json
{
  "server": {
    "port": "53",
    "log_level": "info",
    "tls": { "port": "853", "self_signed": true },
    "dnscrypt": {
      "port": "8443",
      "provider_name": "2.dnscrypt-cert.example.com",
      "es_version": "xwingpq",
      "cert_ttl": "30d"
    },
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "database": {
        "db_path": "/var/lib/zjdns/cache.db",
        "mmap_size_mb": 16,
        "cache_size_mb": 16
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
    { "address": "sdns://...", "protocol": "dnscrypt" },
    { "address": "9.9.9.9:8443", "protocol": "dnscrypt",
      "server_name": "2.dnscrypt-cert.quad9.net",
      "public_key": "67C847B8C8758CD120245543BE756746DF34DF1D84C00B8C470368DF821D863E" }
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
| 家庭 | 1 万 | ~20MB | 16MB | ~20MB | `mmap_size_mb: 16, cache_size_mb: 16` |
| 高负载 | 5 万 | ~100MB | 128MB | ~50MB | `mmap_size_mb: 128, cache_size_mb: 32` |
| 保守 | 5 万 | ~100MB | 64MB | ~30MB | `mmap_size_mb: 64, cache_size_mb: 8` |

- **`mmap_size_mb`**：设太小会退化到 `read()` I/O。设太大浪费虚拟地址空间（64 位系统无所谓）。建议 ≥ 数据库文件大小。
- **`cache_size_mb`**：DNS 查询符合 Zipf 分布（少数热门域名占大部分请求），不需要覆盖全库。8MB 足够缓存 b-tree 内部节点 + 热门叶子页。
- **`db_path`**：空串 = 纯内存模式（进程重启数据丢失）。

```json
// 默认值（家庭场景）
"cache": { "max_entries": 10000, "mmap_size_mb": 16, "cache_size_mb": 16 }

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
./zjdns --sql /var/lib/zjdns/cache.db "SELECT rl.timestamp, e.qname, rl.result, rl.response_time_ms FROM request_log rl JOIN entries e ON rl.entry_id = e.id ORDER BY rl.timestamp DESC LIMIT 10"
```

### 常用查询

```sql
-- 缓存命中率（request_log + entry_hit_counters 合并）
SELECT result, SUM(cnt) AS total FROM (
  SELECT result, COUNT(*) AS cnt FROM request_log
  WHERE id > (SELECT cleared_before FROM stats_meta) GROUP BY result
  UNION ALL
  SELECT 'hit' AS result, SUM(hit_count) AS cnt FROM entry_hit_counters
) GROUP BY result ORDER BY total DESC;

-- 各上游服务器的请求量（非命中请求，含平均响应时间 ms）
SELECT rl.server, COUNT(*) AS requests, ROUND(AVG(rl.response_time_ms), 1) AS avg_ms
FROM request_log rl WHERE rl.server != '' GROUP BY rl.server ORDER BY requests DESC;

-- rcode 分布（request_log + entry_hit_counters 合并）
SELECT rcode, SUM(cnt) AS total FROM (
  SELECT rcode, COUNT(*) AS cnt FROM request_log
  WHERE id > (SELECT cleared_before FROM stats_meta) GROUP BY rcode
  UNION ALL
  SELECT rcode, SUM(hit_count) AS cnt FROM entry_hit_counters GROUP BY rcode
) GROUP BY rcode ORDER BY total DESC;

-- 被劫持的查询
SELECT e.qname, e.qtype, rl.server, rl.response_time_ms
FROM request_log rl JOIN entries e ON rl.entry_id = e.id
WHERE rl.hijack = 1 ORDER BY rl.timestamp DESC;

-- 慢查询（>1s）
SELECT e.qname, e.qtype, rl.server, rl.rcode, rl.response_time_ms
FROM request_log rl JOIN entries e ON rl.entry_id = e.id
WHERE rl.response_time_ms > 1000 ORDER BY rl.response_time_ms DESC;

-- 延迟最低的 IP（按地址族分组统计）
SELECT qtype, rdata_ip, latency_ms FROM ip_latency
ORDER BY latency_ms ASC;

-- PTR 反查（某 IP 对应的所有域名）
SELECT DISTINCT pm.name FROM ptr_map pm
JOIN entries e ON pm.entry_id = e.id
WHERE pm.rdata_ip = '104.20.23.154' AND e.expires_at + 2592000 >= unixepoch();

-- Top 10 命中域名（cache hit 统计）
SELECT e.qname, e.qtype, SUM(hc.hit_count) AS requests
FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id
GROUP BY e.qname ORDER BY requests DESC LIMIT 10;

-- 协议分布（request_log + entry_hit_counters 合并）
SELECT protocol, SUM(cnt) AS total FROM (
  SELECT protocol, COUNT(*) AS cnt FROM request_log
  WHERE id > (SELECT cleared_before FROM stats_meta) GROUP BY protocol
  UNION ALL
  SELECT protocol, SUM(hit_count) AS cnt FROM entry_hit_counters GROUP BY protocol
) GROUP BY protocol ORDER BY total DESC;

-- DNSSEC 状态分布（仅限非命中请求，hits 不记录 DNSSEC 状态）
SELECT dnssec_status, COUNT(*) AS cnt FROM request_log
WHERE id > (SELECT cleared_before FROM stats_meta)
GROUP BY dnssec_status ORDER BY cnt DESC;

-- 某域名的请求历史（非命中请求：miss/stale/zone/error/blocked/badcookie）
SELECT rl.timestamp, rl.protocol, rl.result, rl.rcode, rl.response_time_ms, rl.server, rl.hijack
FROM request_log rl JOIN entries e ON rl.entry_id = e.id
WHERE e.qname = 'www.google.com' ORDER BY rl.timestamp DESC LIMIT 20;

-- 某域名的缓存命中统计（按协议/rcode 聚合）
SELECT e.qname, hc.protocol, hc.rcode, SUM(hc.hit_count) AS hits
FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id
WHERE e.qname = 'www.google.com'
GROUP BY hc.protocol, hc.rcode ORDER BY hits DESC;
```

## 支持的标准

| RFC / 草案 | 标准 | 实现 |
|------------|------|------|
| [1928](https://www.rfc-editor.org/info/rfc1928) / [1929](https://www.rfc-editor.org/info/rfc1929) | SOCKS5 | TCP CONNECT + UDP ASSOCIATE |
| [2308](https://www.rfc-editor.org/info/rfc2308) | Negative Caching | SOA 负面 TTL 缓存 |
| [4033–4035](https://www.rfc-editor.org/info/rfc4033) | DNSSEC | 信任链验证 + RRSIG |
| [5155](https://www.rfc-editor.org/info/rfc5155) | NSEC3 | 已验证否定（DoS 防护：迭代次数上限 150） |
| [6840](https://www.rfc-editor.org/info/rfc6840) | DNSSEC Clarifications | 特殊标签处理（Digest 类型、NXT 等） |
| [6891](https://www.rfc-editor.org/info/rfc6891) | EDNS(0) | FORMERR 自动回退无 EDNS 重试 |
| [7766](https://www.rfc-editor.org/info/rfc7766) | DNS over TCP | 连接池复用 + 流水线（最多 16 路并发） |
| [7828](https://www.rfc-editor.org/info/rfc7828) | EDNS TCP Keepalive | 长连接空闲超时协商 |
| [7830](https://www.rfc-editor.org/info/rfc7830) / [8467](https://www.rfc-editor.org/info/rfc8467) | EDNS Padding | 查询 128B / 响应 468B（DoT/DoQ/DoH 加密链接专用） |
| [7858](https://www.rfc-editor.org/info/rfc7858) | DNS over TLS | DoT TLS 1.3 |
| [7871](https://www.rfc-editor.org/info/rfc7871) | EDNS Client Subnet | ECS 子网隐私控制 |
| [7873](https://www.rfc-editor.org/info/rfc7873) | DNS Cookies | HMAC-SHA256 服务器 Cookie |
| [8484](https://www.rfc-editor.org/info/rfc8484) | DNS over HTTPS | DoH (HTTP/2) |
| [8767](https://www.rfc-editor.org/info/rfc8767) | Serving Stale | 过期缓存服务 + 后台预取 |
| [8914](https://www.rfc-editor.org/info/rfc8914) | Extended DNS Errors | EDE 代码传递 |
| [9000](https://www.rfc-editor.org/info/rfc9000) / [9114](https://www.rfc-editor.org/info/rfc9114) | QUIC / HTTP/3 | DoQ + DoH3 传输层 |
| [9077](https://www.rfc-editor.org/info/rfc9077) | NSEC/NSEC3 TTL | 负面缓存 TTL 封顶 (10800s) |
| [9156](https://www.rfc-editor.org/info/rfc9156) | QNAME Minimisation | 递归查询名最小化 |
| [9250](https://www.rfc-editor.org/info/rfc9250) | DNS over QUIC | DoQ |
| [9461](https://www.rfc-editor.org/info/rfc9461) / [9462](https://www.rfc-editor.org/info/rfc9462) | SVCB / DDR | 加密解析器自动发现 |
| [draft-denis-dprive-dnscrypt](https://datatracker.ietf.org/doc/draft-denis-dprive-dnscrypt/) | DNSCrypt v2 | XChacha20 AEAD + X-Wing PQ KEM |

## 开发

```bash
golangci-lint run && golangci-lint fmt   # 零警告，gofumpt 格式化
go test ./... -short
go test -bench=. -short ./...
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns
```

## 许可证

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
