# ZJDNS

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success)](https://golangci-lint.run/)

高性能递归 DNS 解析服务器，内置 SQLite 关系型缓存引擎、DNSSEC 密码学验证链、DoT/DoQ/DoH/DoH3 全协议支持。

## 快速开始

```bash
# 构建
go build -o zjdns ./cmd/zjdns

# 纯递归模式（内存缓存）
./zjdns

# 指定配置文件
./zjdns -config config.json

# 生成示例配置
./zjdns -example
```

```bash
# DNS 查询测试
dig @127.0.0.1 -p 53 example.com                 # UDP
dig @127.0.0.1 -p 53 example.com +tcp             # TCP
kdig @127.0.0.1 -p 853 example.com +tls           # DoT
kdig @127.0.0.1 -p 853 example.com +quic          # DoQ
kdig @127.0.0.1 -p 443 example.com +https         # DoH
```

## 核心特性

### 缓存引擎

基于 SQLite WAL 模式的关系型缓存，四表设计：

| 表 | 说明 |
|----|------|
| `entries` | DNS 响应缓存（16 列，UNIQUE 约束，zstd 压缩 BLOB） |
| `hit_counters` | 热命中计数器（WITHOUT ROWID，entry_id 即行，六协议分布） |
| `ip_latency` | 延迟探测结果（IP 为键，所有域名共享同 IP 行，qtype 自动推断） |
| `ptr_map` | PTR 反向映射（IP→域名，WITHOUT ROWID，ON DELETE CASCADE） |

- **Wire format 加速**：`msg_wire` BLOB 存储 zstd 压缩的 DNS 响应，`Get()` 解压缩 + `Msg.Unpack()` 一步还原，缓存命中 ~0.5ms
- **延迟驱动排序**：A/AAAA 记录按 `ip_latency` 探测结果排序（最快优先），同一 CDN IP 多域名共享延迟数据，在 `Get()` 时批量查询重排
- **热路径预编译语句**：`Get`、`RecordServe`、`UpdateLatency` 查询在初始化时 `Prepare()`，避免每次调用重复编译 SQL
- **CHECK 约束**：布尔列（`cacheable`、`validated`、`fallback`、`prefetch`、`hijack`、`dnssec_ok`）均带 `CHECK (col IN (0,1))` 数据完整性保护
- **PTR 反查**：轻量 `ptr_map` 表，`SELECT ... WHERE rdata_ip = ? JOIN entries` 查询
- **驱逐策略**：TTL 惰性过期 + 条数上限最旧淘汰（优先淘汰 `expires_at + staleMaxAge < now` 的条目），`ON DELETE CASCADE` 自动清理关联表
- **Summary 快照**：启动/关闭时输出一行聚合统计（条目数、命中率、六协议分布、rcode 分布、hijack/prefetch/stale 计数）
- **持久化**：`db_path` 指定 SQLite 文件路径，跨重启保留全量缓存

### DNS 解析

- **递归解析**：从 IANA 根服务器（静态根提示 + 延迟排序缓存）逐步解析至 TLD 和权威服务器，完整 DNSSEC 信任链
- **上游转发**：主/备服务器并发查询（`errgroup` + 首胜策略），上游优先
- **混合模式**：上游 DNS 与 `builtin_recursive` 可同时配置，并发竞争
- **SOCKS5 代理**：每上游可选代理（TCP CONNECT + UDP ASSOCIATE，RFC 1928/1929）
- **连接池**：TCP/DoT RFC 7766 查询流水线 + DoQ QUIC 原生流复用，按需拨号入池
- **CNAME 追踪**：多级追踪（最大 16 级），防循环检测
- **按接口绑定**：所有监听器按网卡 IP 逐一绑定，端口冲突自动跳过
- **延迟探测**：ICMP/TCP/UDP/HTTP/HTTPS/HTTP3 统一引擎，异步写入 `ip_latency`

### 安全

- **DNSSEC**：完整密码学信任链（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 已验证否定（RFC 5155）
- **QNAME 最小化**：RFC 9156，默认启用，计数器推进 + 按比例暴露标签
- **劫持防护**：根/TLD 越权响应检测（`Detector.Validate`）→ UDP→TCP 自动回退绕过 GFW 中间盒注入
- **DNS Cookie**：HMAC-SHA256（RFC 7873），服务器密钥每 30 分钟轮换，无效 Cookie 返回 BADCOOKIE
- **CIDR 过滤**：基于标签的 IP 匹配，支持取反（`!tag`），IPv4 预转换为 `uint32` 位运算
- **安全传输**：DoT (RFC 7858)、DoQ (RFC 9250)、DoH (RFC 8484)、DoH3，TLS 1.3 + KTLS 可选卸载

### 可观测性

- **Summary 快照**：启动/关闭时自动输出聚合统计行
- **组件级日志**：`log_level` 支持 `level:COMP1,COMP2` 语法（如 `debug:UPSTREAM,SECURITY`），17 个日志前缀
- **CLI 分析工具**：`zjdns -analyze <db> <query>` 直接 SQL 查询缓存数据库
- **pprof**：标准 Go 性能分析端点

## 配置示例

```json
{
  "server": {
    "port": "53",
    "log_level": "info",
    "tls": { "port": "853", "self_signed": true },
    "features": {
      "hijack_protection": true,
      "dnssec_enforce": true,
      "cache": {
        "max_entries": 10000,
        "mmap_size_mb": 16,
        "cache_size_mb": 4,
        "db_path": "/var/lib/zjdns/cache.db",
        "prefer_stale": true
      },
      "latency_probe": [
        { "protocol": "ping", "timeout": 200 },
        { "protocol": "tcp", "port": 443, "timeout": 200 }
      ]
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

`log_level` 支持组件过滤：`debug:UPSTREAM,RECURSION` 仅输出指定组件 Debug 日志。

### 缓存调优

| 参数 | 占用 | 说明 |
|------|------|------|
| `max_entries` | 磁盘 | 条目数上限，1 万条 ≈ 15MB |
| `mmap_size_mb` | 虚拟内存 | 数据库文件 mmap，OS page cache 管理 |
| `cache_size_mb` | 物理内存 | SQLite 内部 page cache，真实占用 RAM |
| `db_path` | 磁盘路径 | 数据库文件位置；空串 = 内存模式 |

```json
// 家庭场景：1 万条，~20MB 磁盘，4MB RAM
"cache": { "max_entries": 10000, "mmap_size_mb": 16, "cache_size_mb": 4 }

// 高负载场景：5 万条，~100MB 磁盘，16MB RAM
"cache": { "max_entries": 50000, "mmap_size_mb": 128, "cache_size_mb": 16 }
```

## 数据库查询

```bash
# 方式一：sqlite3 直接查询
sqlite3 /var/lib/zjdns/cache.db "SELECT COUNT(*) FROM entries"

# 方式二：内置 analyze（对齐表格输出）
./zjdns -analyze /var/lib/zjdns/cache.db "SELECT e.qname, e.hit_udp FROM entries e"
```

### 常用查询

```sql
-- 缓存命中率
SELECT
  COALESCE(SUM(hc.hit_udp + hc.hit_tcp + hc.hit_dot + hc.hit_doq + hc.hit_doh + hc.hit_doh3), 0) AS total_hits,
  COUNT(*) AS total_entries
FROM hit_counters hc JOIN entries e ON hc.entry_id = e.id;

-- 各上游服务器的请求量与平均响应时间
SELECT e.server, COUNT(*) AS requests, ROUND(AVG(e.response_time_ms), 1) AS avg_ms
FROM entries e GROUP BY e.server ORDER BY requests DESC;

-- rcode 分布
SELECT rcode, COUNT(*) AS cnt FROM entries GROUP BY rcode ORDER BY cnt DESC;

-- 被劫持的查询
SELECT qname, qtype, server, response_time_ms
FROM entries WHERE hijack = 1 ORDER BY response_time_ms DESC;

-- 慢查询（>1s）
SELECT qname, qtype, server, rcode, response_time_ms
FROM entries WHERE response_time_ms > 1000 ORDER BY response_time_ms DESC;

-- 延迟最低的 IP（按地址族分组统计）
SELECT qtype, rdata_ip, latency_ms FROM ip_latency
ORDER BY latency_ms ASC;

-- PTR 反查（某 IP 对应的所有域名）
SELECT DISTINCT pm.name FROM ptr_map pm
JOIN entries e ON pm.entry_id = e.id
WHERE pm.rdata_ip = '104.20.23.154' AND e.expires_at + 2592000 >= unixepoch();

-- Top 10 命中域名
SELECT e.qname, e.qtype,
  SUM(hc.hit_udp + hc.hit_tcp + hc.hit_dot + hc.hit_doq + hc.hit_doh + hc.hit_doh3) AS hits
FROM entries e JOIN hit_counters hc ON e.id = hc.entry_id
GROUP BY e.qname, e.qtype ORDER BY hits DESC LIMIT 10;

-- 协议命中分布
SELECT SUM(hc.hit_udp) AS udp, SUM(hc.hit_tcp) AS tcp,
       SUM(hc.hit_dot) AS dot, SUM(hc.hit_doq) AS doq,
       SUM(hc.hit_doh) AS doh, SUM(hc.hit_doh3) AS doh3
FROM hit_counters hc;

-- DNSSEC 状态分布
SELECT dnssec, COUNT(*) AS cnt FROM entries GROUP BY dnssec ORDER BY cnt DESC;
```

## 支持的标准

| RFC | 标准 | 实现 |
|-----|------|------|
| 4033–4035 | DNSSEC | 信任链验证 + RRSIG |
| 5155 | NSEC3 | 已验证否定（DoS 防护：迭代次数上限 150） |
| 6891 | EDNS(0) | FORMERR 自动回退无 EDNS 重试 |
| 7766 | DNS over TCP | 连接池复用 + 流水线（最多 16 路并发） |
| 7830/8467 | EDNS Padding | 查询 128B / 响应 468B |
| 7858 | DNS over TLS | DoT TLS 1.3 |
| 7871 | EDNS Client Subnet | ECS 子网 |
| 7873 | DNS Cookies | HMAC-SHA256 服务器 Cookie |
| 8484 | DNS over HTTPS | DoH (HTTP/2) |
| 8767 | Serving Stale | 过期缓存服务 + 后台预取 |
| 8914 | Extended DNS Errors | EDE 代码传递 |
| 9077 | NSEC/NSEC3 TTL | 负面缓存 TTL 封顶 (10800s) |
| 9156 | QNAME Minimisation | 递归查询名最小化 |
| 9250 | DNS over QUIC | DoQ |
| 9461/9462 | SVCB / DDR | 自动发现 |

## 开发

```bash
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns
go test ./... -short
go test -bench=. -short ./...
golangci-lint run && golangci-lint fmt
```

## 许可证

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
