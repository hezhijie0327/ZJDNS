# ZJDNS

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success)](https://golangci-lint.run/)

高性能递归 DNS 解析服务器。SQLite 关系型缓存引擎、DNSSEC 密码学验证、DoT/DoQ/DoH/DoH3 全协议支持。

> **生产就绪状态**：本项目尚未经过生产环境充分验证，请谨慎用于关键业务。

## 快速开始

```bash
# 构建
go build -o zjdns ./cmd/zjdns

# 启动（纯递归模式，内存缓存）
./zjdns

# 启动（指定配置）
./zjdns -config config.json
```

```bash
# 测试解析
dig @127.0.0.1 -p 53 example.com                 # UDP
dig @127.0.0.1 -p 53 example.com +tcp             # TCP
kdig @127.0.0.1 -p 853 example.com +tls           # DoT
kdig @127.0.0.1 -p 853 example.com +quic          # DoQ
kdig @127.0.0.1 -p 443 example.com +https         # DoH
```

## 核心特性

### 缓存引擎

基于 SQLite WAL 模式的关系型缓存，三表设计：

| 表 | 说明 |
|----|------|
| `entries` | 缓存条目（查-命-标 11 列，UNIQUE 约束） |
| `records` | DNS 记录行（引-标-数-探，DELETE CASCADE） |
| `metadata` | 解析元数据 + 协议命中计数 + 事件计数（1:1，DELETE CASCADE） |

- **无内存缓存层**：SQLite B-tree + mmap 直接作为存储引擎，热页由 OS page cache 零拷贝服务
- **延迟驱动排序**：`records.latency_ms` 列存储探测延迟，`ORDER BY latency_ms ASC` 自然最快优先
- **PTR 反查**：`SELECT ... FROM records WHERE rdata_ip = ? JOIN entries`，无需单独反向索引
- **DNSKEY 缓存**：与普通 DNS 缓存共享同一套 `entries + records` 表
- **NS 地址缓存**：A/AAAA 记录 + latency_ms，根服务器和每 NS 地址统一存储
- **全维度分析**：metadata 记录 rcode、响应时间、来源服务器、DNSSEC 状态、hijack/fallback/prefetch 标记、六协议命中、stale/rewrite 计数
- **SQL 数据分析**：`SELECT m.server, SUM(m.hit_doh) FROM entries e JOIN metadata m ON e.id = m.entry_id GROUP BY m.server`
- **Summary 快照**：启动/关闭时输出一行聚合统计（条目数、命中率、平均响应时间、协议分布、rcode 分布等）
- **持久化**：`db_path` 指定数据库文件路径，跨重启保留全量缓存和 metadata
- **驱逐策略**：TTL 惰性过期 + 条数上限最旧淘汰 + 5 分钟定期清理

### DNS 解析

- **递归解析**：从 IANA 根服务器逐步解析至 TLD 和权威服务器，完整 DNSSEC 信任链
- **上游转发**：主/备服务器并发查询 + 首胜策略，上游优先
- **混合模式**：上游 DNS 与内置递归（`builtin_recursive`）可同时配置
- **SOCKS5 代理**：每上游可选代理（TCP CONNECT + UDP ASSOCIATE，RFC 1928/1929）
- **连接池**：TCP/DoT RFC 7766 查询流水线 + DoQ QUIC 原生流复用
- **CNAME 解析**：多级追踪（最大 16 级），防循环
- **按接口绑定**：所有监听器按网卡 IP 逐一绑定，端口冲突自动跳过
- **延迟探测**：ICMP/TCP/UDP/HTTP/HTTPS/HTTP3 统一引擎，结果写入 `latency_ms`

### 安全

- **DNSSEC**：完整信任链验证（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 已验证否定（RFC 5155）
- **QNAME 最小化**：RFC 9156，默认启用
- **劫持防护**：根/TLD 越权响应检测 + UDP→TCP 自动回退
- **DNS Cookie**：HMAC-SHA256（RFC 7873），密钥无缝轮换
- **CIDR 过滤**：基于标签的 IP 过滤
- **安全传输**：DoT (RFC 7858)、DoQ (RFC 9250)、DoH (RFC 8484)、DoH3，TLS 1.3 + KTLS

### 可观测性

- **Summary 快照**：启动/关闭时自动输出聚合统计行，包含缓存条目数、命中率、平均响应时间、六协议分布、rcode 分布、hijack/fallback/prefetch/stale/rewrite 计数
- **CLI 分析工具**：`zjdns -analyze <db> <query>` 直接查询缓存数据库，对齐表格输出
- **SQL 数据分析**：`SELECT m.server, AVG(m.response_time_ms) FROM entries e JOIN metadata m ON e.id = m.entry_id WHERE m.rcode = 0 GROUP BY m.server`
- **问题诊断**：`WHERE m.hijack = 1` 查找被劫持的查询，`WHERE m.rcode = 1` 查找 FORMERR，`WHERE m.response_time_ms > 1000` 查找慢查询
- **组件级日志过滤**：`debug:UPSTREAM,SECURITY` 仅输出指定组件 Debug 日志
- **pprof**：标准 Go 性能分析端点

## 配置示例

```json
{
  "server": {
    "port": "53",
    "log_level": "debug:UPSTREAM,SECURITY",
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
      "stats": {
        "interval": 3600,
        "reset_interval": 86400
      }
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

`log_level` 支持组件过滤：`debug:UPSTREAM,RECURSION` 仅输出指定组件 Debug 日志。

### 缓存容量调优

| 参数 | 占用 | 说明 |
|------|------|------|
| `max_entries` | **磁盘** | 条目数上限。1 万条 ≈ 20MB，单条目约 2KB（entry 行 + 若干 records 行） |
| `mmap_size_mb` | **虚拟内存** | 数据库文件映射到进程地址空间，OS 自动管理物理页换入换出，不实际占用物理 RAM |
| `cache_size_mb` | **物理内存** | SQLite 内部 page cache，真实占用 RAM。缓存 B-tree 索引热点页 |
| `db_path` | **磁盘路径** | 数据库文件位置。空串 = 内存模式（不落盘，重启后缓存丢失） |

**调大策略**：更多条目 → 调 `max_entries`；更快命中 → 调 `cache_size_mb`；大文件映射 → 调 `mmap_size_mb`。

```json
// 家庭场景（默认）：1 万条，约 20MB 磁盘，4MB 物理内存
"cache": { "max_entries": 10000, "mmap_size_mb": 16, "cache_size_mb": 4 }

// 高负载场景：5 万条，约 100MB 磁盘，16MB 物理内存
"cache": { "max_entries": 50000, "mmap_size_mb": 128, "cache_size_mb": 16 }
```

## 数据库查询示例

```bash
sqlite3 /var/lib/zjdns/cache.db
```

```sql
-- 缓存命中率
SELECT cache_hits * 100.0 / NULLIF(total_requests, 0) AS hit_rate FROM stats;

-- 协议分布
SELECT udp_requests, tcp_requests, dot_requests, doq_requests FROM stats;

-- DNSSEC 验证概览
SELECT dnssec_secure, dnssec_bogus, dnssec_insecure FROM stats;

-- 延迟最低的根服务器
SELECT rr_text, latency_ms FROM records r
JOIN entries e ON r.entry_id = e.id
WHERE e.qname = '.' AND e.qtype = 0
ORDER BY r.latency_ms ASC;

-- 某 IP 对应的所有域名（PTR）
SELECT DISTINCT r.name FROM records r
JOIN entries e ON r.entry_id = e.id
WHERE r.rdata_ip = '104.20.23.154' AND e.expires_at + 2592000 >= unixepoch();
```

## 支持的标准

| RFC | 标准 | 实现 |
|-----|------|------|
| 4033-4035 | DNSSEC | 信任链 + RRSIG |
| 5155 | NSEC3 | 已验证否定 |
| 6891 | EDNS(0) | FORMERR 自动回退 |
| 7766 | DNS over TCP | 连接复用 + 流水线 |
| 7830/8467 | EDNS(0) Padding | 128B 查询 / 468B 响应 |
| 7858 | DNS over TLS | DoT TLS 1.3 |
| 7871 | EDNS Client Subnet | ECS |
| 7873 | DNS Cookies | Cookie 验证 |
| 8484 | DNS over HTTPS | DoH |
| 8767 | Serving Stale | 过期缓存 + 预取 |
| 8914 | Extended DNS Errors | EDE 代码 |
| 9077 | NSEC/NSEC3 TTL | 负面 TTL 封顶 |
| 9156 | QNAME Minimisation | 递归最小化 |
| 9250 | DNS over QUIC | DoQ |
| 9461/9462 | SVCB / DDR | 自动发现 |

## 开发

```bash
# 构建
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns

# 测试
go test ./... -short

# 基准测试
go test -bench=. -short ./...

# 代码检查
golangci-lint run && golangci-lint fmt
```

## 许可证

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
