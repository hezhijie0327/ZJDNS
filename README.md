# ZJDNS

[![Go Version](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache%202.0--Commons%20Clause-blue)](LICENSE)
[![Lint](https://img.shields.io/badge/golangci--lint-0%20issues-success)](https://golangci-lint.run/)

高性能递归 DNS 解析服务器，支持 DNSSEC 密码学验证、LRU 内存缓存（SQLite 持久化）、ECS、DoT/DoQ/DoH/DoH3 安全传输协议。

> **生产就绪状态**：本项目尚未经过生产环境充分验证，请谨慎用于关键业务。

## 快速开始

```bash
# 构建
go build -o zjdns ./cmd/zjdns

# 生成默认配置
./zjdns -generate-config > config.json

# 启动（纯递归模式）
./zjdns

# 启动（指定配置）
./zjdns -config config.json
```

```bash
# 测试解析
dig @127.0.0.1 -p 53 example.com                # UDP
dig @127.0.0.1 -p 53 example.com +tcp            # TCP
kdig @127.0.0.1 -p 853 example.com +tls          # DoT
kdig @127.0.0.1 -p 853 example.com +quic         # DoQ
kdig @127.0.0.1 -p 443 example.com +https        # DoH
```

## 核心特性

### DNS 解析

- **递归解析**：从 IANA 根服务器（13 组）逐步解析至 TLD 和权威服务器，完整 DNSSEC 信任链
- **上游转发**：主/备服务器并发查询 + 首胜策略（First-Win），上游优先，备路结果立即可用
- **混合模式**：上游 DNS 与内置递归（`builtin_recursive`）可同时配置
- **SOCKS5 代理**：每上游可选代理（TCP CONNECT + UDP ASSOCIATE，RFC 1928/1929），所有协议 + 递归模式全覆盖
- **连接池**：TCP/DoT RFC 7766 查询流水线 + DoQ QUIC 原生流复用，连接失败自动回退单次连接，死连接自动替换
- **CNAME 解析**：多级追踪（最大 16 级），防循环，超限返回 SERVFAIL
- **按接口绑定**：所有监听器按网卡 IP 逐一绑定，端口冲突时自动跳过已占用地址，无需 `SO_REUSEADDR`
- **EDNS 缓冲区**：上游查询 1232 字节（DNS Flag Day 2020），递归查询 4096 字节，避免根区域 DNSSEC 签名委托 UDP 截断
- **延迟探测**：统一探测引擎（ICMP/TCP/UDP/HTTP/HTTPS/HTTP3），按最快 IP 动态重排 A/AAAA 记录

### 安全

- **DNSSEC**：递归模式完整信任链验证（根 KSK→TLD DS→权威 DNSKEY→RRSIG），NSEC/NSEC3 已验证否定（RFC 5155），EDE 错误码传播
- **NSEC/NSEC3 TTL 上限**：RFC 9077，负面缓存 TTL 取 `min(SOA.TTL, SOA.Minttl, 10800)`，防止过度否定
- **QNAME 最小化**：RFC 9156，递归解析时仅向各级权威发送最小必要 QNAME，默认启用。检测 minimised 查询返回的 CNAME 与原始 QNAME 不匹配时自动用完整 QNAME 重试（§2.3）
- **劫持防护**：根/TLD 越权响应检测 + UDP→TCP 自动回退
- **DNS Cookie**：HMAC-SHA256 服务端 Cookie（RFC 7873），密钥无缝轮换，入口早期验证
- **CIDR 过滤**：基于标签的 IP 过滤（文件/内联规则），IPv4 位运算优化
- **安全传输**：DoT (RFC 7858)、DoQ (RFC 9250)、DoH (RFC 8484)、DoH3，TLS 1.3 + KTLS 零拷贝卸载
- **证书管理**：自签名 ECDSA P-384 CA，动态签发，过期预警

### 缓存

- **LRU 内存缓存**：固定容量（默认 4 MB），RLock 零读争用，atomic 访问时间淘汰
- **全局 TTL 管理器**（`internal/ttl`）：统一 TTL 计算，cache 与 rewrite 共用。Stale TTL 周期性倒数（30→1→30），每轮给后台刷新新的机会；Rewrite TTL 独立周期性倒数（每个 RR 单独取模）
- **SQLite 持久化**：每条写入即时持久化（write-through），启动自动恢复，WAL 模式高性能并发。纯 Go 无 CGo，支持静态编译
- **过期服务**：RFC 8767 过期缓存服务（最大 30 天），上游不可用时兜底
- **预取**：TTL 剩余 ≤40% 时后台异步刷新，ECS 感知分区

### 可观测性

- **锁无关统计**：全部计数器使用 `atomic.Uint64`，热路径零 mutex
- **组件级日志过滤**：`debug:UPSTREAM,SECURITY` 仅输出指定组件 Debug 日志，避免刷屏
- **pprof**：标准 Go 性能分析端点
- **JSON 统计日志**：定期输出（可配间隔），含命中率/劫持/DNSSEC 等

## 支持的 RFC

| RFC | 标准 | 实现 |
|-----|------|------|
| [1928](https://www.rfc-editor.org/rfc/rfc1928) | SOCKS Protocol Version 5 | 代理客户端 |
| [4033-4035](https://www.rfc-editor.org/rfc/rfc4033) | DNSSEC | 信任链 + RRSIG + AD/CD |
| [5155](https://www.rfc-editor.org/rfc/rfc5155) | NSEC3 | 已验证否定 + 迭代上限 |
| [7766](https://www.rfc-editor.org/rfc/rfc7766) | DNS over TCP | 连接复用 + 流水线 + 乱序 |
| [9077](https://www.rfc-editor.org/rfc/rfc9077) | NSEC/NSEC3 TTL | 负面 TTL 封顶 + 积极缓存 |
| [9156](https://www.rfc-editor.org/rfc/rfc9156) | QNAME Minimisation | 递归最小化查询（默认启用）|
| [6891](https://www.rfc-editor.org/rfc/rfc6891) | EDNS(0) Extensions | FORMERR 自动回退（无 EDNS 重试）|
| [7830](https://www.rfc-editor.org/rfc/rfc7830) | EDNS(0) Padding | 响应 + 查询填充 |
| [8467](https://www.rfc-editor.org/rfc/rfc8467) | EDNS(0) Padding Policies | 128B 查询 / 468B 响应块对齐 |
| [7858](https://www.rfc-editor.org/rfc/rfc7858) | DNS over TLS | DoT TLS 1.3 |
| [7871](https://www.rfc-editor.org/rfc/rfc7871) | EDNS Client Subnet | ECS 客户端子网 |
| [7873](https://www.rfc-editor.org/rfc/rfc7873) | DNS Cookies | Cookie 验证 + 轮换 |
| [8484](https://www.rfc-editor.org/rfc/rfc8484) | DNS over HTTPS | DoH HTTP/2 |
| [8767](https://www.rfc-editor.org/rfc/rfc8767) | Serving Stale | 过期缓存 + 预取 |
| [8914](https://www.rfc-editor.org/rfc/rfc8914) | Extended DNS Errors | 24 种 EDE 代码 |
| [9250](https://www.rfc-editor.org/rfc/rfc9250) | DNS over QUIC | DoQ + 0-RTT |
| [9461/9462](https://www.rfc-editor.org/rfc/rfc9461) | SVCB / DDR | 自动发现 |

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
      "cache": { "size": 4194304, "persist": { "file": "/var/lib/zjdns/cache.db" } },
      "ecs_subnet": { "ipv4": "auto", "ipv6": "auto" }
    }
  },
  "upstream": [
    { "address": "builtin_recursive" }
  ]
}
```

`log_level` 支持组件过滤：`debug:UPSTREAM,RECURSION` 仅输出 UPSTREAM + RECURSION 的 Debug 日志。无前缀的消息始终通过（安全性设计）。

## 包结构

```
zjdns/
├── cmd/zjdns/                        # 二进制入口（main.go + banner.go + version.go + bench_test.go）
├── config/                           # 配置类型、加载、验证（config_validate.go）、默认值
├── edns/                             # EDNS(0) 扩展（ECS、Cookie、EDE、Padding）
│                                     #   ECSOption 为 config.ECSOption 的类型别名
├── cache/                            # LRU 内存缓存 + SQLite 持久化 + PTR 反向索引
│                                     #   memory.go（LRU）+ sqlite.go（write-through）
├── cidr/                             # CIDR IP 过滤（基于标签的匹配、IPv4 位运算优化）
├── rewrite/                          # 域名重写规则
├── stats/                            # 锁无关统计（PersistStore 接口，不依赖 cache）
├── internal/
│   ├── cli/                          # CLI 辅助（参数解析、示例配置）
│   ├── log/                          # 分级日志 + TimeCache + 组件过滤 + IsDebug
│   ├── pool/                         # sync.Pool + QUIC 应用层错误码
│   ├── ttl/                          # 全局 TTL 管理器（周期性 stale 倒数、预取判断）
│   ├── dnsutil/                      # DNS 工具函数（含 JoinDNSPort）
│   ├── ipdetect/                     # ECS 公网 IP 自动检测
│   └── latency/                      # 统一延迟探测引擎
└── server/
    ├── server.go                     # 生命周期、构造、监听器编排
    ├── listen.go                     # 协议桥接（UDP/TCP dispatch → io.Copy）
    ├── server_tasks.go               # 后台任务 + 优雅关闭
    ├── handler/                      # DNS 查询处理管线
    │   ├── handler.go                #   主流程（validateDNSQuery + processRewrite）
    │   ├── handler_cache.go          #   缓存处理（命中/过期/缺失、后台刷新、预取）
    │   └── message.go                #   EDNS 构建、Cookie 生成、域名恢复
    ├── client/                       # 出站查询客户端（UDP/TCP/DoT/DoQ/DoH/DoH3/SOCKS5）
    │   ├── socks5.go                 #   SOCKS5：类型、握手、共享辅助函数
    │   ├── socks5_tcp.go             #   SOCKS5 TCP CONNECT 路径
    │   ├── socks5_udp.go             #   SOCKS5 UDP ASSOCIATE 路径 + PacketConn
    │   └── pool/                     # TCP/DoT RFC 7766 流水线 + QUIC 连接池
    ├── resolver/                     # 递归解析 + 上游转发 + DNSSEC 信任链
    │   ├── recursive.go              #   核心递归循环（depth → root → TLD → authoritative）
    │   ├── recursive_helpers.go      #   提取的助手：QNAME最小化、NS收集、DNSSEC验证
    │   ├── qname_minimise.go         #   RFC 9156 QNAME 最小化算法
    │   ├── recursive_cache.go        #   NS 地址延迟排序缓存
    │   ├── dnssec_chain.go           #   DNSSEC 信任链 + 区域切割处理
    │   ├── nameserver.go             #   并发 NS 查询 + 劫持拒绝
    │   ├── upstream.go               #   上游转发（processUpstreamResponse）
    │   └── resolver.go               #   Resolver 类型 + ShuffleSlice
    ├── security/                     # DNSSEC 密码学 + NSEC/NSEC3 否定 + 劫持检测
    ├── tls/                          # TLS 安全传输监听器（DoT/DoQ/DoH/DoH3）
    └── probe/                        # A/AAAA 延迟探测与记录重排
```

**依赖分层** — 严格单向无环：

```
internal/（基础层：log/pool/ttl/dnsutil/ipdetect/latency）
    → config（域基础层）
        → edns/cache/cidr/rewrite/stats（域包层）
            → server/子包（resolver/security/client/tls/handler）
                → server/（顶层装配）→ main
```

## 开发

```bash
# 构建
go build -ldflags "-s -w -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ) -X main.CommitHash=$(git rev-parse --short HEAD)" -o zjdns ./cmd/zjdns

# 测试
go test ./... -short

# 基准测试
go test -bench=. -short ./...

# 代码检查（零警告）
golangci-lint run && golangci-lint fmt

# 安装 pre-commit hook
sh scripts/install-hook.sh                 # Linux / macOS
pwsh scripts/install-hook.ps1              # Windows PowerShell
```

## 许可证

[Apache License 2.0 with Commons Clause v1.0](LICENSE)
