# 综合审计报告 — 2026-07 第二轮深度审计

## 概述

对 ZJDNS 代码库（204 个 Go 文件）进行全面深度审计，按 AUDIT-METHODOLOGY.md 框架执行。7 个并行 Agent 逐文件审计了所有非测试文件，覆盖 6 个审计维度。

## 发现统计

| 严重程度 | 数量 | 占比 |
|----------|------|------|
| **CRITICAL** | 1 | 1.1% |
| **HIGH** | 3 | 3.2% |
| **MEDIUM** | 41 | 43.1% |
| **LOW** | 50 | 52.6% |
| **总计** | **95** | 100% |

## 各子系统分布

| 子系统 | CRITICAL | HIGH | MEDIUM | LOW | 总计 |
|--------|----------|------|--------|-----|------|
| Foundation (internal/*) | 0 | 0 | 9 | 14 | 23 |
| Domain (config/db/cache/edns/zone/ruleset) | 0 | 1 | 5 | 9 | 15 |
| Protocol (server/protocol/*) | 0 | 0 | 4 | 6 | 10 |
| Upstream (server/upstream/*) | 1 | 0 | 5 | 10 | 16 |
| Resolver (server/resolver/*) | 0 | 1 | 4 | 3 | 8 |
| Handler (server/handler/*) | 0 | 1 | 8 | 2 | 11 |
| Defense/Server/CLI | 0 | 0 | 6 | 6 | 12 |
| **总计** | **1** | **3** | **41** | **50** | **95** |

## CRITICAL 发现

| # | 文件 | 行号 | 描述 |
|---|------|------|------|
| C1 | server/upstream/tls/dtls.go | 68 | DTLS 读缓冲区仅 4096 字节，大型 DNSSEC 响应导致 `slice bounds out of range` panic |

## HIGH 发现

| # | 文件 | 行号 | 描述 |
|---|------|------|------|
| H1 | cache/store.go | 515-518 | `evictOldest` 清理 SQL 使用绝对时间戳 `defaultStaleMaxAge`（2592000），导致 `ip_latency` 过期条目永不被清理 |
| H2 | server/handler/prefetch.go | 54-63 | `PrefetchCooldown` map 无界增长——持续访问的条目永不过期，导致内存耗尽 |
| H3 | server/resolver/nameserver.go | 127-144 | NXDOMAIN 响应 `*dns.Msg` 在 CAS 竞争失败时从池中泄漏 |

## 关键主题

### 池安全（4 个发现）
- NXDOMAIN 池泄漏（H3）、DoT 写入器缓冲区泄漏（M）、pool.Buffer.Put 超大缓冲区（M）

### 内存/资源安全（8 个发现）
- PrefetchCooldown 无界增长（H2）、L1 缓存 RR 别名共享（2×M）、DNSCrypt nil-map 写入（M）、pending.Group panic 泄漏（M）

### SQL/数据正确性（3 个发现）
- 陈旧清理时间戳错误（H1）、迁移中 Version 无并发保护（M）、DDL SQL 注入风险（L）

### 耦合/架构（6 个发现）
- CLI 导入 server 协议（M）、Resolver 兄弟子包导入（M）、TLCP 关闭不一致（M）

### 错误处理（8 个发现）
- crypto/rand.Read 错误丢弃（5×M）、zone 文件插入错误静默丢失（M）

## 修复计划

### Sprint 1：CRITICAL + HIGH（4 个，立即修复）
1. **C1**：DTLS 缓冲区 → 使用 `dns.MaxMsgSize` 或 `pool.UDPBufferSize`
2. **H1**：陈旧清理时间戳 → 替换为 `log.NowUnix() - defaultStaleMaxAge`
3. **H2**：PrefetchCooldown 有界 → 添加 LRU 驱逐或最大 map 大小
4. **H3**：NXDOMAIN 池泄漏 → 在 CAS 失败后调用 `pool.DefaultMessage.Put()`

### Sprint 2：MEDIUM（41 个）
按模式分组：池纪律（4）、RR 别名（3）、错误丢弃（8）、锁（5）、死代码/未使用（5）、架构（6）、性能（5）、其他（5）

### Sprint 3：LOW（50 个）
文档、微优化、代码异味、维护性
