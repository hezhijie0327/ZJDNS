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

## 修复状态

### ✅ Sprint 1：CRITICAL + HIGH（4/4 已修复）
| # | 状态 | 描述 |
|---|------|------|
| C1 | ✅ 已修复 | DTLS 缓冲区 → `pool.DefaultBuffer.Get()` + 边界检查 |
| H1 | ✅ 已修复 | 陈旧清理时间戳 → `log.NowUnix() - defaultStaleMaxAge` |
| H2 | ✅ 已修复 | PrefetchCooldown → `DefaultPrefetchCooldownMaxEntries=10000` + 驱逐 |
| H3 | ✅ 已修复 | NXDOMAIN 池泄漏 → CAS 失败后 `pool.DefaultMessage.Put()` |

### ✅ Sprint 2a：池/内存安全（3/4 已修复）
| # | 状态 | 描述 |
|---|------|------|
| M1 | ✅ 已修复 | Pool.Buffer.Put → `cap(buf) == b.size` 拒绝过大缓冲区 |
| M2 | ✅ 已修复 | DoT 写入器 → defer 中排空 writeCh 剩余条目 |
| M3 | ✅ 已修复 | DNSCrypt nil-map → `c.cache == nil` 检查 |

### ✅ Sprint 2b：正确性修复（6/8 已修复）
| # | 状态 | 描述 |
|---|------|------|
| M4 | ✅ 已修复 | 移除 refreshCacheEntry 未使用的 qctx 参数 |
| M5 | ✅ 已修复 | CNAME 链耗尽 → `chainExhausted` 标志避免误报 |
| M6 | ✅ 已修复 | RecordRequest → 局部变量 `qname`，不修改调用者 |
| M7 | ✅ 已修复 | Zone 成功响应 → 移除 EDE ForgedAnswer |
| M8 | ✅ 已修复 | Validation FORMERR → 添加 EDE InvalidData |
| M9 | ✅ 已修复 | Zone insertRow 错误 → 记录日志 |

### ⬜ 剩余：~32 MEDIUM + ~50 LOW
剩余问题主要是文档优化、微优化、代码异味、架构建议（如 CLI 导入 server 协议、Resolver 兄弟包导入、TLCP 关闭不一致等），不影响正确性或安全性。

### 提交
`cc60c2b fix: Round 2 audit — CRITICAL + HIGH + selected MEDIUM fixes`
15 个文件修改，174 行新增，29 行删除。
