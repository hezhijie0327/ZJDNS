# 32 · 交叉分析：文档一致性

> 审计 Agent：Phase 2b · Docs
> 范围：全部 .md 文件与代码交叉验证、CLAUDE.md 准确性、godoc 覆盖


以下是 ZJDNS 项目中文档一致性的审计报告。

---

## CLAUDE.md — 类型引用验证

CLAUDE.md "Key Types" 表格中列出的所有 19 个类型都已通过 grep 确认存在于代码库中：

| 类型 | 包 | 状态 |
|------|------|--------|
| `ServerConfig` | `config/config.go:5` | 存在 |
| `UpstreamServer` | `config/config.go:130` | 存在 |
| `ProtocolSettings` | `config/config.go:24` | 存在 |
| `DB` | `database/db.go:21` | 存在 |
| `Store` | `cache/cache.go:57` | 存在 |
| `Entry` | `cache/cache.go:64` | 存在 |
| `AsyncStatsWriter` | `cache/async_writer.go:22` | 存在 |
| `Server` | `server/server.go:45` | 存在 |
| `QueryContext` | `server/handler/context.go:18` | 存在 |
| `QueryHandler` | `server/handler/middleware.go:28` | 存在 |
| `Wrapper` | `server/handler/middleware.go:45` | 存在 |
| `Resolver` | `server/resolver/resolver.go:66` | 存在 |
| `Recursive` | `server/resolver/recursive.go:27` | 存在 |
| `Client` | `server/upstream/client.go:47` | 存在 |
| `Conn` / `ConnPool` | `server/upstream/pool/tcp.go:35:53` | 存在 |
| `Detector` | `server/defense/poisonguard.go:27` | 存在 |
| `Engine` | `ruleset/ruleset.go:20` | 存在 |
| `Map[K, V]` | `internal/lrumap/lru.go:25` | 存在 |
| `DTLSSessionStore` | `internal/lrumap/dtls_session.go:11` | 存在 |
| `Message` / `Buffer` | `internal/pool/pool.go:12:17` | 存在 |
| `DNSStamp` | `internal/stamp/stamp.go:36` | 存在 |

类型别名 `edns.ECSOption = config.ECSOption`（`edns/ecs.go:16`）和 `handler.Question = resolver.Question`（`server/handler/handler.go:25`）均存在。

中间件类型（9 个）：`Response`, `CacheStore`, `Validation`, `Zone`, `EDNS`, `CacheLookup`, `PTR`, `DNS64`, `Resolution` 全部在 `server/handler/middleware/` 中存在。`AssembleChain` 在 `server/handler/middleware/chain.go:67` 中存在。

---

## docs/ARCHITECTURE.md — 引用验证

ARCHITECTURE.md 中引用的所有防御机制文件均存在：
- `server/defense/hopguard.go` -- 存在 (7770 bytes)
- `server/defense/poisonguard.go` -- 存在 (5529 bytes)
- `server/upstream/plain/udp.go` -- 存在 (16211 bytes)
- `server/upstream/plain/tcp.go` -- 存在 (3208 bytes)
- `server/upstream/pool/tcp.go` -- 存在 (14645 bytes)

所有 DNSCrypt 文件（`server/protocol/dnscrypt/` 中 7 个，`server/upstream/dnscrypt/` 中 5 个）和 DTLCP 文件（每个目录中 5 个）均存在。`State` 结构体包含 ARCHITECTURE.md 描述的所有 PQ 字段（`pqPublicKey`, `pqCertContext`, `pqTicket`, `pqResumeSecret`, `pqTicketExpiry`）。`GenerateDNSCryptConfig` 位于 `server/protocol/dnscrypt/generate.go:207`，并通过 `cmd/zjdns/cli/generate.go:108-109` 中的 `generateDNSCryptConfig` 调用。

---

## 导出类型/函数的 Godoc 注释

通过 grep 扫描 `config/`、`cache/`、`database/`、`ruleset/`、`zone/`、`edns/`、`server/`、`internal/` 中导出类型和函数前的注释行，所有导出类型/函数都有适当的 godoc 注释。未发现缺失。

---

## 审计发现

### 发现 1: CLAUDE.md —— 基准测试数量过时

- **文件**: `CLAUDE.md:132`
- **严重程度**: 低
- **问题描述**: 文档称 "~90 benchmarks across 14 files"。当前实际为 98 个基准测试函数分布在 21 个文件中。
- **风险**: 依赖 CLAUDE.md 进行开发环境配置的开发者可能会被误导。
- **修复建议**: 更新为 "~98 benchmarks across 21 files"。

### 发现 2: CLAUDE.md —— 导入层描述不完整

- **文件**: `CLAUDE.md:233-234`
- **严重程度**: 低
- **问题描述**: "Import Layers" 部分（第 233-234 行）仅列出 `edns→config` 作为域包导入 config 的例外，但 "Key rules" 部分（第 245 行）正确列出了所有四种：`edns→config`, `cache→config`, `zone→config`, `ruleset→config`。两个部分互相矛盾。
- **风险**: 开发者可能不清楚缓存、区域和规则集包也允许导入 config。
- **修复建议**: 在导入层部分添加缺失的例外：`cache→config`, `zone→config`, `ruleset→config`。

### 发现 3: CLAUDE.md —— 项目结构 internal 包不完整

- **文件**: `CLAUDE.md:215`
- **严重程度**: 低
- **问题描述**: 项目结构树显示 `internal/ ← log, pool, ttl, dnsutil, ipdetect, latency, pending, stamp, ...`。当前实际有 13 个 internal 子包，但此列表缺失了 5 个：`dns64`, `dnscryptcrypto`, `ipttl`, `lrumap`, `siphash`。其中 `lrumap` 在 Key Types 表中有文档记录，但项目结构树中遗漏。
- **风险**: 新开发者可能不清楚可用工具包，或重构时忽略这些包。
- **修复建议**: 更新列表为 `log, pool, ttl, dnsutil, ipdetect, ipttl, latency, lrumap, pending, stamp, siphash, dns64, dnscryptcrypto`。

### 发现 4: CLAUDE.md —— SOCKS5 被列为传输协议

- **文件**: `CLAUDE.md:304`
- **严重程度**: 低
- **问题描述**: `Client` 类型说明写为 "...all protocols (UDP/TCP/DoT/DoQ/DoH/DoH3/DTLS/DTLCP/TLCP/DNSCrypt/SOCKS5)"。SOCKS5 是一种代理机制，而非传输协议。它适用于所有上游协议（UDP、TCP、TLS 等），而不是一种独立协议。
- **风险**: 开发者可能认为 SOCKS5 是一种可路由协议，或 SOCKS5 支持受限于特定的传输方式。
- **修复建议**: 将 "SOCKS5" 移至说明末尾，如 "UDP/TCP/DoT/DoQ/DoH/DoH3/DTLS/DTLCP/TLCP/DNSCrypt (SOCKS5 proxy for all)"，或在其文档行中说明 SOCKS5 是透明的代理层。

### 发现 5: docs/ARCHITECTURE.md —— "SQL Lookup" 引用于 BadgerDB 重构后过时

- **文件**: `docs/FLOWCHARTS.md:488`
- **严重程度**: **中**
- **问题描述**: "延迟探测" 流程图显示 "Batch SQL Lookup ip_latency table"。该项目已从 SQLite 重构为 BadgerDB KV 存储。延迟数据现在存储在 `e:ip:{ip}\x00_lat` BadgerDB 键下，而非 SQL 表中。代码库中没有 SQL 查询延迟数据。
- **风险**: 认真阅读流程图的开发者可能会寻找不存在的 SQL 代码。流程图中此项明确有误。
- **修复建议**: 将 "Batch SQL Lookup ip_latency table" 替换为 "Batch BadgerDB Lookup (e:ip: key prefix)" 或仅写 "Batch Lookup (ip latency)" 以保持与存储无关。

### 发现 6: README.md —— CLI 示例中省略 --addr 标志

- **文件**: `README.md:27`
- **严重程度**: 低
- **问题描述**: `--generate-config --dnscrypt` 示例显示 `./zjdns --generate-config --dnscrypt --provider example.com`，未提及 CLI 实际支持的可选 `--addr` 标志（默认为 `127.0.0.1:8443`）。
- **风险**: 用户可能不知道可以自定义 DNSCrypt 绑定地址，或认为 DNSCrypt 端口不可配置。
- **修复建议**: 添加 `[--addr <addr>]` 到示例中，使其与第 85 行的 CLI 帮助文本一致。

### 发现 7: FLOWCHARTS.md —— DDR 功能未覆盖

- **文件**: `docs/FLOWCHARTS.md`（整篇文档）
- **严重程度**: 低
- **问题描述**: DDR（Discovery of Designated Resolvers，RFC 9462）是 `FeatureFlags` 中的一个可配置选项，通过 `config/ddr.go` 中的 `addDDRRecords()` 实现。FLOWCHARTS.md 中没有任何流程图描述此功能。
- **风险**: 使用 DDR 的开发者无法通过架构图表了解 SVCB 记录生成流程。
- **修复建议**: 考虑添加一个 DDR SVCB 记录生成和广告流程图。

### 发现 8: FLOWCHARTS.md —— KTLS 功能未覆盖

- **文件**: `docs/FLOWCHARTS.md`（整篇文档）
- **严重程度**: 低
- **问题描述**: KTLS（Kernel TLS offload）是 `FeatureFlags` 中的一个可配置选项，通过 `config/config.go:95` 中的 `KTLSSettings` 实现。FLOWCHARTS.md 中没有任何图表描述此功能。
- **风险**: 在 Linux 上使用 KTLS 的开发者无法通过架构图表了解其工作原理或影响。
- **修复建议**: 考虑在 TLS 处理流程中添加一个注明平台限制的 KTLS 说明或流程图，或至少在 TLS 连接图中添加 KTLS 引用。

---

## 总结

| # | 文件 | 行号 | 严重程度 | 描述 |
|---|------|------|----------|------|
| 1 | CLAUDE.md | 132 | 低 | 基准测试数量过时（~90→98 个函数，14→21 个文件） |
| 2 | CLAUDE.md | 233-234 | 低 | 导入层列表不完整，与 Key Rules 部分矛盾 |
| 3 | CLAUDE.md | 215 | 低 | internal/ 包列表缺失 5 个包 |
| 4 | CLAUDE.md | 304 | 低 | SOCKS5 被列为传输协议 |
| 5 | docs/ARCHITECTURE.md / FLOWCHARTS.md | 488 | **中** | "SQL Lookup" 引用在 BadgerDB 重构后过时 |
| 6 | README.md | 27 | 低 | CLI 示例中省略 --addr 标志 |
| 7 | docs/FLOWCHARTS.md | — | 低 | DDR 功能未在流程图中覆盖 |
| 8 | docs/FLOWCHARTS.md | — | 低 | KTLS 功能未在流程图中覆盖 |

**严重程度评估：** 发现 5 列为**中**，因为它引用了当前代码库中不存在的 SQL 表结构。其他所有发现均为**低**，属于文档漂移——准确但不完整，不会导致功能混淆。代码中所有符号引用均有效；无断链。