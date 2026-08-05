# HANDOVER — 2026-08 第二轮审计（未完成部分）

> 生成时间: 2026-08-05。综合报告与修复计划已存档：`docs/audit/2026-08-round2/`（12-synthesis.md / 00-plan.md / _manual-verification.md / raw-phase12.jsonl）。
> 本文件记录审计中断时未完成/未确认的事项。修复完成后删除本文件。

## 已完成

- Phase 1 包级审计 7 agent + Phase 2 交叉审计 19 agent：**24/26 完成**，152 条原始发现已存档（`docs/audit/2026-08-round2/raw-phase12.jsonl`）
- 人工核验确认：C1（Get 格式标记缺失 → 旧条目 panic）、C2（DNSCrypt encrypt 清空 pre-packed）、H1/H2（MQTYPE 双路径失效）、H3（bridge refs 双重 Add 回归）、H4（明文监听器 Pseudo 为空）、M1/M2/M4/M6/M8
- 上轮修复回归抽样：H3/H4/M8（TLS/TLCP Shutdown 锁、TLCP 写超时）完好

## 未完成（按优先级）

### 1. 2 个 agent 未完成（工作流 wf_7b74e8a4-0c0 被用户中断）

- 未完成 agent：**protocol 包级**（server/protocol/* 的独立审计）与 **1 个 Phase 2 交叉维度**（从 journal 对照 26-24=2）
- 继续方式：`Workflow({scriptPath: ".../workflows/scripts/zjdns-audit-2026-08-r2-wf_7b74e8a4-0c0.js", resumeFromRunId: "wf_7b74e8a4-0c0"})` — 已完成 agent 走缓存，仅重跑未完成部分。或直接用 Agent 补跑 protocol 审计（重点：TLS/QUIC/DoH/DTLS 的 pre-packed 适配——**C2 的协议扩散检查**）。

### 2. C2 的 DNSCrypt 调用链最终确认（机制已确认，到达性待实证）

- 已确认：miekg v0.6.89 `Len()`（msg.go:609-629）不读 Data；`Pack()`（msg.go:160）对 cap 足够时 `Data[:l]` 截断重写 → pre-packed 消息被清空为 header+question。
- 已确认：`udpResponseWriter.WriteMsg`（dnscrypt/udp.go:41-49）无条件 `encrypt(m)`，无 `len(m.Data)` 守卫（对比 bridge.go:233）。
- **待确认**：handler.ServeDNS 返回的响应在 DNSCrypt 路径是否带 pre-packed Data（理论上与 UDP/TCP 相同——Response 中间件直发路径返回 Data 形态；写个单测即可实证：cache 命中 + DNSCrypt writer → 断言加密后响应非空）。
- **扩散检查**：TLS（tls.go WriteMsg 路径，之前 grep 无结果——TLS 用 miekg dns.Server 的 handler 回调，响应经 `w.WriteMsg(response)`，**可能同病**，必须检查！）、QUIC/DoQ、DoH、DoH3、DTLS/DTLCP、TLCP。修复 C2 时应全局搜索 `Pack()` 在协议 writer 中的调用。

### 3. MEDIUM 待核验项

- M3 `fetchCertOverTCP/UDP` 裸 net.Dial（cert.go:83）：确认对端不可达时阻塞时长与查询预算关系。
- M5 `cache_lookup.go:247` serveExpiredWithRefresh 前台 TryGo 失败 → done 永不关闭 → 定时器路径第二 TryGo 的 select 等 `<-done` 直到 refreshCtx 超时（需读代码确认闭包结构）。
- M7 TLCP 响应 ID 不回验（tlcp.go:89）——对齐 tls.go:107-110 修。

### 4. LOW 清单整理（raw-phase12.jsonl 中 73 条）

- 已知主题：lrumap.Set 覆盖不触发 OnEvict（foundation-01）、DNSCrypt PQ 注释残句（foundation-02）、HandlePanic 注释与代码不符（foundation-03）、TLCP 证书、常量、文档类 ~16 条 comment、8 条 flowcharts（FLOWCHARTS.md 新功能零覆盖）
- 修复时逐条对照 raw-phase12.jsonl，已在 00-plan.md Sprint 3 挂账

### 5. benchmark 基线未刷新（本审计未改代码，无需）

## 关键文件索引

| 文件 | 内容 |
|------|------|
| `docs/audit/2026-08-round2/12-synthesis.md` | 综合报告（C1/C2/H1-H4 + MEDIUM + 主题 + Sprint 计划） |
| `docs/audit/2026-08-round2/00-plan.md` | 逐项修复计划 |
| `docs/audit/2026-08-round2/_manual-verification.md` | 人工核验笔记（含已验证无问题的清单） |
| `docs/audit/2026-08-round2/raw-phase12.jsonl` | 24 agent 原始发现（152 条，JSONL） |
| `docs/audit/2026-08-round2/agents/` | **每个 agent 一份 md 存档**（26 个文件：01-foundation.md ~ 26-flowcharts.md；`03-protocol.pending.md` 与 `25-goversion.pending.md` 为未完成 agent 占位） |
| `~/.claude/projects/.../subagents/workflows/wf_7b74e8a4-0c0/journal.jsonl` | workflow 全程记录（可 resume） |

> 注：同 scope 出现两个 agent 实例是 workflow 重试所致（失败后自动重启同一 prompt）；存档只取有结果的实例。完整存档脚本：`$CLAUDE_JOB_DIR/tmp/dump_agents.go`（已不在工作区，需要重生成时用 `go run` 指向 journal 目录）。

## 下一步

1. （可选）resume workflow 补跑 2 个未完成 agent
2. Sprint 1：修 C1 + C2（含 TLS 等协议扩散检查）
3. 每 Sprint 后质量门禁 + benchmark 对比，完成后删除本文件
