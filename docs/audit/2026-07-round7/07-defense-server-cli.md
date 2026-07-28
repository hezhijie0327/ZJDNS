# Defense + Server + CLI 审计报告 (Phase 1)

审计范围: `server/defense/*`, `server/{server, bridge, init, tasks}.go`, `cmd/zjdns/*`
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 2 | Poisonguard TLD 检测永久失效、权威级盲点（设计限制） |
| HIGH | 4 | HopGuard 竞态、bridge TCP 条目无界增长、sync.Map Range 删除竞态、CLI 层级违规 |
| MEDIUM | 6 | typed-nil 接口、关闭竞态、每请求分配、死代码、参数验证、SQL 多语句 |
| LOW | 9 | pool 损坏恢复、pprof 超时、nil 守卫、日志缺失、EDNS nil 守卫、goroutine 追踪 |

**共 21 个发现** (2 CRITICAL, 4 HIGH, 6 MEDIUM, 9 LOW)

## CRITICAL

### C1: Poisonguard TLD 检测永久失效 — 从未触发

- **文件**: `server/defense/poisonguard.go:169`
- **类别**: `defense-algorithm`
- **描述**: `isTLD` 检查 `dnsutil.Labels(domain) == 1`，但所有 zone 名称经过 `dnsutil.Canonical` 处理（FQDN 形式）。对于 "com." 返回 2 个 label（"com" + ""）而非 1。因此 `isTLD` 对所有真实 TLD zone 返回 false，导致 classify 落在 `default: VerdictUncertain`。无调用方检查 VerdictUncertain。
- **风险**: TLD 级别 GFW 注入从未被检测或拒绝。仅 root 级检测有效。
- **修复**: 修复 FQDN label 计数：`return dnsutil.Labels(dnsutil.Fqdn(domain)) == 2`

### C2: Poisonguard 权威级盲点 — 设计限制

- **文件**: `server/defense/poisonguard.go:126-129`
- **类别**: `defense-algorithm`
- **描述**: classify 的 default 分支（权威服务器）始终返回 VerdictUncertain。只有 root 和（修复后）TLD 级别的注入被检测。权威级别的 GFW 注入完全不可检测。
- **风险**: "zone-authority cross-validation" 防御声明过于夸大实际覆盖范围。
- **修复**: 此乃架构设计限制。在防御模块描述和架构文档中明确记录。

## HIGH

### H1: HopGuard Feed vs Validate 竞态窗口

- **文件**: `server/defense/hopguard.go:95-110`
- **类别**: `lock`
- **描述**: Feed 序列：Get（无保护）→ LoadOrStore（原子）→ st.mu.Lock()。Get 和 LoadOrStore 之间，另一个 goroutine 可能观察不到 state。Validate 通过单次 Get 读取并立即返回——可能看到 "无 state" 而 Feed 正在创建。
- **风险**: 新上游服务器的初始学习阶段短暂分歧。
- **修复**: 预创建 state 对象再使用。

### H2: bridge.go tcpWriteMu 无界增长

- **文件**: `server/bridge.go:46-58`
- **类别**: `resource`
- **描述**: tcpWriteMu sync.Map 随唯一客户端 IP:port 无限增长。攻击者从不同端口开大量短连接可在 sweep 周期之间膨胀内存。
- **风险**: 大量唯一 TCP 地址短时间内导致内存耗尽。
- **修复**: 按 IP（非 IP+port）聚合 key 或添加 LRU 逐出。

### H3: tasks.go sync.Map Range 内删除竞态

- **文件**: `server/tasks.go:108-116`
- **类别**: `lock`
- **描述**: TCP write map sweep 在 Range 回调中调用 Delete。并发 LoadOrStore 创建 data race 风险。
- **风险**: 条目可能在使用中被删除或陈旧条目残留。
- **修复**: 先收集候选再删除。

### H4: CLI generate.go 导入层级违规

- **文件**: `cmd/zjdns/cli/generate.go:15`
- **类别**: `coupling`
- **描述**: CLI 包直接导入 `server/protocol/dnscrypt`。任何协议包更改导致 CLI 重编译。
- **风险**: 脆弱的依赖图。
- **修复**: 将 GenerateDNSCryptConfig 提取到 `internal/dnscryptcrypto`。

## MEDIUM (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| M1 | `server/server.go:240-249` | typed-nil 接口 — nil `*Prober` 在接口中通过 nil 检查 |
| M2 | `server/tasks.go:272-274` | shutdown channel 关闭竞态 — 仅 nil 守卫无 sync.Once |
| M3 | `server/bridge.go:46` | LoadOrStore 每请求分配 — 已存在时仍构造 tcpWriteEntry |
| M4 | `server/init.go:51-58` | makeFlushFunc 未用 verb 参数抽象不对称 |
| M5 | `cmd/zjdns/cli/parse.go:167-183` | --decode/--encode 无 --dnsstamp 时静默忽略 |
| M6 | `cmd/zjdns/cli/sql.go:27` | --sql 多语句可能绕过 query_only |

## LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `server/bridge.go:198-206` | packSafe panic 后消息状态未定义仍返回到 pool |
| L2 | `server/server.go:372` | pprof ReadTimeout=0 |
| L3 | `server/server.go:379-381` | ServeDNS 缺少 nil receiver 守卫 |
| L4 | `server/server.go:384` | Start() 缺少启动日志 |
| L5 | `server/tasks.go:60-74` | refreshECSOnce 假设 EDNS handler 非 nil |
| L6 | `server/tasks.go:159-279` | 协议服务器 errgroup coordinator 孤儿 goroutine |
| L7 | `cmd/zjdns/version.go:19-24` | 版本字符串格式不对称 |
| L8 | `server/bridge.go:187-189` | detectRequestProtocol 单字节匹配脆弱 |
| L9 | `cmd/zjdns/cli/probe.go:69-75` | InsecureSkipVerify+空 CurvePreferences |
