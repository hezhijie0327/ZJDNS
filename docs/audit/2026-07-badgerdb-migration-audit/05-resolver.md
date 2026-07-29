# 05 · Resolver 包审计

**包范围**：`server/resolver`、`server/resolver/dnssec`、`server/resolver/probe`

**审计日期**：2026-07-29
**审计重点**：递归解析正确性、DNSSEC 验证、延迟探测、goroutine 管理

---

## 审计摘要

Resolver 层是 ZJDNS 最复杂的子系统。递归解析、DNSSEC 链验证、延迟探测逻辑正确。发现 1 个 MEDIUM 问题——探测间隔检查依赖已修复的 C1 bug。

**发现总数**：0 CRITICAL + 0 HIGH + 1 MEDIUM + 0 LOW

---

## MEDIUM（1 项）

### M-R1：`probe.go:112,210` 的 `LatencyLastProbe` 调用受 C1 bug 影响

- **文件**：`server/resolver/probe/probe.go:112,210`
- **类别**：correctness（关联 C1）
- **问题**：`LatencyLastProbe` 返回值的 `bool` 部分用于判断"是否有最近的探测数据"。在 C1 修复前，此函数永远返回 `true`，导致 `ProbeNSAddrs` 和 `probeAddress` 中的间隔检查无效。
- **状态**：C1 已修复后，间隔检查将按预期工作。

---

## DNSSEC 验证链审计

| 步骤 | 实现 | 正确性 |
|------|------|--------|
| 根信任锚加载 | `dnssec/trust_anchor.go` | ✅ |
| DS→DNSKEY 验证 | `dnssec/crypto.go` | ✅ |
| 链式信任验证 | `dnssec/dnssec_chain.go` | ✅ |
| NSEC/NSEC3 否定验证 | `recursive_helpers.go` | ✅ |
| UserMeta validated flag | `cache/store.go:264` | ✅ |

---

## ✅ 验证通过

| 检查项 | 状态 |
|--------|------|
| QNAME minimisation (RFC 9156) | ✅ max 16 steps |
| CNAME chain 检测 | ✅ max 16 depth |
| EDNS0 无应答重试 (RFC 6891 §6.2.2) | ✅ |
| NXDOMAIN fallback 存储 | ✅ |
| 并发 NS 查询限制 | ✅ errgroup SetLimit |
| singleflight 去重 | ✅ `internal/pending` |
| 延迟排序 A/AAAA | ✅ `sortAnswerByLatency` |
| Poisonguard zone cross-validation | ✅ |
| NS 地址延迟缓存 | ✅ latency-sorted |
| Goroutine HandlePanic | ✅ 所有 `go func` 有 `defer HandlePanic` |
