# 07 · Defense 包审计

**包范围**：`server/defense`（hopguard、poisonguard、spoofguard、splitguard）

**审计日期**：2026-07-29
**审计重点**：防御算法正确性、状态管理、并发安全

---

## 审计摘要

四层防御系统设计精良。HopGuard 使用 `lrumap.Map` 管理 per-upstream TTL 状态，正确。算法无 CRITICAL/HIGH 问题。

**发现总数**：0 CRITICAL + 0 HIGH + 0 MEDIUM + 0 LOW

---

## 防御算法逐一审计

### HopGuard

- **状态管理**：`lrumap.New[string, *serverState](256)` — bounded LRU ✅
- **TTL 学习**：32 样本基线，±2 TTL 容忍 ✅
- **并发安全**：`lrumap.Map` 内置并发安全 ✅

### Poisonguard

- **Zone 分类**：Root / TLD / Authoritative 三级 ✅
- **根区验证**：仅 NS/DS for TLDs + glue for root-servers.net ✅
- **TLD 验证**：仅 NS/DS sub-delegations + self-referencing A/AAAA ✅
- **Authoritative 级别**：`VerdictUncertain`——设计限制已记录 ✅

### Spoofguard

- **多读循环**：UDP 读取 N 个响应 ✅
- **即时拒绝规则**：`AR=0+NOERROR+EDNS` (GFW 指纹) ✅
- **即时接受规则**：`AN≥2`/`NS>0`/`AD=1` ✅
- **模糊收集**：≤500ms 窗口，选最丰富 ✅

### Splitguard

- **分段策略**：随机 [1,4] 字节 + stretch jitter ✅
- **实现位置**：`tcp.go` + `pool/tcp.go` ✅

---

## ✅ 验证通过

| 检查项 | 状态 |
|--------|------|
| 状态机无逃逸路径 | ✅ |
| 边界条件处理 | ✅ |
| HopGuard 状态淘汰 | ✅ LRU + bounded |
| Per-upstream 配置独立 | ✅ |
| 防御机制可组合 | ✅ |
