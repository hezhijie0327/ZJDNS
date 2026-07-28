# Defense Audit — server/defense/*

**日期**: 2026-07-28
**范围**: server/defense (hopguard.go, poisonguard.go — 2 文件)

> **注**: Spoofguard 实现在 `server/upstream/plain/udp.go` 中，Splitguard 实现在 `server/upstream/pool/tcp.go` 中。两者均不在 `server/defense/` 目录下，但通过 `config.UpstreamServer` 的开关控制。

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| F1 | LOW | constants | `hopguard.go:126` | 学习日志间隔的魔法数字 `8` |
| F2 | LOW | comment-accuracy | `poisonguard.go:140` | `classifyRoot` 注释暗示检查响应胶水记录，实际检查查询目标 |
| F3 | LOW | performance | `poisonguard.go:83` | `Validate` 中每个 RR 不必要的 `dnsutil.Canonical` 分配 |
| F4 | LOW | architecture | `poisonguard.go:119-175` | 未导出的 `classify*` 函数通过测试 helper 间接测试 |

---

## 无问题维度

- **内存安全**: Hopguard 使用容量为 256 的 LRU map；Poisonguard 无状态。无泄漏。
- **锁正确性**: `serverState.mu` 正确保护所有字段。无死锁路径。
- **Panic 检测**: `HopGuard` 方法对 nil 接收者有防护。Poisonguard 检查 `response == nil`。无裸类型断言。
- **RFC 一致性**: 基于 TTL 的检测是经验性启发，有充分文档说明。
- **函数排序**: 两个文件均遵循 `type → const → func` 顺序。构造函数位置正确。

---

## 架构说明

| 机制 | 位置 | 类型 |
|------|------|------|
| Hopguard | `server/defense/hopguard.go` | UDP TTL 指纹 |
| Poisonguard | `server/defense/poisonguard.go` | 递归 zone-authority 交叉验证 |
| Spoofguard | `server/upstream/plain/udp.go` | UDP 多读检测循环 |
| Splitguard | `server/upstream/pool/tcp.go` | TCP 分段（通过 SetNoDelay） |
