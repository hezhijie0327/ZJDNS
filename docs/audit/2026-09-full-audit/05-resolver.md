# Resolver 审计 (server/resolver/*) — 15 findings: 0H/5M/10L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| R1 | MED | delegation_snapshot.go:174-213 | 委派缓存 OnEvict/Range 锁内 spill.Put(与 D2 同根) | ✅ 并入 D2 |
| R2 | MED | delegation_snapshot.go:176,210,214 | spill 错误静默丢弃(磁盘满 = 静默禁用磁盘层) | ✅ |
| R3 | MED | zonecut.go:323 | resolveChildNameservers 传 depth=0 绕过递归深度预算(签名区链可无限加深) | ✅ |
| R4 | MED | dnssec/crypto.go:411-426, extract.go:123-138 | groupRRset/canonicalCompare 每记录每比较分配 Canonical 字符串 | ✅ |
| R5 | MED | dnssec/nsec.go:54,172, crypto.go:232, dnssec_chain.go:57,457 | KeyTag 记忆化未覆盖 NSEC/DS/DNSKEY 验证循环 | ✅ |
| R6 | LOW | dnssec/crypto.go:62-73 | NewCryptoValidator godoc 错挂 sigBufPool | ✅ |
| R7 | LOW | dnssec/crypto.go:353-355 | 死分支 if groupValidated break | ✅ |
| R8 | LOW | probe/probe.go:138-147 | probeAndReorder 未用 ecsResponse 参数 | ✅ |
| R9 | LOW | recursive_helpers.go:255 等 5 处 | `_ =` 无注释 | ✅ |
| R10 | LOW | recursive.go:285-287,742-743 | TLD probe 注释与代码不符;CNAME 超限 Debug vs 文档 warn | ✅ |
| R11 | LOW | nameserver.go:223, forward.go:253 | MQTYPE optionless 重试用 Background 而非 WithoutCancel | ✅ |
| R12 | LOW | recursive_helpers.go:183 | validateNODATAWithNSEC ctx 非首参 | ✅ |
| R13 | LOW | recursive.go:245-248 | 取消窗口搁浅 1 个池化消息 + 有界 goroutine | ✅ |
| R14 | LOW | nameserver.go:291-298 | winner 驱逐后残留 straggler 可搁浅 1 个池化消息 | ✅ |
| R15 | LOW | delegation_snapshot.go:241 | sort.Slice → slices.SortFunc | ✅ |
