# 审计计划 — 2026-07 Round 7

## 审计范围

- **Phase 1**: 7 个包组并行审计（151 个非测试 Go 文件）
- **Phase 2**: 18 个维度的交叉分析
- **Phase 3**: 综合报告

## Phase 1 审计组

| 组 | 文件数 | 状态 |
|----|--------|------|
| 01-foundation | 26 | ✅ 完成 |
| 02-domain | 23 | ✅ 完成 |
| 03-protocol | 24 | ✅ 完成 |
| 04-upstream | 18 | ✅ 完成 |
| 05-resolver | ~19 | ⏳ 待完成 |
| 06-handler | 16 | ✅ 完成 |
| 07-defense-server-cli | ~25 | ✅ 完成 |

## Phase 2 交叉分析维度

| # | 维度 | 方法 | 状态 |
|---|------|------|------|
| 1 | CrossCut Context | `grep context.Background/TODO` | ✅ 完成 |
| 2 | CrossCut Error | `grep fmt.Errorf.*%v.*err` | ✅ 完成 |
| 3 | CrossCut Goroutine | `grep 'go func'` + HandlePanic 审计 | ✅ 完成 |
| 4 | CrossCut Resource | `grep 'func.*Close()'` + 幂等性检查 | ✅ 完成 |
| 5 | CrossCut Validation | `grep '_ :='` + ParseIP/PareCIDR 审计 | ✅ 完成 |
| 6 | CrossCut Logging | `grep 'log.Info/Warn'` 热路径审计 | ✅ 完成 |
| 7 | CrossCut LRU | `grep 'lrumap.New'` + OnEvict 审计 | ✅ 完成 |
| 8 | CrossCut RedundantPairs | `grep 'func.*With[A-Z]'` | ✅ 完成 |
| 9 | CrossCut Constants | 扫描魔法数字 | ✅ 完成 |
| 10 | CrossCut RFC | RFC 存档完整性 | ✅ 完成 |
| 11 | CrossCut Comments | TODO/FIXME 过期检查 | ✅ 完成 |
| 12 | CrossCut Ordering | decorder + New* 位置 | ✅ 完成 |
| 13 | CrossCut GoVersion | Go 1.26 特性采用 | ✅ 完成 |
| 14 | CrossCut DeadCode | 未用符号 | ✅ 完成 |
| 15 | CrossCut Perf | N+1 SQL / 热路径分配 | ✅ 完成 |
| 16 | CrossCut Arch | 导入分层验证 | ✅ 完成 |
| 17 | CrossCut Docs | ARCHITECTURE.md 一致性 | ✅ 完成 |
| 18 | CrossCut Pool | sync.Pool Get/Put 对称性 | ✅ 完成 |

## 修复优先级

### Sprint 1 (CRITICAL) — 立即修复

基于已完成的 6 个审计组:

1. **cache/store.go**: sync.Pool 双重归还 (domain C1)
2. **zone/parse.go**: 裸 "." / "*." domain header panic (domain C2, C3)
3. **dnscrypt/crypto.go**: sharedKeyCache data race (protocol C1)
4. **dnscrypt/server.go**: wg.Go() bypass WaitGroup swap (protocol C2)
5. **tls/quic.go**: DoQ poolKey 作为拨号地址错误 (upstream C1)
6. **dnscrypt/state.go**: deleteState nil 指针竞态 (upstream C2)
7. **poisonguard.go**: TLD 检测永久失效 (defense C1)
8. **poisonguard.go**: 权威级盲点 — 文档化 (defense C2)

### Sprint 2 (HIGH) — 下个发布周期

约 18 个 HIGH 发现（来自 Foundation/Domain/Protocol/Upstream/Handler/Defense）

### Sprint 3 (MEDIUM + LOW) — 后续

约 89 个 MEDIUM + LOW 发现
