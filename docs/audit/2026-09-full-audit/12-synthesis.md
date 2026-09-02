# 2026-09 全项目审计 — 综合报告

时间:2026-09-03 · 方法:docs/AUDIT-METHODOLOGY.md 完整流程(Phase 1 包级 7 agent → Phase 2 交叉维度 4 agent(19 维分组) → Phase 3 综合) · 基线:`go build` / `go test -short ./...` / `go test -race -short ./...` / `golangci-lint run` 全绿。

## 总量

| 来源 | 文件 | C | H | M | L |
|------|------|---|---|---|---|
| Foundation (internal/*) | 01-foundation.md | 0 | 1 | 6 | 10 |
| Domain (config/cache/edns/zone/ruleset) | 02-domain.md | 0 | 2 | 4 | 10 |
| Protocol (server/protocol/* + server + cmd) | 03-protocol.md | 0 | 3 | 6 | 10 |
| Upstream (server/upstream/*) | 04-upstream.md | 0 | 4 | 6 | 9 |
| Resolver (server/resolver/*) | 05-resolver.md | 0 | 0 | 5 | 10 |
| Handler (server/handler/*) | 06-handler.md | 0 | 1 | 3 | 11 |
| Defense (server/defense + call sites) | 07-defense.md | 1 | 0 | 4 | 4 |
| CrossCut 锁/goroutine/资源 | 08-crosscut.md (X) | 0 | 2 | 2 | 1 |
| CrossCut 错误/ctx/校验/死代码 | 08-crosscut.md (E) | 0 | 0 | 1 | 8 |
| CrossCut 日志/常量/RFC | 08-crosscut.md (C) | 0 | 0 | 4 | 6 |
| CrossCut 文档/流程图/注释 | 09-docs.md (T) | 0 | 0 | 6 | 16 |
| **合计(未去重)** | | **1** | **13** | **47** | **99** |

去重:X1=D1、X2=P1、E/U 重叠若干 → 实际独立发现约 150。全部纳入修复计划。

## 主题分析(系统性根因)

1. **池计数纪律**(U1/U2/U3):`p.total` 在 Acquire 死连接过滤、dialAndAdd 死替换、QUIC.Put 三条路径上漂移 — 与 2026-08 H1(UDP 池无界建键)同根:总量账本没有单一维护点。
2. **锁内 IO**(D2/R1/X-相关):lrumap.OnEvict 同步落盘(spill.Put → WriteAt/Compact)在 entries 锁内执行 — 违反"锁内不要做 IO"铁律,Compact 期间全缓存停顿。
3. **use-after-Put**(D1):cache.Set 在 `pool.Put` 归零结构体后再读 `msg.Data` — DNSSEC DO=0 过滤整体失效。与 2026-08 C1(serve-stale Data 未清)互为镜像:池对象读写时序仍是高发区。
4. **共享端口防御面**(P2/P3/X4):demux 引入后 DNSCrypt/DTLCP 共享 UDP 路径绕过了独立端口的入参过滤(最短包长)与有界 goroutine 纪律;78b23d6 只修了 shared dispatch 路径,standalone DTLCP accept 循环仍是裸 channel send。
5. **跨处理器重复**(M2/M4/M5、L9):DoH3 accept 循环、DTLS/DTLCP response 写出、cert leafNotAfter 三组复制粘贴已出现行为漂移 — 方法论"跨协议一致性"模式的再次验证。
6. **代理路径滞后**(U4):DoQ 修了 SOCKS5 relay 释放钩子(2026-08 H3),DoH3/WarmUpQUIC 的相同构造漏修。
7. **文档漂移**(T 系列):pool 上限 4/32 vs 实际 8/512、spoofguard 行为描述与代码相反、config.example.json 过不了自身校验。

## 行动计划

Sprint 1(CRITICAL+HIGH,发现即修复)→ Sprint 2(MEDIUM)→ Sprint 3(LOW 批量)→ 质量门禁(build/fix/lint/test 零警告)→ benchmark 回归对比 → docs/debug E2E 全协议验证 → 分批提交 + patch 版本号。
