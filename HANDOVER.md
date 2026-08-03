# HANDOVER — 2026-08 Round 8 审计修复进度（最终状态）

审计日期: 2026-08-03 | 报告: docs/audit/2026-08-round8/

## ✅ 全部完成（6 commits）

| Commit | 内容 |
|--------|------|
| `baf39cc` | Squash: Round 8 全部 112 findings (5C/12H/~55M/~40L) |
| `09dbd02` | MEDIUM follow-up: 热路径分配 + 正确性硬化的 10 项 |
| `54525e2` | Zone rewrite 死代码删除 (RewrittenName/restoreDomain/EffectiveName) |
| `48b0e28` | DDR ALPN 修复 + FLOWCHARTS.md 更新 |
| `0997a73` | Zone dynamic 规则 qtype 修复 + 2 个新测试 |

## 修复清单

### CRITICAL 5/5
C1–C5（双重归还、nil 解引用、DNSSEC 绕过、zone 错误响应）

### HIGH 12/12
H1–H12（数据竞争、资源泄漏、死锁、use-after-free）

### MEDIUM ~40
- **热路径分配 6 项**: zone struct key (2-4.5x), edns math/rand, dnscrypt pool, KEM 移锁, cache 预分配, quic ctx.AfterFunc
- **正确性 4 项**: stats 常量化, dnscrypt wg 同步, tls listenerMu, plain shutdown 超时
- **Zone 2 项**: rewrite 死代码删除, dynamic qtype 修复
- **DDR 1 项**: ALPN 注册顺序
- **存储层 3 项** (M-batch): load backup, bounded decompress, PTR cleanup
- **DNSCrypt 3 项** (M-batch): lifecycle, handshake timeout, proxy ID
- **其他 ~20 项**: cache-hit rcode, pooled-write deadline, shutdown-safety etc.

### LOW ~40
注释修正、死字段删除、FLOWCHARTS.md 更新、DDR/ALPN endpoint、常量提取等

## 新增测试
- `TestEvaluator_DynamicNonConfigQtype` — 动态规则不对非配置 qtype 响应
- `TestPTR_ConcurrentReadWrite` — PTR 索引并发读写 race 检测
- 已有覆盖的：pending 并发、hopguard Feed、poisonguard TLD DS

## 质量门禁（全部通过）
- [x] go build ./...
- [x] golangci-lint run（0 issues）
- [x] go test -short ./...（全部通过）
- [x] go test -race（新测试通过）
- [x] Benchmark 基线已刷新（zone Evaluate 2-4.5x 加速，无真实回归）

## 剩余可选项（非阻塞）
- DTLS 空闲超时测试（需 DTLS server 基础设施）
- DNSCrypt 关停测试（需完整 server 基础设施）
- cache store expiresAt 周期清扫（当前 SetOnEvict 已处理）
- 部分文档/注释微优化
