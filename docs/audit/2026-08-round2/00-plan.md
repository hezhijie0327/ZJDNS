# 2026-08 第二轮审计 — 修复计划（快速存档版）

> 修复时先读 `12-synthesis.md`（核验证据）与 `raw-phase12.jsonl`（全部原始发现）。
> 按 AUDIT-METHODOLOGY §2.1 分 Sprint；每 commit 主题行带发现编号（C1/H1/M1 等）；每 Sprint 后质量门禁 + benchmark 对比。

## Sprint 1 — CRITICAL（立即修复）

### C1. `cache/store.go:267` — Get 格式标记缺失 → 升级后旧条目 panic

- 修复：Get 解析前检查 `msgWire[0]`：
  - `== cacheFormatPrePacked (0x02)` → 现路径（offset 表 + wire）
  - 否则 → 旧格式：`isZstdCompressed(msgWire)` 检测后解压，无 offset 表（entry.TTLOffsets 空 → buildFromPrePacked 跳过 TTL 调整）
- 同时给 `msgWire` 加最小长度守卫（`len(msgWire) >= 3` 才读 `[1:3]`），防损坏行。
- 测试：写入旧格式（zstd 裸 wire）行 → Get 不 panic 且正确解包；`TestGetLegacyFormat`。

### C2. `server/protocol/dnscrypt/crypto.go:29` — encrypt() 清空 pre-packed 响应

- 修复：`encrypt()` 开头 `if len(m.Data) > 0 { packet = m.Data }` 直接使用（跳过 Pack），或先 `m.Unpack()` 再 Pack（代价高，不推荐）。Normalize 的 `res.Len()` 对 Data 形态同样误算——一并在 WriteMsg 层处理（`if len(m.Data) > 0` 时用 `len(m.Data)` 判断截断）。
- 测试：DNSCrypt UDP 缓存命中（pre-packed）→ 加密响应含完整 RR（集成测试）。

## Sprint 2 — HIGH（下个发布周期）

### H1. `mqtype.go:78` — miss 路径不合并

- 修复方向 A（推荐）：MQTYPE 链位置移到 CacheStore **外侧**（chain.go 中 Wrap 顺序调换）→ post 时 CacheStore 已构建响应；注意同时调整 CacheStore 的 `Res != nil` 跳过逻辑与 MQTYPE 的 forwarding 判断。
- 修复方向 B：merge 直接基于 `qctx.ResolutionResult` 构建（不依赖 qctx.Res），在 CacheStore post 之后执行（需要拆函数）。
- 测试：`mqtype_recursive_test.go` 增加真实链（AssembleChain）miss 路径集成测试，断言响应含 MQRESPONSE。

### H2. `mqtype.go` + `response.go:73` — hit 路径 merge 被 Unpack 抹掉

- 修复：merge 产物写入 pre-packed Data（原地 patch 或 rebuild wire），或 Response 中间件对 `Pseudo` 非空的 pre-packed 消息先 Unpack 再 merge（顺序调整）。
- 测试：AssembleChain 缓存命中 + MQTYPE-Query 集成测试，断言合并 RR 与 MQRESPONSE 出现在最终 wire。

### H3. `bridge.go:110` — refs 双重 Add（删除重复行）

- 修复：删除 line 110 的 `entry.refs.Add(1)`（保留 :98 锁内 Add 与 :115/:155 的 -1）。
- 测试：请求完成后 `refs.Load() == 0` 断言（H1 修复时同型测试，补到 f7e7f13 的 shard 结构上）。

### H4. `mqtype.go:56` — 明文监听器 MQTYPE-Query 不可见

- 修复：MQTYPE.pre 镜像 EDNS.pre 的 `if len(qctx.Req.Pseudo) == 0 { qctx.Req.Options = 0; qctx.Req.Unpack() }`（失败 → FORMERR），保证明文 UDP/TCP 上 findMQQUERY 可见。
- 测试：用 `dns.Server`（MsgOptionUnpackQuestion 形态）构造请求 → MQQUERY 可见 + FORMERR 校验生效。

## Sprint 3 — MEDIUM + LOW（文档/优化）

| # | 位置 | 修复 |
|---|------|------|
| M1 | upstream/dnscrypt/state.go:104 | state() 加 `c.cache == nil` 守卫（对齐 buildState） |
| M2 | upstream/plain/udp.go:166 | ctx.Done 分支归还 sg.last/prev/nonEDNS |
| M3 | upstream/dnscrypt/cert.go:83 | `DialContext(ctx, ...)`（复用 plain/udp.go 模式） |
| M4 | cache/store.go:314 | `_ = entry.Unpack()` 失败时跳过 latency 排序（不 rebuild） |
| M5 | cache_lookup.go:247 | 前台 TryGo 失败时关闭 done（或 goroutine 侧检查）——待核验后修 |
| M6 | mqtype.go:269 | entryRcode 读扩展 rcode（解析 OPT） |
| M7 | tlcp/tlcp.go:89 | 响应 ID 回验（对齐 tls.go）——待核验后修 |
| M8 | docs/FLOWCHARTS.md | 补 MQTYPE 中间件、querylog.clear、pre-packed 直发、TCP 写入分片流程图 |
| 其余 | raw-phase12.jsonl | 逐项确认（lrumap OnEvict 覆盖语义、注释残留、常量、文档） |

## 门禁清单（每 Sprint 后）

```bash
go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt
go test -short ./...
# benchmark 对比（>15% 回归即回滚）
go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
```
