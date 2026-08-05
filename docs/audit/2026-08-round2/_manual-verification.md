# 2026-08 第二轮审计 — 人工核验笔记（Phase 3 输入）

> 审计主循环人工读码确认的发现。与 workflow agent 结果合并去重后进入综合报告。

## C1 — CRITICAL — cache/store.go Get() 格式迁移缺陷（越界 panic）

- **位置**: `cache/store.go:267`（Get 的 pre-packed 解析）
- **类别**: memory / upgrade-compat
- **问题**: Get() 无条件按 `cacheFormatPrePacked` (0x02) 格式解析 `msgWire[1:3]` 为 TTL offset 表，**不检查 `msgWire[0] == 0x02`**。
  - v3.11.11 及更早的 Set 存储 `zdnsutil.Compress(msg.Data)`（zstd 裸 wire，无前缀）或裸 wire（≤v3.11.10）。
  - zstd 帧头字节 1-2 = 0xB52F = 46383 → `AcquireTTLOffsets(46383)` 分配后循环 `msgWire[3+i*2:]` 在 i≈百级处**越界 panic**。
  - 裸 wire：msgWire[0:2]=DNS ID（随机），msgWire[2:3]=flags 高字节 → 同样随机大数 → 越界 panic。
- **影响窗口**: 升级后 7 天（DefaultMaxCacheableTTL）+ 3 天 stale（DefaultStaleMaxAge）= **最长 10 天内命中旧条目即 panic**（每个查询由 bridge.go HandlePanic 恢复 → 查询丢弃）。
- **证据**: `git show 5256aec^:cache/store.go`（Set 存 `zdnsutil.Compress(msg.Data)`）；`git show ba1f78c:cache/store.go`（Get 引入时即无条件解析）。
- **修复方向**: Get 检查 `msgWire[0] != cacheFormatPrePacked` 时按旧格式解析（zstd magic 检测 + 解压，无 TTL offset 表）；或启动时迁移清空旧格式条目。

## H1 — HIGH — MQTYPE 中间件：递归模式 miss 路径不合并

- **位置**: `server/handler/middleware/mqtype.go:78`（`if qctx.Res == nil { return err }`）
- **类别**: rfc / logic
- **问题**: 链顺序 Response→CacheStore→MQTYPE→…→Resolution。缓存 miss 时 Resolution 只设置 `qctx.ResolutionResult`（qctx.Res 仍为 nil），MQTYPE 的 post 处理先于 CacheStore 的响应构建 → merge 从不执行。
- **影响**: RFC 10029 §3.4 MUST（"A conforming server ... MUST return an MQTYPE-Response option in its response"）+ §5（客户端把无 MQRESPONSE 的响应视为无效）。递归模式首次查询（未缓存）必然发生 → 客户端 MQTYPE 功能在递归模式完全失效。
- **证据**: chain.go:141-152（MQTYPE 在 CacheStore 内侧）；resolution.go:63-75（只设 ResolutionResult）；mqtype_test.go 只用 fake next 直接设 Res（未覆盖真实管线）。
- **修复方向**: merge 移到 CacheStore post 之后（链上移到 CacheStore 外侧）或基于 `qctx.ResolutionResult` 构建合并响应。

## H2 — HIGH — MQTYPE 中间件：hit 路径 merge 产物被 Unpack 抹掉

- **位置**: `server/handler/middleware/response.go:73` + `mqtype.go:180-196` 交互
- **类别**: rfc / logic
- **问题**: 缓存命中时 CacheLookup 设置 pre-packed Res（`Data != nil`、Answer/Pseudo 为空）。MQTYPE merge 往 `msg.Answer`/`msg.Pseudo` 追加合并 RR 和 MQRESPONSE。随后 Response 中间件 `shouldAddEDNS=true`（`len(qctx.Req.Pseudo) > 0`，MQTYPE-Query 客户端必有）→ 走 Unpack 路径 → miekg/dns v0.6.89 `msg.go:160,428` 用 wire 内容**重建** Answer 与 Pseudo → merge 产物全部丢失。
- **影响**: 同 H1——客户端收到纯主响应、无 MQTYPE-Response。递归模式两条路径（miss/hit）全部失效。
- **证据**: `codeberg.org/miekg/dns@v0.6.89/msg.go` Unpack 实现（`m.Pseudo = make([]RR, ...)` 重建）；response.go:58-88。
- **修复方向**: merge 后置（在 Response finalize 前重新打包），或 merge 修改 pre-packed 的 Data 而非解包字段。

## H3 — HIGH — server/bridge.go refs 双重 Add → sweep 死代码 → tcpWriteMu 无界增长（H1 回归）

- **位置**: `server/bridge.go:98`（锁内 `refs.Add(1)`）+ `server/bridge.go:110`（锁外 `refs.Add(1)`）
- **类别**: memory / regression
- **问题**: 每个 TCP 请求执行两处 `refs.Add(1)`，而 goroutine（line 155）与 SERVFAIL 路径（line 115）各只有一个 `defer refs.Add(-1)`。每请求净 +1 → refs 永不归零 → `sweepTCPWriteMu`（tasks.go:137 `refs.Load() != 0 → continue`）永不删除任何 entry → 每 TCP 客户端连接一条永久 entry（含 writeMu+capacity channel），进程生命周期无界增长。
- **证据**: H1 修复提交 9f6001c 只有一处锁内 Add；f7e7f13（v3.11.13 TCP shard 化）复制成两份。
- **修复方向**: 删除 line 110 的重复 Add（保留锁内 Add + goroutine/SERVFAIL 的 -1）。

## M1 — MEDIUM — mqtype.go:269 entryRcode 只读低 4 位

- 扩展 RCODE（≥16，如 BADVERS=16）位于 OPT TTL 高字节，`ResponseWire[3] & 0x0F` 恒读低 4 位 → 扩展 rcode 条目被误判为 0 → RCODE 匹配检查失效（RFC 10029 §3.4 RCODE 一致性）。

## M2 — MEDIUM — cache/store.go:314 `_ = entry.Unpack()` 丢弃错误

- latency 排序路径解包失败时 Answer 可能部分填充 → `rebuildResponseWire` 产出损坏 wire 并被服务。

## M3 — LOW — cache/store.go:625 `count < 0` 死条件

- `EntryCount()` 为 int64 非负，`count < 0` 恒假（dead check）。

## M4 — LOW — resolution.go:49 `findMQQUERY` 的 invalid 被 `_` 丢弃

- 依赖 MQTYPE 前置 FORMERR；若 MQTYPE 中间件被禁用，非法 MQ 选项会透传到上游。

## 已验证无问题（防重复报告）

- modernc SQLite `columnBlob` 每次 Scan 新分配（zero-copy Get 的引用安全）✓
- `DecompressTo`/`decompressBufPool` 生命周期（owned 拷贝 + clear+Put）✓
- `pool.Message.Put` 全 struct 清零（无 Data 残留）✓
- QueryContext 池化全字段字面量清零 ✓
- StmtEntryFallback SQL（prefix 唯一性、ORDER BY CASE 正确）✓
- scanTTLOffsets 偏移计算（uint16 上限内安全）✓
- zonecut.go 递归→权威 MQTYPE 合并（defer Put 时序、fallback 逻辑）✓
- forward.go MQTYPE 透传 + Rcode 处理 ✓
- recursive.go 911e242 SERVFAIL 修复（无双重 Put、分支位置正确）✓
- nsec.go NXNAME 检测、CapValidatedTTL canon 一次化 ✓
- resinfo.go RFC 9606（DDR 门控、zone 冲突检查）✓
- chaos.go querylog.clear（与既有 clear 端点同模式）✓
- any.go RFC 8482 实现（新文件，CacheServed 短路正确）✓
- edns.go 跳过重复解包优化（Pseudo 非空即完整解包的前提成立）✓
