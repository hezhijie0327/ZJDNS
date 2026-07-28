# Phase 2 交叉分析报告

审计日期: 2026-07-28

## 交叉分析维度结果

### 1. CrossCut Context — context.Background()/TODO() 审计

发现 14 个调用点（非 test/main）：

| 文件 | 行号 | 评估 |
|------|------|------|
| `internal/latency/prober.go` | 33 | 仅 nil fallback — 可接受但缺少警告 |
| `server/server.go` | 71 | 顶级服务器生命周期 — 正确 |
| `server/tasks.go` | 179,190,200 | shutdown context — 正确 |
| `server/handler/middleware/cache_lookup.go` | 150 | refreshCtx nil fallback — 应永远不可达 |
| `server/protocol/tlcp/server.go` | 116 | 服务器生命周期 — 正确 |
| `server/protocol/tls/quic.go` | 122 | QUIC 0-RTT 验证 — 正确 |
| `server/protocol/tls/server.go` | 165,308,314 | 服务器生命周期 — 正确 |
| `server/protocol/dnscrypt/server.go` | 104 | 服务器生命周期 — 正确 |
| `server/upstream/warmup.go` | 51 | WarmUp — 正确（启动时） |
| `server/resolver/probe/probe.go` | 145,182,226 | nil fallback — 应记录警告 |
| `server/upstream/socks5/socks5.go` | 451 | 10 秒超时 — 正确 |

**结论**: 无严重违规。服务器生命周期使用正确。cache_lookup 和 probe 中的 nil fallback 应最终消除。

### 2. CrossCut Error — %v error wrapping 审计

**结果**: 无 `fmt.Errorf.*%v.*err` 模式。所有 error wrapping 使用 `%w`。✅

### 3. CrossCut Goroutine — HandlePanic + owner 审计

所有 goroutine 已审计。每个有 HandlePanic 或等价的 panic recovery。

**例外**:
- `server/protocol/dnscrypt/server.go:264` — `go func()` 无 HandlePanic（仅 Wait+close done channel）
- `internal/log/log.go:324` — 使用自定义 stderr panic recovery（log 包不能用 HandlePanic）
- `server/tasks.go:153` — signal handler goroutine 无 errgroup/WaitGroup 追踪（有文档说明）

**结论**: 整体良好。2 个已知缺口有文档说明。

### 4. CrossCut Resource — Close() 幂等性审计

| 类型 | 文件 | 幂等机制 |
|------|------|----------|
| `*DB` | `database/db.go:133` | `atomic.CompareAndSwapInt32` ✅ |
| `*SQLiteCache` | `cache/store.go:78` | 委托给 AsyncStatsWriter + DB ✅ |
| `*AsyncStatsWriter` | `cache/async_writer.go:66` | `sync.Once` ✅ |
| `*Prober` (latency) | `internal/latency/prober.go:46` | `closeOnce` ✅ |
| `*Prober` (resolver) | `server/resolver/probe/probe.go:67` | 待审计 |
| `*Client` (upstream) | `server/upstream/client.go:289` | nil 守卫（非幂等） |
| `*Client` (plain) | `server/upstream/plain/client.go:39` | 待审计 |
| `*Client` (tls) | `server/upstream/tls/client.go:101` | 待审计 |
| `*Client` (dnscrypt) | `server/upstream/dnscrypt/client.go:217` | nil 守卫 + 清除缓存 |
| `*Dialer` (socks5) | `server/upstream/socks5/socks5.go:196` | `d.mu.Lock()`（非幂等 — 第二次调用死锁） |
| `*Evaluator` (zone) | `zone/zone.go:103` | 委托给 db.Close() ✅ |
| `*Engine` (ruleset) | 无 Close() | 无可关闭资源 ✅ |

**结论**: 核心层良好。SOCKS5 Close 非幂等（MEDIUM 关注）。几个上游客户端 Close 无原子守卫。

### 5. CrossCut Validation — 参数校验审计

**ParseIP/ParseCIDR**: 全部正确检查 nil 或使用 comma-ok 模式。

**`_` 丢弃值**: 大多数有注释。`database/db.go:95,108,119` 的 `_ = sqldb.Close()` 在 error 路径中 — 可接受。`cache/async_writer.go:168,177` 有注释说明。

**裸类型断言**: 无发现。✅

**结论**: 参数校验整体良好。少数 `_` 丢弃缺少注释。

### 6. CrossCut Logging — 热路径 log 级别审计

**中间件热路径**: 全为 Debug 级别。✅

**cache/store.go Warn**: 仅 error/decompress/commit 失败路径 — 非每查询。✅

**Server 启动**: 合理 Info 级别。✅

**协议处理器**: DNSCrypt key rotation Warn 非热路径。✅

**结论**: 日志纪律良好。无热路径 info/warn 刷屏。

### 7. CrossCut LRU — lrumap.OnEvict 审计

| 位置 | 值类型 | OnEvict | 评估 |
|------|--------|---------|------|
| `handler/pending.go:56` | `*pendingCall` (含 channel) | ✅ 有 | 正确 |
| `tls/quic.go:29` | `time.Time` (纯数据) | ✅ 无需 | 正确 |
| `tls/http3.go:24` | `time.Time` (纯数据) | ✅ 无需 | 正确 |
| `dnscrypt/server.go:123,331` | `[32]byte→[32]byte` (纯数据) | ✅ 无需 | 正确 |
| `defense/hopguard.go:53` | `*serverState` (含 mutex) | ❌ 无 | **MEDIUM** |
| `upstream/client.go:112` | `*socks5.Dialer` | ✅ 有 | 正确 |
| `upstream/tlcp/client.go:34` | `*http.Client` | ✅ 有 | 正确 |
| `upstream/tls/client.go:75` | `*quic.Config` (纯配置) | ✅ 无需 | 正确 |
| `upstream/tls/client.go:76-77` | `*http.Client` | ✅ 有 | 正确 |
| `upstream/dnscrypt/client.go:32` | `*State` (纯数据) | ❌ 无 | **MEDIUM** |

**结论**: hopguard serverState 和 DNSCrypt State 缺少 OnEvict。两者都持有 mutex 和潜在资源。

### 8. CrossCut RedundantPairs — With* 函数审计

无 true `Foo`/`FooWithBar` 冗余对。`CloseWithLog`、`serveExpiredWithRefresh`、`validateNODATAWithNSEC` 等为特定用途方法。

### 9. CrossCut Constants — 魔法数字审计

| 数字 | 位置 | 评估 |
|------|------|------|
| `86400` | `database/stmts.go`, `database/schema.go`, `cache/store.go` | 应提取为 `config.SecondsPerDay` |
| `2000` | `dnscrypt/server.go:123,331` | 应提取为命名常量 |
| `65535` | `config/validate.go:219` | 应引用标准库或命名常量 |
| `10000` | `database/db.go:58` (DSN busy_timeout) | DSN 字符串内 — 可接受 |
| `4096` | 多处 | 正确提取为常量 |

**结论**: 少量魔法数字残余。

### 10. CrossCut RFC — 存档完整性

| 协议 | RFC | 状态 |
|------|-----|------|
| DNS 核心 | 1034, 1035, 2181, 6891, 等 | ✅ 已存档 |
| DNSSEC | 4033, 4034, 4035, 等 | ✅ 已存档 |
| DoT/DoH/DoQ | 7858, 8484, 9250 | ✅ 已存档 |
| QUIC/HTTP3 | 9000, 9114 | ✅ 已存档 |
| DNSCrypt | draft-denis-* | ✅ 已存档 |
| **TLCP/DTLCP** | GB/T 38636, GM/T 0128 | ❌ **未存档** |
| DNS Cookie | 7873, 9018 | ✅ 已存档 |

**结论**: TLCP/DTLCP 国标文档未存档。51 个 RFC 文件总数不错。

### 11. CrossCut Comments — TODO/FIXME 审计

**结果**: 无 TODO/FIXME/HACK/临时 标记。✅

### 12. CrossCut Ordering — 声明顺序审计

**decorder 合规**: 所有文件遵循 `type → const → var → func`。

**命名**: `database.Open()` 而非 `NewDB()` — 偏离惯例但可接受（SQL 惯用语）。

### 13. CrossCut GoVersion — Go 1.26 特性采用

**已采用**: `clear()`, `min()/max()`, `slices.SortStableFunc`, `sync.WaitGroup.Go()`

**未采用**:
- `errors.AsType[T]` (Go 1.25) — 代码仍用 `errors.As()`
- `slices.Backward` / `slices.Reverse` (Go 1.23) — 无手写反向循环需要替换

**结论**: Go 1.26 特性采用良好。`errors.AsType` 可用于现代化。

### 14. CrossCut DeadCode — 未用符号

`staticcheck -checks U1000` 未安装。手动审查未发现明显死代码。

### 15. CrossCut Perf — N+1 / 热路径分配

**N+1 SQL**: 所有 `rows.Next()` 循环正确 — 无嵌套查询。

**热路径分配**: 
- `ReadTCPMsg` 用 `new(dns.Msg)` 而非 pool (foundation MEDIUM)
- QueryContext 每查询分配 (handler MEDIUM)
- DNSCrypt decrypt 绕过 pool (protocol HIGH)

### 16. CrossCut Arch — 导入分层

**违规**: `cmd/zjdns/cli/generate.go` → `server/protocol/dnscrypt`（有文档说明的已知偏差）

**Domain 层**: 无跨 domain 导入违规。✅

### 17. CrossCut Docs — 文档一致性

**ARCHITECTURE.md 缺口**:
- ❌ 防御机制（hopguard, poisonguard, spoofguard, splitguard）完全缺失
- ✅ 防御表格存在于 CLAUDE.md

**CLAUDE.md 准确性问题**:
- ❌ "max 10 steps" → 代码使用 `DefaultMaxRecursionDepth = 16`
- ✅ 防御表格正确

### 18. CrossCut Pool — sync.Pool Get/Put 对称性

**逐对审计**: 每个 `pool.DefaultMessage.Get()` 有对应的 `defer pool.DefaultMessage.Put()` 或显式 Put。

**例外**: 
- `cache/store.go:152-157` — 双重归还（CRITICAL，见 Domain 审计）
- `server/protocol/dnscrypt/crypto.go:158` — 使用 `&dns.Msg{}` 而非 pool（有文档说明）

**Buffer pool**: 正确的 Get/Put 对称性。✅
