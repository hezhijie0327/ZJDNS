# 综合审计报告：BadgerDB 迁移后审计

**日期**：2026-07-29
**范围**：全项目 207 个 Go 源文件，40 个包
**重点**：SQLite→BadgerDB 架构重构遗留问题、BadgerDB API 使用正确性、死代码

---

## 审计总结

SQLite→BadgerDB 迁移（commit `bb7aae2`）执行得非常彻底——Go 代码中无任何 SQLite/database/sql 残留。`go.mod` 无 SQL 依赖。旧的 `database/migration.go`、`database/schema.go`、`database/sqlutil.go`、`database/stmts.go` 及 16 个 SQL 迁移文件已全部删除。

**发现总数**：1 CRITICAL + 5 HIGH + 11 MEDIUM + 3 LOW = 20 项

---

## CRITICAL（1 项）

### C1：`LatencyLastProbe` 总是返回 true——延迟探测系统被绕过

- **文件**：`cache/stats.go:358-368`
- **类别**：correctness / badgerdb
- **问题**：

```go
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
    _ = c.db.Badger.View(func(txn *badger.Txn) error {
        _, err := txn.Get(database.EIPLatencyKey(ip))
        return err  // 当 key 不存在时返回 ErrKeyNotFound
    })
    // 无论 View 返回什么错误，都返回 true
    return log.NowUnix(), true
}
```

View 闭包的返回值被 `_` 丢弃。当 key 不存在时，`txn.Get()` 返回 `ErrKeyNotFound`，闭包返回它，`View()` 返回它，但调用方用 `_` 丢弃了错误。结果是：**无论 key 是否存在，函数永远返回 `(now, true)`**。

- **风险**：`server/resolver/probe/probe.go:112` 检查 `LatencyLastProbe` 来决定是否需要重新探测 IP。由于此函数永远返回 `true`，**延迟探测系统认为每个 IP 都刚被探测过**，导致：(1) 新 IP 不会被及时探测，(2) A/AAAA 记录排序无法基于最新延迟数据，(3) 冷启动时所有 IP 的延迟数据都缺失但系统不自知。

- **修复**：
```go
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
    if c.db.IsClosed() {
        return 0, false
    }
    var found bool
    _ = c.db.Badger.View(func(txn *badger.Txn) error {
        _, err := txn.Get(database.EIPLatencyKey(ip))
        if err != nil {
            return nil  // key 不存在不是 View 级错误
        }
        found = true
        return nil
    })
    if !found {
        return 0, false
    }
    return log.NowUnix(), true
}
```

---

## HIGH（5 项）

### H1：`database.Open()` 接受但忽略 `maxEntries` 参数——死参数链

- **文件**：`database/db.go:32`、`config/config.go:124`、`server/server.go:137`
- **类别**：dead-code
- **问题**：`Open(path, maxEntries, ...)` 接受 `maxEntries` 但函数体内从未使用。整个参数链都是活的——`ServerConfig.Cache.MaxEntries` 被配置验证、`initDatabase()` 传递——但到达 `Open()` 后被静默忽略。`DefaultMaxCacheEntries = 10000` 常量也不再有效果。
- **风险**：用户配置 `max_entries` 以为在控制缓存大小，实际无效。BadgerDB 的缓存大小由 `BlockCacheSize` 和 `IndexCacheSize` 控制。
- **修复**：从 `Open()` 签名移除 `maxEntries` 参数，更新所有调用点。考虑将 `Config.CacheConfig.MaxEntries` 标记为 deprecated 或移除。

### H2：SQL 时代残留注释

- **文件**：
  - `zone/parse.go:28`：`// loadFile parses a zone file and inserts entries directly into SQL.` — 应改为 "into BadgerDB"
  - `cmd/zjdns/cli/parse.go:57`：孤立的 `// SQL` 注释——旧 `--sql`/`--sql-rw` flag 定义位置的残留
- **类别**：comments / dead-code
- **风险**：误导新开发者以为项目仍在使用 SQL。
- **修复**：改正 `parse.go:28` 注释；删除 `cli/parse.go:57` 的孤立注释。

### H3：`cache/benchmark_test.go` 是死文件

- **文件**：`cache/benchmark_test.go`（整个文件）
- **类别**：dead-code
- **问题**：文件内容仅为 `// Benchmarks are now in cache_test.go to avoid duplication.`——实际的 benchmark 代码已在 `cache_test.go` 中。空 benchmark 文件不贡献任何测试覆盖。
- **修复**：删除此文件。

### H4：`testStore()` 绕过 `New()` 构造函数

- **文件**：`cache/cache_test.go:16-22`
- **类别**：test-coverage / correctness
- **问题**：
```go
func testStore() *Cache {
    db, _ := database.Open("", 0, 0, 0, 0)
    return &Cache{db: db}  // 绕过 New()，asyncWriter 为 nil
}
```
直接构造 `Cache{db: db}` 跳过了 `New()` 中的 `asyncWriter` 初始化。`RecordRequest` 在 asyncWriter 为 nil 时走同步回退路径——这在 13 个使用 `testStore()` 的测试中从未被验证。
- **风险**：测试路径与生产路径不同，async writer 相关的 bug 无法被现有测试捕获。
- **修复**：将 `testStore()` 改为调用 `New(db)`。

### H5：Zone `queryWildcardBatch` 中 `defer it.Close()` 在循环内

- **文件**：`zone/zone.go:342`
- **类别**：correctness / resource
- **问题**：
```go
for _, suffix := range suffixes {
    it := txn.NewIterator(opts)
    defer it.Close() //nolint:gocritic // defer in loop is required for per-suffix iteration
    // ... 使用 iterator ...
    it.Close()  // 376 行：显式关闭
}
```
在循环内 `defer` 会导致所有 iterator 堆积到函数返回才释放。虽然有显式 `it.Close()` 和 `nolint:gocritic`，但如果循环中间 panic 或提前返回，只有 defer 能保护。如果 suffix 数量增至上百个，资源堆积会很严重。
- **风险**：在 `maxWildcardLabels=16` 的限制下风险较低，但模式不健壮。
- **修复**：提取内部循环为独立函数，使 defer 作用域局限在单次迭代：
```go
func (e *Evaluator) queryWildcardForSuffix(suffix string, ...) Result {
    _ = e.db.Badger.View(func(txn *badger.Txn) error {
        it := txn.NewIterator(opts)
        defer it.Close()
        // ...
    })
}
```

---

## MEDIUM（11 项）

### M1-M4：`database/keys.go` 中的死代码函数

- **文件**：`database/keys.go`
- **类别**：dead-code
- **问题**：以下导出函数在整个代码库中无任何调用方：
  - **M1**：`ParseStatDayFromKey(key []byte) int64` — 第 404 行
  - **M2**：`MaxKey(prefix []byte) []byte` — 第 418 行
  - **M3**：`StatsKeyDayCutoff(cutoff int64) []byte` — 第 410 行
  - **M4**：`ParseStatDay(key []byte) (int64, bool)` — 第 393 行（仅被 M1 调用）
- **风险**：增加二进制大小和维护负担，误导开发者以为有调用方。如果将来需要这些函数（如 stats 清理），可以从 git 历史恢复。
- **修复**：删除这 4 个函数。如果 `ParseStatDay` 是为未来 stats pruning 保留的，添加 `// TODO: use in stats pruning` 注释或直接删除。

### M5：关于 zstd 压缩的误导性注释

- **文件**：
  - `cache/store.go:217`：`// Set stores a DNS response in the cache. Wire format is zstd-compressed.`
  - `zone/wire.go:14`：`// Wire encoding: zstd(dns.Msg.Pack())`
- **类别**：comments
- **问题**：实际存储的是原始 DNS wire format（`dns.Msg.Pack()` 输出）。BadgerDB 在 SSTable block 级别做 zstd 压缩（`WithCompression(options.ZSTD)`）。注释暗示应用层做了 zstd，可能误导开发者在存储前额外压缩——造成 CPU 浪费的双重压缩。
- **修复**：改为 `// Wire format is raw DNS wire format (BadgerDB handles block-level zstd compression).`

### M6：`EntryKeyPrefix()` 文档注释重复

- **文件**：`database/keys.go:41-43`
- **类别**：comments
- **问题**：
```go
// EntryKeyPrefix returns the prefix for all cache entry keys.
// EntryKeyPrefix returns the prefix for all cache entry keys (including the e:ip: sub-space).
```
两行注释描述同一函数，第二行更完整。第一行应删除。
- **修复**：删除第 42 行。

### M7：`Zone.Close()` 为空操作

- **文件**：`zone/zone.go:80`
- **类别**：dead-code
- **问题**：`func (e *Evaluator) Close() error { return nil }` — 注释说"保留用于向后兼容"。迁移已完成，无调用方依赖此方法（数据库关闭由 `cache.Cache.Close()` 负责）。
- **修复**：删除 `Close()` 方法和接口中的对应声明（如有）。

### M8：`LatencyLastProbe` 命名不准确

- **文件**：`cache/stats.go:358`
- **类别**：naming
- **问题**：函数名暗示返回"上次探测时间"，但实际返回 `log.NowUnix()`（当前时间）。延迟值本身（`EncodeLatencyValue`）只存储了 `latency_ms`（2 字节），不包含时间戳。因此无法返回真正的"上次探测时间"——能检测的只是 key 是否存在。
- **风险**：调用方 `probe.go` 按最小间隔（`LatencyProbeMinInterval`）控制探测频率。由于函数总是返回当前时间，间隔检查实际是：上次探测是否在 N 秒内→比较现在与现在→永远为真→从不认为需要重新探测。这与 C1 的 bug 叠加。
- **修复**：要么重命名为 `HasLatencyData(ip string) bool`，要么在延迟值中编码时间戳（将 value 从 2 字节扩展到 10 字节：`[0:2]latency_ms [2:10]timestamp`）。

### M9：延迟条目无 TTL

- **文件**：`cache/stats.go:345-355`
- **类别**：badgerdb / resource
- **问题**：`UpdateLatency` 写入 `e:ip:{ip}\x00_lat` 不设 `WithTTL`。延迟条目仅在 `FlushDB("cache")`（`DropPrefix("e:")`）时清理。在长期运行的服务器上，历史上探过的所有 IP 的延迟条目都会永久保留。
- **风险**：对拥有大量唯一 IP 的服务器（CDN 场景），延迟条目可能无限累积，占用 LSM 空间。但实际数据量很小（每 IP 仅 2 字节），所以严重度为 MEDIUM。
- **修复**：添加 `WithTTL(time.Duration(config.DefaultLatencyProbeMinInterval*2) * time.Second)` 或类似 TTL。

### M10：`database.DB` 缺少 `View`/`Update` 包装器

- **文件**：`database/db.go`、所有调用点（22 处 `db.Badger.View/Update`）
- **类别**：code-quality / coupling
- **问题**：所有调用点都重复 `IsClosed()` 检查→`db.Badger.View/Update/DropPrefix` 模式。`DB` struct 的 `Badger` 字段是公开的，调用方直接访问而非通过包装方法。这意味着：
  - `IsClosed` 检查在每个调用点重复
  - 无法在包装层统一添加日志/指标/超时
  - 调用方与 badger 类型紧密耦合（传 `*badger.Txn` 参数）
- **修复**：在 `DB` 上添加包装方法：
```go
func (db *DB) View(fn func(txn *badger.Txn) error) error {
    if db.IsClosed() { return ErrDBClosed }
    return db.Badger.View(fn)
}
// 同理 Update、DropPrefix
```
注意：这需要修改所有调用方，工作量大。可分批迁移。

### M11：`docs/ARCHITECTURE.md` 引用不存在的 `ZoneStorage` 接口

- **文件**：`docs/ARCHITECTURE.md:141`
- **类别**：docs
- **问题**："`ZoneStorage` interface: `Evaluator` depends on `ZoneStorage` (not concrete `*database.DB`)" — 实际代码中 `zone.Evaluator` 直接持有 `*database.DB`。`ZoneStorage` 接口不存在。
- **修复**：更新文档为：`Evaluator` 直接使用 `*database.DB`。

---

## LOW（3 项）

### L1：`zone/zone_test.go:577` 中的 SQL 时代注释

- **文件**：`zone/zone_test.go:577`
- **类别**：comments
- **问题**："The old QueryRow approach only checked one row arbitrarily" — 引用了已删除的 SQLite 实现。
- **修复**：改为 "Only one result row is checked"。

### L2：`database.Open` 的 `maxEntries` 参数位置不当

- **文件**：`database/db.go:32`
- **类别**：api-design
- **问题**：`Open(path, maxEntries, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB)` — `maxEntries` 夹在 `path` 和内存配置参数之间，逻辑上不属于同一组。
- **修复**：与 H1 一起处理——移除 `maxEntries` 参数即可解决。

### L3：异步 WriteBatch 错误被静默丢弃

- **文件**：`cache/async_writer.go:174`
- **类别**：error-handling
- **问题**：`_ = wb.Set([]byte(key), ...)` — `WriteBatch.Set` 的错误被丢弃。虽然 `WriteBatch.Set` 仅在 OOM 时失败（极其罕见），但丢弃错误不符合防御性编程原则。
- **风险**：极低——stats 本就是 best-effort。
- **修复**：保留 `_` 但添加注释：`// _ = error: WriteBatch.Set only fails on OOM; best-effort stats`

---

## BadgerDB 专项审计结论

### ✅ 正确使用的特性
| 特性 | 状态 |
|------|------|
| `WithTTL` 原生过期 | ✅ 正确用于 cache entry + ptr_map |
| `WithMeta` (UserMeta) | ✅ validated flag 正确读写 |
| `IsDeletedOrExpired` | ✅ 遍历时正确过滤僵尸条目 |
| `WriteBatch` 异步写入 | ✅ stats 使用 WriteBatch + 内存预聚合 |
| `Sequence` (bandwidth=1000) | ✅ 合理平衡 crash 容忍与写盘频率 |
| `DropPrefix` | ✅ 仅管理操作使用，不在热路径 |
| 二进制 key 编码 | ✅ BigEndian + offset-based 解析 |
| `NumVersionsToKeep(1)` | ✅ 正确禁用 MVCC |
| `DetectConflicts(false)` | ✅ upsert 模式正确 |

### ⚠️ 可改进的用法
| 问题 | 严重度 |
|------|--------|
| `LatencyLastProbe` 丢弃 View 错误导致逻辑错误 | **CRITICAL** |
| 延迟条目无 TTL | MEDIUM |
| 所有调用点绕过 `DB` 包装层 | MEDIUM |
| 死代码（`ParseStatDayFromKey`、`MaxKey` 等） | MEDIUM |
| 误导性注释（"zstd-compressed"） | MEDIUM |

### ✅ 避免的反模式
- ✅ 无应用层 zstd（信任 BadgerDB block 级压缩）
- ✅ 无手写 TTL 驱逐（使用原生 `WithTTL`）
- ✅ 无 `fmt.Sprintf` 构造 key（使用 BigEndian 二进制编码）
- ✅ value 中无冗余 `expiresAt` 字段
- ✅ 无 `MergeOperator` 使用
- ✅ 无 `DiscardEarlierVersions`（`NumVersionsToKeep(1)` 已全局禁用 MVCC）
- ✅ 无 NUL-scanner 解析二进制字段（使用 offset-based）
- ✅ prefix scan 正确使用 `PrefetchValues=false` 优化
- ✅ `Item.Key()` 使用安全（立即转为 string）

---

## 修复优先级

| Sprint | 项目 | 数量 |
|--------|------|------|
| **Sprint 1** | CRITICAL: C1 | 1 |
| **Sprint 2** | HIGH: H1-H5 | 5 |
| **Sprint 3** | MEDIUM + LOW | 14 |

### Sprint 1 修复顺序：
1. **C1** — `LatencyLastProbe` 逻辑修复（单行改动 + 闭包重构）

### Sprint 2 修复顺序：
1. **H2** — 注释修正（单行改动）
2. **H3** — 删除 `benchmark_test.go` 死文件
3. **H4** — `testStore()` 改为使用 `New()`
4. **H5** — 提取 `queryWildcardForSuffix` 独立函数
5. **H1** — 移除 `maxEntries` 参数链（跨 4 个文件，需仔细处理）

### Sprint 3 修复顺序：
1. **M1-M4** — 删除 4 个死函数
2. **M5** — 修正 zstd 注释
3. **M6** — 删除重复注释行
4. **M7** — 删除 `Zone.Close()` 空方法
5. **L1-L3** — 注释修正

---

## 衡量标准

本次审计：
- 207 个 Go 源文件覆盖
- 22 处 `db.Badger.View/Update` 调用点审查
- 12 处 `lrumap.New` 实例检查（全部正确设置 OnEvict）
- 21 处 `go func()` goroutine 审计
- 3 处 `DropPrefix` 错误处理验证
- 0 处 `%v` 错误包装断裂发现
- 0 处 SQLite 代码残留发现
