# 02 · Domain 包审计

**包范围**：`config`、`database`、`cache`、`edns`、`zone`、`ruleset`

**审计日期**：2026-07-29
**审计重点**：BadgerDB 使用正确性、SQLite 残留、死代码、key 编码

---

## 审计摘要

Domain 层是本次审计的重点——SQLite→BadgerDB 迁移的核心区域。迁移非常彻底（零 SQL 代码残留），但发现了 1 个 CRITICAL 逻辑错误和多个死代码/注释问题。

**发现总数**：1 CRITICAL + 3 HIGH + 8 MEDIUM + 2 LOW

---

## CRITICAL（1 项）

### C-D1：`LatencyLastProbe` 总是返回 true

- **文件**：`cache/stats.go:358-368` → 已修复
- **根因**：View 闭包返回的 `ErrKeyNotFound` 被 `_` 丢弃
- **影响**：延迟探测系统被绕过，新 IP 不被探测

---

## HIGH（3 项）

### H-D1：`database.Open` 的 `maxEntries` 死参数

- **文件**：`database/db.go`、`config/config.go:124`、`server/server.go:137`
- **状态**：✅ 已修复——参数已从签名中移除
- **说明**：`Open()` 接受但忽略 `maxEntries`。`Config.CacheConfig.MaxEntries` 配置项和 `DefaultMaxCacheEntries=10000` 常量均无效果。

### H-D2：SQL 时代残留注释

- **文件**：`zone/parse.go:28`、`cmd/zjdns/cli/parse.go:57`
- **状态**：✅ 已修复

### H-D3：`cache/benchmark_test.go` 死文件

- **文件**：`cache/benchmark_test.go`
- **状态**：✅ 已删除

---

## MEDIUM（8 项）

### M-D1-M4：`database/keys.go` 中 4 个死函数

- **状态**：✅ 已删除——`ParseStatDay`、`ParseStatDayFromKey`、`StatsKeyDayCutoff`、`MaxKey`

### M-D5：误导性 "zstd-compressed" 注释

- **文件**：`cache/store.go:217`、`zone/wire.go:14`
- **状态**：✅ 已修正——注释现在正确描述为 raw DNS wire format

### M-D6：`EntryKeyPrefix()` 重复 godoc

- **状态**：✅ 已修复

### M-D7：`Zone.Close()` 空操作

- **文件**：`zone/zone.go:80`
- **状态**：✅ 已删除

### M-D8：延迟条目无 TTL

- **文件**：`cache/stats.go:345-355`
- **状态**：✅ 已修复——添加了 `WithTTL`（2× probe interval）

---

## LOW（2 项）

### L-D1：`testStore()` 绕过构造函数——测试/生产路径分歧

- **文件**：`cache/cache_test.go:16-22`
- **状态**：✅ 已修复——`testStore()` 现在调用 `New(db)`

### L-D2：`zone/zone_test.go:577` SQL 时代测试注释

- **状态**：保留——描述测试行为背景，不影响功能

---

## BadgerDB 存储层专项分析

### Key 编码审计

全部 5 种 key 前缀的编码格式已验证，符合 BigEndian + offset-based 解析规范：

| Key 前缀 | 编码方式 | Round-trip 测试 |
|----------|----------|-----------------|
| `e:` | `{qname}\x00{ecsAddr}\x00{ecsPrefix:2B}\x00{dnssec:1B}\x00{qtype:2B}\x00{qclass:2B}` | ✅ |
| `e:ip:` | `{ip}\x00{entryID:8B}\x00{name}` / `{ip}\x00_lat` | ✅ |
| `s:` | `{statDay:8B}\x00{result}\x00{protocol}\x00{rcode:2B}\x00{dnssec}\x00{poisoned}` | ✅ |
| `z:` | `{isWildcard:1B}\x00{qname}\x00{qtype:2B}\x00{qclass:2B}\x00{matchTags}` | ✅ |
| `r:` | `{type}\x00{value}\x00{tag}` | ✅ |

### Value 编码审计

全部 value 编码/解码对验证通过，round-trip 测试覆盖完整。

### Transaction 使用审计

| 操作 | 事务类型 | 正确性 |
|------|----------|--------|
| `Get()` | `db.Badger.View` (只读) | ✅ |
| `Set()` | `db.Badger.Update` (读写) | ✅ |
| `Stats()` | `db.Badger.View` (只读) | ✅ |
| `RecordRequest()` async | `WriteBatch` (异步) | ✅ |
| `RecordRequest()` sync | `db.Badger.Update` (读写) | ✅ |
| `ReverseLookup()` | `db.Badger.View` (只读) | ✅ |
| `UpdateLatency()` | `db.Badger.Update` (读写) | ✅ |
| `FlushDB()` | `db.Badger.DropPrefix` (管理) | ✅ |
| `LoadRules()` zone | `db.Badger.Update` + `DropPrefix` | ✅ |
| `LoadRules()` ruleset | `db.Badger.Update` + `DropPrefix` | ✅ |

### 已知反模式检查

| 反模式 | 状态 |
|--------|------|
| 应用层 zstd + BadgerDB zstd 双重压缩 | ✅ 未发现 |
| 手写 TTL 驱逐替代 `WithTTL` | ✅ 未发现 |
| value 中存冗余 `expiresAt` | ✅ 未发现 |
| `fmt.Sprintf` 构造 key | ✅ 未发现 |
| NUL 分隔符解析二进制字段 | ✅ 正确使用 offset-based |
| `NumVersionsToKeep(1)` + `DiscardEarlierVersions` | ✅ 未冗余使用 |
| `Item.Key()` 跨迭代 | ✅ 全部转为 string |
| `Entry.WithDiscard()` vs `txn.Delete` | ✅ 仅用 `DropPrefix` 做批量清理 |
