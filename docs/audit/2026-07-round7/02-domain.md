# Domain 层审计报告 (Phase 1)

审计范围: `config/`, `database/`, `cache/`, `edns/`, `zone/`, `ruleset/` (23 个源文件, 6 个包)
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 3 | sync.Pool 双重归还、zone 文件解析器 panic (×2) |
| HIGH | 2 | Flush/Close 竞态、cookie MAC ipLen 不匹配 |
| MEDIUM | 14 | 性能、耦合、SQL 模式、context 缺失、接口设计 |
| LOW | 12 | 边界情况、文档、微优化 |

**共 31 个发现** (3 CRITICAL, 2 HIGH, 14 MEDIUM, 12 LOW)

## CRITICAL

### C1: cache/store.go — sync.Pool 双重归还 (msg Unpack error 路径)

- **文件**: `cache/store.go:152-157`
- **类别**: `memory`
- **描述**: `SQLiteCache.Get()` 中, msg.Unpack() 失败时 (line 152), error 路径先调用 `pool.DefaultMessage.Put(msg)` (line 153), 然后 defer 注册的 `pool.DefaultMessage.Put(msg)` (line 157) 再次 Put 同一个 msg 指针。Pool 持有同一 `*dns.Msg` 的两个引用, 两次并发 Get() 可获取同一个对象, 导致 data race。
- **风险**: Data race, 并发修改共享 dns.Msg, 崩溃或损坏 DNS 响应。
- **修复**: 删除 line 153 的显式 Put, 仅用 defer 处理。

### C2: zone/parse.go — 裸 "." 或 "*." domain header 导致 panic

- **文件**: `zone/parse.go:96`
- **类别**: `panic`
- **描述**: 当 zone 文件行以 "." (裸 root) 或 "*." (裸 wildcard 前缀) 开头, curRawName 变为 "", `strings.Fields("")` 返回空切片, Line 96 访问 `fields[0]` 导致 runtime panic: "index out of range [0] with length 0"。
- **风险**: 畸形/恶意 zone 文件导致服务器在规则加载时崩溃 (DoS)。
- **修复**: 访问前添加 `if len(fields) == 0 { continue }`。

### C3: zone/parse.go — 单字符 "." domain header panic

- **文件**: `zone/parse.go:84-96`
- **类别**: `panic`
- **描述**: `line[0] == '.'` 检查无长度守卫, 单个 "." 字符触发 domain header 路径, 设置 `curRawName = line[1:] = ""`, 同理 fields[0] panic。
- **风险**: 同 C2, 通过构造 zone 文件实现 DoS。
- **修复**: 添加 `len(line) > 1` 条件。

## HIGH

### H1: cache/async_writer.go — Flush() 与 Close() 竞态导致永久阻塞

- **文件**: `cache/async_writer.go:101-112`
- **类别**: `goroutine`
- **描述**: `Flush()` 使用 unbuffered flushSig channel。如果 `Close()` 并发调用, 它关闭 `w.ch` (通过 closeOnce) 导致后台 goroutine 立即退出。`Flush()` 然后发送到 flushSig, 但 goroutine 已退出无人读取, 发送永久阻塞。
- **风险**: 并发 Flush+Close 时 hang, 阻塞清理或 shutdown。
- **修复**: 使用 buffered flushSig channel (capacity 1)。

### H2: edns/cookie.go — clientIP nil 时 ipLen 不匹配

- **文件**: `edns/cookie.go:221-231`
- **类别**: `panic`
- **描述**: `rfc9018MAC()` 中 clientIP 为 nil 时, To4()/To16() 都返回 nil, ipLen 保持 16 (默认值), 但 ip 只有 4 字节。hash 包含 12 字节零值, 产生的 MAC 无法匹配任何有效客户端。
- **风险**: nil clientIP 的 cookie 验证静默失败。
- **修复**: 设置 `ipLen = 4` 或 `ipLen = len(ip)`。

## MEDIUM (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| M1 | `config/validate.go:139` | validProtocols map 每次调用创建 — 应为 package-level var |
| M2 | `database/stmts.go:57,70` | prepared statement placeholder 数量与常量硬耦合 |
| M3 | `database/migration.go:398` | pragma 函数参数化表名 — 某些 SQLite 驱动不支持 |
| M4 | `cache/stats.go:219-221` | DNSSEC 常量拼接到 SQL — 潜在注入风险 |
| M5 | `cache/store.go:577-597` | ECS /0 fallback 产生 "0.0.0.0" 而非 "" — 缓存未命中 |
| M6 | `zone/zone.go:55-61` | ZoneStorage 接口包含 Close() — 生命周期耦合 |
| M7 | `zone/wire.go:98-100` | dns.New() 失败静默忽略 — 无声数据损坏 |
| M8 | `database/db.go:166-180` | SQL* 方法无 context — shutdown 时可能 hang |
| M9 | `zone/parse.go:195-225` | tokenize 不处理转义引号 |
| M10 | `zone/parse.go:196` | token slice 无预分配 capacity |
| M11 | `config/load.go:20,26` | ReadFile + Stat 双重 syscall |
| M12 | `config/validate.go:490-500` | validate* 函数有副作用 — 修改输入 |
| M13 | `config/validate.go:107-108` | log level 验证硬编码字符串 |
| M14 | `zone/parse.go:29-31` | zone 文件无大小限制 |

## LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `ruleset/ruleset.go:200-204` | 无效 CIDR 静默跳过 |
| L2 | `config/config.go:202-207` | ProviderName 不验证 domain |
| L3 | `ruleset/ruleset.go:250-263` | tldPlusOne 不处理多段 TLD |
| L4 | `ruleset/iptrie.go:88-89` | IP trie match 结果可能重复 tag |
| L5 | `cache/ptr.go:58-60` | insertPtrMap error 仅记录不传播 |
| L6 | `zone/wire.go:26-29` | Msg.Pack() error 静默丢弃 |
| L7 | `database/migration.go:52-82` | compareSemver 不处理 pre-release 后缀 |
| L8 | `cache/store.go:393-400` | entryCount 在高 REPLACE 率下漂移 |
| L9 | `config/config.go:92` | DNS64 Config 指针未验证 nil |
| L10 | `cache/store.go:411` | PRAGMA optimize 在事务外调用 |
| L11-L12 | — | 其他次要边界情况 |
