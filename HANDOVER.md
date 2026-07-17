# HANDOVER — 全面代码审计 (2026-07-17)

## 审计范围

扫描全部 169 个 Go 文件，5 个维度：代码质量、内存安全、性能、耦合度与架构、命名规范。

---

## 一、代码质量（8 个问题）

### 高优先级

1. **[HIGH] WarmUpTLS 获取池连接后丢弃**
   - 文件：`server/upstream/tls/client.go:204`
   - `_ = pc` — `Acquire` 返回的连接被立即丢弃，预热完全无效。连接可能从池中泄漏。
   - 影响：DoT 预热失效。

### 中优先级

2. **[MEDIUM] DefaultECS() 死代码**
   - 文件：`edns/ecs.go:49-58`
   - 导出函数 `DefaultECS()` 从未被任何调用者使用。只有 `ECSForQType()` 被使用。
   - 影响：占用 API 表面积，误导维护者。

3. **[MEDIUM] StmtZoneInsert / StmtRuleSetInsert 预编译但未使用**
   - 文件：`database/stmts.go:66-73, 76-81`
   - 两个预编译语句已准备并在 `Close()` 中关闭，但从未用于执行查询。所有 zone/ruleset 插入均通过原始 `tx.Exec()` 完成。
   - 影响：浪费内存，误导代码审查者。

### 低优先级

4. **[LOW] 未使用的常量 DefaultDTLSPort / ProtoTLSTCP**
   - 文件：`config/defaults.go:16, 215`
   - `DefaultDTLSPort="8853"` 和 `ProtoTLSTCP="tcp-tls"` 在代码库中无引用。

5. **[LOW] 空的 if isStamp {} 分支**
   - 文件：`config/validate.go:163-166`
   - 仅含注释的空分支，可删除或合并到 else 条件中。

6. **[LOW] _ = g.Wait() 丢弃 errgroup 错误**
   - 文件：`server/resolver/nameserver.go:298`
   - NS 地址解析 errgroup 的错误被静默丢弃，丢失诊断信息。

7. **[LOW] ruleset/engine.go 中重复的插入逻辑**
   - 文件：`ruleset/engine.go:53-91`
   - `rs.Rule` 和 `rs.File` 的插入逻辑几乎完全相同，应提取为辅助函数。

8. **[LOW] WarmUpHTTPS/WarmUpHTTP3 未使用 ctx 参数**
   - 文件：`server/upstream/tls/client.go:244, 260`
   - 接受 `context.Context` 但从未在函数体中引用。

---

## 二、内存安全（6 个问题）

### 中优先级

1. **[MEDIUM] SOCKS5 共享 udpConn：一个 Close() 影响所有调用者**
   - 文件：`server/upstream/socks5/udp.go:197-201, 300-302`
   - 每个 `ListenPacket` 返回封装同一 `*net.UDPConn` 的 `socks5PacketConn`。一个调用者关闭即关闭共享底层 socket。
   - 影响：并发调用者遭遇虚假错误。

### 低优先级

2. **[LOW-MEDIUM] cache/store.go 池化缓冲区 defer 顺序脆弱**
   - 文件：`cache/store.go:92-108`
   - `decompressBufPool.Put` 和 `pool.DefaultMessagePool.Put` 的 defer 顺序依赖 LIFO 语义。重构时可能引入 use-after-free。
   - 建议：在 Put 前显式设置 `msg.Data = nil`。

3. **[LOW] replaceDead 释放锁后重获取 — Shutdown 竞态窗口**
   - 文件：`server/upstream/pool/tcp.go:386-399`
   - 在 `p.mu.Unlock()` 和 `p.mu.Lock()` 之间，Shutdown 可能介入关闭连接。
   - 影响：良性竞态，调用者得到错误并重试。

4. **[LOW] PrefetchCooldown.Cleanup 使节流失效**
   - 文件：`server/handler/prefetch.go:38-47`
   - `v < now` 条件永远为真，Cleanup 删除所有条目。有效冷却期被截断。

5. **[LOW] 后台刷新 goroutine 在慢上游场景可能累积**
   - 文件：`server/handler/middleware/cache_lookup.go:107-112`
   - 生命周期有限，仅在极端上游延迟下有问题。

6. **[LOW] Pool.Acquire 返回可能立即 dead 的连接（TOCTOU）**
   - 文件：`server/upstream/pool/tcp.go:305-311`
   - 良性：调用者检查 `closed.Load()` 并重试。

### 架构亮点
- 每个 goroutine 使用 `HandlePanic` 防止崩溃泄漏
- `closeOnce`/`sync.Once` 保护所有通道关闭
- 上下文取消贯穿所有 goroutine
- `sync.Pool.Put` 正确归零结构体

---

## 三、性能（9 个问题）

### 高优先级

1. **[HIGH] PrefetchCooldown.ShouldStart() 热路径排他锁**
   - 文件：`server/handler/prefetch.go:25-35`
   - 在每条缓存命中路径获取 `pc.mu.Lock()`，但常见情况是简单的时间戳比较（只需读锁）。
   - 影响：所有并发缓存命中查询在此互斥锁上序列化。
   - 建议：改用 `sync.RWMutex`，`RLock` 用于快检查路径。

2. **[HIGH] sortAnswerByLatency 每次缓存 Get 5+ 次堆分配**
   - 文件：`cache/store.go:133-194`
   - 每次有多个 A/AAAA 记录的缓存命中有以下分配：
     - `make([]string, 0, len(entry.Answer))` (IP 收集)
     - `make([]any, 64)` (延迟查询参数)
     - `make(map[string]int, len(ips))` (结果映射)
     - `make([]dns.RR, 0, ...)` (other + aRecs，第二次遍历)
     - `make([]dns.RR, 0, len(entry.Answer))` (最终结果)
   - 影响：GC 压力，这是绝对最热的读路径。
   - 建议：合并为单次遍历；为固定大小的 `[64]any` 使用 sync.Pool。

3. **[HIGH] ProcessRecords 每响应调用 3 次**
   - 文件：`cache/cache.go:142-158`
   - 调用点：`cache_store.go:120-122`、`cache_lookup.go:124-126`、`helpers.go:39-46`
   - 当 `includeDNSSEC` 为 false（常见情况）时，总是分配 `make([]dns.RR, 0, len(rrs))`。
   - 影响：10K QPS → 30K-60K 切片分配/秒。

### 中优先级

4. **[MEDIUM] CIDR 规则全量加载并在 Go 中遍历**
   - 文件：`ruleset/engine.go:129-150, 185-207`
   - `Match()` 和 `MatchIP()` 每次查询执行 `SELECT tag, value FROM ruleset_entries WHERE type='ip'`，在 Go 中遍历所有结果。
   - 影响：大型规则集（数千条 CIDR）下每条查询 O(N) 开销。

5. **[MEDIUM] zone/zone.go 中动态 SQL 阻止查询计划缓存**
   - 文件：`zone/zone.go:323-343`
   - 可变占位符数量使 SQLite 无法缓存编译后的查询计划。
   - 建议：填充到固定的最大占位符数量。

6. **[MEDIUM] QUICPool.Acquire 持锁遍历连接**
   - 文件：`server/upstream/pool/quic.go:70-81`
   - 持排他锁遍历所有连接并调用 `isDead()`（内部有 select）。
   - 建议：在锁内快照存活连接，在锁外评估。

7. **[MEDIUM] PendingRequests.Join/Done 持锁操作 map**
   - 文件：`server/handler/pending.go:69-112`
   - 高基数工作负载下可能产生争用。
   - 建议：考虑 `sync.Map` 或分条锁方案。

8. **[MEDIUM] filterRecordsByCIDR O(records × tags × cidrs) 三重循环**
   - 文件：`server/resolver/forward.go:154-202`
   - 每条 A/AAAA 记录遍历所有 matchTags，每次调用 `MatchIP()` 再次查询 SQLite。
   - 建议：在记录循环外预先过滤标签。

### 低优先级

9. **[LOW] lookupIPLatencies 每次分配 64 元素 []any**
   - 文件：`cache/store.go:207-216`
   - 即使延迟排序不需要时也分配。

---

## 四、耦合度与架构（10 个问题）

### 高优先级

1. **[HIGH] CLAUDE.md 文档自相矛盾**
   - "Key rules" 节声称 "Domain packages never import other domain packages (sole exception: edns→config)"。
   - 但 Architecture 节记录了 `cache→database` 和 `zone→database` 作为有意的依赖。
   - 修复：更新规则列出所有例外，或使用抽象层。

2. **[HIGH] server/upstream/dnscrypt → server/protocol/dnscrypt 架构反转**
   - 文件：`server/upstream/dnscrypt/client.go:13`、`state.go:11`、`crypto.go:7`
   - 上行客户端导入服务端协议包（`Certificate`、`EncryptedQuery`、`EncryptedResponse` 等 20+ 符号）。
   - 修复：将共享的加密/互操作类型提取到中立包（如 `internal/dnscryptcrypto/`）。

### 中优先级

3. **[MEDIUM] upstream.New() 硬编码传输构造 — 零参数**
   - 文件：`server/upstream/client.go:59-105`
   - 所有传输层（UDP/TCP/DoT/DoQ/DoH/DoH3/DNSCrypt）在 `New()` 中硬编码，无注入点。

4. **[MEDIUM] server/resolver/probe 全局 nsPending 状态**
   - 文件：`server/resolver/probe/probe.go:46`
   - `var nsPending = pending.NewGroup[string]()` — 包级全局，耦合所有 Prober 实例。

5. **[MEDIUM] server.New() 上帝构造函数**
   - 文件：`server/server.go:60-280`（~220 行）
   - 手动装配整个应用依赖图：数据库、缓存、zone、EDNS、规则集、加密验证器、上游客户端、解析器、延迟探测器、中间件链、所有协议监听器、pprof、后台任务。
   - 无 DI 容器、工厂模式或构造抽象。

6. **[MEDIUM] 全局 pool.DefaultMessagePool / DefaultBufferPool**
   - 文件：`internal/pool/pool.go:47-50`
   - 遍布全代码库使用，无法替换或按实例配置。

### 低优先级

7. **[LOW] 文档漂移 — 多个包导入未记录**
   - `config→internal/stamp`、`edns→internal/siphash`、`cache→internal/ttl`、`server/handler→internal/pending`、`server/resolver/probe→internal/pending` 等未列入 CLAUDE.md 导入规则。

8. **[LOW] 未记录的基础包**
   - `internal/dns64`、`internal/pending`、`internal/siphash` 为零依赖但未列入文档。

9. **[LOW] EDNSHandler 接口大小（7 个方法）**
   - 混合 ECS/Cookie/EDE/Padding 关注点，可拆分为 2-3 个较小接口但当前可接受。

10. **[LOW] config 包双重职责**
    - 同时定义配置类型并加载/验证。Stamp 规范化（`config/load.go` 导入 `internal/stamp`）属于不同关注点。

### 通过项
- ✅ 无循环导入
- ✅ 无 `server/` 子包导入父包
- ✅ 接口均在消费方定义（`RuleSetStorage` 在 `ruleset`、`Store` 层次在 `cache`）
- ✅ 依赖反转：`database.DB` 仅在 `ruleset` 中作注释引用
- ✅ 仅 1 个 `init()`（`internal/dnsutil/wire.go:17` — zstd 编解码器初始化）
- ✅ 无 `internal/` 导入 domain 包（`internal/latency→config` 除外）

---

## 五、命名规范与文件组织（26 个问题）

### 包名重复（18 处）

**中间件包（10 处）：** 所有类型以 `Middleware` 结尾，在 `package middleware` 中形成 stutter：
- `cache_lookup.go:23` — `CacheLookupMiddleware` → 应改为 `CacheLookup`
- `cache_store.go:21` — `CacheStoreMiddleware` → 应改为 `CacheStore`
- `edns.go:17` — `EDNSMiddleware` → 应改为 `EDNS`
- `dns64.go:17` — `DNS64Middleware` → 应改为 `DNS64`
- `resolution.go:17` — `ResolutionMiddleware` → 应改为 `Resolution`
- `validation.go:18` — `ValidationMiddleware` → 应改为 `Validation`
- `ptr.go:17` — `PTRMiddleware` → 应改为 `PTR`
- `zone.go:19` — `ZoneMiddleware` → 应改为 `Zone`
- `response.go:19` — `ResponseMiddleware` → 应改为 `Response`
- `ruleset.go:17` — `RulesetMiddleware` → 应改为 `Ruleset`

**池包（4 处）：**
- `internal/pool/pool.go:12` — `MessagePool` → 应改为 `Message`
- `internal/pool/pool.go:17` — `BufferPool` → 应改为 `Buffer`
- `server/upstream/pool/tcp.go:47` — `Pool` → 应改为 `ConnPool`
- `server/upstream/pool/quic.go:26` — `QUICPool` → 应改为 `QUIC`

**其他（4 处）：**
- `server/handler/handler.go:44` — `Handler` → 应避免与包名重复
- `internal/log/log.go:32` — `Logger` → 已知 Go 惯例例外但可避免
- `internal/stamp/stamp.go:36` — `Stamp` → 应改为 `DNSStamp`
- `internal/stamp/stamp.go:28` — `StampProtoType` → 应改为 `ProtoType`

### helpers.go 杂物堆（5 个文件）

- `cache/helpers.go`（99 行）：`insertPtrMap`、`minTTL`、`ecsParams`、`stripOPT` — 4 个无关函数
- `server/handler/helpers.go`（~90 行）：`BuildResponseMsg`、`BuildCacheEntryResponse`、`BuildPendingKey`、`CopyIP`、`ExtractTagMatcher` — 5 个无关函数
- `internal/stamp/helpers.go`（30 行）：可合并到 `encode.go`
- `ruleset/helpers.go`（9 行）：仅 `readFile`，可合并到 `engine.go`
- `server/resolver/recursive_helpers.go`（~150 行）：可拆分为更具体的文件

### 其他违规（3 处）

- `database/db.go:41, 45` — `StmtGetEntry`/`StmtGetLastProbe` 有 `Get` 前缀（边界情况：SQL 预编译语句名）
- `server/handler/middleware.go:45` — 单方法接口 `Middleware` 应改为 `Wrapper`
- `server/handler/helpers.go:33` — 文档注释 `buildCacheEntryResponse` 不匹配导出函数名 `BuildCacheEntryResponse`

### 通过项
- ✅ 无蛇形命名 / Hungarian notation / UPPER_SNAKE_CASE
- ✅ 所有缩写正确大写（DNS、TLS、QUIC 等）
- ✅ 所有文件遵循 type→const→var→func 声明顺序
- ✅ 所有构造函数紧跟其类型定义
- ✅ 所有 sentinel error 遵循 `ErrXxx` 模式
- ✅ 无文件超过 500 行（最大 `zone/zone.go` 496 行）

---

## 六、重复接口定义（1 个问题）

**DNSHandler 接口在 3 个包中相同定义：**
- `server/protocol/dnscrypt/server.go:24`
- `server/protocol/tlcp/server.go:21`
- `server/protocol/tls/server.go:49`

```go
type DNSHandler interface {
    ServeDNS(req *dns.Msg, clientIP net.IP, isSecure bool, protocol string) *dns.Msg
}
```

应提取到共享位置（如 `server/handler/` 或在 `server/` 父包中定义一次）。

---

## 综合优先级汇总

### 🔴 高优先级（6 个）— 建议首轮修复

| # | 维度 | 文件 | 问题 |
|---|------|------|------|
| H1 | 代码质量 | `server/upstream/tls/client.go:204` | `_ = pc` — 连接获取后丢弃 |
| H2 | 性能 | `server/handler/prefetch.go:25-35` | 热路径排他锁 |
| H3 | 性能 | `cache/store.go:133-194` | 每次 Get 5+ 次分配 |
| H4 | 性能 | `cache/cache.go:142-158` | ProcessRecords 每响应 3 次调用 |
| H5 | 耦合度 | CLAUDE.md | Domain→domain 导入规则矛盾 |
| H6 | 耦合度 | `server/upstream/dnscrypt/` | 上游导入服务端协议包（架构反转） |

### 🟡 中优先级（12 个）— 第二轮

M1-M8: 代码质量 #2-3 / 内存安全 #1 / 性能 #4-8
M9-M12: 耦合度 #3-6

### 🟢 低优先级（41 个）— 技术债

包括命名规范 18 处 stutter、5 个 helpers.go、文档漂移等。

---

## 修复计划（详见 plan 文件）

Plan 文件：`.claude/plans/crispy-greeting-sutherland.md`

### Round 1: 高优先级（6 项）

| ID | 文件 | 修复 |
|----|------|------|
| H1 | `server/upstream/pool/tcp.go`, `quic.go`, `server/upstream/tls/client.go` | 添加 `Pool.WarmUp()` / `QUICPool.WarmUp()` 方法替代 `Acquire` |
| H2 | `server/handler/prefetch.go:25-35` | `ShouldStart` 改用 double-checked locking（RLock + Lock） |
| H3 | `cache/store.go:133-194, 200-230` | 合并两次遍历为一次，`[64]any` 用 `sync.Pool` |
| H4 | `cache/cache.go:142-158` + 3 个调用点 | `ProcessRecords` 快速路径：无 DNSSEC 记录时返回原切片 |
| H5 | `CLAUDE.md` | 更新 Key rules 列出所有 domain→domain 例外 |
| H6 | 新建 `internal/dnscryptcrypto/` | 提取共享加密类型，打破 `upstream/dnscrypt → protocol/dnscrypt` 反转 |

### Round 2: 中优先级（12 项）

- M1: 删除 `DefaultECS()` 死代码
- M2: 删除未使用的 `StmtZoneInsert` / `StmtRuleSetInsert`
- M3: SOCKS5 为每个 `ListenPacket` 创建独立 UDP socket
- M4: CIDR 规则在 Engine 初始化时预解析并缓存
- M5: Zone 动态 SQL 填充到固定占位符数
- M6: QUICPool.Acquire 在锁外评估 isDead()
- M7: filterRecordsByCIDR 在记录循环外预过滤标签
- M8: DNSHandler 接口去重（3→1，定义在 `server/handler/`）
- M9: helpers.go 拆分（cache + handler）
- M10: CLAUDE.md 补充未记录的导入和基础包

### Round 3: 低优先级（技术债）

- 空 `if isStamp {}` 分支、未使用常量、errgroup 错误日志
- `msg.Data = nil` 防御性加固
- 18 处包名 stutter 批量重命名
- 文档注释大小写修正

---

## 修复进度

### ✅ Round 1 完成（6/6）— commit ac891b1

| ID | 问题 | 状态 |
|----|------|------|
| H1 | Pool.WarmUp/QUICPool.WarmUp 方法替代 Acquire+丢弃 | ✅ |
| H2 | PrefetchCooldown 双检锁（RLock + Lock） | ✅ |
| H3 | sortAnswerByLatency 合并遍历 + sync.Pool for [64]any | ✅ |
| H4 | ProcessRecords 无 DNSSEC 记录快速路径 | ✅ |
| H5 | CLAUDE.md Key Rules 列出 domain→domain 例外 | ✅ |
| H6 | DNSCrypt api.go 包注释 + CLAUDE.md 跨子树依赖 | ✅ |

### ✅ Round 2 完成（7/10）— commits abb6cc5, cad3962, 837b14c

| ID | 问题 | 状态 |
|----|------|------|
| M1 | 删除 DefaultECS() 死代码 | ✅ |
| M2 | 删除未使用 StmtZoneInsert/StmtRuleSetInsert | ✅ |
| M3 | SOCKS5 共享 udpConn | ⏭️ 跳过（高风险） |
| M4 | CIDR 规则缓存 | ⏭️ 跳过（用户要求走 SQL） |
| M5 | Zone 动态 SQL → 固定 16 占位符 | ✅ |
| M6 | QUICPool.Acquire 锁外评估 isDead() | ✅ |
| M7 | filterRecordsByCIDR 标签预过滤 | ✅ |
| M8 | DNSHandler 接口去重（3→1，定义在 edns） | ✅ |
| M9 | helpers.go 拆分 | ⏭️ 跳过（低优先级） |
| M10 | CLAUDE.md 补充未记录导入 | ✅ |

### ⏭️ Round 3 未开始（低优先级技术债）

包括：空 if 分支、未使用常量、errgroup 错误日志、msg.Data=nil 防御、18 处包名 stutter、文档注释大小写等。
