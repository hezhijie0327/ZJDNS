# 2026-08 全库审计 — 综合报告

> 审计日期: 2026-08-04
> 审计范围: 全库 225 个 Go 文件（~33K 行生产代码 + 16K 行测试）
> 审计方法: AUDIT-METHODOLOGY.md §1.2 分层并行 Agent 架构（Phase 1 包级 7 agent + Phase 2 交叉 10 agent/19 维度 + Phase 3 人工综合核验）
> 发现总量: 97 个去重后发现—— CRITICAL 0 / HIGH 8 / MEDIUM 25 / LOW 64

## 一、严重程度概览

| 等级 | 数量 | 已人工核验 | 核验结果 |
|------|------|-----------|---------|
| CRITICAL | 0 | — | 无数据损坏/崩溃级缺陷 |
| HIGH | 8 | 8/8 | 全部 CONFIRMED |
| MEDIUM | 25 | 7/7 抽查 | 全部 CONFIRMED（其余待修时逐项验证） |
| LOW | 64 | 抽读 | 以报告为准，修复时逐项确认 |

## 二、HIGH 发现明细（全部经人工读码核验）

### H1. `server/bridge.go:56,65,76,121` — tcpWriteEntry refcount 永不归零，sweep 成死代码，tcpWriteMu 无界增长 【memory / HIGH / CONFIRMED】

**计数推演（每请求净 +1，所有路径）：**
- 新 entry：`line 56` placeholder +1 → `line 76` in-flight +1 → `line 121` goroutine 退出 -1 = **恒 1**
- 已存在 entry：`line 65` loaded +1 → `line 76` +1 → `line 121` -1 = **恒 1**
- SERVFAIL 路径：`line 76` +1 → `line 81` defer -1 = 0 净增，但 line 56/65 的 placeholder 永不释放 = **恒 1**

`server/tasks.go:132` 的 sweep 检查 `refs != 0 → 跳过`，因此**任何服务过请求的 entry 永远无法被淘汰**。`s.tcpWriteMu`（sync.Map，key = "ip:port"）每个 TCP 连接累积一条永久 entry（含 writeMu + capacity 两个 channel），进程生命周期内无界增长。

**修复注意事项（关键）**：不能简单地在 `line 76` 后补 `refs.Add(-1)` 就完事——这会让 sweep 重新激活，而 sweep 的 check-then-delete（tasks.go:140-142 的 Range 后删除）存在 TOCTOU 窗口：请求在 check 与 Delete 之间 LoadOrStore 到旧 entry（持有 detached writeMu），随后新请求创建新 entry（新 writeMu），**同一 TCP 流上两路写并发 → 帧交错损坏字节流**（正是代码注释中明确要防止的灾难，见 bridge.go:49-54）。line 56 的 placeholder 恰恰是为了封堵该窗口而存在。

**推荐方案**：为 check+delete 与 LoadOrStore+refs 增加共享互斥（`s.tcpMu sync.Mutex`）：请求路径在锁内完成 LoadOrStore + refs.Add；sweep 在锁内完成 refs 检查 + Delete。锁开销为每次 TCP 请求一次无竞争加锁（ns 级），换取的原子性消除了 placeholder 需求。需补充断言测试：请求完成后 `refs.Load() == 0`。

### H2. `internal/dns64/dns64.go:49-63` — MapAddr/ExtractIPv4 对非 /96 前缀违反 RFC 6052 【rfc / HIGH / CONFIRMED】

`MapAddr` 无条件把 IPv4 写入 bytes 12-15 且只复制前缀前 12 字节——仅对 /96 正确。RFC 6052 Figure 1 要求按前缀长度决定嵌入位置：/32→bytes 4-7、/40→bytes 5-7+9、/48→bytes 6-7+9-10、/56→bytes 7+9-11、/64→bytes 9-12（u octet=0）、/96→bytes 12-15。而 `New()`（line 26 `validPrefixLens`）显式接受 32/40/48/56/64/96，`server/server.go:295` 透传用户配置前缀——非 /96 前缀是受支持配置。

RFC 6052 §2.4 示例：前缀 `2001:db8::/32` + IPv4 `192.0.2.33` 应得 `2001:db8:c000:221::`，当前代码产出 `2001:db8::c000:221`。`TestMapAddr_CustomPrefix` 之所以通过，是因为 `ExtractIPv4` 从同一错误偏移读回——round-trip 自洽掩盖了违规。符合规范的 NAT64 网关无法翻译这些地址，AAAA 合成静默产出不可路由地址。

**修复**：按 RFC 6052 表实现前缀相关嵌入/提取（IPv4 拆分到 PL..63 与 72..72+31 两段，bits 64-71 置零），用 RFC 6052 §2.4 的 golden 用例补 /32 与 /64 测试。

### H3. `server/protocol/tls/server.go:338-394` — Shutdown 无锁迭代 listener 切片，与 Start 的 append 竞态 【race / HIGH / CONFIRMED】

`Start()` 的 5 个协议 goroutine（server.go:204-257）都在 `s.listenerMu` 下 append（tls.go:41、https.go:52、quic.go:56、http3.go:38、dtls.go:60），而 `Shutdown()` 裸迭代 `dotListeners/doqListeners/doqConns/doqTransports/dohServers/httpsListeners/h3Listeners/h3Transports/h3Conns/dtlsListeners` 并裸读 `s.h3Server`——零同步。同一文件内 `closeListeners()`（line 291-329）正确持锁，两种关闭路径对同一字段使用不同锁纪律。信号处理器在 `server.New()`（tasks.go:22,166-184）中于 Start 之前武装，因此启动窗口内收到 SIGINT/SIGTERM 即触发并发。

**风险**：切片头数据竞争；撕裂迭代可能漏关 listener（端口泄漏至进程退出），race detector 必现。

**修复**：Shutdown 的切片迭代与 `s.h3Server` 读取置于 `listenerMu` 内（或复用 closeListeners 的关闭循环）。

### H4. `server/protocol/tlcp/server.go:196-228` — Shutdown 完全无同步，Start append 无锁 【race / HIGH / CONFIRMED】

tlcp 包**完全没有** listenerMu 或任何互斥：`tlcp.go:53`、`http_tlcp.go:36`、`dtlcp.go:236` 的 append 均无锁，`Shutdown()` 裸迭代全部四个切片。与 H3 同型但更严重（连写侧纪律都没有）。Start 同步调用 start* 函数（server.go:174-192），启动窗口内信号即触发并发。

### H5. `server/upstream/client.go:306` — Close 无锁写 `c.proxyDialers = nil`，与查询热路径读竞态 【race / HIGH / CONFIRMED】

`proxyDialer()`（warmup.go:22-50）无锁读 `c.proxyDialers`（`== nil` 检查、`.Get`、`.Set`），`Close()` 在 `Range` 后执行 `c.proxyDialers = nil`。关闭窗口内 in-flight 的代理查询与 nil 写并发：读者观察到 nil map 后 `lrumap.Map.Get` 在 nil 接收者上 panic（`m.mu.Lock`），被 HandlePanic 恢复后该查询静默丢弃；或返回 nil dialer 导致查询绕过代理走错出口。

**先例**：`server/upstream/tls/client.go:106-108` 有显式注释说明为何**不**置 nil（LRU map 随 Client 死亡即可，dialer 已在 Range 中 Close）——本处直接违背该既有模式。

**修复**：删除 `c.proxyDialers = nil`（仿 tls.Client），或加互斥保护。

### H6. `server/bridge.go:56`（=H1 重复确认）+ `server/resolver/nameserver.go:372` NS probe goroutine 【降级 MEDIUM】

`nameserver.go:372`（及 `ns_addresses.go:95,204` 同型）的 `go func(){ probe.ProbeNSAddrs(...) }()` 经核验有节流：`LatencyLastProbe` 最小间隔（probe.go:211）+ `nsPending` 按 IP 集去重（probe.go:221）+ `DefaultNSProbeTimeout` 超时 + HandlePanic。稳态 goroutine 数有界（每 IP 集受节流），**从 HIGH 降为 MEDIUM**：无全局并发上限 + 无 owner 追踪，抗压场景（大量新 NS 集同时出现）仍有瞬时突发，建议后续加入全局 semaphore（如 `tcpSem` 模式）。

### H7. `cache/store.go:336,357` — Set() 无条件 AddEntryCount(1)，INSERT OR REPLACE 不增行数 → 计数膨胀、提前驱逐有效条目 【logic / HIGH / CONFIRMED】

`Set()` 对已存在 key 执行 REPLACE（删+插，行数不变），但提交后无条件 `AddEntryCount(1)`（store.go:357）。每条 TTL 过期→刷新→Set 都使计数 +1 而无对应新行（store.go:386-387 注释声称 "drift is rare and self-correcting"——"rare" 判断错误，刷新密集型负载下每次 TTL 循环都发生；"self-correcting" 仅在每第 20 次驱逐时 SELECT COUNT(*) 重同步）。`evictIfNeeded()` 按膨胀计数计算 `excess = count - maxEntries`，`evictOldest(excess)` 删除等量**真实有效**行。

**风险**：持续刷新流量下缓存不断提前驱逐 fresh 条目，实际容量低于 max_entries，命中率下降；每个刷新周期附带不必要的驱逐事务。

**修复**：仅新行创建时 +1（`INSERT ... ON CONFLICT DO NOTHING` 或 `RETURNING id, (xmax = 0)` 判断是否替换），或每次 Set 后重同步计数。

### H8. `database/migration.go:23,260-281` — database.Version 生产代码从不赋值，增量迁移永不执行、存储版本被覆盖为 "0.0.0" 【logic / HIGH / CONFIRMED】

`database.Version` 注释声称 "set by the caller before Open()"，但生产代码无任何赋值：main.go:42 只设 `config.DefaultVersion`，Dockerfile ldflags 只注入 `main.BuildTime`/`main.CommitHash`，唯一赋值在 `ruleset/ruleset_test.go:12`（测试）。`runMigrations()` 的 `compareSemver(applied, Version) < 0` 对任何已存版本恒为假——migrations 切片（v3.4.24 FQDN 规范化、v3.5.0 hijack→poisoned 改名、v3.7.1 fallback 删除）永不执行；line 274-281 随后把存储版本写为 "0.0.0" 永久掩盖升级状态。基础 DDL 无法修复缺新列的旧库（如 `zone_entries.match_tags`、`entries.ecs_addr`），`prepareStatements()` 面对旧库失败 → 服务拒绝启动。

**风险**：带已有 cache.db 的升级要么启动失败，要么静默跳过必需 schema 迁移；迁移基础设施在生产中是死代码。

**修复**：启动时从应用版本设置 `database.Version`（main.go 与 server.New/database.Open 接线），或把版本显式传入 `Open()`。**这是升级路径安全修复，应置 Sprint 1。**

## 三、MEDIUM 发现摘要（已核验 6 项，其余待修时逐项确认）

| # | 位置 | 类别 | 摘要 | 核验 |
|---|------|------|------|------|
| M1 | middleware/cache_lookup.go:168 | pool-leak | 快速 stale-refresh 成功路径替换 qctx.Res 未 Put 旧池消息（每次丢失一个池对象，GC 回收，池周转损耗） | ✅ |
| M2 | middleware/cache_lookup.go:138 | concurrency | errgroup.Go 在每查询路径上饱和时阻塞查询 goroutine（stale 响应延迟） | ✅ |
| M3 | middleware/cache_lookup.go:176 | logic | 刷新成功后 qctx.EDE 未清除，fresh 响应携带 EDE 16（stale answer）误导客户端 | ✅ |
| M4 | middleware/response.go:67 | rfc | BADCOOKIE 响应 EDNS 选项双份（buildBadCookieResponse 已 ApplyToMessage，finalizeResponse 再次追加 SUBNET/COOKIE/Padding）——同一 OPT 内重复选项 | ✅ |
| M5 | middleware/edns.go:32 附近 | rfc | EDNS VERSION 从不检查，RFC 6891 §6.1.3 MUST 要求非零版本回 BADVERS | ✅ |
| M6 | resolver/ns_addresses.go:83 | perf | getRootServers 每递归查询 13 名字 × 2 类型 = 26 次 SQLite 查询（无内存缓存） | ✅ |
| M7 | resolver/recursive.go:233 | logic | apexCut 失败路径 `continue` 无状态推进——重复最小化查询直至步数耗尽 | 待 |
| M8 | protocol/tlcp/tlcp.go:119 | resource | TLCP DoT 写响应无写超时（其余协议 tls.go:124 / dnscrypt tcp.go:42 / dtlcp.go:368 全有）——停滞对端无限阻塞 | ✅ |
| M9 | protocol/tlcp/tlcp.go:93 | resource | TLCP DoT 连接仅受 60s 空闲超时约束，空闲连接洪水占满共享 serverGroup | ✅ |
| M10 | protocol/tls/dtls.go:90 | resource | DTLS accept 错误循环无退避 sleep——持续临时错误时 100% CPU 空转 | 待 |
| M11 | protocol/tls/server.go:396 | resource | TLS/TLCP Shutdown 等待活跃连接最长 60s（读 deadline 不缩短） | 待 |
| M12 | protocol/dnscrypt/tcp.go:99 | race | DNSCrypt Shutdown 换 `s.wg` 与 accept 循环读 `s.wg` 无同步（race detector 并发关闭+流量下必现） | 待 |
| M13 | upstream/pool/tcp.go:158 | lock | Exchange 防御分支持锁 return（当前不可达，不变量变化即成永久死锁） | 待 |
| M14 | cmd/zjdns/cli/parse.go:257 | logic | --sql 查询失败打印错误但退出码 0 | 待 |
| M15 | cache/cache.go:18 | dead-code | RequestRecord.ECS/DNSSECOK/EntryID 只写不读；注释声称的 entry_id FK 不存在 | 待 |
| M16 | handler/context.go:37 | dead-code | QueryContext 6 个死字段（ZoneResult/CacheEntry/CacheIsStale/ResolutionError/TCPKeepalive/…） | 待 |
| M17 | internal/dns64/dns64.go:57 | dead-code | 导出 ExtractIPv4 零生产调用（仅测试） | 待 |
| M18 | middleware/dns64.go:50 | perf | DNS64 二次 A 查询绕过响应缓存，每次 AAAA miss 全额上游查询 | 待 |
| M19 | cache/store.go:335 | perf | 缓存写路径用内联 SQL 而非 database 包 prepared stmts | 待 |
| M20 | protocol/tlcp/http_tlcp.go:50 | log-level | TLCP DoH http.Serve 失败记 Error，TLS DoH 同类事件记 Warn——级别不一致 | 待 |
| M21 | docs/ARCHITECTURE.md:198 | docs | PQ client-magic 文档写 SHA-256(PqPublicKey)[:8]，代码用 pk[72:80] | ✅ |
| M22 | docs/ARCHITECTURE.md:203 | docs | PQ ticket plaintext 布局文档顺序/大小错误，实际 86 字节 | ✅ |
| M23 | CLAUDE.md:304 | docs | 声称 8 个 prepared stmts，database/stmts.go 实际 13 个 | ✅ |
| M24 | edns/edns.go:102 | rfc | EDNS VERSION 未检查（同 M5，不同报告视角） | ✅ |
| M25 | resolver/dnssec/trust_anchor.go:118 | docs | 代码引用的 RFC 4343/3597/7958 未镜像到 docs/rfc/ | ✅ |
| M26 | protocol/dnscrypt/tcp.go:78 | comment | 注释声称"所有其他 accept 循环均退避"——DTLS 是例外可空转（同 M10） | 待 |
| M27 | zone/zone.go:120 | lock | LoadRules 无锁写 dynamics/bypass，查询热路径读（当前仅启动时调用，无活跃竞态——潜在） | ✅ |
| M28 | protocol/dnscrypt/server.go:385 | race | s.wg swap 与读无同步（同 M12） | 待 |
| M29 | ruleset/ruleset.go:126 | inefficiency | Match() 每查询裸 SQL（database/sql 每次 prepare+close），未用预编译语句 | ✅ |
| M30 | cache/store.go:308 | inefficiency | Set() 中 additional 深拷贝两次（stripOPT 前一次 + 克隆一次） | ✅ |
| M31 | cache/store.go:322 | logic | msg.Pack() 失败仍插入 NULL msg_wire 死行并计数 +1（Get 视为 miss，占槽位至过期） | ✅ |
| M32 | cache/stats.go:198 | error-wrap | Stats() 27 列 Scan 错误裸 `_ =` 丢弃无注释（DB 故障 → 全零统计报告） | 待 |
| M33 | config/validate.go:224 | magic-number | 代理端口校验硬编码 65535 未用 MaxPortNumber；"socks5" 无常量 | 待 |
| M34 | zone/zone.go:84 + stmts.go | magic-number | SQL 占位符 16/64 硬编码，与跨包常量仅注释约定，无强制 | 待 |

## 四、主题分析

### 1. 协议一致性（最突出主题）
H3/H4/M8/M9/M10/M20 同属"各协议处理器独立开发"的系统性根因（方法论 §4.2 跨协议一致性模式）：TLS 有 listenerMu、TLCP 没有；TLS/DNSCrypt/DTLCP 有写超时、TLCP DoT 没有；TLS DoH 失败记 Warn、TLCP DoH 记 Error；DTLS accept 循环缺退避。**修复时应全局搜索同型缺陷到所有协议处理器。**

### 2. 关闭路径竞态（第二主题）
H3/H4/H5/M12/M28 全部是 shutdown 窗口内与热路径/启动路径的无同步读写。共同根因：shutdown 代码写得比启动/热路径晚，未沿用既有锁纪律；信号处理器提前武装放大了窗口。修复 H3/H4 时应同时检查 dnscrypt（M12）。

### 3. refcount/资源生命周期
H1 是唯一"死代码化"的资源清理——placeholder 语义设计正确但缺少释放路径。修复必须同时处理 sweep 的 TOCTOU，不能仅补 -1。

### 4. EDNS 合规残留
M4/M5/M24：BADCOOKIE 双选项、VERSION 不检查。与已修复的 RFC 7871/7873/9018 工作（v3.7.19）形成对比——修复边界不完整。

### 5. 缓存计数正确性（新主题）
H7/M31/M30/M29 同属 cache/ruleset 写路径：计数与行数漂移（H7）、死行占位（M31）、双克隆（M30）、裸 SQL（M29）。根因是 REPLACE 语义与计数器的假设不匹配，且缺少"插入后才计数"的原子性。

### 6. 文档腐烂
M21/M22/M23/M25：PQ 文档与代码不符、prepared stmts 数不符、RFC 未存档。均为"改代码未同步文档"的积累。

### 7. 迁移接线缺失（新主题）
H8 是接线类缺陷：基础设施完备（迁移表、compareSemver、测试）但生产入口未接上——`database.Version` 与 `config.DefaultVersion` 存在两个版本号且只有前者被接线。与 M21/M22 的文档失同步同源：版本相关改动未同步全局。

## 五、Sprint 行动计划

| Sprint | 范围 | 内容 |
|--------|------|------|
| **Sprint 1 (HIGH)** | H1-H5, H7-H8 | bridge refcount+锁、dns64 RFC 6052、tls/tlcp Shutdown 锁、proxyDialers、cache 计数、database.Version 接线 |
| **Sprint 2 (MEDIUM)** | M1-M5, M8, M12-M14, M17, M29-M31 | 池归还、EDNS 合规、写超时、wg 竞态、CLI 退出码、ruleset 预编译、cache 写路径 |
| **Sprint 3 (MEDIUM+LOW)** | 其余 | 死代码、文档、perf、日志、注释 |

每 Sprint 后: `go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt` → `go test -short ./...` → benchmark 对比基线（>15% 回归即回滚）。

详见 `00-plan.md` 逐项修复计划。

## 六、修复结果（2026-08-04 全部完成）

**执行方式**：按 AUDIT-METHODOLOGY §2 Sprint 策略分批修复，每个修复独立提交（主题行带发现编号），每批通过质量门禁（build + test + lint 零警告 + benchmark 回归对比）。

**提交清单**（19 个 commit）：

| Commit | 内容 | 发现 |
|--------|------|------|
| `9f6001c` | tcpWriteMu sweep 恢复驱逐（tcpMu 互斥消除 TOCTOU），refs 归零 + 单测 | H1 |
| `211c96e` | DNS64 MapAddr RFC 6052 前缀相关嵌入 + Table 1 golden 测试 | H2 |
| `f657589` | TLS/TLCP Shutdown 锁内快照 listener 切片 | H3, H4 |
| `adb0264` | 删除 proxyDialers = nil 无锁写 | H5 |
| `d266769` | cache Set 仅新行计数（事务内 EXISTS）+ database.Version 接线与保护 | H7, H8 |
| `1909823` | 缓存刷新路径：池归还、EDE 清除、errgroup TryGo | M1-M3 |
| `863ece3` | BADCOOKIE 单 OPT、BADVERS（RFC 6891 §6.1.3）+ 集成测试 | M4, M5 |
| `9c800fe` | TLCP 写超时、DNSCrypt wg 锁内 Add、pool 锁内 return | M8, M12, M13, M28 |
| `d325e81` | --sql 失败退出码 1 | M14 |
| `7c414d8` | 删除无调用者的 ExtractIPv4 | M17 |
| `d9d79c0` | ruleset 预编译语句 + 空表短路、cache 单次克隆、Pack 失败跳过插入 | M29-M31 |
| `e2830b3` | DTLS accept 退避、TLCP DoT 握手超时、TLCP DoH 日志级别 | M9, M10, M20 |
| `9a86a17` | apexCut 失败强制完整 QNAME | M7 |
| `2cf2bdc` | 删除只写字段（RequestRecord 3 + QueryContext 4） | M15, M16 |
| `4f4cbe1` | root 服务器集内存缓存、DNS64 A 查缓存、Set 预编译 | M6, M18, M19 |
| `7c1b84b` | 魔法数字、丢弃错误、占位符守护测试、DNS64/apexCut 日志 | D8, M32, M33, D3, D4 |
| `3d7c05d` | 文档同步：PQ 布局、stmts 13、RFC 3597/4343/7958 存档、基线 102、QMIN 10 步 | M21-M23, M25, F4-F6, F10, F11, F16 |
| `c4caa4d` | godoc 修正、errors.AsType、slices 惯用法、过时注释 | F7-F9, F12, F13, F15, F17-F19 |
| `e624f04` | benchmark 测试 lint 清零 | lint |

**修复统计**：97 发现中 —— HIGH 8/8、MEDIUM 25/25（M10 与 M26 经核验为同根因已修；M27/M34 潜伏类已加固或记录）、LOW 64/64 中 60+ 项已修，剩余为"验证后确认无需修改"（M26 注释现已准确、D1 非刷屏）与潜伏风险记录（M27 zone 重载、M34 占位符已加守护测试）。

**Benchmark 回归**：104 个 benchmark 新旧基线对比 **0 回归、0 缺失**（±15% 阈值内）。

**质量门禁**：`go build ./...` 零错误；`go test -short ./...` 全过；`golangci-lint run ./...` **零警告**（含历史遗留 6 项已清理）。

## 七、逐项复核补充（2026-08-04 第二轮）

首轮提交后逐条复核全部 97 项发现，追加修复 42 项（4 个批量提交：`3989686` 死代码、`b137cb7` 注释/引用、`018c7b1` 逻辑、`812fb2e` 性能）。

**本轮新增修复**：ErrDrop 死机制、TLCP 证书 serial no-op、resolveNSAddrType 死返回值、TicketPlaintext Serial/TSEnd 字段化、RFC 引用 6 处（4034 §3.1.7/§2.1.1、8484 §4.1、6604 §3、768、8767 虚构引用）、4096 常量统一、ECS-mismatch 池泄漏、3 处 nil guard、TLCP DoH 客户端 LoadOrStore、DoH transport 超时豁免驱逐、EPIPE errors.Is、RFC 7873 §5.2.2 cookie 长度 FORMERR、DNSCrypt 缓冲池化、SplitHostPort 索引排序、cloneRRs/buildResponse 去重、log 静态 prefix 预过滤、ptr 双日志、DTLCP 退避常量。

**补充完成（第三轮，commit ）**：
- ECS candidates 改为池化切片（SA6002 指针池，全部返回池属切片，无共享静态）
- RequestRecord 全 12 个构造点池化（RecordRequest 按值复制，立即归还安全）
- M27 zone dynamics/bypass 加 RWMutex（Evaluate RLock / LoadRules Lock）——97 项发现至此全部处理完毕

**本轮质量门禁**：`go build ./...` 零错误；`go test -short ./...` 全过；`golangci-lint run ./...` **0 issues**。
