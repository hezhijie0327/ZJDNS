# domain — 包级审计报告（config / database / cache / edns / zone / ruleset）

> 审计日期: 2026-08-04 | 审计范围: config(7 文件), database(5), cache(5), edns(4), zone(3), ruleset(2) 共 26 个非测试文件全量精读
> 发现数量: 8（2 HIGH / 2 MEDIUM / 4 LOW）——其中 D4 与综合报告 M27 重复（Phase 2 交叉分析已报告）

### D1 [HIGH] logic — Set() 无条件 AddEntryCount(1)，REPLACE 不增行数 → 计数膨胀、提前驱逐有效条目
- **文件**: cache/store.go:336,357
- **问题**: `Set()` 执行 `INSERT OR REPLACE INTO entries (...)`（line 336）后无条件 `s.db.AddEntryCount(1)`（line 357）。SQLite REPLACE 对已存在 key 是删除+插入——行数不变。每条 TTL 过期后的刷新/重解析（serve-stale 刷新流程、正常 TTL 循环）都会使原子计数 +1 而无对应新行。`evictIfNeeded()`（store.go:380-414）在 `count >= max*9/10` 时按膨胀后的 `excess = count - maxEntries` 调用 `evictOldest(excess)` 删除等量**真实**行。store.go:386-387 注释声称 "INSERT OR REPLACE drift ... is rare and self-correcting"——"rare" 判断错误（刷新密集型负载下每次 TTL 循环都发生），"self-correcting" 仅在每第 20 次驱逐时 SELECT COUNT(*) 重同步（line 397-401）。
- **风险**: 持续刷新流量下缓存不断提前驱逐仍有效（fresh）的条目，实际容量低于配置的 max_entries，缓存命中率下降；每次刷新周期还触发不必要的驱逐事务。
- **修复建议**: 仅在新行创建时 +1：用 `INSERT ... ON CONFLICT DO NOTHING` 或让 INSERT 返回是否替换（`RETURNING id, (xmax = 0)` 式），或每次 Set 后重同步计数（去掉 fast path）。

### D2 [HIGH] logic — database.Version 生产代码从不赋值，增量迁移永不执行、存储版本被覆盖为 "0.0.0"
- **文件**: database/migration.go:23,260-281
- **问题**: `database.Version`（"0.0.0"）注释声称 "set by the caller before Open()"，但生产代码无任何赋值：`cmd/zjdns/main.go:42` 只设 `config.DefaultVersion`；Dockerfile ldflags 只注入 `main.BuildTime`/`main.CommitHash`；唯一赋值在 `ruleset/ruleset_test.go:12`（测试）。因此 `runMigrations()` 的 `compareSemver(applied, Version) < 0`（line 260）对任何已存版本（包括旧二进制写的 "3.x.y"）恒为假——`migrations` 切片（v3.4.24 FQDN 规范化、v3.5.0 hijack→poisoned 改名、v3.7.1 fallback 删除等）永不执行。更糟的是 line 274-281 随后 `INSERT OR REPLACE` 把存储版本写为 "0.0.0"，永久掩盖升级状态。基础 DDL（CREATE TABLE IF NOT EXISTS）无法修复缺新列的旧库（如 `zone_entries.match_tags`、`entries.ecs_addr`），`prepareStatements()` 面对旧库直接失败 → 服务拒绝启动。
- **风险**: 带已有 cache.db 的升级要么启动失败，要么静默跳过必需 schema 迁移；迁移基础设施（及依赖显式设 Version 才能通过的测试）在生产中完全是死代码。
- **修复建议**: 启动时从应用版本设置 `database.Version`（main.go 与 server.New/database.Open 接线处），或去掉间接层把版本显式传入 `Open()`。

### D3 [MEDIUM] inefficiency — ruleset.Match() 每查询裸 SQL，未用 prepared statement
- **文件**: ruleset/ruleset.go:126-129
- **问题**: `Match()` 每次查询执行 `e.db.SQLQuery("SELECT tag FROM ruleset_entries WHERE type='domain' AND value=?", key)`——带参数时 database/sql 每次调用都 prepare+close 语句。database 包存在意义正是预编译（stmts.go 的 StmtZoneExact 等）。该调用在每查询中间件路径上，即使 ruleset 表为空也要付出 prepare 开销。
- **风险**: 最热路径上的 SQL prepare/close 与连接池往返；空规则集部署同样受罪。
- **修复建议**: 在 database/stmts.go 加 `StmtRulesetDomain`（仿 StmtZoneExact）并经 RuleSetStorage 接口暴露；domain 表为空时短路（仿 zone.Evaluator.ruleCount）。

### D4 [MEDIUM] lock — LoadRules() 无锁写 dynamics/bypass，Evaluate() 查询热路径无锁读
- **文件**: zone/zone.go:69-70,120,144（读于 262,277）
- **问题**: `LoadRules()` 重赋值 `e.dynamics`（line 120）与 `e.bypass`（line 144），`Evaluate()` 无锁读两者（line 262,277）；仅 ruleCount/loadedAt 用原子。ruleset.Engine 同型（ruleset.go:31 tags map、:78 写、:149 读；loadIPRules 重建 ipTrie）。当前生产调用方仅启动期（server/server.go:165,173），无活跃竞态。
- **风险**: 未来任何运行时重载调用（zone reload 命令）都会在高负载下触发 "concurrent map read and map write" panic 或撕裂规则状态，且无测试能捕获。
- **修复建议**: sync.RWMutex 保护（Evaluate RLock / LoadRules Lock），或固化 init-only 不变量并强制（如 serving 开始后调用 LoadRules 即 panic）。
- **注**: 与综合报告 M27（Phase 2 交叉分析）重复。

### D5 [LOW] inefficiency — Set() 中 additional 被克隆两次
- **文件**: cache/store.go:308,314
- **问题**: `additional = stripOPT(cloneRRs(additional))`（line 308）仅为了就地过滤 OPT 就深拷贝整片，随后 line 314 再克隆一次。stripOPT 只移动切片元素，可安全作用于原切片。
- **风险**: 每次缓存写入多一次 ADDITIONAL 深拷贝（加密响应每条 RR 可达 468 字节）——miss 路径上的可避免分配。
- **修复建议**: 去掉第一个克隆（对原始切片 stripOPT 后克隆一次）。

### D6 [LOW] logic — msg.Pack() 失败仍插入 NULL msg_wire 死行并计数
- **文件**: cache/store.go:317-325,343
- **问题**: `if err := msg.Pack(); err == nil { msgWire = ... }`（line 322-324）——Pack 失败时 msgWire 保持 nil，事务照常插入 NULL blob 行（schema.go:111 可空），并经 line 357 计数 +1。`Get()` 视 `len(msgWire)==0` 为 miss（store.go:124-126），该行永远无法命中，占据条目槽位直至过期。
- **风险**: 不可缓存响应（如超大消息打包失败）静默产生死行并加剧 D1 的计数漂移。
- **修复建议**: `msgWire == nil` 时跳过插入（返回 0 不动 DB），补一条 Debug 日志。

### D7 [LOW] error-wrap — Stats() 聚合查询错误裸 `_ =` 丢弃且无注释
- **文件**: cache/stats.go:198
- **问题**: 27 列 Scan 的错误被 `_ =` 静默丢弃，无注释。代码库惯例（async_writer.go:168、store.go:412）是注释被丢弃的错误。
- **风险**: 瞬时查询失败时静默产出全零统计报告，难以与真空库区分。
- **修复建议**: 检查并处理错误（返回部分报告 + Warn），或至少注释为何零值可接受。

### D8 [LOW] magic-number — proxy 端口校验硬编码 65535；"socks5" 字符串无常量
- **文件**: config/validate.go:224,218
- **问题**: `port > 65535` 未用同文件其他位置（line 29-30,396）使用的 `MaxPortNumber` 常量；"socks5" 字符串字面量无常量。
- **风险**: 未来端口范围调整或笔误使此校验与其余配置校验静默分叉。
- **修复建议**: 改用 `MaxPortNumber`；可选引入 `ProtoSOCKS5 = "socks5"` 常量。

### D9 [LOW] magic-number — SQL 占位符数量硬编码，与跨包常量靠注释约定
- **文件**: zone/zone.go:84 + database/stmts.go:60（16 个 `?`）；cache/cache.go:39 + database/stmts.go:68-69（64 个 `?`）
- **问题**: `StmtZoneWildcard` 的 16 个占位符 "must match zone.maxWildcardLabels (16)"（stmts.go:56），`StmtIPLatency` 的 64 个 "must match cache.maxLatencyLookupIPs (64)"（stmts.go:68-69）——两边仅注释约定，无编译期/测试期强制。把 16 改 17 或 64 改 128 静默破坏批量查询。
- **风险**: 无辜常量修改后静默查询失败或缓存 key 查找被截断。
- **修复建议**: 用常量生成占位符（`strings.Repeat("?,", n)` 包初始化时构建一次），或每包加测试断言占位符数 == 共享常量。

## 干净结论（agent 明确核验为 OK 的区域）

- `AsyncStatsWriter` 生命周期正确：sync.Once Close、有界 channel、send-after-close 恢复、无 double-close、flush/close 竞态安全
- `database.Close()` 经 CAS 幂等
- `Get()` 的池化缓冲/Msg 别名安全（pool.Put 仅清零 slice 头；Unpack 分配全新 RR 底层数组——internal/pool/pool.go:70-80 有意设计）
- Cookie RFC 9018（SipHash MAC、RFC 1982 算术、密钥轮换）与测试向量一致
- ECS Normalize/VerifyECSResponse 边界安全；ipTrie 除每查询结果切片外零分配
- 导入 DAG 干净（仅文档列出的例外）；scope 内无 context.TODO()；热路径日志均 Debug；所有 nolint 带原因
