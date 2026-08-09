# 09 — SQL 迁移残留审计（cee48da 清扫的补漏）

> 结论：**代码 100% 无 SQL 残留**（grep `sqlite|database/sql|SELECT|INSERT|DELETE FROM|stmt|BatchWriter` 仅命中注释中的历史提及）。残留集中在文档、死端点和逻辑门控。

## M7 [MEDIUM] CleanupLatency 错误挂在 cache state file 门控下

- **位置**：server/tasks.go:47-52
- **类别**：unbounded（清理缺失）
- **问题描述**：周期任务中 `cc.CleanupLatency()` 放在 `if cachePath != ""` 分支内（51 行）。若部署只配置 `latency.state_file`（不配 cache state file），物理清理永不执行 —— 延迟表只靠 LRU 淘汰兜底（有界，但"过期条目物理清除"承诺落空）。x-sql-remnant agent 亦独立命中（tasks.go:51）。
- **修复建议**：`CleanupLatency()` 移到 `latencyPath != ""` 分支（或任一 state file 配置时无条件执行）。

## L2 [LOW] zjdns.delegation.clear 是静默 no-op

- **位置**：server/init.go:93-95（端点注册）、cache/stats.go:63-64（`FlushDB("delegation")` 返回 no-op）
- **类别**：dead-code
- **问题描述**：`cee48da` 删除了 `zjdns.ptr.clear`（当时因为它必然报错），但 `zjdns.delegation.clear` 同样必然无效：FlushDB 对 "delegation" 显式 no-op（"kept for interface parity"），端点却仍注册并回复 "flushed"。用户调用得到虚假的成功反馈。
- **修复建议**：二选一 —— (a) 移除端点；(b) FlushDB("delegation") 真正清空 delegation 缓存（需要访问 resolver 的 delegation lrumap，接口成本高，倾向 (a)）。

## L3 [LOW] 关停快照保存无超时，磁盘挂起可永久阻塞关停

- **位置**：server/tasks.go:323-344（shutdownServer 内快照保存段）
- **类别**：snapshot
- **问题描述**：关停路径的 3 个 `Save*Snapshot`（328/333/338 行）直接同步执行，无 deadline。shutdownServer 其余部分（plain.Shutdown、dnscrypt、pprof、backgroundGroup.Wait）全部有 `DefaultShutdownTimeout` 保护 —— 唯独快照段裸露。结合 H5（持锁写盘），慢盘上的关停 = 全缓存停顿 + 无上限等待。
- **修复建议**：用 `context.WithTimeout(shutdownCtx, DefaultShutdownTimeout)`（或独立较短超时）包裹；超时则 warn 并放弃保存。

## L4 [LOW] 孤儿 "// SQL" 注释块

- **位置**：cmd/zjdns/cli/parse.go:29
- **类别**：dead-code（注释）
- **问题描述**：`--sql` CLI 工具已删除（6ec7150），但 flags 结构体内残留孤立的 `// SQL` 注释（下无任何字段）。
- **修复建议**：删除该注释行。

## 已确认干净的项

- config：`DefaultAsyncFlushInterval`、`DefaultDNSKeyCacheTTL` 等孤儿常量已删除；无 SQL 时代 config 字段残留；
- 文档（CLAUDE.md / ARCHITECTURE.md / README / FLOWCHARTS / DEBUG）：6ec7150 + cee48da 已清理，本轮抽查无 SQL 引用残留（AUDIT-METHODOLOGY.md 本轮已同步更新，见 HANDOVER）；
- benchmark 基线已重定（迁移提交声明），无引用已删路径的陈旧 benchmark；
- `PruneQueryJournal` no-op 与 `Flush()` no-op 为设计保留（接口兼容），非残留。
