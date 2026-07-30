# Resolver 层审计报告 — `server/resolver/*`

## 审计范围

17 个源文件：`resolver.go`, `forward.go`, `recursive.go`, `recursive_helpers.go`, `recursive_ns.go`, `nameserver.go`, `ns_addresses.go`, `qname_minimise.go`, `root_hints.go`, `zonecut.go`, `dnssec_chain.go`, `dnssec/*`, `probe/`

## 发现

### HIGH

#### H1. 递归 NS 路径池消息泄漏

- **文件**: `server/resolver/nameserver.go:71-82`
- **类别**: pool-leak
- **问题**: `msg := pool.DefaultMessage.Get()` 获取消息传递给 `ExecuteQuery`，但从不 `Put`。注释声称"所有权转移至 ExecuteQuery"，但 `ExecuteQuery` 不获取消息所有权——它只读取数据，不执行 `Put`。
- **风险**: 每次递归 NS 查询泄漏约 6-12 个池消息。池枯竭后每次泄漏产生额外分配。
- **修复**: 添加 `defer pool.DefaultMessage.Put(msg)`。

#### H2. ExecuteQuery 消息所有权约定冲突

- **文件**: `server/resolver/forward.go:83-85` vs `nameserver.go:71-77`
- **类别**: api-design
- **问题**: 同一函数 `ExecuteQuery` 存在两种矛盾的所有权约定。转发路径在调用后 Put，递归路径声称所有权已转移。
- **修复**: 统一约定（调用方应始终在调用后可安全 Put）。

### MEDIUM

#### M1. processUpstreamResponse 参数过多（11 个）

- **文件**: `server/resolver/forward.go:240`
- **类别**: code-quality
- **问题**: 违反 CLAUDE.md 中"超过 5 个参数时使用配置结构体"的规范。
- **修复**: 分组到结构体中。

#### M2. tryRRSIGRetry 无文档记录的副作用

- **文件**: `server/resolver/dnssec_chain.go:420-441`
- **类别**: docs
- **问题**: 通过替换 `response.Answer`/`.Ns`/`.Extra` 修改调用方数据，但函数名暗示是检查而非修改。
- **修复**: 文档化副作用或将新数据作为返回值。

#### M3. cacheGlueRecords 混合 A/AAAA 类型

- **文件**: `server/resolver/recursive_ns.go:107-110`
- **类别**: correctness
- **问题**: 所有属于同一 NS 的 glue 记录使用第一个记录的类型存储。若同时存在 A 和 AAAA glue，另一种类型的查询会 miss。
- **修复**: 在缓存前按实际类型分组。

#### M4. EDE 代码信息缺失

- **文件**: `server/resolver/recursive_helpers.go:166-167`
- **类别**: logging
- **问题**: DNSSEC 伪造区域切割错误未包含 EDE 代码或区名称。
- **修复**: 在错误中包含 EDE 代码。

### LOW

#### L1. 死错误处理代码

- **文件**: `server/resolver/nameserver.go:331-333`
- **修复**: 移除 dead 分支。

#### L2. 丢弃 resolveNSAddrType 返回值

- **文件**: `server/resolver/nameserver.go:280,289`
- **修复**: 简化函数签名。

#### L3. captureUpstreamEDE 放置不当

- **文件**: `server/resolver/forward.go:160`
- **修复**: 移至文件顶部/底部。

#### L4. 硬编码 NSEC3 Opt-Out 标记

- **文件**: `server/resolver/dnssec/nsec.go:216`
- **修复**: 使用命名常量。

#### L5. RootKeys() 返回内部切片

- **文件**: `server/resolver/dnssec/crypto.go:183`
- **修复**: 返回副本。

#### L6. 误导性池注释

- **文件**: `server/resolver/recursive_helpers.go:43`
- **修复**: 更新注释。

#### L7. 参数重新赋值

- **文件**: `server/resolver/dnssec/extract.go:152`
- **修复**: 使用局部变量。

#### L8. context 原因未使用

- **文件**: `server/resolver/forward.go:46`
- **修复**: 使用 `context.Cause(queryCtx)`。

#### L9. 冗余 context 超时

- **文件**: `server/resolver/nameserver.go:29-31,79`
- **修复**: 移除一层超时。

### 维度合规

| 维度 | 状态 |
|------|------|
| 代码质量 | ⚠️ M1, L1, L2, L3 |
| 内存安全 | ❌ H1（池泄漏） |
| API 设计 | ❌ H2（所有权冲突） |
| 日志质量 | ⚠️ M4 |
| 注释准确性 | ⚠️ M2, L6 |
| 常量提取 | ⚠️ L4 |
| 其余 | ✅ |
