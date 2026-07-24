# ZJDNS 审计框架

## 概述

本文档定义了 ZJDNS 代码库的端到端审计与修复流程。每次审计均按此框架执行：从多维度并行审查，到按严重程度分 Sprint 修复，到质量门禁收尾。

每次审计的详细发现和修复计划存档于 [`docs/audit/`](audit/)。历史审计记录：

| 时间 | 发现数 | 提交 |
|------|--------|------|
| 2026-07 | 82（15C / 17H / 26M / 24L） | 10 |

---

## 一、审计流程

### 1.1 审计维度

每个文件、每个包在以下 6 个维度接受审查：

| 维度 | 关注点 |
|------|--------|
| **代码质量** | 死代码、冗余代码、重复代码、低效代码 |
| **内存安全** | 泄漏、无界增长、sync.Pool 误用、缓冲区未归还 |
| **锁正确性** | data race、死锁、竞态、锁顺序 |
| **耦合度** | 导入分层违规、不必要依赖、接口放置 |
| **架构设计** | God package、命名一致性、类型别名合理性 |
| **性能** | QPS 瓶颈、SQL 模式、热路径分配 |

### 1.2 审计架构

采用分层并行 Agent 架构：

```
Phase 1: 包级审计（7 agent 并行）
├── Foundation audit: internal/* 基础包
├── Domain audit:     config / database / cache / edns / zone / ruleset
├── Protocol audit:   server/protocol/{plain,tls,tlcp,dnscrypt}
├── Upstream audit:   server/upstream/*
├── Resolver audit:   server/resolver/*
├── Handler audit:    server/handler/*
└── Defense audit:    server/defense/*

Phase 2: 交叉分析（5 agent 并行）
├── CrossCut Locks:    全部 sync.Mutex / RWMutex / Once / atomic / channel / WaitGroup / Pool
├── CrossCut Memory:   goroutine 泄漏、无界增长、资源泄漏、池误用
├── CrossCut DeadCode: 未用符号、重复代码、不必要接口
├── CrossCut Perf:     SQL N+1、热路径分配、索引缺失
└── CrossCut Arch:     导入分层验证、循环依赖风险

Phase 3: 综合报告
└── Synthesis: 汇总排序 → 主题分析 → 行动计划
```

### 1.3 审计报告格式

每个发现包含：

- **文件路径 + 行号**
- **严重程度**：CRITICAL / HIGH / MEDIUM / LOW
- **类别标签**：pool-leak / lock / memory / sql / dead-code / inefficiency / coupling / ...
- **问题描述**：具体的技术问题
- **风险说明**：如果未修复会产生的后果
- **修复建议**：具体的代码变更方向

---

## 二、修复流程

### 2.1 Sprint 策略

按严重程度分三批修复：

| Sprint | 范围 | 标准 |
|--------|------|------|
| Sprint 1 | CRITICAL | 立即修复 — 数据损坏、崩溃、panic、安全绕过 |
| Sprint 2 | HIGH | 下个发布周期 — 池耗尽、goroutine 泄漏、竞态 |
| Sprint 3 | MEDIUM + LOW | 文档/优化 — 耦合、冗余、微优化、注释 |

### 2.2 修复优先级

在同一 Sprint 内，按以下顺序修复：

1. **单字符/单行修复** — SQL 分隔符、切片复制、条件取反等
2. **模式匹配修复** — 池 defer Put、锁内不 IO 等可模板化的缺陷
3. **逻辑重写** — 状态机修正、并发结构重构
4. **死代码删除** — 未用函数/类型/导入

### 2.3 参考实现

池归还纪律以 `server/protocol/tls/tls.go` 为**标准模板**：

```go
// 正确模式 (TLS DoT handler)
resp := s.handler.ServeDNS(msg, clientIP, false, protocol)
defer pool.DefaultMessage.Put(resp)
```

其他所有协议处理器必须遵循此模式。

---

## 三、质量门禁

### 3.1 每次提交前

```bash
go build ./...                    # 零编译错误
go fix ./...                      # 自动修复
golangci-lint run                 # 零警告
golangci-lint fmt                 # 格式化
```

### 3.2 每个 Sprint 后

```bash
go test -short ./...              # 全部测试通过
go test -short ./server/...       # 核心包测试
go test -short ./cache/...        # 缓存测试
```

### 3.3 Linter 纪律

- **零全局排除** — 所有抑制通过 `//nolint:NAME // reason` 内联
- **声明顺序** (`decorder`)：`type → const → var → func`
- **格式化** (`gofumpt`)：禁止空行分组，导入按字母排序
- **每个 nolint 注释** 必须包含 linter 名称和具体原因

### 3.4 提交规范

```
fix: <简短描述> (<审计引用>)

<1-2 行说明问题和修复>

Co-Authored-By: Claude <noreply@anthropic.com>
```

示例：
```
fix: add missing SQL separator in stale cleanup (C1)

Two DELETE statements concatenated without semicolon produced
invalid SQL, silently breaking ip_latency/query_log cleanup.

Co-Authored-By: Claude <noreply@anthropic.com>
```

---

## 四、审计发现分类

### 4.1 严重程度定义

| 等级 | 定义 | 示例 |
|------|------|------|
| **CRITICAL** | 数据损坏、崩溃、panic、安全绕过、数据丢失 | SQL 静默失败、nil-map panic、池双重归还导致连接损坏 |
| **HIGH** | 资源耗尽、goroutine 泄漏、竞态、缓存损坏 | 池泄漏导致 QPS 下降、goroutine 无界增长、浅拷贝共享底层数组 |
| **MEDIUM** | 维护性、边际正确性问题、次优分配 | 耦合违规、死代码、不必要的堆分配、配置验证缺失 |
| **LOW** | 文档、微优化、代码异味 | 误导性注释、重复逻辑、脆弱的假设注释 |

### 4.2 常见根因模式

历次审计中反复出现的系统性根因：

| 模式 | 根因 | 预防措施 |
|------|------|----------|
| **池归还纪律** | 协议处理器独立开发，缺乏共享模板 | 新协议以 TLS DoT handler 为模板；CI 检查每个 `Get()` 是否有对应 `defer Put()` |
| **并发安全** | 临界区过窄或缺失（锁-drop 窗口、无锁写入） | 锁保护区域明确注释；`go test -race` 作为 CI 必需项 |
| **防御算法** | 状态机缺少逃逸路径、过度拒绝合法响应 | 每个防御模块必须有 fuzz 测试和边界条件用例 |
| **死代码/冗余** | 重构后遗留（中间件、迁移、未用字段） | `staticcheck -checks U1000` 集成 CI |
| **SQL 正确性** | 字符串拼接无分隔符、语义歧义 | 使用 prepared statements；SQL 拼接统一通过 `strings.Join` |

---

## 五、工具链

### 5.1 审计工具

| 工具 | 用途 |
|------|------|
| `Agent (Workflow)` | 编排并行审计 + 交叉分析 + 综合 |
| `Grep` | 全库搜索符号、模式、导入 |
| `Read` | 逐文件审查代码 |
| `Bash` (git grep) | 跨包引用验证 |

### 5.2 修复工具

| 工具 | 用途 |
|------|------|
| `Edit` | 精确字符串替换 |
| `Bash` (sed) | 行级删除、导入清理 |
| `Bash` (python) | 跨文件批量重构 |
| `go build` | 编译验证 |
| `golangci-lint` | 代码质量 |
| `go test` | 回归验证 |

---

## 六、经验教训

### 6.1 可复用实践

1. **池对象必须 defer Put**：任何 `pool.DefaultMessage.Get()` 必须在同一函数作用域内用 `defer pool.DefaultMessage.Put()` 配合（或在循环中显式 Put）
2. **锁内不要做 IO**：在锁外关闭旧连接，在锁内操作数据结构
3. **切片共享底层数组**：从 atomic pointer 获取的切片在修改前必须复制
4. **多读循环必须检查 ctx.Done()**：每个 poll 迭代都应可取消
5. **SQL 字符串拼接需要分隔符**：反引号字符串拼接不会自动添加空格或分号

### 6.2 避免的反模式

1. **defer 在循环中**：defer 在函数返回前累积，循环中应使用显式清理
2. **锁内释放再获取**：创建竞态窗口
3. **nil-map 写入**：`sync.Map` 或关闭前清理所有条目再设 nil
4. **`_` 丢弃错误**：特别是验证/解密错误，应至少 debug log

### 6.3 持续改进

- 每次添加新协议处理器时，自动检查池归还纪律
- 死代码检测集成到 CI（`staticcheck -checks U1000`）
- 竞态检测器作为 CI 必需项（`go test -race`）
- 定期（季度）重新运行全审计流程

---

## 七、审计报告存档

每次审计的详细报告放入 `docs/audit/`，命名规范：

```
docs/audit/<YYYY-MM>-<主题>/
├── 01-foundation.md     ← internal/* 包审计
├── 02-domain.md         ← config / database / cache / edns / zone / ruleset
├── 03-protocol.md       ← server/protocol/*
├── 04-upstream.md       ← server/upstream/*
├── 05-resolver.md       ← server/resolver/*
├── 06-handler.md        ← server/handler/*
├── 07-defense.md        ← server/defense/*
├── 08-crosscutting.md   ← 交叉分析（锁、内存、死代码、SQL、架构）
├── 09-synthesis.md      ← 综合报告（排序、主题分析、行动计划）
└── PLAN.md              ← 逐项修复计划 + 全覆盖清单
```

每轮审计结束后，更新上方 §概述 的历史记录表。
