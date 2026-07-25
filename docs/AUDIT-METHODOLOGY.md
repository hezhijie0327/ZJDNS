# ZJDNS 审计框架

## 概述

本文档定义了 ZJDNS 代码库的端到端审计与修复流程。每次审计均按此框架执行：从多维度并行审查，到按严重程度分 Sprint 修复，到质量门禁收尾。

每次审计的详细发现和修复计划存档于 [`docs/audit/`](audit/)。

---

## 一、审计流程

### 1.1 审计维度

每个文件、每个包在以下 10 个维度接受审查：

| 维度 | 关注点 |
|------|--------|
| **代码质量** | 死代码、冗余代码、重复代码、低效代码 |
| **内存安全** | 泄漏、无界增长、sync.Pool 误用、缓冲区未归还 |
| **锁正确性** | data race、死锁、竞态、锁顺序 |
| **耦合度** | 导入分层违规、不必要依赖、接口放置 |
| **架构设计** | God package、命名一致性、类型别名合理性 |
| **性能** | QPS 瓶颈、SQL 模式、热路径分配 |
| **Panic 检测** | nil 解引用、切片越界、空 map 写入、裸类型断言、通道关闭、除零、use-after-Put |
| **日志质量** | 完整性（关键路径有日志）、精准性（级别正确、信息充分）、不刷屏（info/warn 不在热路径重复打印） |
| **文档质量** | 架构文档与代码一致、CLAUDE.md 类型引用准确、注释不过时/不误导、关键设计决策有记录、公开 API 有 godoc |
| **参数校验** | 公开函数未检查 nil/空字符串/零值参数；构造后未验证字段有效性（如 `net.ParseIP("")` 返回 nil）；错误返回值被 `_` 丢弃导致后续代码基于零值继续执行；`func(_, name string)` 中 `_` 丢弃的参数是否存在应校验但未校验的值 |

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

Phase 2: 交叉分析（9 agent 并行）
├── CrossCut Locks:      全部 sync.Mutex / RWMutex / Once / atomic / channel / WaitGroup / Pool
├── CrossCut Memory:     goroutine 泄漏、无界增长、资源泄漏、池误用
├── CrossCut Panic:      nil 解引用、切片越界、空 map 写入、裸类型断言、死锁、除零
├── CrossCut Validation: 公开函数参数未校验（nil/空字符串/零值）、错误被 _ 丢弃、构造函数未验证字段
├── CrossCut DeadCode:   未用符号、重复代码、不必要接口
├── CrossCut Perf:       SQL N+1、热路径分配、索引缺失
├── CrossCut Arch:       导入分层验证、循环依赖风险
├── CrossCut Logging:    日志级别审计、info/warn 热路径刷屏、错误路径缺失日志、格式一致性
└── CrossCut Docs:       全部 .md 文件与代码一致性、CLAUDE.md 准确性、注释是否过时、godoc 覆盖率

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

### 3.3 Benchmark 回归检测

审计修复可能引入性能回退（如额外的 nil 检查、锁竞争、内存分配）。每个 Sprint 修复完成后必须执行 benchmark 对比：

```bash
# 刷新基线
go test -bench=. -short -benchtime=500ms ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt

# 对比旧基线（>15% 变慢即为回归）
git diff HEAD~1 -- docs/benchmark/benchmark-baseline.txt
```

回归判定标准：

| 变化 | 判断 |
|------|------|
| >15% 变慢 | **回归** — 审计修改影响了热路径，需回滚或优化 |
| <15% 波动 | 测量噪声 — `time.Now()` 调用 ~28ns 是正常下限，<5ns 为编译器架空 |
| >15% 变快 | 附带优化 — 记录到提交信息中 |

回退判定前需确认：(1) 修改确实触及了该 benchmark 的代码路径，(2) 差异不是运行环境波动（CPU 频率、缓存状态）。

### 3.4 Linter 纪律

- **零全局排除** — 所有抑制通过 `//nolint:NAME // reason` 内联
- **声明顺序** (`decorder`)：`type → const → var → func`
- **格式化** (`gofumpt`)：禁止空行分组，导入按字母排序
- **每个 nolint 注释** 必须包含 linter 名称和具体原因

### 3.5 提交规范

**每次提交只包含一类修复**，不要将不同维度/不同包的修复混在一个 commit 中。

**主题行格式**：

```
<type>: <具体描述> (<审计引用>)
```

- `type`: `fix`（修 bug）、`perf`（性能）、`refactor`（重构）、`docs`（文档）
- `<具体描述>`：说明**修复了什么**，不是审计阶段。禁止 `Round X audit`、`fix audit findings` 等笼统描述
- `<审计引用>`：可选，引用审计报告中的发现编号（如 `C1`、`H3`、`M7`）

**Good（描述具体修复内容）**：

```
fix: add SQL separator in stale entry cleanup (C1)

Two DELETE statements concatenated without semicolon produced
invalid SQL, silently breaking ip_latency/query_log cleanup.

Co-Authored-By: Claude <noreply@anthropic.com>
```

```
fix: acquire writeMu in TCP SERVFAIL path to prevent stream corruption (H1)

The capacity overflow branch in handleDNSRequest wrote SERVFAIL
directly to the TCP connection without acquiring writeMu, racing
with pipelined response writes and corrupting the byte stream.

Co-Authored-By: Claude <noreply@anthropic.com>
```

```
fix: check discarded errors in TLCP self-signed cert generation (H1)

rand.Int and smx509.ParseCertificate errors were silently discarded
with _, causing nil-pointer dereference panics when entropy or DER
parsing failed.

Co-Authored-By: Claude <noreply@anthropic.com>
```

**Bad（禁止使用）**：

```
fix: Round 1 audit fixes           ← 太笼统，无法知道改了什么
fix: fix audit findings             ← 同上
fix: Round 1+2 audit — 11 HIGH fixes ← 数量没有意义，描述具体内容
fix: various bug fixes              ← 无法 git bisect 定位
```

**多个修复分多次提交**：

```
git commit -m "fix: acquire writeMu in TCP SERVFAIL path (H1)"   ← 一个修复一个 commit
git commit -m "fix: check nil synth before DNS64 log (H2)"       ← 另一个修复另一个 commit
```

**同一类修复（同一维度、同一根因）可以合并**：

```
git commit -m "fix: annotate 5 missing defer HandlePanic calls (M1-M5)"
```

---

## 四、审计发现分类

### 4.1 严重程度定义

| 等级 | 定义 | 示例 |
|------|------|------|
| **CRITICAL** | 数据损坏、崩溃、panic、安全绕过、数据丢失 | SQL 静默失败、nil-map panic、池双重归还导致连接损坏、参数 nil 未检查导致 panic |
| **HIGH** | 资源耗尽、goroutine 泄漏、竞态、缓存损坏、死锁 | 池泄漏导致 QPS 下降、goroutine 无界增长、浅拷贝共享底层数组、mutex 成功路径未解锁、错误被 `_` 丢弃导致基于零值的错误逻辑 |
| **MEDIUM** | 维护性、边际正确性问题、次优分配、日志质量、文档质量 | 耦合违规、死代码、不必要的堆分配、配置验证缺失、info/warn 热路径刷屏、错误路径无日志、架构文档与代码不一致、空字符串/零值参数未经校验传入深层调用 |
| **LOW** | 文档、微优化、代码异味 | 误导性注释、重复逻辑、脆弱的假设注释、Debug 日志格式不一致 |

### 4.2 常见根因模式

历次审计中反复出现的系统性根因：

| 模式 | 根因 | 预防措施 |
|------|------|----------|
| **池归还纪律** | 协议处理器独立开发，缺乏共享模板 | 新协议以 TLS DoT handler 为模板；CI 检查每个 `Get()` 是否有对应 `defer Put()` |
| **并发安全** | 临界区过窄或缺失（锁-drop 窗口、无锁写入） | 锁保护区域明确注释；`go test -race` 作为 CI 必需项 |
| **防御算法** | 状态机缺少逃逸路径、过度拒绝合法响应 | 每个防御模块必须有 fuzz 测试和边界条件用例 |
| **死代码/冗余** | 重构后遗留（中间件、迁移、未用字段） | `staticcheck -checks U1000` 集成 CI |
| **SQL 正确性** | 字符串拼接无分隔符、语义歧义 | 使用 prepared statements；SQL 拼接统一通过 `strings.Join` |
| **跨协议一致性** | 同类型 bug 在不同协议处理器中重复出现（DTLS/DTLCP 固定缓冲区） | 修复一个协议 bug 后，全局搜索相同模式到所有协议处理器 |
| **Pool buffer 生命周期** | `response.Data` 指向已归还的 pool buffer（use-after-free） | `pool.Put` 前必须 `response.Data = nil`，参考 `tcp.go` 的 `resp.Data = nil` 模式 |
| **TODO 管理** | TODO 注释累积但不实现，变成虚假安全感 | 每个 TODO 要么实现、要么改为 NOTE 并说明原因、要么删除 |
| **日志质量** | info/warn 在热路径重复打印刷屏；错误路径缺少上下文（无 qname/qtype/server）；日志级别误用（error 用于可恢复、debug 用于关键信号） | 每查询一条日志原则：info 仅用于状态变更，warn 仅用于可恢复异常且带采样，error 仅用于不可恢复；热路径日志全部 debug；每个日志含足够定位信息 |
| **文档腐烂** | 架构文档描述已删除的类型/字段/中间件；CLAUDE.md 类型参考表过时；注释引用的行号/函数名已失效；新功能无文档 | 每次 PR 检查受影响的 .md 文件；`grep` 文档中的类型名/函数名确认仍存在；注释中用 `FindSymbol` 而非行号引用代码 |
| **参数校验缺失** | 公开函数未检查 nil/空字符串/零值参数直接使用；构造后未验证字段有效性（如 `net.ParseIP("")` 返回 nil 后直接传入下游）；错误返回值被 `_` 丢弃，后续代码基于零值继续执行 | 每个公开函数入口处检查关键参数；`net.ParseIP` / `net.ParseCIDR` 结果立即判 nil；`_` 丢弃错误必须注释原因；构造函数返回前验证内部状态 |
| **提交信息不规范** | 使用 `Round X audit`、`fix audit findings` 等笼统描述，无法从 `git log` 了解具体改了什么 | 主题行描述**具体修复内容**（"fix: acquire writeMu in TCP SERVFAIL path"），不是审计阶段；一个 commit 只含一类修复；跨维度修复分多次提交 |

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
| `go test -bench=.` | Benchmark 回归检测（对比基线） |

---

## 六、经验教训

### 6.1 可复用实践

1. **池对象必须 defer Put**：任何 `pool.DefaultMessage.Get()` 必须在同一函数作用域内用 `defer pool.DefaultMessage.Put()` 配合（或在循环中显式 Put）
2. **锁内不要做 IO**：在锁外关闭旧连接，在锁内操作数据结构
3. **切片共享底层数组**：从 atomic pointer 获取的切片在修改前必须复制
4. **多读循环必须检查 ctx.Done()**：每个 poll 迭代都应可取消
5. **SQL 字符串拼接需要分隔符**：反引号字符串拼接不会自动添加空格或分号
6. **每查询一条日志原则**：hot-path（每次查询都经过的路径）只用 Debug；Info 仅用于状态变更（启动/关闭/重载）；Warn 用于可恢复异常且应带采样或限流；Error 仅用于不可恢复
7. **日志必须含定位信息**：错误/Warn 日志至少包含 qname/qtype/server/error 中与上下文相关的字段；不要打印"query failed"而没说哪个查询
8. **禁止 info/warn 在热路径**：`log.Infof` / `log.Warnf` 不得出现在每次查询都会执行的代码路径中（如 ServeDNS、middleware Wrap、upstream Exchange）。每查询超过一条 info/warn 即为刷屏
9. **文档与代码同步更新**：修改函数签名、删除类型/字段、新增/删除中间件时，检查 `docs/*.md` 和 `CLAUDE.md` 是否引用该符号；用 `git grep` 确认
10. **注释引用符号名，不引用行号**：行号在每次编辑后失效。注释中如果必须引用代码位置，使用函数名/类型名（可 grep），而非行号
11. **`_` 丢弃的值必须注释类型和原因**：`result, _ := someFunc()` 必须注释 `// _ = error: <原因>`，防止被调用函数签名变更后 `_` 静默丢弃不同类型的值。不写注释的 `_` 在重构时是定时炸弹——函数返回值从 `(T, error)` 变为 `(T, Cleanup)` 时编译通过但语义全变
12. **废弃参数应删除而非改名 `_`**：`func f(name, target string)` 中如果 `name` 不再使用，应将 `name` 从签名中删除并更新所有调用方，而不是改成 `func f(_, target string)`。`_` 参数只用于接口实现（无法改签名）和 callback（协议要求）。Standalone function 的 `_` 参数是 dead code

### 6.2 避免的反模式

1. **defer 在循环中**：defer 在函数返回前累积，循环中应使用显式清理
2. **锁内释放再获取**：创建竞态窗口
3. **nil-map 写入**：`sync.Map` 或关闭前清理所有条目再设 nil
4. **`_` 丢弃值不注释**：`_` 丢弃的值必须注释类型和原因（如 `// _ = error: DNSKEY query best-effort`）。不注释的 `_` 在函数签名重构时是定时炸弹——返回值从 `(T, error)` 变为 `(T, Cleanup)` 时编译通过，但 `_` 静默丢弃了 Cleanup 导致资源泄漏。裸类型断言 `v := x.(*T)` 应改用 comma-ok。**`func f(_, name string)` 将参数改名 `_` 而非从签名中删除——如果这不是接口实现，应直接删参并更新所有调用方**
5. **info/warn 刷屏**：热路径上的 `log.Infof` / `log.Warnf` 在高 QPS 下产生海量日志，淹没真正重要的信号。所有每查询日志必须是 Debug 级别
6. **日志缺少上下文**：`log.Warnf("resolve failed: %v", err)` 不包含 qname/qtype/server，无法定位问题
7. **错误级别膨胀**：可恢复的错误（超时、单次查询失败）用 Warn，不可恢复的（配置错误、数据库损坏）用 Error。不要把每个 upstream 超时都打成 Error
8. **格式不一致**：同一组件内混用 `log.Infof("TLS: ...")` 和 `log.Infof("[TLS] ...")` 和 `log.Infof("tls: ...")` — 应统一使用 23 个规范前缀
9. **架构文档过时**：`ARCHITECTURE.md` 描述已删除的中间件/类型/表；类型引用表未随代码更新。每次重构后 grep 文档确认引用的符号仍存在
10. **注释与代码矛盾**：注释说"Phase 3 会改回来"但 Phase 3 永远不会来；注释描述的行为与实际代码不一致。每个注释在所在函数修改后必须重新验证
11. **公开 API 无 godoc**：导出的类型/函数/方法缺少文档注释，或 godoc 只重复函数名没有说明用途和参数含义

### 6.3 持续改进

- 每次添加新协议处理器时，自动检查池归还纪律
- 死代码检测集成到 CI（`staticcheck -checks U1000`）
- 竞态检测器作为 CI 必需项（`go test -race`）
- 定期（季度）重新运行全审计流程
- 审计修复后执行 benchmark 瓶颈分析：
  1. 刷新基线 `go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort`
  2. 排序 `ns/op` 找最慢 20 个 benchmark，确认是否被审计修改触及
  3. 按模块分中位数，对比旧基线识别 >15% 回归
  4. 对可疑回归做 `-benchmem` 分配分析，确认根因后回退或优化
- 每次审计修复后刷新 benchmark 基线，对比检测性能回归
- 每次审计包含专门的 CrossCut Logging 阶段：grep `log\.(Info|Warn)` 确认不在热路径，grep `log\.Error` 确认是可恢复还是不可恢复
- 每次审计包含 CrossCut Docs 阶段：grep 全部 .md 文件中的类型名/函数名/字段名，与代码交叉验证是否仍存在
- 每次审计包含 CrossCut Validation 阶段：grep `_, :=\|_ = ` 确认每个 `_` 丢弃的 error 有注释说明原因；grep `func.*_.*,\|\.(.*)` 确认裸类型断言；grep `net\.ParseIP\|net\.ParseCIDR` 确认结果判 nil；grep `func.*(_.*,\|func.*(_.*)` 排除接口/callback 后确认没有 standalone function 用 `_` 隐藏废弃参数

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
├── 08-logging.md         ← 日志质量审计（级别、刷屏、上下文）
├── 09-debug-coverage.md  ← Debug 日志覆盖率审计
├── 10-docs.md            ← 文档一致性审计（与代码交叉验证）
├── 11-validation.md      ← 参数校验审计（nil/空值/零值/_丢弃/裸断言）
├── 12-synthesis.md       ← 综合报告（排序、主题分析、行动计划）
└── 00-plan.md            ← 逐项修复计划 + 全覆盖清单
```

每轮审计结束后，更新上方 §概述 的历史记录表。
