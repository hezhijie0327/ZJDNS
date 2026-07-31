# ZJDNS 审计框架

## 概述

本文档定义了 ZJDNS 代码库的端到端审计与修复流程。每次审计均按此框架执行：从多维度并行审查，到按严重程度分 Sprint 修复，到质量门禁收尾。

每次审计的详细发现和修复计划存档于 [`docs/audit/`](audit/)。

---

## 一、审计流程

### 1.1 审计维度

每个文件、每个包在以下 18 个维度接受审查：

| 维度 | 关注点 |
|------|--------|
| **代码质量** | 死代码、冗余代码、重复代码、低效代码 |
| **内存安全** | 泄漏、无界增长、sync.Pool 误用、缓冲区未归还 |
| **锁正确性** | data race、死锁、竞态、锁顺序 |
| **耦合度** | 导入分层违规、不必要依赖、接口放置 |
| **架构设计** | God package、命名一致性、类型别名合理性 |
| **性能** | QPS 瓶颈、KV 操作模式、热路径分配 |
| **Panic 检测** | nil 解引用、切片越界、空 map 写入、裸类型断言、通道关闭、除零、use-after-Put |
| **错误处理** | `%w` 包装链路完整；`errors.Is`/`As` 使用正确；sentinel error vs custom type 选择合理；同一函数内包装策略一致（要么全 Wrap 要么全不 Wrap） |
| **Context 传播** | 所有 I/O 函数第一参数为 `context.Context`；取消信号正确传播到下游；无 `context.TODO()` 出现在生产代码；`WithoutCancel`/`WithTimeout` 使用场景正确 |
| **Goroutine 生命周期** | 每个 goroutine 有 `defer HandlePanic`；有明确的父 goroutine/owner；有取消路径（ctx.Done 或 done channel）；`errgroup` 使用 `SetLimit` 限制并发；channel 由唯一 owner 关闭 |
| **资源生命周期** | `Close()` 幂等（`sync.Once` 或 atomic 守卫）；New 创建的资源在 Close 中全部释放；`Close()` 不阻塞（不在锁内做 IO）；`SetReadDeadline` 用于取消阻塞的 IO |
| **日志质量** | 完整性（关键路径有日志）、精准性（级别正确、信息充分）、不刷屏（info/warn 不在热路径重复打印） |
| **文档质量** | 架构文档与代码一致、CLAUDE.md 类型引用准确、注释不过时/不误导、关键设计决策有记录、公开 API 有 godoc |
| **参数校验** | 公开函数未检查 nil/空字符串/零值参数；构造后未验证字段有效性（如 `net.ParseIP("")` 返回 nil）；错误返回值被 `_` 丢弃导致后续代码基于零值继续执行；`func(_, name string)` 中 `_` 丢弃的参数是否存在应校验但未校验的值 |
| **常量提取** | 魔法数字是否抽取为命名常量（含 `config/defaults.go`）；常量值是否符合 RFC/IETF 推荐（默认端口、超时、缓冲区大小）；同一常量是否跨包重复定义（应统一到一处） |
| **RFC 一致性** | 实现是否偏离 RFC 规范；RFC 要求的边界条件/错误处理是否完整；新引入的 RFC 是否已在 `docs/rfc/` 存档；代码中的 RFC 注释引用是否正确（RFC 编号、章节号是否有效） |
| **注释准确性** | 注释是否引用已删除/移动/重命名的函数、类型、字段；注释描述的行为是否与当前代码一致；TODO/FIXME/HACK 是否仍然有效还是已过期；注释中的行号引用是否已失效 |
| **函数排序** | 文件内声明顺序是否严格遵循 `type → const → var → func`（decorder 强制）；同一接收者的方法是否聚合而非散落；构造/初始化函数是否在最靠近类型的位置（即紧跟 var 块之后的第一个 func）；新增函数是否随机插入在无关函数之间 |
| **Go 版本特性** | 代码是否采用了当前最低 Go 版本的语言/库特性；是否存在可用 `new(expr)`、`errors.AsType[T]`、`slices.Reverse` 等新版标准库替代的手写模式；`go fix` 现代器覆盖的迁移是否已应用 |
| **流程图覆盖** | `docs/FLOWCHARTS.md` 是否覆盖全部核心功能和协议；新增特性/协议/中间件是否同步更新了流程图；mermaid 语法是否正确可渲染 |
| **BadgerDB 存储** | TTL 使用是否正确（直接 `ExpiresAt` 赋值 + `IsDeletedOrExpired`）；`WriteBatch` vs `db.Update` 选择是否合理；key 编码是否二进制 BigEndian 一致；prefix scan 效率；`DropPrefix` 清理范围；`Sequence` bandwidth 和 crash 容忍；`UserMeta` 使用；是否存在应用层 zstd 双重压缩 |

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

Phase 2: 交叉分析（18 agent 并行）
├── CrossCut Locks:      全部 sync.Mutex / RWMutex / Once / atomic / channel / WaitGroup / Pool
├── CrossCut Memory:     goroutine 泄漏、无界增长、资源泄漏、池误用
├── CrossCut Panic:      nil 解引用、切片越界、空 map 写入、裸类型断言、死锁、除零
├── CrossCut Error:      错误包装链路（%w）、sentinel error 定义位置、errors.Is/As 正确性、包装策略一致性
├── CrossCut Context:    ctx 第一参数约定、取消传播、context.TODO() 扫描、WithoutCancel 误用
├── CrossCut Goroutine:  每个 goroutine 的 HandlePanic、owner、取消路径；errgroup SetLimit；channel 关闭 owner
├── CrossCut Resource:   Close() 幂等性（sync.Once/atomic）、New/Close 对称性、Close 内不阻塞 IO
├── CrossCut Validation: 公开函数参数未校验（nil/空字符串/零值）、错误被 _ 丢弃、构造函数未验证字段
├── CrossCut DeadCode:   未用符号、重复代码、不必要接口
├── CrossCut Perf:       热路径分配、前缀扫描效率
├── CrossCut Arch:       导入分层验证、循环依赖风险、接口契约满足性
├── CrossCut Logging:    日志级别审计、info/warn 热路径刷屏、错误路径缺失日志、格式一致性
├── CrossCut Docs:       全部 .md 文件与代码一致性、CLAUDE.md 准确性、注释是否过时、godoc 覆盖率
├── CrossCut Constants:  魔法数字扫描、RFC 推荐值对比、跨包重复常量检测
├── CrossCut RFC:        实现 vs RFC 规范逐条对照、docs/rfc/ 存档完整性、RFC 注释引用有效性
├── CrossCut Comments:   注释引用符号存在性检查、注释行为描述 vs 代码实际行为、过时 TODO/FIXME
├── CrossCut Ordering:   构造函数位置、方法聚合度、声明顺序（decorder）、随机插入检测
├── CrossCut GoVersion:  go.mod 版本对应的语言/库特性采用；手写模式可用标准库替代；`go fix` 现代器覆盖检查
└── CrossCut Flowcharts:  docs/FLOWCHARTS.md 覆盖率 — 全部核心功能/协议是否有流程图；新增特性是否同步更新

Phase 3: 综合报告
└── Synthesis: 汇总排序 → 主题分析 → 行动计划
```

### 1.3 审计报告格式

每个发现包含：

- **文件路径 + 行号**
- **严重程度**：CRITICAL / HIGH / MEDIUM / LOW
- **类别标签**：pool-leak / lock / memory / sql / dead-code / inefficiency / coupling / kv / ...
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

**重要：严重程度决定修复顺序，不决定是否修复。CRITICAL、HIGH、MEDIUM、LOW 全部必须修复。**
LOW 不是"可跳过"——它是"最后修"，但必须修完。不允许因等级低而选择性忽略。

### 2.2 修复优先级

在同一 Sprint 内，按以下顺序修复：

1. **单字符/单行修复** — key 分隔符、切片复制、条件取反等
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
fix: add key separator in stale entry cleanup (C1)

Two key writes without proper separator produced
invalid keys, silently corrupting ip_latency/query_log cleanup.

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
| **CRITICAL** | 数据损坏、崩溃、panic、安全绕过、数据丢失 | KV 操作静默失败、nil-map panic、池双重归还导致连接损坏、参数 nil 未检查导致 panic |
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
| **键值编码** | 编码格式不一致、NUL 字节碰撞二进制字段、偏移计算错误 | 统一使用 `database/keys.go` 二进制 BigEndian 编码函数；二进制字段用 offset-based 解析（不用 NUL 分隔）；每对 encode/decode 必须有 round-trip 测试 |
| **跨协议一致性** | 同类型 bug 在不同协议处理器中重复出现（DTLS/DTLCP 固定缓冲区） | 修复一个协议 bug 后，全局搜索相同模式到所有协议处理器 |
| **Pool buffer 生命周期** | `response.Data` 指向已归还的 pool buffer（use-after-free） | `pool.Put` 前必须 `response.Data = nil`，参考 `tcp.go` 的 `resp.Data = nil` 模式 |
| **TODO 管理** | TODO 注释累积但不实现，变成虚假安全感 | 每个 TODO 要么实现、要么改为 NOTE 并说明原因、要么删除 |
| **日志质量** | info/warn 在热路径重复打印刷屏；错误路径缺少上下文（无 qname/qtype/server）；日志级别误用（error 用于可恢复、debug 用于关键信号） | 每查询一条日志原则：info 仅用于状态变更，warn 仅用于可恢复异常且带采样，error 仅用于不可恢复；热路径日志全部 debug；每个日志含足够定位信息 |
| **文档腐烂** | 架构文档描述已删除的类型/字段/中间件；CLAUDE.md 类型参考表过时；注释引用的行号/函数名已失效；新功能无文档 | 每次 PR 检查受影响的 .md 文件；`grep` 文档中的类型名/函数名确认仍存在；注释中用 `FindSymbol` 而非行号引用代码 |
| **参数校验缺失** | 公开函数未检查 nil/空字符串/零值参数直接使用；构造后未验证字段有效性（如 `net.ParseIP("")` 返回 nil 后直接传入下游）；错误返回值被 `_` 丢弃，后续代码基于零值继续执行 | 每个公开函数入口处检查关键参数；`net.ParseIP` / `net.ParseCIDR` 结果立即判 nil；`_` 丢弃错误必须注释原因；构造函数返回前验证内部状态 |
| **提交信息不规范** | 使用 `Round X audit`、`fix audit findings` 等笼统描述，无法从 `git log` 了解具体改了什么 | 主题行描述**具体修复内容**（"fix: acquire writeMu in TCP SERVFAIL path"），不是审计阶段；一个 commit 只含一类修复；跨维度修复分多次提交 |
| **魔法数字** | 硬编码数值散落在业务逻辑中；默认值不符合 RFC 推荐；同一常量在多个包中独立定义 | `grep -nE '[0-9]{3,}'` 找长数字；与 RFC/IETF 标准值逐一对比；重复常量统一到 `config/defaults.go` 或所属包的最顶层 |
| **RFC 偏离** | 实现时对规范理解有误；边缘条件被省略；RFC 更新后实现未跟进；新增 RFC 未存档到 `docs/rfc/` | 每个协议实现文件顶部标注 RFC 章节引用；实现前先 `cp rfc{number}.txt docs/rfc/`；审计时逐条核对 MUST/SHOULD/MAY 条款 |
| **注释腐烂** | 代码移动/重命名/删除后注释未更新；注释引用的函数名/行号已失效；TODO 的触发条件已不存在但注释仍在；"临时方案"注释超过 6 个月未清理 | 每次重构后 `grep` 被移动符号的旧名确认无残留引用；注释中用函数名而非行号引用代码；每个 TODO 加截止日期，过期即处理 |
| **函数散乱** | 新增方法时随意插入在文件末尾或两个无关函数之间；同一接收者的方法跨文件散落；其他类型插入在主类型和其构造器之间 | 新增方法时找到同一接收者的方法块再插入；同一接收者的方法按调用链/复杂度排序（公开在前，私有在后）；在 `type → const → var → func` 顺序下，`New*` 应是 var 块之后的第一个 func；const/var 夹在类型和 `New*` 之间是**正确行为**（decorder 要求），不应标记为问题 |
| **手动有界缓存** | 用 `map[K]V` + `sync.Mutex`/`sync.RWMutex` 手写容量限制和淘汰逻辑，存在随机淘汰（`range` 第一个元素）、TOCTOU 窗口（check-then-set 不在同一锁内）、无界内存增长风险（清扫逻辑遗漏或 OOM 阈值过高） | 所有有界缓存统一使用 `lrumap.Map[K, V]`（`internal/lrumap`）：并发安全、LRU 淘汰语义、零手动锁。审计时 grep `map\[.*\].*sync\.(Mutex|RWMutex)` 查找未迁移的手动实现；`LoadOrStore` 替代 check-then-set 模式；确需自定义淘汰回调的场景才单独实现 |
| **冗余函数对** | `Foo(a)` + `FooWithB(a, b)` 成对出现：两者做同一件事，后者只是多了可选参数。不限于构造函数 — `Replace`/`ReplaceAll`、`Read`/`ReadWith` 等都适用。每增加一个可选参数就多一个函数，API 线性膨胀 | 合并为单一函数，可选行为通过导出字段/option 设置（如 `m.OnEvict = fn`）。审计时 `grep -rn 'func.*With[A-Z]' --include='*.go'` 找到所有 `With*` 函数，检查是否存在对应的无 `With` 版本 |
| **LRU 淘汰资源泄漏** | `lrumap.Map` 缓存持有可释放资源的值（网络连接、channel、句柄），淘汰时未设置 `OnEvict` 回调导致 goroutine/fd 泄漏 | 每个 `lrumap.New` 调用点审计：(1) 值类型是否实现了 `Close()` 或持有 channel/goroutine？(2) 是 → 必须设 `OnEvict`；(3) 否（纯数据）→ 无需 |
| **错误包装断裂** | 中间层函数用 `fmt.Errorf("...: %v", err)` 而非 `%w`，导致 `errors.Is`/`As` 在上层失效；或反之，用 `%w` 包装了不应暴露给调用方的内部 sentinel | `grep -rn 'fmt.Errorf.*%v.*err' --include='*.go'` 找出所有用 `%v` 包装 error 的地方，判断是否应改用 `%w`；`grep -rn 'errors\.Is\|errors\.As'` 确认 sentinel 可被检测到 |
| **Context 断裂** | 函数接受 `ctx` 但内部创建 `context.Background()` 或 `context.TODO()` 绕过取消链；goroutine 使用父 ctx 而非派生 ctx 导致取消泄漏 | `grep -rn 'context\.Background()\|context\.TODO()' --include='*.go'` 排除 `main.go` 和 `_test.go` 后审计每个调用点 |
| **Close 非幂等** | `Close()` 可被多次调用（shutdown 重试、defer 链），但实现未用 `sync.Once` 或 atomic 守卫 | `grep -rn 'func.*Close()' --include='*.go'` 检查每个 `Close()` 方法是否有 `sync.Once`、`atomic.CompareAndSwap` 或 nil channel 守卫 |
| **Goroutine 无 owner** | goroutine 被 `go func()` 启动后无任何机制等待其退出；父函数返回后子 goroutine 成为孤儿 | `grep -rn 'go func' --include='*.go'` 排除 `_test.go`，审计每个 goroutine 是否被 errgroup/WaitGroup/channel 追踪 |
| **Go 特性滞后** | 代码停留在旧版 Go 风格 — 手写模式已有标准库替代（如 `errors.As` 循环 → `errors.AsType[T]`、手写反向切片 → `slices.Reverse`/`slices.Backward`、`fmt.Errorf("x")` 可受益于新版分配优化） | `go fix ./...` 检查是否有未应用的现代器；`grep -rn 'errors\.As(' --include='*.go'` 检查可否替换为 `errors.AsType[T]`；`grep -rn 'for i := len' --include='*.go'` 检查手写反向迭代 |

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
5. **KV key 构造用二进制 BigEndian，不用 fmt.Sprintf**：字符串字段用 `\x00` 分隔，数值字段用 `binary.BigEndian.PutUint*` 写入固定偏移。二进制字段含 `0x00` 时 NUL 解析会错位——key 解析函数必须用 offset-based 而非 NUL 扫描。每对 encode/decode 必须对应
6. **每查询一条日志原则**：hot-path（每次查询都经过的路径）只用 Debug；Info 仅用于状态变更（启动/关闭/重载）；Warn 用于可恢复异常且应带采样或限流；Error 仅用于不可恢复
7. **日志必须含定位信息**：错误/Warn 日志至少包含 qname/qtype/server/error 中与上下文相关的字段；不要打印"query failed"而没说哪个查询
8. **禁止 info/warn 在热路径**：`log.Infof` / `log.Warnf` 不得出现在每次查询都会执行的代码路径中（如 ServeDNS、middleware Wrap、upstream Exchange）。每查询超过一条 info/warn 即为刷屏
9. **文档与代码同步更新**：修改函数签名、删除类型/字段、新增/删除中间件时，检查 `docs/*.md` 和 `CLAUDE.md` 是否引用该符号；用 `git grep` 确认
10. **注释引用符号名，不引用行号**：行号在每次编辑后失效。注释中如果必须引用代码位置，使用函数名/类型名（可 grep），而非行号
11. **`_` 丢弃的值必须注释类型和原因**：`result, _ := someFunc()` 必须注释 `// _ = error: <原因>`，防止被调用函数签名变更后 `_` 静默丢弃不同类型的值。不写注释的 `_` 在重构时是定时炸弹——函数返回值从 `(T, error)` 变为 `(T, Cleanup)` 时编译通过但语义全变
12. **废弃参数应删除而非改名 `_`**：`func f(name, target string)` 中如果 `name` 不再使用，应将 `name` 从签名中删除并更新所有调用方，而不是改成 `func f(_, target string)`。`_` 参数只用于接口实现（无法改签名）和 callback（协议要求）。Standalone function 的 `_` 参数是 dead code
13. **魔法数字必须抽取为命名常量**：任何数值字面量（超时、端口、缓冲区大小、重试次数）必须定义为 `config/defaults.go` 或所在包顶部的命名常量。常量值必须与 RFC/IETF 推荐值一致。同一常量只定义一次，跨包引用
14. **新增 RFC 必须存档后再实现**：引入新协议或修改现有协议实现前，先将对应 RFC 文本放入 `docs/rfc/`（命名 `rfc{NUMBER}.txt`），阅读确认 MUST/SHOULD/MAY 条款，再编码。代码中引用 RFC 时注明具体章节号（如 `RFC 7873 §5.2`）
15. **注释引用符号名而非行号**：行号在每次编辑后失效。注释中引用代码位置使用函数名/类型名（可 grep），而非行号。代码移动后立即 grep 旧符号名检查注释残留
16. **构造函数紧跟类型定义**：在 `type → const → var → func` 顺序下，`type Foo struct` 之后的 const/var 是正常的（decorder 要求），`func NewFoo` 应是 var 块之后的**第一个 func**。不应有其他类型或其他接收者的方法插入在 `type Foo` 和 `func NewFoo` 之间。同一接收者的方法聚合在一个连续块中，不跨文件散落 |
17. **有界缓存统一用 lrumap**：任何需要容量上限的缓存（证书、HTTP client、proxy dialer、连接配置）统一使用 `lrumap.Map[K, V]`（`internal/lrumap`）。它内置并发安全 + LRU 淘汰 + `LoadOrStore` 原子操作。禁止用 `map[K]V` + `sync.Mutex` 手写淘汰逻辑 — 这种模式在审计中反复出现且每次实现都有细微并发 bug（TOCTOU、随机淘汰而非 LRU、清理泄漏） |
18. **可选行为用导出字段，不用冗余函数对**：`Foo(a)` 是唯一函数；可选回调/配置通过导出字段设置（如 `m.OnEvict = fn`）。禁止 `Foo(a)` + `FooWithB(a, b)` 成对出现 — 不限构造函数，`Replace`/`ReplaceAll`、任何 `DoX`/`DoXWithY` 都算。每增加一个可选参数就多一个函数，API 线性膨胀。审计命令：`grep -rn 'func.*With[A-Z]' --include='*.go'` 列出所有带 `With` 的函数，人工核对是否存在对应的无 `With` 版本 |
19. **lrumap 持有资源型值必须设 OnEvict**：如果 `lrumap.Map[K, V]` 的 V 是 `*socks5.Dialer`、`*pendingCall`（含 channel）、`*http.Client` 等持有 goroutine/fd/连接的资源型值，必须设 `OnEvict` 回调释放资源。纯数据值（`string`、`int`、`time.Time`、不可变 struct）无需。审计方法：列出所有 `lrumap.New` 调用点，对每个值类型判断是否实现了 `Close()` 或包含 `chan`/`sync.WaitGroup` 字段 |
20. **错误包装用 %w 不用 %v**：`fmt.Errorf("context: %w", err)` 保留错误链，`errors.Is`/`As` 可穿透。仅在有意对上层隐藏实现细节时才用 `%v`。审计命令：`grep -rn 'fmt.Errorf.*%v.*err'` |
21. **每个 goroutine 都要有 owner**：`go func()` 启动后，要么被 errgroup 追踪，要么通过 `done` channel/`ctx.Done()` 被父 goroutine 管理。fire-and-forget goroutine 必须有 `defer HandlePanic`。审计命令：`grep -rn 'go func' --include='*.go'` |
22. **Close 必须幂等**：`Close()` 多次调用不 panic，不 double-close channel。实现模式：`sync.Once`、`atomic.CompareAndSwapInt32`、或 nil channel 检查 |
23. **跟踪 Go 版本特性采用**：每次 Go 版本升级后审计：`go fix ./...` 应用现代器；`errors.As` → `errors.AsType[T]`；`slices.Backward` 替代手写反向迭代；`new(expr)` 简化指针构造。通过 `grep -rn 'for i := len.*-1' --include='*.go'` 找手写反向循环 |

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
12. **魔法数字散落**：`time.Second * 30`、`65535`、`4096` 等裸数值直接出现在业务逻辑中。应全部抽取为命名常量并统一在 `config/defaults.go`
13. **常量值不符合 RFC**：如 DNS 端口写成 `5353` 而非 RFC 1035 规定的 `53`；缓冲区大小不遵循 RFC 6891 的 `1232`/`65535` 等。所有常量值必须可追溯到具体 RFC 章节
14. **乱序插入**：在文件末尾或两个无关函数之间随意插入新增方法。应找到同一接收者的方法块，按 `公开 → 私有`、`简单 → 复杂` 的顺序插入
15. **`New*` 与类型之间有其他类型或方法**：其他类型或其他接收者的方法插入在 `type Foo struct` 和 `func NewFoo` 之间。const/var 在二者之间是**正确的**（decorder 要求 `type → const → var → func`）——这不是问题。问题是插入了不相关的 type 或 method |
16. **注释残留**：代码已删除/移动/重命名但旧注释还在原地；TODO 的截止日期已过但无人处理；注释说"临时方案"但已存在超过两个版本
17. **新 RFC 未存档**：实现了新协议功能但 `docs/rfc/` 中没有对应 RFC 文本。先存档 RFC，再编码
18. **手写有界 map**：用 `map[K]V` + `sync.Mutex` + `len >= cap` 检查 + `range` 随机踢一个来实现"有界缓存"。这不能保证 LRU 语义，`range` 在 map 上的迭代顺序是随机的，且 check-then-set 和 check-evict-set 存在 TOCTOU 窗口。应使用 `lrumap.Map[K, V]` |
19. **冗余函数对**：`Foo(a)` + `FooWithB(a, b)` 成对出现。可选行为应通过导出字段设置（`m.OnEvict = fn`），而非新建函数。不限构造函数 — `Replace`/`ReplaceAll`、`Read`/`ReadWith` 等都适用。每增加一个可选参数就多一个函数，API 线性膨胀 |
20. **lrumap 持有资源型值未设 OnEvict**：V 为 `*socks5.Dialer`、`*pendingCall`（含 channel）、`*http.Client` 等持有 goroutine/fd 的类型，淘汰时不调用 `OnEvict` 导致资源泄漏 |
21. **错误包装用 %v**：`fmt.Errorf("...: %v", err)` 切断了错误链 — 上层的 `errors.Is(err, ErrFoo)` 永远返回 false。应默认用 `%w`，仅在故意隐藏实现细节时用 `%v` 并注释原因 |
22. **Context 断裂**：函数签名有 `ctx context.Context`，内部却 `context.Background()` 绕过取消链；或 goroutine 继承了父 ctx 导致父函数返回后 goroutine 立即被取消 |
23. **Close 非幂等**：`Close()` 无 `sync.Once`/atomic 守卫 — 第二次调用 double-close channel 导致 panic，或重复关闭连接产生竞态 |
24. **Goroutine 无回收**：`go func()` 后无任何机制等待其退出 — errgroup、WaitGroup、done channel 三者至少有一 |
25. **Go 特性滞后**：手写 `for i := len(s)-1; i >= 0; i--` 反向迭代（用 `slices.Backward`）、`errors.As` 循环（用 `errors.AsType[T]`）、裸 `new(T)` 可简化为 `new(expr)` |

### 6.3 BadgerDB 专项审计

ZJDNS 使用 BadgerDB v4 LSM-tree KV 存储（`github.com/dgraph-io/badger/v4`）。以下 API 和行为是审计的关键基准。

#### 6.3.1 BadgerDB API 参考

| API | 用途 | 审计关注点 |
|-----|------|-----------|
| `db.View(fn)` | 只读事务 | 闭包内不应调用 `txn.Set`/`txn.Delete`（会 panic）。View 不阻塞 Update |
| `db.Update(fn)` | 读写事务 | 同步提交，适合关键数据。不应在热路径用 `Update` 写大批量数据 |
| `WriteBatch` | 异步批量写入 | 内部自动拆分大事务，异步提交。适合 stats 等 best-effort 数据。`wb.Set` 错误应检查 |
| `Entry.ExpiresAt` + `Item.ExpiresAt()` | 原生 TTL 过期 | 直接赋值 `Entry.ExpiresAt = uint64(now + dur)` 替代 `WithTTL()`。LSM compaction 时自动清理。TTL 值 = DNS TTL + stale max age。读时通过 `Item.ExpiresAt()` 反推 timestamp |
| `Entry.WithMeta(b)` | 1 字节元数据 | ZJDNS 用 `UserMeta` 存 `validated` 标志（0/1）。`Item.UserMeta()` 读取 |
| `Item.IsDeletedOrExpired()` | 条目有效性检查 | 遍历时过滤已过期/已删除条目，避免对僵尸条目操作 |
| `Item.ExpiresAt()` | 读取 TTL 时间戳 | BadgerDB 原生 API，不需要在 value 里存 `expiresAt` |
| `Item.KeyCopy(dst)` | 安全的 key 复制 | 跨迭代保存 key 时必须用 `KeyCopy`，`item.Key()` 仅在 `it.Next()` 前有效 |
| `Sequence` | 单调递增 ID | bandwidth=1000（租约 1000 个 ID 后才写盘）。crash 时最多丢失 1000 个 ID，可接受 |
| `DropPrefix(p)` | 批量删除 | 阻塞所有写入直到完成。适合管理操作，不适合热路径 |
| `RunValueLogGC(ratio)` | vlog 垃圾回收 | ValueThreshold≥64KB 后 vlog 基本为空，不必定期调用 |
| `Subscribe(ctx, cb, matches)` | 进程内 pub/sub | 不能用于跨实例缓存一致性。仅进程内通知 |
| `Stream` / `StreamWriter` | 并发迭代 / 快速导入 | 适合备份恢复。Stream 产生无序输出。StreamWriter 覆盖已有数据 |
| `MergeOperator` | 读-改-写优化 | 盲写增量，compaction 时合并。每个 key 一个 goroutine + ticker，不适合大量唯一 key 的 stats |
| `WithValueThreshold(n)` | LSM inline 阈值 | 当前 64KB：DNS 值全部 inline，无 vlog IO |
| `WithIndexCacheSize(n)` | Bloom filter 缓存 | 当前 64MB：移出 Go heap，减少 GC 压力 |
| `WithNumVersionsToKeep(1)` | 禁用 MVCC | 每条 key 只保留最新版本，`DiscardEarlierVersions` 冗余 |
| `WithDetectConflicts(false)` | 禁用冲突检测 | 缓存 upsert 模式，last-writer-wins 语义正确 |
| `WithCompression(options.ZSTD)` | block 级 zstd | SSTable block 级压缩，应用层不应再做 zstd（双重压缩浪费 CPU） |

#### 6.3.2 BadgerDB 常见反模式

1. **应用层 zstd + BadgerDB zstd 双重压缩**：zdnsutil.Compress 后存入 BadgerDB，BadgerDB 再做 block 级 zstd。zstd 压缩已压缩数据无效，浪费 CPU。解法：直接存 raw wire，信任 BadgerDB block 级压缩
2. **手写 TTL 驱逐替代原生 ExpiresAt**：自己扫描、排序、删除过期条目。`Entry.ExpiresAt` 直接赋值 + `IsDeletedOrExpired` 更高效，compaction 自动回收空间
3. **value 里存冗余 metadata 字段**：BadgerDB 原生 `ExpiresAt` 管理物理过期，`UserMeta` 存储 validated 标志。value 即 raw DNS wire — timestamp 和 entryTTL 均在读时从 BadgerDB/解包后的 wire 反推，零 header 开销
4. **`fmt.Appendf` 构造 key**：每次分配 + reflect。应用层 key/value 编码都用 `binary.BigEndian.PutUint*` + `copy`，与 value 编码风格一致
5. **NUL 分隔符解析二进制字段**：数值字段 BE 编码可能含 `0x00` 字节（如 qtype=A=1 编码为 `[0x00, 0x01]`）。NUL 扫描会将这些字节误认为分隔符。解法：固定偏移 offset-based 解析
6. **绕过 `database.DB` 包装层直接访问 `.Badger`**：所有调用方应通过 `db.View`/`db.Update`/`db.DropPrefix` 等方法访问，统一内置 `IsClosed` 检查
7. **stats 用 `db.Update` 同步事务而非 `WriteBatch`**：`Update` 同步提交，stats 写多了阻塞热路径。`WriteBatch` 异步提交 + 内存预聚合是正确方案
8. **`Sequence` bandwidth 过大或过小**：bandwidth=1000 平衡 crash 容忍（最多丢 1000 个 ID）和写盘频率。bandwidth=1 每次 `Next()` 都写盘
9. **`NumVersionsToKeep(1)` 与 `DiscardEarlierVersions` 同时使用**：前者已全局禁用 MVCC，后者完全冗余
10. **prefix scan 不设 `PrefetchValues=false`**：只计数时不读 value，省一次 LSM 查找
11. **`Item.Key()` 跨迭代使用**：`it.Next()` 后 key 可能被覆盖，跨迭代保存必须 `Item.KeyCopy(nil)`
12. **`Entry.WithDiscard()` 标记而非 `txn.Delete`**：对于大批量删除，标记丢弃让 compaction 回收比立即删除更高效

### 6.4 持续改进

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
- 每次审计包含 CrossCut Constants 阶段：grep 长数字字面量（`\d{3,}`）确认已抽取为命名常量；逐项对比常量值与 RFC 推荐值；`grep -rn 'const\|Default' config/defaults.go` 确认无跨包重复定义
- 每次审计包含 CrossCut RFC 阶段：检查 `docs/rfc/` 目录确认所有协议实现有对应 RFC 存档；grep RFC 注释引用确认编号和章节号有效；逐条核对 MUST/SHOULD 条款覆盖率
- 每次审计包含 CrossCut Comments 阶段：grep 注释中的函数名/类型名与 `go doc` 交叉验证仍存在；grep `TODO\|FIXME\|HACK\|临时` 确认每个有截止日期且未过期；检查被移动/删除代码附近的注释是否仍有残留引用
- 每次审计包含 CrossCut Ordering 阶段：检查每个 `New*` 函数是否紧跟对应类型定义；检查同一接收者的方法是否聚合而非散落；检查声明顺序 `type → const → var → func`（`decorder` linter 已覆盖）；检查文件末尾是否有随机插入的新函数（无前置关联）
- 每次审计包含 CrossCut RedundantPairs 阶段：`grep -rn 'func.*With[A-Z]' --include='*.go'` 列出所有带 `With` 的函数，核对是否存在对应的无 `With` 版本 → 合并为导出字段；`grep -rn 'lrumap\.New\[' --include='*.go'` 列出所有 lrumap 实例，逐个检查值类型是否持有资源 → 是否设了 `OnEvict`
- 每次审计包含 CrossCut Error 阶段：`grep -rn 'fmt.Errorf.*%v.*err' --include='*.go'` 找出所有用 `%v` 包装 error 的位置，判断是否应改用 `%w`；`grep -rn 'errors\.Is\|errors\.As'` 确认 sentinel 可被检测到
- 每次审计包含 CrossCut Context 阶段：`grep -rn 'context\.Background()\|context\.TODO()' --include='*.go'` 排除 `main.go` 和 `_test.go` 后审计每个调用点
- 每次审计包含 CrossCut Goroutine 阶段：`grep -rn 'go func' --include='*.go'` 排除 `_test.go`，审计每个 goroutine 是否有 owner（errgroup/WaitGroup/channel）、是否有 `defer HandlePanic`
- 每次审计包含 CrossCut Resource 阶段：`grep -rn 'func.*Close()' --include='*.go'` 检查每个 `Close()` 是否有 `sync.Once` 或 atomic 守卫，确保幂等
- 每次审计包含 CrossCut GoVersion 阶段：`go fix ./...` 应用所有现代器；`grep -rn 'for i := len.*-1\|for i := .*-1;.*>=' --include='*.go'` 找手写反向迭代 → `slices.Backward`；`grep -rn 'errors\.As(' --include='*.go'` 评估 → `errors.AsType[T]`
- 每次审计包含 CrossCut Flowcharts 阶段：检查 `docs/FLOWCHARTS.md` 中的 mermaid 流程图是否覆盖了所有核心功能和协议 —— 整体架构、中间件管道、缓存查询、递归解析、DNSSEC 验证链、EDNS 处理、四层防御（含每种详解）、TC→TCP 回退、连接池与协议协商、SOCKS5 代理、Zone 规则、Singleflight 去重、DNS64 合成、DNSCrypt 密钥管理、异步统计写入、规则集引擎、延迟探测、服务生命周期。新增特性/协议/中间件时必须同步更新流程图。

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
