# AUDIT-METHODOLOGY.md — ZJDNS 审计 playbook

ZJDNS 全仓库审计的可复用手册，覆盖：并行包级审计、交叉维度扫描、Sprint 修复、
对抗性修复面复查（Round C）、全协议 E2E 回归、防御注入矩阵、benchmark 分配契约。
下一轮照此执行：基线 → Phase 1 并行审计 → 修复 → Round C 复查 → E2E → 文档。

目标设定：**按轮审计，直到一轮审计不再产生新发现为止。** 每个修复带红灯→
绿灯回归测试；每轮把新根因模式落进 §5（同一错误不审计两次）。轮次不设
独立存档——教训就地沉淀进本文件（§5 根因模式表），历史修复明细以 git log 为准。

## 1. 基线（每轮开头）

```sh
sh scripts/prepare-etls.sh          # eTLS replacement 目录就绪（每 clone 一次）
go build ./...                      # 零编译错误
go test -short ./... -count=1       # 全部测试（看退出码，勿接管道 tail）
golangci-lint run                   # 零警告
go test -bench=. -short -benchtime=500ms -benchmem ./...   # 基线数字
```

- 重点面 = 上一轮以来的提交 diff（`git log <上轮基线>..HEAD`）——迁移类
  commit 逐个亲审（eTLS/协议栈迁移的历史事故多在自己引入的接合点）。
- 依赖升级不搭审计便车：先独立提交（build+test 绿），再开审计轮。

## 2. 审计架构与维度

Phase 1：7 个并行只读包级审计（foundation=`internal/*`、domain=`config/cache/edns/zone/ruleset/spillfile`、
protocol、upstream、resolver、handler、defense）——每个 agent 先读上轮教训避免重复报告。
Phase 2：交叉维度扫描（锁、内存、panic、错误包装 %w、context 传播、goroutine
owner、Close 幂等、参数校验、死代码、性能、架构分层、日志、文档一致性、
常量与 RFC 值、RFC 引用有效性、注释准确性、声明顺序、Go 版本特性、流程图覆盖）。
Phase 3：综合排序 → Sprint 分批修复 → **Round C 对抗复查**（逐 commit 读 diff，
专抓"修复自身引入的回归"——连续两轮复查无新发现才收尾）。

20 个审计维度里最易出活的入口（grep 命令即审计命令）：

| 维度 | 入口 |
|------|------|
| 错误包装 | `grep -rn 'fmt.Errorf.*%v.*err'`——应 %w 的位置 |
| context 断裂 | `grep -rn 'context.Background()\|context.TODO()'`（排除 main/test） |
| goroutine owner | `grep -rn 'go func'`——逐一核对 errgroup/WaitGroup/done channel + HandlePanic |
| Close 幂等 | `grep -rn 'func.*Close()'`——sync.Once / atomic CAS / nil 守卫 |
| 手写有界缓存 | `grep -rn 'map\[.*\].*sync\.(Mutex|RWMutex)'`——应迁移 `lrumap` |
| 冗余函数对 | `grep -rn 'func.*With[A-Z]'`——Foo/FooWithB 合并为导出字段 |
| lrumap 资源泄漏 | `grep -rn 'lrumap.New'`——值持 fd/goroutine 必须 OnEvict |
| 魔法数字 | `grep -nE '[0-9]{3,}'`——抽常量、对 RFC 推荐值、跨包唯一 |
| Go 特性滞后 | `go fix ./...`；`errors.As`→`errors.AsType[T]`、手写反向循环→`slices.Backward` |
| 注释风格 | 日期/审计编号/pprof 战史/`previously` 叙述不得出现（现在时约束） |
| 流程图覆盖 | 新特性/协议/中间件必须同步 `docs/FLOWCHARTS.md`（mermaid 可渲染） |

## 3. 修复流程

| Sprint | 范围 | 标准 |
|--------|------|------|
| 1 | CRITICAL/HIGH | 立即——数据损坏、崩溃、DoS、防御绕过 |
| 2 | MEDIUM | 资源耗尽、竞态、缓存污染、安全一致性 |
| 3 | LOW | 注释漂移、微优化、纪律缺口 |

- 优先序：单行修复 → 模式匹配修复（可模板化）→ 逻辑重写 → 死代码删除。
- 每个修复**带回归测试**（先证明测试在修复前失败）；一类修复一个 commit，
  主题行写具体修复内容 + 审计编号（`fix: … (R1)`），禁止 `fix: audit fixes`。
- 提交前：`go fix ./... && golangci-lint run && golangci-lint fmt`（零警告）。

## 4. 质量门禁

### 4.1 benchmark 回归

```sh
# 刷新基线（必须 -benchmem：alloc 回归不体现在 ns/op）
go test -bench=. -short -benchtime=500ms -benchmem ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
```

| 指标 | 判定 |
|------|------|
| ns/op >15% 变慢 | 回归——回滚或优化 |
| allocs/op 任何增加 | **回归**——零分配路径（缓存命中直发）的分配是契约破坏 |
| 异常快/慢 | 先验证 benchmark 测的是预期路径（响应断言），再下结论 |
| 跨版本对比 | `git worktree add` 在旧 commit 上跑同命令（同机同参数才可比）；依赖浮动后的分配回归用此法归因（同数字=上游代价） |

### 4.2 E2E 门禁

14 协议专用口 + 7 组共享端口 + MQTYPE（forward/递归合并/FORMERR）+ 递归真网
（DNSSEC + CNAME 链）+ **无 EDNS TCP 缓存命中**（防直发路径盲区）+ 12 协议压测
（fail=0；环境噪声以修复前二进制同签名复现排除）+ 内存两轮压测精确一致 +
`-race` 全绿 + 域名清单全量解析 A/B（新旧失败集合 diff 为空）。全协议方法见
`docs/debug/DEBUG.md` 与 `docs/benchmark/LOADTEST.md`。

### 4.3 防御注入矩阵

确定性注入测试台（`docs/poc/interception`）：脚本化上游按威胁模型（bare /
case-blind / EDNS-forging）注入 N 个逐包变化假应答 + 延迟真答，逐守卫组合
计数泄漏率——**单开 × 组合 × 三威胁模型全 0 泄漏**；无守卫基线必须 100% 泄漏
（证明测试台有效）。测试台自身也是被审对象。

### 4.4 pprof 取证

allocs 差分（负载前后各采一次，`-base` 归因 B/查询）→ CPU 画像（健康缓存
命中路径 syscall/netpoll>90%、应用栈个位数）→ goroutineleak 必须为空 →
内存两轮精确一致。**平台墙**：macOS loopback ~10⁵ qps 数据报过栈墙——跨机
QPS 对比失效，可比的是分配与 CPU/查询。疑象先做判别实验再归因（换池实现、
调 GOGC、QPS-vs-worker 的 Little 定律校验）。

## 5. 根因模式（历轮沉淀——修复前先对照）

| 模式 | 根因 | 预防 |
|------|------|------|
| **池归还纪律** | 协议处理器独立开发，缺共享模板 | 新协议以 TLS DoT handler 为模板；每个 `Get()` 配对 `defer Put()`；`Put` 前 `Data=nil` |
| **并发安全** | 临界区过窄/缺失、锁-drop 窗口 | 锁保护区注释化；`-race` 必过 |
| **防御算法** | 状态机缺逃逸路径、过度拒绝合法响应 | fuzz + 边界用例；降级路径逐条问"凭什么清标" |
| **跨协议一致性** | 同型 bug 在多协议处理器重复 | 修一处后全局搜同模式 |
| **spill 持久化** | 追加写静默失败、索引失步、启动扫描错位 | Put/Compact 错误必记日志；Compact 全程持锁 + temp/rename 原子替换；损坏区分冷启动 |
| **Pool buffer 生命周期** | `response.Data` 指向已归还缓冲（use-after-Put） | 归还前置 nil；struct 字面量里先读派生值再 Release |
| **TODO 管理** | TODO 累积成虚假安全感 | 实现、改 NOTE 说明原因、或删除 |
| **日志质量** | info/warn 热路径刷屏；缺定位信息 | 每查询一条日志原则：热路径 Debug；warn 采样；error 不可恢复；日志带 qname/qtype/server |
| **文档腐烂** | 架构文档描述已删类型；AGENTS.md 过时 | 每次 PR grep 受影响 .md；符号名引用而非行号 |
| **参数校验缺失** | 公开函数不查 nil/空值；`net.ParseIP` 结果未判 nil；`_` 丢错未注释 | 入口校验；`_` 必须注释类型与原因；standalone 函数的 `_` 参数直接删 |
| **提交信息不规范** | `fix: audit fixes` 无法 bisect | 主题行写具体修复内容 + 审计编号 |
| **魔法数字** | 裸数值散落；跨包重复定义 | 抽常量到 `config/defaults*.go`；可追溯 RFC 章节 |
| **RFC 偏离** | 理解偏差/边缘省略/新 RFC 未存档 | 实现前 `cp` 进 `docs/rfc/`；代码引用带章节号；实现后跑合规探针 |
| **注释腐烂** | 引用已移动符号、过期 TODO、行号引用 | 重构后 grep 旧符号名；TODO 带截止日期 |
| **函数散乱** | 方法随机插入；同一接收者跨文件散落 | 找到接收者方法块再插入；`New*` 紧跟类型（const/var 夹在中间是 decorder 要求，正常） |
| **手动有界缓存** | map+mutex 手写淘汰：随机淘汰、TOCTOU、无界增长 | 统一 `lrumap.Map[K,V]`（LoadOrStore 原子）；自定义淘汰才单独实现 |
| **冗余函数对** | `Foo` + `FooWithB` 成对膨胀 | 合并为单一函数 + 导出字段（如 `m.OnEvict`） |
| **LRU 淘汰资源泄漏** | lrumap 值持连接/goroutine 无 OnEvict | 每个 `lrumap.New` 调用点核对值类型 |
| **错误包装断裂** | `%v` 切断错误链 | 默认 `%w`；有意隐藏才 `%v` 并注释 |
| **Context 断裂** | 签名带 ctx 内部绕过；goroutine 继承父 ctx | 排除 main/test 逐点审；`WithoutCancel` 剪断一切取消链——要根取消传播用根 ctx 派生 |
| **Close 非幂等** | 二次 Close panic/竞态 | sync.Once / atomic CAS / nil channel |
| **Goroutine 无 owner** | fire-and-forget 孤儿 | errgroup/WaitGroup/done 三选一 + `defer HandlePanic` |
| **Go 特性滞后** | 手写模式已有标准库替代 | `go fix`；`errors.AsType`、`slices.Backward`、`new(expr)` |
| **预打包响应重 Pack** | 帧写入方无条件 Pack——预打包命中变 12 字节头帧 | 守护 `len(Data)==0` 才 Pack；E2E 必含无 EDNS TCP 缓存命中 |
| **池槽位所有权别名** | getter 返回槽内指针与后续 Put 悬垂 | 返回即清槽（所有权转移）或文档化契约 |
| **错误变量遮蔽** | 内层 `resp, err :=` 遮蔽外层 → 返回 (nil, nil) | 内外层用不同变量名（acqErr/exErr） |
| **池归还后读取** | 同语句里 ReleaseWire 先于字段求值执行 | 归还前把派生值读入局部变量 |
| **上下文键误用** | `http.ServerContextKey` 存的是 Server 不是 Conn；非 stdlib TLS 栈需显式通道 | 断言前查 stdlib 键的真实类型；E2E 验证凭据非空 |
| **修复引入回归** | 修复带新缺陷；验证只盯原始发现不看 diff | Round C：逐 commit 读 diff + 全量测试 + 声称行为的 E2E 复验 |
| **注入测试台保真度** | 伪造包不经意携带真实流量特征（SetReply 复制 DO 位→物化 OPT） | 裸 GFW 模型显式 `Security=false`；多威胁模型开关逐一标注 |
| **测试台状态泄漏** | 全局预热计数跨场景泄漏；残留进程占端口 | 每场景重启 rig；跑前 pgrep/lsof 清场；抽查日志确认防御路径真实执行 |
| **单开 Guard 缺口** | 组合测试全绿掩盖单开缺口 | 矩阵含"每 guard 单开 × 每威胁模型"；降级路径的接受逻辑重审 |
| **水平触发轮询自旋** | poll(2) + MSG_PEEK 不消费 → 全核自旋 | 零进展指数退避 + POLLRDHUP/POLLHUP + POLLERR/NVAL；测试断言 CPU 而非只断言正确性 |
| **聚合点丢标记** | per-hop 安全标记在聚合层被丢弃/覆盖 | 聚合显式传播 + AND 语义；E2E 覆盖特性声称的每条路径 |
| **预计算 keys 与增长容器失步** | 循环内 append 增长 dst，预计算 keys 越界 | keys 与容器 lockstep 增长；单测覆盖"追加后再去重" |
| **地址级状态冒充 per-query 验证** | "基线已武装"被当作"本包已验证" | 验证标记 per-query 传播；每条降级路径问"凭什么清标"（TTL=0/分歧态都否） |
| **校验依赖死代码分支** | `SplitHostPort("http://host")` 不报错 → URL 校验从不执行 | URL 族直接 url.Parse 查 scheme/host；测试含 http:// 形态 |
| **closed-channel select 自旋** | 一次性信号 case 拿到 closed channel 永远 ready → 紧自旋烧核 | case 体内 `ch = nil`（一次性语义）；测试断言 CPU share |
| **注册-重注册轮次失配** | 循环内每轮新 key 注册，break 进下一轮时本轮注册泄漏 | 枚举全部 break/return 出口核对配对；maxPipe=1 类微型配额让单次泄漏可观测 |
| **防御状态机异常出口降级** | conn 死亡/预算耗尽出口绕过正常确证纪律 | 异常出口跑同一确证标准；滴注攻击（间隔<窗口）显式测试 |
| **恢复路径采样捕获** | 拒绝样本 1/N 回灌无内容门/上限——N 倍速灌包赢众数竞争 | 独立直方图 + 按 verified 流量比例封顶合并（一次性副本）；拒绝路径不驱动重建节拍；保留时间重建防纯漂移锁死 |
| **多实例字段 last-wins** | 多 shard 启动把各自状态发布到共享字段 | per-instance 状态走参数；多实例启动路径进 E2E |
| **依赖浮动 alloc 归因** | 升级后 bench 跨包一致 +N allocs，误判给本地改动 | worktree 隔离（仅含依赖 bump 的 commit 跑同参数 bench）归因 |
| **后台最优化任务无准入上限** | 逐 key 去重 + 引擎内部信号量不约束**排队调用方**——flood 旋转 distinct key，每个调用 spawn 一个阻塞在引擎信号量上的 goroutine，无界增长（测速轮：任意 distinct 多 A 域名 × bgGroup 无 SetLimit） | best-effort 优化任务在 spawn 点加轮次上限（非阻塞 try-acquire，满了就丢——丢弃是正确语义）；回归测试断言 spawn 数 ≤ 上限而非只断言功能正确 |

## 6. 环境陷阱清单

- **管道接 `| head`/`| tail` 会吞退出码**——全量测试判定用 exit code——
  管道截断会吞掉 FAIL 行。
- **压测/测试残留进程占端口**：QUIC 复测全挂实为前轮进程未退净占用 UDP 口——
  跑前 `pgrep` + `lsof` 清场。
- **zsh 不做 word-splitting**：`$var` 展开成单参数——脚本用显式分支或 `sh -c`。
- **dig 无 EDNS/大小写变体要显式混入**：全用 DNSSEC 域名会把预打包直发路径整个
  掩盖（RR sections 过滤强制走解包）。
- **测试台/夹具也是被审对象**：DO=1 下 rig 真答 pack 失败曾让整个防御矩阵失效
  （假 NO RESPONSE）；伪造包要显式控制 OPT/DO 位。
- **外部 helper 会失效**：文档引用的第三方测试工具（如 go-socks5 cmd 包）上游
  会删除——依赖的测试工具收编进仓库（docs/debug/socks5srv 先例）。
- **RFC 探针教训**：扩展 RCODE 在响应 OPT TTL 高字节（只读 header 低 4 位会把
  BADVERS 误判成 NOERROR）；手工构造 DNS 包 ARCOUNT 必须与附加节匹配；EDNS
  TTL 布局 = ext-rcode(31..24) | version(23..16) | DO(15) | Z(14..0)。

## 7. 收尾闭环

1. 修复 → 全量测试 + lint 零警告 → bench 基线对比（§4.1）→ E2E 门禁（§4.2）。
2. Round C 复查无新发现 → 刷新 `docs/benchmark/benchmark-baseline.txt` 与
   `loadtest-baseline.txt` → 新根因模式落进 §5 → 流程图同步（`docs/FLOWCHARTS.md`）→
   AGENTS.md / ARCHITECTURE.md 与代码一致性核对。
3. 提交风格：约定式粒度（`fix:`/`perf:`/`docs:`…），一类修复一个 commit，
   文档与代码分开；Co-authored-by 只留一行。
