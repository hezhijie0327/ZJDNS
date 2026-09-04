# POC 精华指南

防御机制概念验证程序速查。每个 POC 的完整说明（问题 → 原理 → 演示输出 → 关键洞察）
见 [README.md](README.md)；本文提炼算法要点与代码/界面约定，**新增或修改 POC 前必读**。

## 一览表

| POC | 防御层 | 镜像源码 | 关键函数 | `-real` 上游 |
|-----|--------|----------|----------|-------------|
| **hopguard** | UDP upstream（IP TTL 指纹） | `server/defense/hopguard.go` | `HopGuard.Validate` / `Feed` | 8.8.8.8:53 |
| **spoofguard** | UDP upstream（多读注入检测） | `server/upstream/plain/udp.go` | `processPacket` / `pickBest` / `executeUDPCollect` | 8.8.8.8:53 |
| **splitguard** | TCP upstream（DPI 分段规避） | `internal/dnsutil/tcpframe.go` | `WriteTCPMsgSegmented` | 8.8.8.8:53 |
| **poisonguard** | Recursive（root/TLD 劫持检测） | `server/defense/poisonguard.go` | `Detector.Validate` / `IsPoisonedByTLD` | root/TLD 服务器 |
| **capsguard** | 所有 upstream（DNS 0x20 随机化） | `server/defense/capsguard.go` + `server/upstream/client.go` | `RandomizeCase` / `ExecuteQuery` | 8.8.8.8:53 |

## 各 POC 算法精华

### HopGuard — IP TTL 指纹
- 学习 32 个样本后武装：`threshold = max(mode_freq/4, 4)`，mode 恒过，邻居需达阈值
- 判定：TTL 在 `trusted ± 2` 内通过，否则拒绝；每 32 样本历史 ×¾ 衰减（武装后同样周期重建）
- 恢复路径：拒绝的 TTL 以 **1/16 均匀采样**回灌直方图 —— anycast 重路由的合法 TTL 漂移
  在下次重建时赢得 mode 竞争并重新武装（Scenario C 演示）；攻击者 TTL 被稀释 16× 永远赢不了
- 全部基线衰减殆尽 → 自动解除武装重回学习态
- 读路径无锁（`hopView` 不可变快照 + `atomic.Pointer`，主线 v4.4.7）
- `-real` 通过 x/net 控制消息 API（`ipv4.FlagTTL` / `ipv6.FlagHopLimit`，
  与生产 `internal/ipttl` 同构）读取每包 IP 层 TTL，完整运行学习/武装/拒绝；
  仅 Windows 不支持，降级为 DNS 层信号（污染 IP + 记录 TTL），**判定逻辑不伪装武装**

### Spoofguard — UDP 多读注入检测
- 自适应收集窗：单包等 150ms，第二个包出现（疑似注入）则等满 500ms；
  定时器自适应重臂 —— 有候选时精确在窗口到期刻唤醒（不再固定 100ms 轮询量化，主线 v4.4.7）
- 快返：`AN≥2 | NS>0 | AD=1` 直接服务；两条**相同** EDNS 响应即确定性确认
- 歧义（无 EDNS 单答案）：≥2 个响应 → 重查确认（最多 3 轮），匹配才服务
- `-real` 用真实数据跑同一 `sgState` 规则引擎，verdict 一致

### Splitguard — TCP 分段
- 每段 `[1, segSize]`（默认 4）随机字节，首段含 2 字节长度前缀，`TCP_NODELAY`
- 任何单段都不含完整域名标签 → DPI 无法匹配
- `-real` 同一路径对比普通 TCP vs 分段 TCP（普通被 RST、分段存活 = DPI 实证）

### Poisonguard — root/TLD 劫持检测
- root/TLD 对子域返回数据记录 = POISONED（权威层内容无法区分 → UNCERTAIN，盲区由 spoofguard/hopguard 覆盖）
- 豁免：带匹配 RRSIG 的签名答案；TLD 探针 `RD=0` 直接问 TLD 服务器
- `-real` 用同一 `detector.validate` 判定真实 root/TLD 响应

### CapsGuard — DNS 0x20 问题随机化
- 每个 ASCII 字母 1 bit 随机（50% 翻转 case 位）；响应必须逐字节回显 question
- 不匹配 → 丢弃 + 一次未随机化重试（§6.4 基线回退）
- **连续** 8 次不匹配 → 该上游 10 分钟内跳过随机化（无重试翻倍；成功回显即清零计数，S8）
- PTR 反向查询豁免回显校验（Cisco DNS guard 等中间盒会改写反向名）
- `-real` 复用 `randomizeCase` + 模拟模式的四列表格与统计行

## 界面与代码约定（所有 POC 强制一致）

1. **清屏 + 彩色方框头**：`\033[2J\033[H` 后渲染 `╔═╗` 框（`XxxGuard — 副标题`），
   所有模式（含 `-real`）必须带框头
2. **main() 分发顺序**：`flag` → `-h` 帮助 → 清屏+框头 → `if *realMode { realTest(...); return }` → 模拟模式。
   ⚠️ `-real` 分发必须在框头**之后**（spoofguard/capsguard 的模式），否则 real 输出裸文本
3. **real 模式复用模拟渲染结构**：场景标题（`━━━ Scenario ... ━━━`）、同款表格、同款统计行——
   real 只是**换数据源**，渲染与判定走与模拟完全相同的代码路径
4. **表格渲染抽成共享函数**：模拟与 real 共用一个 `render*` 函数
   （如 capsguard 的 `renderRows`、hopguard 的 `renderRealTable`），列宽与框线精确匹配
5. **统计行格式**：黄色 `→ N queries: M retries (mismatch rate = M/N)`
6. **诚实标注**：平台/网络限制直接打印说明（如 hopguard 的 IP TTL 仅 Windows 不可用），
   不伪造防御生效的假象
7. **着色常量统一**：`reset/bold/dim/red/green/yellow/cyan` 七个 ANSI 常量
8. **判定逻辑复用模拟状态机**：spoofguard 的 `sgState`、poisonguard 的 `detector`、
   capsguard 的 `simulate/renderRows`、hopguard 的 `hgState` —— real 模式不得另写判定逻辑
9. **算法镜像注释**：文件头注明 `// Algorithm mirror (server/.../xxx.go)`

## 新增 POC 检查清单

- [ ] 模拟模式：清屏 + 方框头 + 场景表格 + 统计行
- [ ] `-real` 复用模拟渲染（框头后分发，同一状态机/规则引擎）
- [ ] `-h` 帮助文本 + `-real`/`-server`/`-qname` 标志
- [ ] 算法镜像注释指向真实源码
- [ ] README.md 增加一节（问题 → 原理 → 演示输出 → 关键洞察）+ 更新架构对照表
- [ ] 本文档一览表 + 算法精华更新
- [ ] `go build ./... && golangci-lint run` 零告警
- [ ] 手动跑一遍 `go run ./<poc> -real` 验证界面一致

## 真实网络观察（2026-08，CN 网络实测）

| 信号 | 实测现象 | 对应 POC |
|------|----------|----------|
| google UDP | 裸单答案 A 假包（Facebook 157.240.x/69.171.x、185.45.x、SoftLayer 174.132.x）3 包/轮，真实 8 答案 EDNS（142.251.x） | spoofguard 每轮 FAST-RETURN 选中真实响应 |
| google TCP | 普通 TCP 被 RST（`connection reset by peer`）；分段 TCP 存活（~600ms 拿到 8 答案） | splitguard |
| TLD 层 | `a.gtld-servers.net` 对 `www.google.com` 返回注入 A 记录；root 响应干净 | poisonguard POISONED |
| 0x20 回显 | 8.8.8.8 逐字节回显随机 case | capsguard 5/5 ACCEPT |
| baidu | 干净双答案，无注入 | hopguard Source=REAL |
