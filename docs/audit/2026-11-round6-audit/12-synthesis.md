# Round 6 审计 — 综合报告(2026-11)

## 范围与重点

1. 依赖全量浮动(Round 5 后首次):miekg/dns v0.6.134、pion/dtls v4.0.3、quic-go 20261110、gmsm v0.45.3、compress 20261111、x/{crypto,sys,sync,text}——上游增量逐 commit 分类(必须适配 0 / 自动受益 全部 / 可采纳 1 评估后拒绝 / 无关)。
2. 全项目 20 维度新鲜审计(7 包级 agent 并行 + 交叉核对),重点:性能、内存安全与占用、吞吐、递归性能、每协议 QPS、缓存性能与占用。
3. 对标分析:dnscrypt-proxy / encrypted-dns-server / coredns 逐项目对比,10 项可借鉴点(每项含 ZJDNS 现状 grep 核实),2 项本轮采纳。

## 流程

| 阶段 | 内容 | 产出 |
|------|------|------|
| 基线 | build/test/lint/bench 全绿;update-deps.sh 浮动 + build/test 复验 | deps commit `7974576d` |
| Phase 1 | 7 并行包级审计(foundation/domain/protocol/upstream/resolver/handler/defense) | 1 CRITICAL 级别评估后无 + 4 HIGH + 13 MEDIUM + ~25 LOW + 1 生产 bug(P3 测试补齐时抓获) |
| 对标 | 3 仓库克隆分析,已具备能力清单 + 明确不采纳清单 + 10 项借鉴点 | 08-reference-comparison.md |
| 修复 | 10 个主题 commit(防御标记链 / collect 加固 / 传输层 / 协议层 / 缓存核心 / 递归+域 / handler+foundation / mqtype / R1 / U1+S1S2),每项带红灯→绿灯回归测试 | 全部修复 |
| 门禁 | lint 0 警告;`go test -short ./...` 全绿;race(12 包并发敏感集)全绿;bench 对比:唯一 alloc 回归经 worktree 隔离证明为依赖来源(fork Pack 路径 +2 allocs,0-alloc 直发契约完好),另 4 项 >15% 改善(lrumap F2) | 基线刷新(140 项,新增 3 项) |
| E2E | 14 协议 + 共享口 7 组 + MQTYPE(3 场景)+ 递归真网 + 无 EDNS TCP 缓存命中 + 12 协议压测 + 内存收敛 | 全过 |

## 关键发现(修复)

| 编号 | 严重度 | 概要 |
|------|--------|------|
| R1 | HIGH | fallback waitLoop 对 closed primariesDone channel 紧自旋——primary 全灭 + 慢 fallback 时每在途查询烧满一核(CPU share 0.98 实证),一行修复(一次性 nil)+ CPU 断言测试 |
| U1 | HIGH | 发散 EDNS 轮 break 泄漏 collect 注册(容量槽+inflight+缓冲),~8 条注入查询僵尸化一条 UDP 池连接直至重启——防御层自身成为 DoS 向量 |
| S1+S2 | HIGH | spoofguard 状态机两条逃逸:conn 死亡时未确证候选以 err=nil 服务(绕过静默窗口+跨轮确证);deadline 分支无视分歧态——滴注攻击 23 包/查询即可在 9s 预算尽头服务末包假答案。修复后一律 fail-closed(TCP 回退) |
| S3 | MEDIUM | hopguard 武装态拒绝采样可被 32 包/查询同 TTL 洪泛捕获(注释声称的 "cannot win the mode competition" 是速率条件句)——独立直方图 + mode/4 合并上限 + 不驱动 rebuild 节拍(防加速衰减)+ 保留时间重建(防纯漂移锁死) |
| S5+S7 | MEDIUM | 非任何 qtype 的 per-datagram 验证缺失:单读 TTL 采集被丢弃,地址级武装单独清标(违反文档不变量);TTL=0 获胜包也算验证。修复后标记语义与 AGENTS.md 声明一致 |
| D1 | MEDIUM | 客户端可控 ECS 变体无上限繁殖缓存键(~2000 报文清空缓存+线性上游放大)——键粒度封顶到出站 scope |
| P1 | MEDIUM | 共享口多 shard addrCache last-wins:3/4 的 DoQ/DoH3 客户端每连接多付一个 Retry RTT + 数据竞争 |
| H1 | MEDIUM | MQTYPE 本地拒绝路径被 QTx 解析阻塞(3s + 4 上游查询/攻击包) |
| DE1 | LOW(生产 bug) | demux OPT rdlength 偏移读错(读 TTL 高位)——P3 补测试时抓获并修复 |
| 其余 | MEDIUM×7 + LOW×~24 | 见 00-plan.md 全表 |

## 性能变化

- 改善:TLCP DoT 写合并 +9.5%(pipelined 场景更大);lrumap RLock(MapLen -31%,sharded Get -16%);DoQ 池命中省 140ns/976B;DNSCrypt 每查询省 ~330B + 一次 string;DoH GET 免一次 base64;ruleset 免 IP 双重转换;CNAME-hop 命中回归 wire 池(热路径 ~30MB/s 分配消除)。
- 代价:cache Get +~7%(D3 canonical 校验,带内);依赖 fork Pack 路径 +2 allocs(隔离证明为上游来源,记录于 deps commit)。
- 0-alloc 直发契约(缓存命中直发/ServeDNS)无任何变化。

## 递归性能专项

勿回退清单(Round 5)全部核实仍在位。本轮新增:P1 快路径后的 per-shard Retry 白名单修复直接改善共享口 DoQ/DoH3 首连接延迟;U4 collect 重传消除单丢包的整预算惩罚;R2 wire 池释放恢复 CNAME-hop 池化。

## 对标结论(08-reference-comparison.md)

ZJDNS 在缓存(replay protection 独有、serve-stale、RFC 8198 aggressive、分片 LRU)、连接池(三池+pipelining)、防御体系上强于对标;本轮采纳 REF-1(IP_RECVERR)/REF-6(PMTUDISC_DONT+RCVBUF);REF-2/3/4/5/7/8/9/10 记录为后续候选(各自工程量与设计冲突已在报告评估)。

## 方法论新增(已回写 AUDIT-METHODOLOGY.md §4.2)

1. closed-channel select 自旋:一次性触发的 case 必须在 case 体内 nil 掉 channel;CPU-share 断言测试(wall vs cpu 时间)。
2. 注册-重注册轮次配对:循环体内每轮新 key 注册的,跳出循环的 break 路径必须释放本轮注册(枚举全部 break/return 出口)。
3. 防御状态机降级面:conn 死亡/预算耗尽两条"异常出口"与正常出口跑同一确证标准——fail-closed 方向;每个"safe/verified"判定逐条问"这个包凭什么算已验证"(TTL=0/分歧态/地址级状态都否)。
4. 恢复路径采样上限:被拒绝样本进独立桶、按 verified 流量的比例上限合并、绝不驱动重建节拍(否则攻击者加速基线衰减)——修复自身要防"纯漂移锁死"回归(时间重建兜底)。
5. 多 shard/多实例字段发布:last-wins 字段在 N 实例启动时静默失效 3/4;参数传递优先于共享字段。
6. 依赖浮动的 alloc 回归归因:worktree 隔离(同机同参数跑 HEAD vs HEAD~deps)是判定"我们的改动 vs 上游代价"的判别实验。

## Round C 复查(09-roundc-review.md)

逐 commit 对抗审查 10 个修复 commit:无 HIGH 级新缺陷;抓获 1 个修复自身回归(RC-1:S6 重写使 spoofguard-only 部署全量标记——`!hopArmed` 短路掉 per-query verified,缓存整体失效)+ RC-2(GetTypes 单侧 canonical)+ RC-3(replay 拒绝路径漏 Put)+ RC-4(TC drain 缺直接测试)。全部修复于 `28a74100`(标记条件改三分量语义:capsguard §6.4 重试无条件标记 / 无 per-query 验证标记 / hopguard 学习期全标)。RC-5(跨轮确证第 2 轮 conn-death 服务单候选——与单窗口语义同类的已接受残留)、RC-6(DTLCP admitSem 不跨协议)记录为残留。build/vet/test/race 复验全绿。

## 收尾状态

- 12 个 commit(1 deps + 10 fix + 1 Round C),版本 v4.8.27。
- 基线:benchmark 140 项(bench-baseline.txt)+ loadtest 记录(loadtest-baseline.txt)。
- AUDIT-METHODOLOGY.md:历史表 Round 6 行 + §4.2 六个新根因模式。
