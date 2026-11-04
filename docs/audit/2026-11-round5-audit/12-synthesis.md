# Round 5 审计 — 综合报告(2026-11)

## 范围与重点

1. 上轮(Round 4, 9c6df186)以来 41 个提交的变更面:demux MSG_PEEK 嗅探、internal/ktls 新包、eHTTP→Go 1.27 net/http 原生 custom-TLS 迁移、双栈 TLS/DTLS(TLS 1.2 互操作恢复)、pion/dtls v3→v4 主线迁移、DoQ stream-credit、EDE 65281 defense-uncertain 标记。
2. 全项目 20 维度常规审计(方法论 §1.1)。
3. 用户指定专项:性能、内存安全与占用、吞吐量、递归性能。

## 流程

| 阶段 | 内容 | 产出 |
|------|------|------|
| 基线 | build/test(43 包)/lint/bench 全绿;bench 对比仅 1 项噪声(MapGetSpreadSingle 复测排除) | 可信起点 |
| 亲审 | 逐 commit 审 41 提交的迁移 diff;DoQ credit 顺序对照 quic-go v0.65 源码确认安全;Go 1.27 connectionStater 确认 eTLS r.TLS 填充有效 | 迁移面无 CRITICAL/HIGH |
| Phase 1 | 7 并行包级审计 agent(foundation/domain/protocol/upstream/resolver/handler/defense) | 1 CRITICAL + 4 HIGH + 9 MEDIUM + ~20 LOW + 4 性能机会 |
| 交叉 | OnEvict 全量核查(lrumap 24 调用点全合规)、注释风格/热路径日志/context/错误包装扫描 | 干净 |
| 修复 | 8 commits 分批(A/B/C/D/E/F/G/RC),每批带回归测试,pre-commit hook 全过 | 全部修复 |
| Round C | 复查 agent 逐 diff 对抗审查 + 自查(P1 切片别名对照 pool 契约核实安全) | E2E 循环冒烟抓获 mergeRRs dstKeys 越界 panic(P2 修复自身回归)→ 945b712f 修复 |
| E2E | 14 协议 + 共享端口 7 组 + MQTYPE + 递归 + PM1 迁移 + 12 协议压测 + 内存收敛 + 65281 真网链路 | 全过 |

## 关键发现(修复)

| 编号 | 严重度 | 概要 |
|------|--------|------|
| C1(×3 独立确认) | CRITICAL | EDE 65281 在递归路径整体失效:resolveInner 聚合丢 UpstreamEDE 且硬编码 Cacheable:true,handleRecursiveQuery 无条件覆盖回 true — 防御不确定(可能注入)的递归应答按完整 TTL 进缓存 |
| H1 | HIGH | demux MSG_PEEK 部分头部自旋:poll 水平触发 + PEEK 不消费 → 对端发 1-4 字节停发即全核自旋(实证 42 万次/300ms),256 并发停滞连接打满所有核 |
| H2+H3 | HIGH | hopArmed 地址级武装冒充 per-query 验证:collect 失败降级单读的响应(无任何验证)在基线武装时被清标进缓存;0x20 echo 已验证的响应在 hopguard 学习期被误标(文档-代码矛盾) |
| H4 | HIGH | hopguard 基线学习纪律回归:nonEDNSSafe(CNAME 形态)分支无条件 Feed,注入者用 CNAME 形态可 1:1 污染学习直方图 |
| M1/M2 | MEDIUM | MQTYPE QTx prefetch panic 挂死 merge(handler goroutine 永久阻塞);带 no-cache EDE 的 QTx 结果被 merge 进响应且丢标记 |
| M6/M7/M9 | MEDIUM | QUIC/HTTP3 同端口通过校验(两 listener 争绑);RFC 8198 wildcard 合成用过期 covering 证明;DoH http:// 上游静默明文(SplitHostPort 死代码分支) |
| RC | HIGH | mergeRRs dstKeys 预计算与 append 增长的 dst 失步 → 越界 panic(E2E 抓获,单元测试 dst 不增长全漏检) |
| LOW 批 | — | 双 PADDING、deferral drain、多 EDE 择取、DoQ 写 deadline、TLCP 无消费者队列驻留、dnscrypt 双重池化防御、NSEC zone 容量、verifyMemo 失效、注释失实等 |

## 性能优化(无 bug)

- P1: stripCrossZoneRecords 无符号区快路径早退(递归热路径每层省 4+ 分配)
- P2: mergeRRs 双侧 dedup keys 预计算(O(dst×src) 次 rr.String → 每侧一次)
- P3: 零 NXDOMAIN deferral 窗口免 timer

Benchmark 对比基线 **0 回归**(含 0-alloc 直发契约);压测 QPS 与历史同量级。

## 递归性能专项结论

现状已优(勿回退):withEarlierTimeout、首 6+75ms widen、infra 3+500ms、fillServer 共享 backing array、四级 memo(nsAddrFmt/rootCache/zoneKeyMemo/verifyMemo)、DNSKEY/NS-address 双 singleflight、≥2-names 早退、首个 NOERROR 即时 cancel。本轮仅加 P1 快路径;F4(委派缓存 uncertain 门控)确认为已接受权衡(有 DNSSEC/lame/poisonguard 三层兜底,硬门控使学习期委派缓存永不预热)。

## E2E 门禁(全过)

14 协议冒烟 14/14;共享端口 7/7;MQTYPE A 可见/AAAA 剥离/warm;递归真网(cloudflare DNSSEC + baidu CNAME 链);PM1 迁移补测(DoH 专用口 h2/http1.1/TLS1.2 完整响应——迁移四接合点全验证);12 协议压测全部 fail=0(19-45k qps);无 EDNS TCP 缓存命中(预打包直发);内存收敛 77520kB 精确一致;0 PANIC;65281 递归链路真网验证(hopguard 学习期 9 次标记、重复查询全 miss)。

## 方法论新增(已回写 AUDIT-METHODOLOGY.md §4.2)

1. 水平触发轮询自旋:peek 类循环必须零进展退避 + RDHUP + POLLERR/NVAL;测试要断言 CPU 而非只断言正确性(正确性测试自己就在自旋中通过)。
2. 聚合点丢标记:聚合函数要显式传播安全字段并 AND 语义;特性 E2E 必须覆盖其声称的每条路径(65281 首次只在转发路径验证而漏网递归)。
3. 预计算 keys 与增长的容器失步:lockstep 增长;单测覆盖"追加后再去重"。
4. 地址级状态冒充 per-query 验证:验证标记必须 per-query 传播;逐条降级路径问"凭什么清标"。
5. 校验依赖死代码分支:URL 族校验直接 url.Parse 查 scheme/host,勿以 SplitHostPort 失败为前提;测试含 http:// 形态。
