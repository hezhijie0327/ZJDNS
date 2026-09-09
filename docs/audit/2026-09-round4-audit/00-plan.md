# Round 4 审计 — 综合报告(2026-09)

## 范围与重点

1. **手搓 Plain UDP/TCP 服务器**(d268acc5 分片 REUSEPORT 监听器、519a5a03 MsgPool 回收、ef89bcc0 出站路径去 dns.Client)——用户指定重点。
2. **Guard 系列功能验证**:单开 & 组合,递归/forward 路径,目标 ~100% 拦截——用户指定重点。
3. 全项目 20 维度常规审计(方法论 §1.1)。

## 流程

| 阶段 | 内容 | 产出 |
|------|------|------|
| Round A | 亲审 protocol/plain + shared + server/bridge + internal/pool 容量类路由 | 方法论核查,1 LOW(并入修复) |
| Phase 1 | 7 个并行包级审计 agent(protocol/upstream/resolver/handler/foundation/domain/defense) | 4 HIGH + 14 MEDIUM + ~30 LOW |
| Sprint 1-3 | 发现即修复,分 16 个主题提交 | 见下表 |
| Phase 2 | 交叉审计:注释风格 sweep + 文档一致性(32 项)+ Round C 修复面复查 | 2 个修复自身引入的回归被 Round C 抓获 |
| Round D | 终扫:验证最后修复 + 高频改动文件对抗性复查 | 1 LOW 回归 + 2 同类遗留 |
| Guard 验证 | 确定性注入测试台(docs/poc/interception)矩阵实测 | 2 个单开缺口修复,最终全矩阵 0 泄漏 |
| E2E | 真实网络(8.8.8.8/递归)+ loopback 14 协议 + 共享端口 + pprof-dual 双端压测 | 全部通过 |

## 修复清单(HIGH)

| 编号 | 发现 | 修复 |
|------|------|------|
| H1 | TruncateWire 无 OPT 时 ARCOUNT 残留 → 截断响应不可解析(RFC 2181 §9 截断路径对带 glue 的非 EDNS 响应整体失效) | 无条件清 ARCOUNT;回归测试 ×2 |
| H2 | upstream.Client.Close 漏关 tlcpClient → TLCP/DTLCP 连接池 + readLoop goroutine + HTTP-TLCP idle conns 全部泄漏过 shutdown | 补一行 nil-safe Close |
| H3 | Secondary.Lookup 返回原始 TTL 且 Cacheable=true → MQTYPE QTx 合并无限重置缓存 TTL lease(条目永不过期);pooled wire 不释放 | 衰减剩余 TTL + Cacheable=false + 释放 wire(读 wire 字段必须先于 ReleaseWire——Round C 抓到初版释放后读的竞态) |
| H4 | TLCP DoT/DoH SNI 永远为空(gotlcp 懒握手 ConnectionState 零值;r.TLS 对非 crypto/tls 恒 nil)→ ACL 客户端名规则被静默绕过 | 首帧读后解析一次;DoH 经 ConnContext hook 传递 *tlcp.Conn(Round C 抓到 ServerContextKey 误用并修复) |

## 防御算法 HIGH

| 发现 | 修复 |
|------|------|
| HopGuard 基线投毒:fast-return(AN≥2/NS>0/AD=1 可伪造)1:1 喂入学习直方图;hopguard-only 学习期首包直返;一旦武装于攻击者 TTL,1/16 采样恢复数学上不可达(modeCount/2 共晋升条件) | Feed 门控 = 已武装 ∨ 确证(重复一致);hopguard-only 未武装走完整 spoofguard collect 纪律;wantTTL 进 UDP 池键(共享 socket 静默禁用 TTL 捕获) |

## Guard 拦截率实测(docs/poc/interception 测试台)

威胁模型:① GFW 裸伪造(非 EDNS 单答案/变 IP/回显大小写/独立 TTL)② 大小写盲模板 ③ EDNS 伪造者。

| 配置 | ① | ② | ③ |
|------|----|----|----|
| spoofguard 单开 | 30/30 | 30/30* | 29/30 + 1 fail-closed |
| hopguard 单开(预热) | 30/30 | 30/30 | 30/30 |
| capsguard 单开 | **修复前 0/30 → 修复后 30/30** | **0/30 → 30/30** | 30/30 |
| spoofguard+hopguard | 30/30 | 30/30 | 30/30 |
| spoofguard+capsguard | 30/30 | 30/30 | 30/30 |
| hopguard+capsguard | 30/30 | 30/30 | 30/30 |
| 全三 | 30/30 | 30/30 | 30/30 |

修复内容:capsguard A/AAAA 查询纳入 collect 纪律(0x20 未随机化重试的首包接受即伪造);发散 EDNS 候选跨轮签名交集确证(替代随机决胜)。
*= ②③ 模型下 spoofguard 单开的 EDNS 伪造者残余由失败关闭(TCP 升级歧义)兜底,无泄漏。

真实网络(8.8.8.8 forward + 递归全五层):spoofguard 日志显示每查询 2 个非 EDNS 伪造被降级收集、真实多答案快速返回;递归全五层 20/20 真实 IP、0 伪造、0 误杀;对照无防御 fallback 配置同网络实测被注入(31.13.92.37/157.240.7.20 段)。

## MEDIUM/LOW 摘要

- **协议**: 共享 UDP 组按"真实共享端口"重建(QUIC=8443/DTLS=DTLCP=8853 双重绑定修复);共享端口 DoQ/DoH3 Retry 白名单从未预热;13 处启动日志移到 bind 成功后;DNSCrypt UDP bind 泄漏;DTLCP 直读池缓冲;buildDOTFrame 委托 PackStreamFrame。
- **递归**: 向后引用无进度保证(30s 放大向量)→ RFC 1034 §5.3.2 closer-zone 门;MQTYPE strip 后 verifyMemo 失效;全零 TTL 委派缓存 7 天 → 10s 下限;取消误报为权威失败;mqtype 跨上游去重。
- **cache/lrumap/spillfile**: lrumap Clear/Get 升级幽灵节点(可复现双重 OnEvict + 容量击穿);spillfile miss 记忆 TOCTOU(世代计数器);cache Close 排空异步 writer;三处 Entry wire 泄漏;Flush 失败 Warn。
- **upstream**: 5 个安全传输非池化回退缺 ctx 门;非池化 UDP 回退缺问题回显校验(RFC 7766 §7);HTTPTLCP 每查询 url.Parse → 端点缓存;全零 TTL;socks5 常量/ctx。
- **注释/文档**: 20 文件历史叙述清零;HopGuard 流程图/POC/DEBUG/ARCHITECTURE 与新学习纪律同步;AGENTS.md 防御表更新。

## E2E 门禁(pprof-dual ×2 + 手动矩阵)

| 指标 | 结果 |
|------|------|
| 协议冒烟 | 14/14 |
| 压测 | 每协议 ok>34 万,fail=0 |
| goroutine 泄漏 | 0(双端) |
| PANIC | 0 |
| falling back | 0 |
| 内存收敛(同进程二轮) | 22403.50kB == 22403.50kB(精确一致,67 万查询) |
| 共享端口 | 7/7 |
| 外部上游 | AliDNS TLS/HTTPS/QUIC/HTTP3 + DNSpod TLCP 全通 |
| DNSSEC | sigfail→SERVFAIL,sigok→NOERROR |
| MQTYPE 递归合并 | A 可见/AAAA 剥离+warm 命中 |

## 方法论新增(已回写 AUDIT-METHODOLOGY.md)

1. SetReply 复制 DO 位 → fork Pack 自动物化 OPT:注入测试台的伪造包必须显式清除 Security 位,否则测的是 EDNS 伪造者模型而非 GFW 裸模型。
2. 注入台的 arm 计数器是全局 seq:每个测试场景必须重启 rig,否则预热相位跨场景泄漏(本轮实测踩坑:陈旧实例导致假 0/30)。
3. Guard 威胁模型矩阵:单开 × 多模型是缺口探测器(组合全绿掩盖单开缺口——capsguard 0x20 重试竞态、发散 EDNS 随机决胜均在单开下才暴露)。
4. 修复自身回归:Round C 复查抓获 2 个(HIGH 级)——验证轮次必须覆盖修复 diff 本身,不止原始发现。
