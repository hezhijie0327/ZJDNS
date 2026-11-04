# Round 5 审计 — 逐项修复计划(2026-11)

基线:`9c6df186`(Round 4 收尾)→ HEAD(41 提交)。重点面:demux MSG_PEEK、internal/ktls 新包、eHTTP→net/http 原生迁移、双栈 TLS/DTLS、pion/dtls v3→v4、DoQ stream-credit、EDE 65281 defense-uncertain 标记。

基线状态:build ✓ / `go test -short ./...` 43 包 ✓ / golangci-lint 0 警告 ✓ / benchmark 基线对比仅 1 项噪声(lrumap MapGetSpreadSingle ±50% 波动带内,复测排除)。

## 发现汇总与去重

六个 agent 独立完成(foundation/domain/protocol*/upstream/resolver/handler/defense;*见 03-protocol.md)。交叉确认以 ×N 标注独立发现次数。

### Sprint 1 — CRITICAL / HIGH

| 编号 | 严重度 | 位置 | 问题 | 修复 |
|------|--------|------|------|------|
| C1 (×3: D1/F1/R5-01) | CRITICAL | cname.go:326 + forward_process.go:285 | EDE 65281 防御不确定标记在递归路径整体失效:resolveInner 聚合丢 UpstreamEDE 且硬编码 Cacheable:true;handleRecursiveQuery 无条件覆盖回 true。hopguard 学习期/capsguard 未验证的递归应答按完整 TTL 进缓存,毒答案爆炸半径 = TTL 而非 1 次查询 | 聚合传播任一 hop 的 no-cache 标记;覆盖改为 AND;补递归全链路测试 |
| H1 (Foundation F-1) | HIGH | internal/demux/sniff_peek.go:59-82 | MSG_PEEK 嗅探部分头部(1-4 字节)自旋:poll 水平触发 + PEEK 不消费 → 无新数据立即返回 → 全核自旋(实证 42 万次/300ms);对端发 1-4 字节停发即触发,256 并发停滞连接打满所有核;部分数据+FIN 场景自旋满 10s 后误报超时 | 进度检测 + POLLRDHUP 订阅(Linux)+ 零进展指数退避 |
| H2 (D2) | HIGH | server/upstream/client.go:267-274 | hopArmed 是地址级武装,非本包验证结果:单读回退路径(collect 失败落入)与 TTL=0 包(ErrNoControlMessage 被吞)在基线恰好武装时被当"正向验证"清标 → 未验证响应进缓存 | Uncertain 判定追踪本查询验证(collect 路径回填/单读一律标记) |
| H3 (D3) | HIGH | server/upstream/plain/udp.go:50-83 | collect 失败的降级链 fail-open:errCollectClosed(伪造 ICMP port-unreachable 可触发)/ErrKeyCollision/写错误落入单读首包接受,无多读无 TTL 验证,与 H2 组合毒答案被缓存 | guards 开启时 collect 非取消类错误 fail-closed(走 TCP),或单读强制 Uncertain |
| H4 (D5) | HIGH | server/upstream/plain/udp.go:518-536 | hopguard 基线学习纪律回归:nonEDNSSafe(CNAME 形态)分支无条件 Feed,注入者用 CNAME 形态可 1:1 污染学习直方图(corroborated-only 纪律唯一漏洞点) | 与其他 Feed 点一致加 Confident‖confirmed 门 |

### Sprint 2 — MEDIUM

| 编号 | 位置 | 问题 | 修复 |
|------|------|------|------|
| M1 (HF-1) | middleware/mqtype.go:103-112 + mqtype_merge.go:93 | QTx prefetch goroutine panic 后 merge 的 `for range types` 收不满 → handler goroutine 永久挂起 | goroutine 内 defer 发送(res.qt 置后) |
| M2 (HF-2) | middleware/mqtype_merge.go:97-155 | merge 不检查 IsZJDNSNoCacheEDE:65280/65281 的 QTx RR 被 merge 进响应且不传播标记,下游可缓存 | QTx 录用加 no-cache EDE 门 |
| M3 (D4,并入 C1) | recursive.go:360-363 | 递归 MQTYPE 预热(warmFromMQResponse)无 uncertain 门,防御不确定层 bundled 类型直接 cache.Set | hopUncertain 时跳过 |
| M4 (D6/F3,并入 C1) | recursive.go:443-445 | lame-delegation 终端跳过 applyDefenseUncertainty | 补调用 |
| M5 (D7/F2,并入 C1) | forward_process.go:248-259 | uncertain NXDOMAIN 分支不传 noCacheEDE,下游收不到 65281 | 同 NOERROR 路径 |
| M6 (R5-02) | config/validate.go:294-332 | QUIC 与 HTTP3 端口相等时通过校验,注释自declared 二者字节级不可区分;两 listener 争绑同端口 | 分组前显式拒绝该组合 |
| M7 (R5-03) | cache/nsec.go:221-319 | RFC 8198 wildcard 合成不校验 covering 区间剩余 TTL,过期证明继续合成 | covering 选中后加 remaining>0 门 |
| M8 (U-1) | server/upstream/client.go:267-274 | 双 guard 同开时 0x20 回显已验证仍被标记(hopguard 学习期),与代码注释/AGENTS.md 声明矛盾,无谓损缓存命中率 | echo 验证成功即清标 |
| M9 (U-2) | config/validate_upstream.go + upstream/tls/endpoint.go | DoH/DoH3 上游地址未强制 https scheme,http:// 配置静默明文发出 | dohEndpointFor 拒绝非 https |

### Sprint 3 — LOW / 性能

| 编号 | 位置 | 问题 |
|------|------|------|
| L1 (HF-3) | middleware/edns.go:70 + response.go:142-148 | RFC 7830 §4.4 双 PADDING(BADVERS + secure + 客户端带 PADDING 时) |
| L2 (HF-4) | middleware/stats.go:20、cache_store.go:39-40 | 历史叙述注释 ×2 |
| L3 (D8/F7/R5-06) | resolver/forward_fallback.go:107 | fillCacheFromResult 缺 IsZJDNSNoCacheEDE 兜底 |
| L4 (D9) | plain/spoofguard.go:391-403 | takeCandidates 签名碰撞泄漏池化消息 |
| L5 (D10) | plain/spoofguard.go:405-416 | answerSignature 注释失实(TTL 实际参与) |
| L6 (U-3) | upstream/dnscrypt/client.go:292-315 | 非池化路径潜在双重池化(当前 no-op,防御性移除) |
| L7 (U-4) | upstream/tls/dtls.go:220-223 | 注释失实(不存在的 pool re-acquire) |
| L8 (U-5) | upstream/tls/tls.go | DoT ALPN 协商结果不校验(TLCP 路径有校验) |
| L9 (R5-04) | cache/nsec.go:574-595 | insertRanges 上限偏离 1 |
| L10 (R5-05) | resolver/forward_process.go:31-48 | captureUpstreamEDE 只取首个 EDE(RFC 8914 允许多个) |
| L11 (RF5) | resolver/ns_concurrent.go:430-438 | NXDOMAIN deferral 返回路径漏 drain 池消息 |
| L12 (RF6) | resolver/dnssec_chain.go:282-284 | tryRRSIGRetry 改写后 verifyMemo 未即时失效(不变量固化) |
| L13 (RF8) | resolver/ns_concurrent.go:474-478 | 层级超时错误语义丢失(诊断) |
| L14 (FF-2) | demux/sniff_peek.go:37-38 | Control 注释夸大独占保证 |
| L15 (PL2) | shared/tcp.go:51-53 | TLCP 路由无条件注册:无 TLCP 消费者时形如 TLCP 的连接进永无人 Accept 的队列(≤64 fd 驻留至 Shutdown) |
| L16 (PL3) | tls/quic.go:362 | DoQ respondQUIC 无写 deadline — 不读响应的客户端钉住 stream handler + credit 槽位(受 64 streams/conn 自限) |
| L17 (PL4) | internal/ktls/limit.go:69 | Accept 阻塞在 sem,listener Close 不唤醒(与旧 dnsutil.LimitListener 同构,有限延迟) |
| L18 (PL5) | shared/manager.go:158-170 | Mux.Start 中途失败不清理已启动组(进程退出兜底) |
| L19 (PL6) | tls/https.go vs handlers.go | 专用口 DoH ALPN 仅 ["h2"],共享口 ["h2","http/1.1"] — 仅提 http/1.1 的客户端在专用口被拒 |
| L20 (PL7) | tls/handlers.go:94-97 | 共享口 ListenEarly 失败后 transport 黑洞(独立口路径硬失败) |
| PM1 (协议侧) | tls/https.go + ktls | eHTTP→net/http 迁移四接合点无集成测试 → 全协议 E2E 阶段补 DoH 专用/共享口 × h2/http1.1 × TLS1.2 |
| P1 (RP1) | resolver/zonecut.go:30-109 | stripCrossZoneRecords 无符号区快路径早退(省 4+ 分配/层) |
| P2 (HP-1) | middleware/mqtype_merge.go:169-202 | mergeRRs dst 侧 keys 未预计算(O(dst×src) 次 rr.String) |
| P3 (RP2) | resolver/ns_concurrent.go:425-429 | DeferralWindow=0 时仍建 timer |

PI8(DoQ credit 顺序)由 protocol agent 与亲审双重对照 quic-go v0.65 源码确认安全("completed and ReleaseStreamCredit, in any order",幂等),不修。

### 记录不修(设计权衡/事实)

- RF4(F4):委派缓存不受 uncertain 门控 — 委派有 DNSSEC 验证 + lame 检测 + poisonguard 交叉验证兜底;硬门控会让学习期委派缓存永不预热。文档化权衡。
- R5-07:entries.go Set 的 wire 别名安全性依赖 DefaultCompressionThreshold(256) < wireBufferSize(2048) 隐式关系 — 补互指注释。
- U-6:DTLS 单记录 ~16K 上限边界(实际 DNS 查询远小,TC/TCP 兜底)。
- FF-3:limit.go NewLimitListener 与类型间隔(limitConn)——decorder 不检查,重构收益低。

## 修复顺序

1. C1+M3+M4+M5(同根因族,一个 commit 族)→ 验证:新增递归 65281 全链路测试
2. H1 → 验证:sniff_peek_test 增停滞场景 + CPU 行为断言
3. H2+H3(H2/H3 联动:单读强制 Uncertain 即同时闭合两者的一半)→ 验证:defense_uncertain 测试扩展
4. H4 → 验证:hopguard Feed 门测试
5. M1-M9 → 各自单测
6. L/P 批量 → lint + bench

每批:`go fix ./... && golangci-lint run && golangci-lint fmt && go test -short ./...`(零警告、全绿);全部完成后 benchmark 对比 + 全协议 E2E + Round C 修复面复查。
