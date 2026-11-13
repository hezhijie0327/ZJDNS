# ZJDNS Round 6 Defense 审计报告

范围:`server/defense/*`(hopguard / capsguard / poisonguard)、spoofguard(`server/upstream/plain/{spoofguard,udp}.go`)、splitguard(`server/upstream/plain/tcp.go` + `pool/tcp_conn.go` + `internal/dnsutil/tcpframe.go`)、标记产生与消费链(`server/upstream/{client,execute,capsguard}.go`、`pool/udp_conn.go`、`server/resolver/*`、`edns/ede.go`)。

基线:`88de480b`(HEAD)。Round 5(D1–D10)修复经代码核实全部在位:cname 合并传播 noCacheEDE(cname.go:263-267)、三值 Verified 签名(udp.go:29 + client.go:56)、ambiguity fail-closed(udp.go:61-63)、nonEDNSSafe Feed 门(udp.go:539)、lame 终端补标(recursive.go:447)、NXDOMAIN noCacheEDE(forward_process.go:275)、fillCacheFromResult 兜底(forward_fallback.go:109)、takeCandidates 碰撞 Put(spoofguard.go:400-403)。本轮不重复报告。

---

## 发现

### S1 | HIGH | 状态机逃逸(fail-open) | server/upstream/plain/udp.go:357-379

```go
case pkt, ok := <-collectCh:
    if !ok {
        // The conn died mid-collect ...
        uc.ReleaseCollect(matchKey)
        ...Put(prev/nonEDNS/previous/prevRoundSigs)...
        if sg.last != nil {
            sg.last.ID = originalID // tracking ID must not escape
            return sg.last, nil     // ← 成功返回
        }
        return nil, errCollectClosed
```

**问题描述**:collect 期间连接死亡(readLoop 退出 → `close()` 关闭 collectCh,udp_conn.go:429-432)时,只要存在任一候选 `sg.last`,就以 `err == nil` 成功返回。而 `sg.last` 在此处**必然是未经确证的候选**——fast-accept(TTL-confident / 快信号 / identical-repeat / hopguard-armed 直返)都会立即 return,不会留着 `sg.last` 继续循环;唯一设置 `sg.last` 又不返回的路径是 `collectEDNSCandidate` 的 collect 分支(spoofguard.go:379)。`ExecuteUDP` 对 collect 成功统一 `return resp, true, nil`(udp.go:54-57)→ `Verified=true`。

**风险说明**:该分支同时绕过两个控制:(a) **静默窗口**——候选未经 150/500ms 静默期佐证即被服务;(b) **分歧跨轮确证**——`sg.divergentEDNS=true` 时正常路径要求签名跨轮匹配否则 `errAmbiguousNoConfirm` → TCP 回退(fail-closed,execute.go:107),此处被完全忽略,直接服务"最后到达的包"(注入者可见真实应答后置后发包即可选定赢家)。触发条件:链路上攻击者伪造 ICMP port-unreachable 杀死 connected UDP socket(4 元组与 tracking ID 均可见,Round 5 D3 已认定此能力在威胁模型内)。后果:spoofguard-only 部署下本应 TCP 回退的分歧场景变为假答案直达客户端(Uncertain 标记仅保证不入缓存,hopArmed=false);当 hopArmed(见 S7 的 TTL=0 空洞或同地址多 upstream 配置)或 capsguard 回显可复制(注入者逐字节复制 question 即可)时**可入缓存**。这是 Round 5 D3 修复(降级单读标记 Uncertain)后残存的另一半攻击面:有候选时的 conn-death 不走降级,而是被当作正向验证。

**修复建议**:`!ok` 分支仅在 `!sg.divergentEDNS`(且最好 `now.Sub(sg.lastRecv) > sg.collectWindow()` 或 `sg.packets == 1`)时服务 `sg.last`;分歧状态下返回 `errCollectClosed` 走既有 fail-closed(TCP 回退)路径。补一条"分歧轮 conn 死亡不服务"的单测。

---

### S2 | HIGH | 状态机逃逸 / 降级清标依据不足 | server/upstream/plain/udp.go:568-589

```go
if now.After(maxDeadline) {
    safe := sg.last != nil || sg.nonEDNSSafe || sg.rejected <= 1
    resp, respTTL := sg.pickBest()
    ...
    if safe { ... return resp, nil }   // verified=true
    // Ambiguous at the deadline — never serve it.
```

**问题描述**:deadline 分支的 `safe` 判定只看"有没有 EDNS 候选",不查 `sg.divergentEDNS`。分歧候选对在最后一刻仍处于窗口期内(窗口未过期,443 行的分歧处理分支未触发)时,`sg.last != nil` 即判 safe,直接 pickBest 服务——分歧场景下 pickBest 是随机/末包获胜的掷硬币,而设计对分歧的承诺是"仅服务跨两轮签名都出现的答案,否则 fail-closed"(451-510 行注释)。

**风险说明**:存在无需 ICMP 的确定性利用(逐行核实):每个新数据包都会重置 `s.lastRecv`(spoofguard.go:204),窗口过期条件是 `now.Sub(sg.lastRecv) > collectWindow()`(500ms)。注入者以 <500ms 间隔持续滴注**内容各不相同**的假 EDNS 应答(同 ID+question),即可让窗口永远不过期 → 轮次永不推进、跨轮确证永不运行 → 直到 9s(`DefaultDNSQueryTimeout`)预算耗尽进入 deadline 分支,`sg.last`(攻击者最后一个假包)被当作 safe 服务,`Verified=true`。真实应答早已被后续假包挤出 prev/last 双槽(spoofguard.go:370-372 Put 旧 prev)。代价仅 ~23 个数据包/查询。后果同 S1:所有 spoofguard 部署下每查询投毒;hopArmed/回显可复制时入缓存。附带效应:滴注使受保护 upstream 的每个 A/AAAA 查询被拖满 9s(延迟 DoS,正常分歧路径 ~1.5s 即 fail-closed)。

**修复建议**:`safe` 中排除分歧态——`sg.divergentEDNS && !sg.confirmed` 时 deadline 分支返回 `errAmbiguous`(已有,走 TCP 回退)而非服务;或对分歧态执行一次跨轮签名比对再决定。补"滴注攻击下 deadline 不服务分歧尾包"的单测(可用短 timeout 配置)。

---

### S3 | MEDIUM | 学习/恢复路径攻击面(基线捕获) | server/defense/hopguard.go:212-224 + server/upstream/plain/udp.go:391-397

```go
func (h *HopGuard) ShouldSampleRejected(serverIP string) bool {
    ...
    return st.rejected.Add(1)%hopGuardRejectionSample == 0
}
// udp.go:391-397
if hg != nil && !hg.Validate(server.Address, pkt.TTL) {
    if hg.ShouldSampleRejected(server.Address) { hg.Feed(server.Address, pkt.TTL) }
    pkt.Release(); continue
```

**问题描述**:武装后每 16 个被 Validate 拒绝的包有 1 个直通 `Feed` 进入直方图(恢复路径)。该门在 `processPacket` **之前**——数据包只需匹配 tracking ID,内容/形态完全不受 spoofguard 约束。注释声称"attacker-injected TTLs are diluted 16x and still cannot win the mode competition",但该论断是速率条件句:武装态 rebuild 每 32 次 Feed 触发、3/4 衰减对真伪计数等比,伪 TTL 只需采样计数超过真实计数即可成为 mode(`rebuildTrusted` 无条件 `trusted[mode]`,hopguard.go:318-320)。

**风险说明**:利用节奏(核实):真实应答到达前(RTT 差)注入者可先发 B 个同 TTL 假包,每查询采样 ≈ B/16 次 Feed;真实侧每查询仅 1 次 Feed。B≈32 即伪:真 ≈ 2:1,一两个 rebuild 周期(64–128 查询)后伪 TTL 成为 mode 并被提升为 trusted → 此后注入包通过 Validate、`ttlConfident=true` → `collectEDNSCandidate` fast-accept → `Verified=true` → **可缓存**——hopguard 被整体攻陷,且 65281 标记机制因"验证通过"而失效。反向后果:若伪计数压倒真实(> 2×),真实 TTL 跌出 trusted(协同提升需 `≥ mode/2`)→ 真实应答被持续拒绝 → SERVFAIL/全量标记 DoS。经验 GFW(2-3 假包/查询)不构成威胁;定向 on-path 攻击者(每查询 30+ 包)可达成。

**修复建议**:恢复路径采样提升设置上限(如 rejection-sourced 计数不得超 mode 的 1/4,或 rejection 采样仅允许在真实 Feed 出现 N 次后各提升 1);或要求采样 TTL 先以独立小桶观察、需连续多个 rebuild 保持且伴随真实流量衰减验证才可入 trusted。至少在文档/注释中修正"cannot win"的绝对表述。

---

### S4 | MEDIUM | 学习期窗口攻击面(确证可自证) | server/upstream/plain/spoofguard.go:352-369, 453-509 + udp.go:421-423

**问题描述**:hopguard 学习期(未武装)的 Feed 门是 `hg.Confident || sg.confirmed`(udp.go:421)、`sg.packets == 1`(udp.go:516/539)、跨轮签名匹配(udp.go:465)、re-query 匹配(udp.go:550)。"identical-repeat 确证"与"跨轮签名匹配"都建立在"GFW 假包逐包变化"的经验假设上——**确定性伪造者把同一假答案发两遍即自证**:第二包触发 `sameUDPAnswer` confirm(spoofguard.go:357-368)→ 立即服务 + `sg.confirmed=true` → Feed 无条件放行攻击者 TTL(1:1,与真实流量等速)。跨轮确证同理:确定性伪造者两轮重复同一假答案,签名必匹配(udp.go:465-481),假答案直接跨轮"确证"获胜。

**风险说明**:学习窗口内(每地址前 32 个确证样本;`hopGuardCacheCapacity=256` 的 LRU 驱逐后还会重开)确定性 on-path 攻击者可与真实服务器 1:1 灌注直方图:按 `rebuildTrusted` 规则,达到 mode 一半计数即协同提升为 trusted → 武装后攻击者 TTL 通过 Validate → fast-accept → Verified=true → 缓存投毒,且是**持续性**的(基线长期记忆该 TTL)。同假设也使武装后分歧路径的跨轮确证对确定性伪造者失效(见 S2 的滴注变体)。这是整个 spoofguard/hopguard 确证体系的设计边界,非实现 bug;但在本轮"学习期攻击面"维度下应显式记录:防御强度以"注入者非确定性"为先验,国家级对手可廉价满足确定性。

**修复建议**(可选,择一):(a) 学习期 Feed 只接受 `sg.packets == 1`(静默佐证)与 TCP 来源样本,拒绝 identical-repeat/跨轮签名两类可自证来源;(b) 学习期改用双 vantage( TCP 重发对照)确证;(c) 至少在 AGENTS.md/代码注释中把"corroborated-only"的成立条件(伪造者非确定性)写成显式前提,并在 hopguard 文档标注学习窗口可被确定性注入者捕获。

---

### S5 | MEDIUM | 降级清标依据不足 / 文档-代码矛盾 | server/upstream/client.go:282-292(+ AGENTS.md)

```go
hopArmed := server.HopGuard && c.plainClient.HopGuard().Confident(server.Address)
collectEligible := ... Qtype == TypeA || TypeAAAA
if !capsEchoVerified && (!hopArmed || (collectEligible && !result.Verified)) && (server.CapsGuard || server.HopGuard) {
    result.Uncertain = true
```

**问题描述**:非 A/AAAA 查询(`collectEligible=false`)在 `hopArmed` 时清标——单读 datagram(无 collect 纪律、无 per-packet TTL 验证、无 0x20 回显时)仅凭**地址级**武装基线即判"非 Uncertain"、正常入缓存。AGENTS.md 的表述是"an armed baseline alone never clears a single-read datagram",与代码直接矛盾。Round C 复审发现 1 已裁定反向问题(H2 原修复使非 A 永久 no-cache 的缓存坍塌),现行 `collectEligible` 形态是有测试钉住的折中(defense_uncertain_test.go:143 `TestExecuteQuery_NonAQtypeArmedCaches`)——但当时只权衡了缓存效率,**未评估安全残差**。

**风险说明**:hopguard-only(无 capsguard)部署下,TXT/HTTPS/SVCB/MX/DNSKEY 等类型的 UDP 应答仅靠 16-bit tracking ID + question 回显防护(on-path 可见二者),注入即入缓存、blast radius = 伪造 TTL。hopguard 用户得到的"防注入"承诺对非 A 类型实际为零(与 guards 全关等价),且 65281 机制恰好不覆盖。GFW 经验形态是 A/AAAA,故现实风险中等;协议演进(HTTPS 记录滥用已见诸真实攻击)会放大它。

**修复建议**:同步两选一:(a) 修代码——`executeUDPPooled` 的底层 `Exchange` 所在 socket 以 `wantTTL` 拨号、readLoop 本就采集了 TTL(udp_conn.go:354-355)却被丢弃,把 TTL 随 resultCh 送达并在单读路径跑一次 `Validate` 即可让非 A 类型获得真正的 per-datagram 验证(顺带补齐 AGENTS.md 不变量);(b) 修文档——在 AGENTS.md 明示"armed baseline 对非 A/AAAA 单读清标"是折中及其残差。推荐 (a),成本一行数据结构改动。

---

### S6 | LOW | 标记覆盖缺口 | server/upstream/client.go:287

**问题描述**:Uncertain 标记条件含 `(server.CapsGuard || server.HopGuard)`——仅开 spoofguard 的 upstream 不产生任何 65281 标记。其降级路径(collect 失败 → 单读首包接受,udp.go:64-98)与学习期服务结果都会正常入缓存。

**风险说明**:spoofguard 是防注入开关,用户开启它说明在意注入;但其降级路径恰好是防御最弱的时刻(单读、无 TTL、无窗口),却无 blast-radius 约束。AGENTS.md 表格将标记范围写为"hopguard/capsguard",属文档化的一致性缺口而非 bug。

**修复建议**:把 `server.Spoofguard` 加入标记条件(降级单读与学习期服务时标 65281),或在 AGENTS.md 标注 spoofguard-only 部署的标记缺失。

---

### S7 | LOW | per-datagram 验证空洞 | server/defense/hopguard.go:89-94 + server/upstream/pool/udp_conn.go:354-360 + udp.go:398

**问题描述**:TTL=0(采集缺失,`ErrNoControlMessage` 被吞或 cmsg 家系不匹配)时 `Validate` 恒真("TTL=0 is invalid at the network layer; passing here avoids rejecting"),`ttlConfident` 正确地要求 `pkt.TTL != 0`,但 collect 内以窗口过期服务的 TTL=0 候选(udp.go:515/527)与 S1/S2 的逃逸路径都返回 `Verified=true`;标记侧 `hopArmed && collectEligible && Verified` 即清标。即:**没通过任何 TTL 指纹检查的 datagram 也能构成"正向验证"**。

**风险说明**:前置条件窄——unix 正常捕获下 TTL=0 罕见;SOCKS5/Windows 是 capture 整体为 nil(此时基线永不武装,`hopArmed=false`,自洽)。现实触发面:偶发 cmsg 缺失、双栈家系错配、以及"同地址一个直连 upstream 武装了基线 + 另一个代理 upstream 共享该地址"的配置。在这些情形下 S1/S2/窗口服务的未验证包可入缓存。

**修复建议**:`ExecuteUDP` 的 verified 语义收紧为"获胜包通过 TTL 验证或内容确证"(spoguardState 记录获胜包的 `ttlValidated/confirmed` 标志),TTL=0 获胜包一律 `verified=false` → 走 65281 标记。

---

## 已核实无问题项(抽样证据)

- **锁/原子**:hopguard `st.mu` 写 + `atomic.Pointer[hopView]` 无锁读,Feed/Validate/Confident 交互正确;`capsDowngradeStat` 指针 + per-stat mutex,LRU Get 拷贝语义已规避;UDPConn `Exchange`/`ExchangeCollect`/`ReleaseCollect`/`close` 的 inflight 双锁协议无 double-close/double-release(executeUDPCollect 全部 12 条 return 路径逐一核对,ReleaseCollect 恰好一次、池化消息恰好归还)。
- **内存**:hopguard states LRU 256 × 直方图 ≤256 个 uint8 键,有界;capsDowngrades LRU 1024、hopguardWarned LRU 512;spoofguardState 每查询栈分配,`copyBuf` 有收缩节律(spoofguard.go:162-168);collectPacket 三级池归还完整(readLoop 溢出/ReleaseCollect drain/各消费点)。
- **panic**:processPacket 的 raw[6..9] 访问有 `len<12` 前置门(udp.go:385);poisonguard nil-RR 防护(poisonguard.go:87-89);全部后台 goroutine 带 HandlePanic。
- **splitguard**:`|split` 池键隔离(plain/tcp.go:48-50)、`SetSegmentation` 与写路径同在 `writeMu`(tcp_conn.go:80-86, 202-208)、非池化回退 `exchangeSegmented` 同样分段、随机段长 [1,4](tcpframe.go:112-147)与 AGENTS.md 一致;DoQ/QUIC 不分段(TCP 语义不适用),无误用。
- **capsguard**:问题 RR 拷贝防 fan-out 共享 Header 竞态(client.go:194-203)、defer 还原原名、PTR 豁免、无字母名/降级地址/§6.4 重试均置 `caseUnverified` → 标记;连续失配语义(downgrade 后计数清零、10min 重试)正确;`randName == original`(随机未翻转,概率 2^-字母数)落入"无法验证"→标记,fail-safe 方向。
- **65281 消费侧**:handler/resolve.go:85、forward_fallback.go:109、mqtype_merge.go:110 三处拒缓存门在位;cname 链一路径 `noCacheEDE` 传播 + `allCacheable` 聚合正确(cname.go:263-267);递归 4 个终态 + 根查询终态全部 `applyDefenseUncertainty`(recursive.go:208/395/424/447);`hopUncertain` 同时覆盖 capsguard 未验证(`nsResponse.uncertain` = `Result.Uncertain`),MQ 预热门在位(recursive.go:363)。
- **poisonguard**:classifyRoot/TLD 的 delegation/RRSIG/NSEC 豁免与 DNSSEC 链一致(有伪造 RRSIG 不豁免测试钉住);probeTLDForPoison 有 DefaultPoisonProbeServers/Timeout 界、verdicts channel 恰好排空;UDP-only 启用注释与 ns_concurrent 三处调用一致(NOERROR/NXDOMAIN/FORMERR retry)。

## 性能

- 每查询固定开销:RandomizeCase 2 alloc(有字母名)+ 问题 RR 拷贝 1 alloc(fan-out 安全必需);`hopguard.Confident` 每查询 2-3 次 sharded LRU Get、`Validate` 每包一次原子 Load + 通常 1-2 键的窗口扫描——均可忽略(benchmark_test.go 有 RandomizeCase 基线)。
- 多读窗口延迟:单包 +150ms、多包 +500ms 由设计;自适应定时器已消除 100ms 量化残差(udp.go:428-442)。**S2 的滴注使受攻击查询从 ~1.5s(分歧 fail-closed)恶化到满 9s 预算**,修复 S2 同时收回该延迟面。
- `answerSignature`/`rr.String()` 仅分歧轮触发;`trustedKeys` 仅 Debug 门内,契约符合。

## 测试缺口建议

1. S1:分歧轮 + conn 关闭 → 不得服务(应 errCollectClosed 走 TCP)。
2. S2:短预算 + 持续分歧滴注 → deadline 不得服务尾包(应 errAmbiguous)。
3. S3:武装基线 + 32 包/查询同 TTL 拒绝洪泛 → 伪 TTL 不得成为 trusted(修复后)。
4. S5(a):hopguard 武装 + 非 A 单读 + 伪造(本地 fake server 注入)→ 不入缓存。

## 已审文件

- /Users/hezhijie/Downloads/ZJDNS/server/defense/{hopguard,capsguard,poisonguard}.go(+ 测试函数清单)
- /Users/hezhijie/Downloads/ZJDNS/server/upstream/plain/{spoofguard,udp,tcp,client}.go
- /Users/hezhijie/Downloads/ZJDNS/server/upstream/{client,execute,capsguard,warmup,defense_uncertain_test}.go
- /Users/hezhijie/Downloads/ZJDNS/server/upstream/pool/{udp_conn,tcp_conn}.go、internal/dnsutil/tcpframe.go、internal/ipttl/{ipttl,capture_unix}.go
- 链路:server/resolver/{recursive,ns_concurrent,cname,forward_process,forward_fallback,resolver}.go、server/handler/{resolve,response}.go、edns/ede.go、config/defaults_dns.go
- docs/audit/2026-11-round5-audit/{07-defense,08-roundc-review}.md(避免重复 + 确认 Round C 对 S5 相关行为的裁定语境)

## 汇总表

| 编号 | 严重程度 | 位置 | 类别 | 摘要 |
|------|----------|------|------|------|
| S1 | HIGH | plain/udp.go:357-379 | 状态机逃逸 | conn 死亡时未确证候选 `sg.last` 以成功返回(Verified=true),绕过静默窗口与分歧跨轮确证;ICMP 杀 socket 可控触发 |
| S2 | HIGH | plain/udp.go:568-589 | 状态机逃逸 | deadline 分支 `safe` 无视 `divergentEDNS`,滴注(<500ms 间隔变体假包)使窗口永不过期,预算耗尽时服务末包假答案;顺带 9s 延迟 DoS |
| S3 | MEDIUM | defense/hopguard.go:212-224 + plain/udp.go:391-397 | 学习/恢复攻击面 | 武装态 1/16 拒绝采样无内容门、无计数上限,~32 包/查询同 TTL 洪泛两个 rebuild 周期内捕获 mode → 基线提升伪 TTL → fast-accept 可缓存 |
| S4 | MEDIUM | plain/spoofguard.go:352-369 等 | 学习期攻击面 | identical-repeat/跨轮签名确证可被确定性伪造者自证,学习窗口 1:1 灌注直方图,武装后持久通过;设计先验(注入者非确定性)未显式化 |
| S5 | MEDIUM | upstream/client.go:282-292 | 降级清标依据 | 非 A/AAAA 单读凭地址级武装基线清标入缓存,违反 AGENTS.md"armed baseline alone never clears a single-read datagram";Round C 只裁定了效率面,安全残差未评估;单读路径 TTL 采集被丢弃,补验成本极低 |
| S6 | LOW | upstream/client.go:287 | 标记覆盖 | spoofguard-only 部署无任何 65281 标记,降级单读路径不受 blast-radius 约束 |
| S7 | LOW | defense/hopguard.go:89-94 等 | per-datagram 验证 | TTL=0(采集缺失)datagram 空过 Validate,collect 服务后 Verified=true 清标;前置条件窄(cmsg 缺失/家系错配/同地址混合配置) |
