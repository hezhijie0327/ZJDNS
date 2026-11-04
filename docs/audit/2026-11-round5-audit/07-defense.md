# ZJDNS Round 5 Defense 审计报告

基线 `9c6df186..HEAD`,defense 相关实质变更为 2 个提交:`0d7dfd43`(EDE 65281 不缓存标记)+ `850eb875`(文档)。`internal/ipttl` 仅为注释/nolint 重排,无语义变化(已逐行核对)。

## 发现

**D1 | HIGH | 漏标(缓存污染) | server/resolver/cname.go:326**
```go
return QueryResult{Cacheable: true, Answer: allAnswers, ... DNSSECEDE: allDNSSECEDE, ...}
```
CNAME 链合并结果硬编码 `Cacheable: true`,且从不传播任何一跳的 `qr.UpstreamEDE`。`applyDefenseUncertainty`(recursive.go:573-581)在每跳的 `resolve()` 终端上正确设置了 `Cacheable=false` + 65281,但合并时全部丢弃——不确定跳的记录(CNAME/答案)随整链被 `StoreIfCacheable` 缓存。递归 + hopguard 模式下每个新权威地址前 32 个确证样本期间都处于 learning(常态),CNAME 查询的"blast radius = one query"承诺系统性失效。修复:合并循环中任一跳 `!qr.Cacheable || qr.UpstreamEDE != nil` 时置 `allUncertain`,最终结果带 65281 且 Cacheable=false。

**D2 | HIGH | 误清标(未验证响应被当正向验证) | server/upstream/client.go:267-274**
```go
hopArmed := server.HopGuard && c.plainClient.HopGuard().Confident(server.Address)
if result.Error == nil && ... && result.Protocol == config.ProtoUDP && !hopArmed {
```
`Confident` 是**地址级**武装状态,不是**本包**验证结果。两条未经 TTL 验证的路径会被清标:(a) collect 失败后落入的 `executeUDPPooled`/`exchangeOneShotUDP` 单读路径(见 D3)——`pool/udp_conn.go:150-261` 的 `Exchange` 只回 payload,TTL 采集结果被丢弃,hopguard Validate 从未运行;(b) collect 内 `ErrNoControlMessage` 被吞(pool/udp_conn.go:356-360)后 TTL=0 的包——`Validate(observed==0)` 恒真(hopguard.go:90-94),而 collect 路径自身的 `ttlConfident` 正确要求 `pkt.TTL != 0`(udp.go:390),ExecuteQuery 的清标条件却没有。基线恰好武装时,这些响应被判"正向验证"→ 缓存。修复:标记判定应追踪本查询实际通过的验证(如 Result 增加由 collect 路径回填的 `TTLValidated`,或单读 fallback 一律 `Uncertain=true`)。

**D3 | HIGH | 状态机 fail-open:collect 失败降级单读首包接受 | server/upstream/plain/udp.go:50-83**
```go
if errors.Is(err, errAmbiguous) || errors.Is(err, errAmbiguousNoConfirm) {
    return nil, err
}
// Pooled collect failed — fall through to pooled single.
```
仅 ambiguity 错误 fail-closed;`errCollectClosed`(socket 中途死亡,如伪造 ICMP port-unreachable 可触发——链路上的攻击者可见 4 元组)、`ErrKeyCollision`、写错误都落入 `executeUDPPooled` → `exchangeOneShotUDP`:首个 ID+question 匹配的 datagram 直接获胜,无多读、无 TTL 验证。注入者抢先应答即赢得单读。与 D2 组合后毒答案被缓存。`errNoResponse` 因预算耗尽实际到不了这里(execute 的 queryCtx 已过期)。该降级链早于本轮(1e0e12f1),但新的 Uncertain 逻辑使其被当作"已验证"。修复:guards 开启时,collect 的非取消类错误应一并 fail-closed(返回错误走 TCP),或单读结果强制 `Uncertain=true`。

**D4 | MEDIUM | 漏标:递归 MQTYPE 预热无视防御不确定 | server/resolver/recursive.go:360-363**
转发路径对 MQ 预热有 `!fallbackMarked` 门(forward_process.go:205,含 65280/65281),递归路径的 `warmFromMQResponse` 无任何门——defense-uncertain 层响应的 bundled QTx 类型记录直接 `cache.Set`(mqtype_client.go:93-103)。修复:`hopUncertain` 时跳过本层预热。

**D5 | MEDIUM | 回归:hopguard 基线仍从未确证样本学习(CNAME 路径) | server/upstream/plain/udp.go:518-536**
```go
if sg.nonEDNSSafe || sg.rejected <= 1 {
    if hg != nil { hg.Feed(server.Address, respTTL) }
```
`rejected <= 1` 是静默确证,但 `nonEDNSSafe`(CNAME 形态)分支无条件 Feed——多包分歧轮里最后到达的 CNAME 响应既无 identical-repeat 也无静默确证。这与上轮修复(81d2a6b0,"corroborated-only")在其他 Feed 点(udp.go:413/508/540/464/569)建立的门矛盾,唯一依托是"GFW 不注入 CNAME 链"这一经验假设;注入者改用 CNAME 形态即可 1:1 污染 learning 直方图。修复:该分支同样加 `hg.Confident(...) || sg.packets == 1` 门。

**D6 | MEDIUM | 漏标:lame-delegation 终端结果跳过不确定标记 | server/resolver/recursive.go:443-445**
```go
if termRes := r.checkLameDelegation(response, ...); termRes != nil {
    return *termRes
}
```
其他三个终端(208/392/421)都调用 `applyDefenseUncertainty`,此处没有。`recursive_helpers.go:174-179` 的同区 referral 终端结果 `Cacheable: true` 携带 Authority 记录,未验证 UDP 响应的该形态会被缓存。经典 GFW 形态不含 referral,故实际风险有限。

**D7 | LOW | 转发 NXDOMAIN 丢失本地 65281 标记 | server/resolver/forward_process.go:258**
NOERROR 路径传 `UpstreamEDE: noCacheEDE`(含本地 Uncertain 生成的 65281),NXDOMAIN 路径传 `upstreamEDE`(本地 Uncertain 时为 nil)。本地 `Cacheable=false` 仍拦缓存,但下游 ZJDNS 收不到 65281(仅上游自带的不丢)。威胁模型(GFW 只注入 A/AAAA NOERROR)下影响小,属一致性缺口。

**D8 | LOW | fillCacheFromResult 缺 IsZJDNSNoCacheEDE 兜底 | server/resolver/forward_fallback.go:107-110**
注释称"mirrors the CacheStore middleware's gates",但缺 `edns.IsZJDNSNoCacheEDE` 检查(handler/resolve.go:85 有)。当前 `res.Cacheable=false` 覆盖了所有产生路径,兜底不对称仅在未来引入时成坑。

**D9 | LOW | takeCandidates 签名碰撞泄漏一个池化消息 | server/upstream/plain/spoofguard.go:391-403**
prev/last 签名相同(A/AAAA/CNAME 之外的类型,`sameUDPAnswer` 恒 false 但 `rr.String()` 相同)时 map 覆盖,前一条未 `pool.Put`。GC 兜底,仅损失复用。

**D10 | LOW | answerSignature 注释失实:TTL 实际参与签名 | server/upstream/plain/spoofguard.go:405-416**
`rr.String()` 包含 TTL,注释称"TTL excluded, matching sameUDPAnswer"。权威服务器对重复查询返回恒定 TTL,行为目前正确;若某权威按查询递减 TTL,跨轮签名永不相交 → `errAmbiguousNoConfirm` → TCP 回退(fail-closed,仅损延迟)。

## 回归核验(上轮修复项,均已代码核实)
1. **hopguard 只从确证样本学习**:udp.go:413(`Confident||sg.confirmed`)、508(`||sg.packets==1` 静默)、464(跨轮签名)、540(re-query 匹配)均正确——除 D5 的 CNAME 洞。
2. **capsguard §6.4 未随机化重试走 collect**:udp.go:44 `isAQtype && (... || server.CapsGuard)` 含 CapsGuard,重试再入多读;非 A/AAAA 保持单读但被 `caseUnverified=true`(client.go:257)标记不缓存,缓存安全。
3. **wantTTL 进 UDP 池键**:udp.go:163-165 `key += "|ttl"` 在位。
4. **降级后跳过随机化的计数**:capsguard.go 连续失配语义 + 成功清零;降级窗口内未随机化 → `caseUnverified=true`(client.go:204-208)→ 标记。
5. **ipttl 改动**:仅字段注释与 `//nolint:unused` 重排,unix/non-unix 语义不变。

其余维度:65280/65281 语义无混用(`IsZJDNSNoCacheEDE` 双码拒缓存,fallbackMarkEDE 仅用于 Fallback);内存均 LRU 有界(states 256、histogram ≤256 键、capsDowngrades/hopguardWarned 有界);hopguard 学习直方图在 `st.mu` 下写、`atomic.Pointer[hopView]` 无锁读,武装原子性正确;nil 防护完备;DoS 面(150/500ms 窗口、≤3 确证轮、collectCh 4 槽、mismatch 采样日志)有界。

## 性能
- client.go:186-193:0x20 每查询复制一个 RR(fan-out 安全所需,必要分配);client.go:267 每查询一次 LRU `Confident` Get(sharded,可忽略)。
- 热路径日志符合契约;`answerSignature`/`rr.String()` 仅在分歧轮。
- **测试覆盖缺口**:`defense_uncertain_test.go` 只测 `Confident` 原语;D1/D2 涉及的标记分支(CNAME 合并丢标、单读清标)与收端拒缓存(IsZJDNSNoCacheEDE→不写缓存)均无测试,建议补 ExecuteQuery 标记表驱动测试 + 一条"上游 65281 → 本地不缓存"E2E。

## 已审文件
- /Users/hezhijie/Downloads/ZJDNS/server/defense/hopguard.go、capsguard.go、poisonguard.go(+ 各测试文件测试函数清单核对)
- /Users/hezhijie/Downloads/ZJDNS/server/upstream/plain/client.go、udp.go、tcp.go、spoofguard.go
- /Users/hezhijie/Downloads/ZJDNS/server/upstream/client.go、capsguard.go、execute.go、defense_uncertain_test.go
- /Users/hezhijie/Downloads/ZJDNS/server/upstream/pool/udp_conn.go(udp.go 结构)
- /Users/hezhijie/Downloads/ZJDNS/internal/ipttl/ipttl.go、capture_unix.go、capture_other.go
- /Users/hezhijie/Downloads/ZJDNS/edns/ede.go;链路追踪:server/resolver/{recursive,ns_concurrent,forward_process,forward_fallback,cname,mqtype_client,recursive_helpers}.go、server/handler/resolve.go、server/handler/middleware/{cache_store,cache_refresh,response}.go、internal/dnsutil/tcpframe.go(splitguard 分段写,无误)