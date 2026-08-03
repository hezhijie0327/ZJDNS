# Resolver 组审计 — server/resolver/*（17 文件，双份独立审计合并）

## CRITICAL

### C2: server/resolver/dnssec/trust_anchor.go:132-133 — ToDS() nil 解引用（见综合报告 C2）
- `dnskey.ToDS(kd.DigestType)` 对非 SHA 摘要类型（GOST type 3 等）或畸形公钥返回 nil（fork 源码 `default: return nil`），随后 `ds.Digest` 裸解引用 → **启动崩溃**。crypto.go:149-155 的 VerifyDelegationDS 有 `computedDS == nil` 守卫，此处遗漏。该函数其余所有异常分支均 fail-closed 跳过，此处是唯一裸解引用。
- 触发：root-anchors.xml 被篡改/损坏、或未来 IANA 引入新摘要算法。当前数据（DigestType=2）不触发——"恰好当前数据没炸"的脆弱路径。
- 修复：`if ds == nil { log.Debugf(...); continue }`。

### C4: server/resolver/dnssec_chain.go:74-91, 415-423 — 根 DNSKEY 信任锚定缺失（见综合报告 C4）
- `isValidWithDNSSEC` 与 `isDNSSECValid` 的根域分支仅 `SelfVerifyDNSKEY`（集合内自签名即通过），**缺少** `ContainsRootKey` 信任锚交叉校验。`ensureZoneDNSKEYs`（:290-307）有该校验，其注释自述："Without this cross-check, a MITM of the root DNSKEY query could inject a self-signed key set and forge the whole chain of trust"——正是此漏洞的描述。三处根域验证点两处缺锚定。
- 攻击：MITM 根 DNSKEY 响应（伪造自签名密钥集）→ SelfVerify 通过 → `CacheZoneKeys(".", ...)` 写入缓存 → 整条 DS/DNSKEY/应答验证链全部以攻击者密钥验证通过 → DNSSEC 链式信任被整体伪造。
- 修复：两处根域分支在 SelfVerifyDNSKEY 成功后补 `if !crypto.ContainsRootKey(dnskeyRecords) { chain.lastEDECode = dns.ExtendedErrorDNSBogus; return false }`，与 ensureZoneDNSKEYs 对齐。

## HIGH

### H12: server/resolver/nameserver.go:43-45, 47-62 — baseMsg 池消息 use-after-put（见综合报告 H12）
- `baseMsg` 由 :43-45 构造并 `defer pool.DefaultMessage.Put(baseMsg)`（defer 顺序使 Put 先于 :32 的 `cancel()` 执行）；`g.Go` 在 `SetLimit(min(len, 6))` 下**阻塞排队**；主流程收到首个响应提前返回（:194-205）后，排队 goroutine 启动读取**已被 Put（清零或被池复用改写）**的 baseMsg → 向权威服务器发送空 Question 或**跨查询数据**（另一客户端 ECS/查询内容泄露）。根服务器（26 地址）路径必现。
- 修复：Put 移入 g.Wait 之后的 wait goroutine，或每个 goroutine 从不可变 question 构造消息而不共享 baseMsg。

## MEDIUM（5 项）

| # | 位置 | 描述 |
|---|------|------|
| M1 | dnssec/nsec.go:446,455 | `CapValidatedTTL` 的 RRset key 用 `dns.TypeToString` 拼接——RFC 3597 未知类型塌缩为同一 "name/" key，不同未知类型 RRset 互相套用 TTL 上限。zonecut.go:103-105 的 `rrsetKey` 已用 `strconv.Itoa` 修复同模式（注释即描述此 bug）——一致性遗漏。 |
| M2 | forward.go:111-118 + nameserver.go:89-91 | `ExecuteQuery` 同时返回 Error 与 Response 时（UDP 截断→TCP 回退失败路径），池化响应未归还——GFW 封锁 TCP 的典型场景每次丢失一个池消息。DNSCrypt 路径（client.go:164-166）显式处理了，普通 UDP 路径遗漏。 |
| M3 | root_hints.go:53,58 | 根提示文件缺失时每次递归查询打一条 Error（失败不缓存设计 + 每次重试都打）——高 QPS 日志刷屏。修复：sync.Once 或失败限流。 |
| M4 | recursive.go:147-151, 282-314 | poisonguard 开启时每次递归解析在权威层对 TLD 服务器多发一次全 QNAME UDP 探测，无记忆化——TLD 丢包时每查询固定 +2s 延迟。修复：按 (tldServer, qname) 缓存最近探测。 |
| M5 | nameserver.go:130-137 | 两个 NS 在 cancel 窗口内同时成功时，第二个响应经缓冲通道入队后 goroutine 退出，该 *dns.Msg 永不 Put——根解析（26 服务器）频繁触发，池消息累积泄漏。 |
| M6 | zonecut.go:138,207,245,258,266 + dnssec_chain.go:158 | `resolveZoneCut`/`updateDNSSECChain` 未做 `crypto == nil` 检查（同组 7 个 DNSSEC 函数均显式判 nil）——外部构造 `Config{Crypto: nil}` 时 zone-cut 路径 nil 解引用 panic（生产装配恒非 nil，潜在地雷）。 |

## LOW（3 项）

| 位置 | 描述 |
|------|------|
| dnssec/nsec.go:28,72 | NSEC 拒绝证明的名称比较区分大小写（normalizedQname 已 ToLower，fork unpack 不转小写）——非小写存储的 zone 混合大小写查询下 NODATA 证明失败；祖先委托 NSEC 过滤可绕过 RFC 6840 §4.1。修复：`dns.EqualName`。 |
| dnssec/nsec.go:330-336 | `stripLeftmostLabel("com.")` 返回 `""` 而非 `"."`——单标签 qname 的 closest encloser 遍历永远无法到达根，NXDOMAIN 证明失败。 |
| recursive_helpers.go:178 | `validateNODATAWithNSEC(response, ctx, ...)` 违反 ctx 第一参数约定（同文件其余函数均符合）。 |
| recursive.go:96 | 注释 "normalizedQname is empty for the root zone" 与代码不符（Canonical(".") 返回 "."）。 |
| recursive_helpers.go:161-162 | 注释 "the pooled message's backing arrays are reused by the next Get" 与 pool 实际行为不符（Put 只清零结构体，数组释放给 GC）。 |
| nameserver.go:281-350 | NS 地址收集无去重——同一地址从多个 NS 名/A+AAAA 双栈重复出现，对同一服务器重复并发查询。 |
| recursive_ns.go:76-87 | glue 记录 map 以记录名大小写为 key，与 NS 名大小写不匹配时 glue 命中但判未覆盖 → 冗余重解析。修复：key 统一 `dnsutil.Canonical`。 |

## 系统性根因

1. **信任锚检查只落在三处根 DNSKEY 验证点中的一处**（C4）——全局搜索 `SelfVerifyDNSKEY` 调用点逐一核对锚定。
2. **first-wins + SetLimit 排队 + 提前返回的组合**（H12 + M5）：池消息共享给仍在排队/运行中的 goroutine 后提前 Put——同一设计模式的多个缺陷形态。
3. **防御性 nil-Crypto 检查不一致**（M6）：7 个函数判 nil、2 个不判。
4. **RRset 身份 key 构造两套标准**（M1）：zonecut.go 已修复 RFC 3597 碰撞，nsec.go 仍用 TypeToString。

## 已排除疑点（有代码证据安全）

- forward.go：每 goroutine 有 HandlePanic + owner；first-wins + cancel 竞态被 drain + EDE 兜底覆盖。
- recursive_ns.go：fire-and-forget 探测 goroutine 均有 HandlePanic + r.ctx 生命周期 + singleflight 去重；glue bailiwick 校验正确。
- qname_minimise.go：RFC 9156 §2.3 步进、10 步封顶、NXDOMAIN/别名跳转均能终止。
- dnssec/crypto.go：RRset 结构校验、RRSIG 有效期显式检查、EDE 1/7/8 分类、ZoneKeys/RootKeys 防御性 nil 检查完备。
- probe/probe.go：pending 单飞 + LatencyLastProbe 节流 + bgGroup owner 齐备。
- resolver.go：concurrencyLimit 单调性成立；New 参数校验完整。
- 池契约：pooled message 切片在 Put 后继续引用是**有意设计**（pool.go 显式零化结构体而非 backing array，cache.Set 对 RR 深拷贝）。
