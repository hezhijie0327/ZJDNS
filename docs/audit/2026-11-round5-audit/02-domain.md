# ZJDNS Round 5 Domain 审计报告

**范围**:`config/`、`cache/`、`edns/`、`zone/`、`ruleset/`、`dnscert/`、`internal/spillfile`(重点:9c6df186 以来的 diff — `edns/ede.go` EDE 65281、`cache/wire.go` OPT TTL 跳过,及其在 handler/resolver 的完整链路)

**Diff 审查结论**:`edns/ede.go` 常量/助手本身正确;`cache/wire.go` 的 OPT TTL 跳过修复正确且重要(`cacheTTL` 在 `cloneRRsNoOPT` 之前被调用,修复前 additional 中幸存的非标准 OPT(TTL≈0)会把整个响应的缓存 TTL 归零)。但 EDE 65281 链路在递归路径上被完全击穿 — 见 R5-01。

---

## 发现

### R5-01 | 严重 | 安全特性失效 | server/resolver/cname.go:326 + forward_process.go:285 + recursive.go:573

**EDE 65281 防御不确定标记在递归路径上被整体丢弃 — "毒答案爆炸半径一次查询" 的承诺在 recursive 模式下完全失效。**

链路核实:
1. `upstream/client.go:270` 对 UDP + HopGuard 学习期 / CapsGuard 未验证的响应设置 `result.Uncertain`;递归 walk 的权威查询确实携带这些防御(ns_concurrent.go:111-112,resolver.go:258-259 继承配置)。
2. `recursive.go:208/392/421` 的 `applyDefenseUncertainty` 在 walk 终态正确设置 `Cacheable=false` + `UpstreamEDE=65281`。
3. **但** 所有递归查询都流经 `cname.resolveInner`(forward_process.go:284),其聚合返回(cname.go:326)硬编码 `Cacheable: true` 且**不携带 `UpstreamEDE` 字段** — 逐 hop 读取了 Answer/Rcode/Validated 等 11 个字段,唯独丢掉这两个。
4. `handleRecursiveQuery`(forward_process.go:285)随后 `qr.Cacheable = !server.SkipCache` 再次覆盖回 true。
5. 结果:`StoreIfCacheable`(handler/resolve.go:85)的 belt-and-suspenders 检查 `IsZJDNSNoCacheEDE(qr.UpstreamEDE)` 因 EDE 为 nil 而放行 — **防御不确定(可能是注入的)响应按完整 TTL 进缓存**;客户端也永远看不到 65281,下游 ZJDNS 拒收机制同样无从触发。

测试盲区:`defense_uncertain_test.go` 只单测 `applyDefenseUncertainty` 本身,`store_nocache_test.go` 只单测 `StoreIfCacheable`;无递归全链路测试。功能提交 0d7dfd43 的 E2E 验证是在转发模式做的(上游 UDP hopguard),递归路径未覆盖。

**附带泄漏(同一根因族)**:
- `recursive.go:362` 的 `warmFromMQResponse` 在 walk 内部直接 `cache.Set`(mqtype_client.go:97/99,绕过 StoreIfCacheable),递归侧调用点**没有** uncertain 门(转发侧 forward_process.go:205 有 `!fallbackMarked` 门) — MQType 附带类型在 hopguard 学习期照样进缓存。
- walk 期间 `storeDelegation`/`cacheGlueRecords` 填充 delegation/glue 缓存同样不看 hopUncertain。[待核实:影响面,delegation 缓存有独立验证,风险较低]

**修复建议**:`resolveInner` 聚合时传播 no-cache 标记(任一 hop 防御不确定 → 聚合结果 `Cacheable=false` + `UpstreamEDE=65281`,可按"最保守 hop"合并);`handleRecursiveQuery:285` 改为 `qr.Cacheable = qr.Cacheable && !server.SkipCache`;`recursive.go:362` 的 warm 调用加 `!hopUncertain` 门;补一条递归模式 E2E/集成测试(hopguard 学习期重复查询不得命中缓存)。

---

### R5-02 | 中 | 配置校验与其自身注释矛盾 | config/validate.go:294-332

**UDP 共享端口分组允许 QUIC(DoQ) 与 HTTP3(DoH3) 同端口共存,违反同文件声明的"二者字节级不可区分、不得共享同一端口"约束。**

代码把 `{proto.QUIC, "server.protocol.quic"}` 与 `{proto.HTTP3.Port, "server.protocol.http3.port"}` 放进同一 candidates 列表按端口分组(≥2 即成 sharedGroup 放行)。而注释(validate.go:297-298)明确"DoQ 与 HTTP3 都是 QUIC、首包无法 demux、不能共存"。服务端接线也证实无此组合的 demux:protocols.go:80-81 的 `http3PortShared` 仅覆盖 DNSCrypt 共享,`wantSharedUDP`(protocols.go:68)不含 QUIC==HTTP3。配置 `quic:"443"` + `http3.port:"443"` 会通过校验,随后两个独立 QUIC listener 争绑同一 UDP 端口(EADDRINUSE 或随机错路)。

**修复建议**:分组前显式排除该组合 — QUIC 与 HTTP3 端口相等时返回端口冲突错误。

---

### R5-03 | 中 | RFC 8198 合成正确性 | cache/nsec.go:221-262, 268-319

**SynthesizeWildcard 从不校验 covering(非存在证明)区间的剩余 TTL — 主区间可已过期仍作为 wildcard 合成/否定应答的证明。**

- 正路径(cname 同理):`synthesizeWildcardNSEC` 只检查 wildcard 表项 `we.ttl - (now-we.ts) > 0`(line 244),`covering` 的过期与否从未检查;`buildProofAuthority(covering, remaining)` 会把已过期 covering 的 NSEC/RRSIG 以 we 的剩余 TTL 写进 Authority。NSEC3 变体(line 290-294)同。
- NODATA 路径(line 253-257)检查了 wildcard-NSEC `r` 的 remaining,但 Authority 里的 covering 记录仍未检查自身过期。
- 同族:`synthesizeNSEC` 的 `nsecWildcardDenied`(line 784-792)扫描的 wildcard-denial 区间也不过期检查。

过期区间只在同 zone 下次 upsert 时被 `pruneNSECRange` 清理,静默期可任意长。缓解:合成出的 RRSIG Expiration 未被改写,严格校验的下游会拒绝;但 ZJDNS 自身与不校验的客户端会在证明过期后继续合成(名字可能已被创建)。`SynthesizeNegative` 的主区间检查(line 179-182)是对的;nsec_test.go:368 只覆盖了那一处。

**修复建议**:`nsecAppendixB`/wildcard 路径选中 covering 后统一加 `covering.ttl - int(now-covering.ts) > 0` 门(wildcard-denial 区间同理),并补测试。

---

### R5-04 | 低 | 边界偏离 | cache/nsec.go:574-595

`insertRanges` 在 `len(s.nsecZones) >= cap` 时只逐出 1 个 zone,但同一次调用可插入 2 个(NSEC 与 NSEC3 key 不同)— 表大小可达 `DefaultAggressiveNSECZones+1`。有界(后续插入先逐出),仅上限偏离 1。建议逐出 `len(新增)-1` 个或改用 `>` 判定后逐出至 `cap-len(new)`。

### R5-05 | 低 | RFC 8914 多选项 | server/resolver/forward_process.go:31-48

`captureUpstreamEDE` 只取 `resp.Pseudo` 中**第一个** EDE 即返回;RFC 8914 允许多个 EDE 选项(按 InfoCode 升序)。ZJDNS 自身出口至多携带一个 EDE(cache_store.go:154 替换而非追加),但两个 ZJDNS 之间夹第三方递归(转发原始 EDE 列表并追加自己的 EDE)时,65280/65281 排在后位会被漏检 → 下游拒缓存标记失效。建议扫描全部 pseudo 记录,优先取 ZJDNS 私有码,其余作普通 EDE 透传。[待核实:实际拓扑可达性]

### R5-06 | 低 | 防御纵深不对称 | server/resolver/forward_fallback.go:107-121

`fillCacheFromResult` 只查 `!res.Cacheable`,没有 `StoreIfCacheable` 那条 `IsZJDNSNoCacheEDE` 的 belt-and-suspenders(注释还声称"mirrors the CacheStore middleware's gates")。当前两个调用点的 `Cacheable` 都以 `!fallbackMarked` 构造所以安全,但任何未来新增调用点漏设即破。建议补同一检查(一行)。

### R5-07 | 低(记录,非缺陷) | 脆弱不变量 | cache/entries.go:378-404 + internal/pool/pool.go:92-97

`Set()` 在 `wire := msg.Data` 别名存活期间调用 `Message.Put`(其内部 `ReleaseWire(msg.Data)` 按 cap==2048 回收)。当前安全仅因:未压缩别名(wire≤256,cap==len)永远不匹配 2048 容量类,而 cap==2048 的响应必 >256 走 Compress 断开别名。该安全性依赖 `DefaultCompressionThreshold(256) < wireBufferSize(2048)` 这一隐式关系,值得在两处注释互指,防未来把阈值调高引入 use-after-put。

---

## 审过文件清单

| 包 | 文件 |
|---|---|
| cache | wire.go, cache.go, entries.go, store.go, spill.go, key.go, stats.go, latency_sort.go, latency_spill.go, nxdomain.go, nsec.go |
| edns | ede.go, edns.go, cookie.go, ecs.go, padding.go, tcp_keepalive.go |
| config | config.go, load.go, defaults.go, ecs.go, validate.go, validate_upstream.go, validate_tls.go*, acl.go, chaos.go, ddr.go, resinfo.go |
| zone | zone.go, zone_match.go, parse.go, wire.go |
| ruleset | ruleset.go, iptrie.go |
| dnscert | generate.go |
| internal/spillfile | spillfile.go, format.go, compact.go, async.go |
| 链路追踪(范围外核实) | server/handler/resolve.go, middleware/cache_store.go, server/resolver/{forward,forward_process,forward_fallback,recursive,cname,ns_concurrent,mqtype_client}.go, upstream/client.go, internal/pool/pool.go, dns fork msg.go/Pack/Unpack |

(*validate_tls.go 仅通读,TLS 证书校验未逐行;非本轮 diff 涉及)

**核实为干净的重点区域**:cache 池纪律(AcquireWire/ReleaseWire 成对、fast-path 双释放、Unpack 后 RRs 不别名 wire — dns fork 解包时拷贝字符串)、spillfile gen/负缓存 TOCTOU(世代检查在 mu 下)、AsyncWriter 生命周期(Close 与 Enqueue 的 RWMutex 防关渠竞态、idempotent)、RFC 9018 cookie(RFC 1982 序列算术、常数时间比较、三世代密钥)、ruleset 双栈 radix trie、zone/ruleset COW 快照、FlushDB 的 spill 复活窗口处理。所有范围内包 `go test -short` 通过。