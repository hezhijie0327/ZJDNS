# ZJDNS Round 6 Domain 审计报告

**范围**：`config/`、`cache/`、`edns/`、`zone/`、`ruleset/`、`internal/spillfile/`（连带核实其支撑件 `internal/lrumap` 与调用方 `server/handler/middleware/`、`server/resolver/`、`server/protocols.go` 的相关链路）

**基线**：Round 5 报告（docs/audit/2026-11-round5-audit/02-domain.md）的全部发现已修复并核实：
- R5-02 修复确认 — `config/validate.go:324-326` 显式拒绝 QUIC==HTTP3 同端口；
- R5-03 修复确认 — `cache/nsec.go:244、295` covering 剩余 TTL 门 + `nsecWildcardDenied`(805-816) 仅计 live 区间；NSEC3 变体 NODATA 路径(319-324)同样有门；
- R5-04 修复确认 — `insertRanges`(584-614) 按 `cap-newZones` 逐出，表大小不超界。
R5-01/R5-05/R5-06 属 resolver/handler 范围，本轮不重复。R5-07 为已记录的脆弱不变量，不重复。

**验证方式**：全部发现均亲读代码逐行核实（含 dns fork 的 RFC3597 hex pack、miekg `dnsutil.Canonical/Fqdn` 语义、`internal/pack.StringHex` 错误路径）；范围内包 `go test -short` 全绿。

---

## 发现

### D1 | cache/key.go:97-110 + cache/entries.go:271-285 + edns/edns.go:139-151 | MEDIUM | 缓存污染/占用上限（可用性）

**客户端可控 ECS 变体可无上限繁殖缓存键：每个变体一条 LRU 槽位 + 一次 miss + 一次上游查询，~2000 个报文即可把默认配置的缓存整体驱逐。**

链路核实：
1. `edns/ecs.go ParseFromDNS`(26-43) 接受任意合法客户端 ECS 并 `Normalize()`（按 SourcePrefix 掩码地址，不缩前缀）；`middleware/edns.go:42` 无条件采纳为 `qctx.ECSOpt`。
2. `cache/key.go setECS`(97-110) 以**完整地址 + 客户端 SourcePrefix** 构造 exact 键：`/32 1.2.3.4` 与 `/32 1.2.3.5` 是两个键。
3. `cache/entries.go Set`(283-285) 直接用该 exact 键写入 LRU——出站前缀截断（`edns/edns.go:143-151`，/24、/56）只作用于发往上游的 wire，**不作用于缓存键**。上游对同一 /24 内所有 /32 变体返回完全相同的应答，却各占一条缓存。
4. `Get` 的 fallback 候选（entries.go:44-62）只能命中**已存在的更粗前缀条目**——首个查询总是写 exact 键，所以去重永远不发生。
5. singleflight 键同样携带 ECS（`BuildPendingKey`，handler/pending.go:141），变体间无去重——每个新变体是一次真实的上游往返。

**风险**：公网可达部署下，攻击者对一个热门名字循环发送随机 (address, prefix) 的合法 ECS 选项：N 个报文 → N 条缓存条目（默认 `DefaultMaxCacheEntries=2000`，全部合法条目被 LRU 驱逐）+ N 次上游查询（放大）。缓存命中率归零、上游流量线性放大。内存有 LRU 上界（不 OOM），但这是标准认知下的 ECS 缓存污染向量（Unbound `cache-max-ecs`、BIND acache 清理均为此存在）。内网/ACL 部署风险有限。

**修复建议**：与出站截断对齐——`Set` 构键时把 ECS 前缀封顶到 `DefaultECSv4Len/DefaultECSv6Len`（24/56）再掩码（Get 的 fallback 候选链已天然命中更粗键，/32 客户端查询会命中 /24 条目）；或按 Unbound 模式对每 qname 的 ECS 变体条目数设上限，超限降级为无 ECS 键。补一条"同 /32 变体只产生一条缓存"的测试。

---

### D2 | config/validate_tls.go:20-29 | MEDIUM | 配置校验缺口 / 功能静默失效

**TLS 族协议（tls/quic/https/http3/dtls）配置了监听端口但 `certificate.tls` 未配置时，校验直接放行，而监听器在 `server/protocols.go:93` 以 `Certificate.TLS.IsEnabled()` 为闸整体不创建——静默不监听；DTLS 的证书文件还被排除在 tlsEnabled 校验之外。**

核实：
1. `validateTLSCertificateConfig`（validate_tls.go:19-22）第一件事就是 `if !tlsCert.IsEnabled() { return nil }`——后续的 tlsEnabled 检查（行 26：`TLS || QUIC || HTTPS || HTTP3`）**只在证书已配置时才运行**。`protocol.tls:"853"` + 无 certificate.tls → 校验通过。
2. 接线侧 `server/protocols.go:93` `if cfg.Server.Certificate.TLS.IsEnabled() { ... tls.New ... }` — 证书未配置时 TLS/QUIC/**DTLS**/HTTPS/HTTP3 五个监听器都不创建，无任何日志。操作者以为 DoT 已上线，853 端口实际无人监听。
3. 即便证书配了：tlsEnabled 不含 `proto.DTLS`，而 protocols.go:43 注释明确 "QUIC/DTLS/HTTP3 use TLS certs" — DTLS-only 部署的 cert_file/key_file 路径、可加载性（LoadX509KeyPair）、权限告警全部跳过，错误推迟到 `tls.New` 才以 "TLS server init" 暴露。
4. 对比：`validateCertDomain`(109-123) 的 needsDomain **包含** DTLS——域名校验与证书校验的协议集合不一致，证实是遗漏而非设计。

**风险**：静默失效类配置错误（最坏：安全协议端口裸奔不监听、用户无感知）；DTLS-only 部署错误诊断推迟到运行期。

**修复建议**：任一 TLS 族协议（含 DTLS）启用而 `!tlsCert.IsEnabled()` 时返回错误（"protocol X requires certificate.tls (files or self_signed)"）；`tlsEnabled` 加入 `proto.DTLS`。补两条校验测试（TLS 无证书、DTLS-only 坏路径）。

---

### D3 | cache/entries.go:283-286 | LOW | 缓存键一致性（大小写变体）

**`Set` 在 `qname = dnsutil.Canonical(qname)` 之前就把原始 qname 装进缓存键——canonical 只作用于 wire 与 NXDOMAIN 索引，不作用于键。调用方契约（"caller must pass a canonical qname"）只写在 `Get` 上，`Set` 无此约束，而 resolver 内部调用方确实传非 lowercase 名。**

核实：
- entries.go:284 `key.qname, ... = qname, ...` 先于 286 行 canonicalize。
- `server/resolver/recursive_ns.go:91` `rrecNameFq := dnsutil.Fqdn(rrec.Header().Name)`（miekg Fqdn 只补点**不转小写**，已查 fork 源码）→ `cacheGlueRecords`(182-185) 以该混合大小写名 `cache.Set(nsName, ...)`。
- 上游记录 owner 会回显 0x20 随机化大小写（AGENTS 明载 capsguard 场景；记录折叠发生在 `resolver.Query` 出口，晚于 walk 内的 cacheGlueRecords）。
- 后果 A：这类条目对客户端路径的 `Get`（qctx.Qname 已 lowercase，handler.go:135）**永不命中**——纯死条目；后果 B：同一 NS 名的不同大小写回显各占一条 LRU 槽位与 spill 记录。
- 对照组：`mqtype_client.go:85` 的调用方显式 `dnsutil.Canonical(qname)` 后才 Set——证明键契约靠调用方自觉维持，是脆弱面。

**风险**：递归模式 + 大小写回显上游下，glue A/AAAA 缓存条目按大小写变体翻倍（有 LRU 上界，不失控），且客户端查询无法复用 walk 已缓存的数据（多付一次解析）。

**修复建议**：把 286 行的 canonicalize 移到 283 行之前（一行顺序调整，`Set` 即对任意调用方大小写安全）；键用 `zjdns/internal/dnsutil.Canonical`（ASCIIFold，免 strings.Map 分配）更佳。

---

### D4 | ruleset/ruleset.go:90-91 + 197-208 | LOW | 死配置（静默失效）

**任何超过 2 个标签的 domain 规则永远不可能匹配任何查询，但 LoadRules 照常计数并报 "loaded"。**

核实：规则键 `domainKey` 不限标签数（"bbc.co.uk" → 键 "bbc.co.uk"）；查询键 `tldPlusOne` 恒返回最右 1-2 个标签（"www.bbc.co.uk" → "co.uk"；"x.analytics.google.com" → "google.com"）。两者做 **map 精确等值** 匹配（`Match` 的 `table.domainRules[key]`）——键标签数 >2 的规则对任何 qname 都不等值。行内注释只承认 "Multi-part TLDs are not handled (documented limitation)"，但死规则范围远大于多段 TLD：`analytics.google.com` 这种 3 标签普通规则同样全灭，且 `LoadRules` 计入 `ruleCount` 输出 "N rules loaded" 日志，操作者无从得知规则无效。

**风险**：以域名规则做分流/封禁的配置静默失效（安全预期落空），无任何告警。

**修复建议**：加载时对 >2 标签的 domain 键 Warn（或直接拒绝）；或把匹配改为后缀匹配（逐级剥标签查 map，最多 3 次查表），同时解决多段 TLD 限制。

---

### D5 | ruleset/ruleset.go:99-129 + server/init.go:186-190 | LOW | 性能（每查询分配）

**配置了任意 ruleset 后（TagMatcher 即挂载），每个查询都走 `net.IP → ip.String()（分配）→ net.ParseIP（再分配）` 双重转换，命中时再分配 map 与 tags slice——而 zone 中间件手里本来就有 `net.IP`。**

核实：`middleware/zone.go:77-79` 每查询调 `m.tagMatcher(qname, qctx.ClientIP)` → `init.go:188` `rulesetEngine.Match(qname, ip.String())` → `ruleset.go:116` `net.ParseIP(ip)`。`ipTrie.match`(80-107) 沿路径 append 各节点 tags（slice 分配），`Match` 命中任何 tag 再 `make(map[string]bool)`。`MatchIP`（bool 返回）已经零分配，说明 trie 本身可零分配服务此路径。

**风险**：热路径每查询 2-3 次小分配（~100B），仅在有 ruleset 的部署可见——与本项目"每查询路径零分配契约"不符；QPS 影响小，属一致性/洁癖级。

**修复建议**：`Engine.Match` 增加 `net.IP` 参数（或 TagMatcher 签名直接传 `net.IP`），trie 内先 `To16` 再走位；domain 规则未命中且 trie 无匹配时保持零分配（现状已满足）。

---

### D6 | zone/wire.go:75-81 | LOW | 错误处理（失败推迟到 serve 时）

**buildRecord 在 dns.New 解析失败时回退构造 RFC3597 记录，把原始 Content（几乎必然不是 hex）塞进 `dns:"hex"` 字段——坏记录在加载时被静默接受，pack 失败推迟到每个命中该规则的查询。**

核实：dns fork `rdata.RFC3597{Data string \`dns:"hex"\`}`（rdata.go:332-335）；pack 走 `internal/pack.StringHex` → `hex.Decode` 对非 hex 输入返回 err（pack.go:396-406，已读源码）。dns.New 失败的两种情况——未知 TYPE、或已知 TYPE 内容非法——前者正确走 RFC3597（但 Content 需 `\# len hex` 型，这类 dns.New 本可成功），后者产生确定性的 serve 期 pack 错误。zone/wire.go 无任何 Warn。zone_test.go 无此回退的覆盖。

**风险**：一条拼错的 Answer content 在加载期无告警；该规则命中时每个查询走 pack 失败路径（响应失败/降级），排查困难。

**修复建议**：回退前校验 Content 形如 `\# <len> <hex>`（或 hex 可解码），否则 Warn + 丢弃该记录；补测试。

---

### D7 | cache/nxdomain.go:63-65 + server/handler/middleware/cache_lookup.go:124 | LOW | 契约不匹配（潜在 nil 解引用）

**NegativeAncestor 显式支持 `e.soa == nil` 时返回 `(nil, remaining, true)`，而唯一调用方无条件 `soa.Header().TTL = ...`——若该分支可达即每查询 panic。**

核实：nxdomain.go:63-65 `if e.soa == nil { return nil, remaining, true }`；cache_lookup.go:124 直接解引用。当前不可达仅因一个**间接约束**：`Set`(entries.go:277-291) 对无 SOA 负响应 `cacheTTL` 返回 0 → 提前 return → `indexNXDOMAIN` 不可达 → `nxEntry.soa` 恒非 nil。任何未来改动放宽该约束（如 RFC 9520 式无 SOA 负缓存）即刻变成远程可触发 nil 解引用。

**修复建议**：二选一：调用方对 `soa == nil` 跳过（合成无 SOA 的 NXDOMAIN cut 响应），或删除 NegativeAncestor 的 nil 分支、在 indexNXDOMAIN 处断言 SOA 存在。加注释互指该不变量。

---

### D8 | cache/stats.go:175-192 | LOW | 注释与代码矛盾（防御路径失效）

**UpdateLatencyBatch 在进入循环前无条件 `hasLatencyData.Store(true)`，而循环内非法 IP 分支的注释声称 "Set the flag only after validation"——注释描述的行为只在单条 UpdateLatency 成立。**

核实：stats.go:179 先置位；:187-191 的 continue 分支带该注释（从 UpdateLatency:162-166 复制而来）。全非法 IP 的 batch（如调用方传错键）会置位 flag 而表为空 → 每个 A/AAAA 多答案缓存命中照走 `sortAnswerByLatency` 前导（addrs/slots/rrToIP map/ips/latencies 共 ~5 次分配）只为得出 "无延迟数据"。当前内部调用方（探测结果）都传合法 IP，实害为零，但注释误导后续维护者以为有此防线。

**修复建议**：把 `hasLatencyData.Store(true)` 移到首个合法 IP 写入 `s.latencies.Set` 之后；或如坚持前置，改写注释为现在时约束并说明为何批量输入可信。

---

### D9 | cache/entries.go:271-409 + internal/spillfile/spillfile.go:119 + server/tasks.go:76-110 | LOW | 内存/磁盘占用上限按条数而非字节

**缓存两级上限（内存 LRU `maxEntries`、spill `spillCap`）与周期压缩（compactSpill）全部按记录条数计量，`Set` 无单条字节上限——上游可控响应尺寸时，实际占用可超 defaults 注释宣称的 envelope（热层 ~3MB、spill 索引 ~4MB）两个数量级。**

核实：`Set` 无消息大小门（最大 DNS 消息 64KB 可入缓存）；`config.DefaultMaxCacheEntries=2000`（defaults_dns.go:12-17 注释按 ~500B 均值估算 ~3MB）；spill `maxWireLen=16MiB` 只防无界分配；`compactSpill` 的 disk cap 判定 `len(entries) <= diskCap` 也是条数。理论最坏：内存 2000×64KB≈128MB，spill 20000×64KB≈1.2GB 磁盘。zstd（>256B 阈值）、`DefaultMaxCacheableTTL`、上游通常 <4KB 响应构成常态缓解；但 64KB 仅 TCP 可达、UDR 需 TC 回退，攻击面为恶意/异常上游或被污染应答（防御不确定标记已另行拒绝入缓存）。

**风险**：小内存设备（注释目标场景 64-128MB）上异常上游可造成内存压力超出设计预期；磁盘 spill 同理。

**修复建议**：`Set` 加单条大小上限（如 wire > 16KB 跳过缓存 + Debug 计数），或 LRU/spill cap 增加字节维度跟踪（evict 时同时扣减字节数）。属纵深防御，优先级低。

---

## 核实为干净的区域（避免后续轮次重复排查）

| 区域 | 结论 |
|---|---|
| cache 池纪律 | AcquireWire 每命中拷贝共享 msgWire（entries.go:184-193 注释准确）；TTLOffsets 池 cap 判定（ReleaseTTLOffsets ≤256）；sorted 快路径双释放（owned/offsets 回池，entries.go:229-246）；`ReleaseOffsets` 幂等设计正确 |
| lrumap（cache 支撑件） | working-set clock LRU：读锁命中 + 冷条目写锁升级，identity 复查防 Clear 幽灵重链（lru.go:119-131）；shard 容量近似偏差已在 shard.go:4-5 注释声明；`Get` 读侧无锁读 `e.val` 与写侧 `e.val=val` 在锁序上安全 |
| spillfile 损坏防御 | wireLen ≤ maxWireLen 在 scan(format.go:176)、lookupInBlock(293)、scanBlock(330) 三处一致；keyLen==0/越界拒绝；截断尾记录 truncateAt 回写 header；neg-miss 世代检查（rememberMiss gen 复核）TOCTOU 正确 |
| spillfile 并发 | fileRef 快照读 + Compact wmu 全程持锁防尾追加丢失；Windows rename 双跳自愈路径正确；AsyncWriter close(RLock 发送 vs 独占 close) 无 send-on-closed 竞态 |
| nsec.go RFC 8198 | R5-03/04 修复完整（见文首）；pruneNSECRange `[:0:0]` 断开 COW 别名；NXNAME 紧凑否定、DS-父侧例外、Opt-Out 排除均正确 |
| cacheTTL / RFC 2308 | OPT 跳过（R5 修复在位）、MSB-set TTL 归零、负缓存无 SOA 不缓存、7 天 cap 正确 |
| edns cookie | RFC 9018 MAC 构造、RFC 1982 序列算术、常数时间比较、三世代密钥——R5 已审，本轮复读无新问题 |
| Flush/FlushDB 生命周期 | writer 排干→清表→重建的顺序正确；spill 复活窗口（drain 后再 truncate）已闭合；Flush 仅 shutdown 调用（tasks.go:366），之后 Enqueue 落 closed-writer 被安全丢弃 |
| zone Evaluator | COW 快照 + 原子发布无锁读；sentinel/exact/wildcard 三级查找与 score 语义自洽；winner RR 克隆防跨查询污染 |
| config | R5-02 修复在位；端口冲突矩阵（TCP/UDP 分离 + 共享组）逻辑复核通过；ACL 解析/Overlap 告警正确；resinfo 的 resolver.arpa NODATA sentinel 顺序陷阱已有正确约束注释 |

## 审过文件清单

| 包 | 文件 |
|---|---|
| cache | cache.go, entries.go, store.go, spill.go, key.go, wire.go, stats.go, latency_sort.go, latency_spill.go, nxdomain.go, nsec.go |
| internal/lrumap（cache 支撑件） | lru.go, shard.go |
| internal/spillfile | spillfile.go, format.go, compact.go, async.go |
| edns | edns.go, ecs.go, cookie.go, ede.go, padding.go, tcp_keepalive.go |
| config | config.go, load.go, defaults.go, defaults_dns.go, ecs.go, validate.go, validate_upstream.go, validate_tls.go, acl.go, chaos.go, ddr.go, resinfo.go |
| zone | zone.go, zone_match.go, parse.go, wire.go |
| ruleset | ruleset.go, iptrie.go |
| 链路追踪（范围外核实） | server/handler/{resolve.go, pending.go, handler.go, context.go}, middleware/{edns.go, cache_store.go, cache_lookup.go, zone.go, resolution.go}, server/resolver/{recursive_ns.go, mqtype_client.go, forward_fallback.go}, server/{protocols.go, init.go, tasks.go}, dns fork（dnsutil.Canonical/Fqdn, rdata.RFC3597, internal/pack.StringHex） |

范围内包 `go test -short` 全部通过。

---

## 汇总表

| 编号 | 严重程度 | 类别 | 位置 | 概要 |
|---|---|---|---|---|
| D1 | MEDIUM | 缓存污染/占用 | cache/key.go:97, entries.go:283, edns/edns.go:143 | 客户端 ECS 变体无上限繁殖缓存键 + 上游放大（~2000 包清空默认缓存） |
| D2 | MEDIUM | 配置校验缺口 | config/validate_tls.go:20-29（+server/protocols.go:93） | TLS 族协议无证书配置时校验放行且监听器静默不创建；DTLS 证书不参与校验 |
| D3 | LOW | 缓存键一致性 | cache/entries.go:283-286 | Set 键取 canonical 之前的原始 qname；resolver 内部混合大小写名产生客户端不可达的大小写变体条目 |
| D4 | LOW | 死配置 | ruleset/ruleset.go:90,197 | >2 标签的 domain 规则永不匹配，加载无告警 |
| D5 | LOW | 性能/分配 | ruleset/ruleset.go:99-129 | 每查询 ip.String→ParseIP 双重转换 + 命中时 map/slice 分配 |
| D6 | LOW | 错误处理 | zone/wire.go:75-81 | buildRecord RFC3597 回退把非法内容推迟到 serve 期 pack 失败 |
| D7 | LOW | 契约不匹配 | cache/nxdomain.go:63 + middleware/cache_lookup.go:124 | NegativeAncestor nil-SOA ok=true 分支与调用方无条件解引用不匹配（当前不可达） |
| D8 | LOW | 注释准确性 | cache/stats.go:175-192 | UpdateLatencyBatch 的 flag 置位先于验证，与注释矛盾 |
| D9 | LOW | 占用上限 | cache/entries.go:271, spillfile.go:119, tasks.go:87 | 两级缓存上限均按条数、无单条字节门，极端响应尺寸可超设计 envelope 两个数量级 |
