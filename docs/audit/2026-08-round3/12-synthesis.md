# 2026-08 第三轮审计 — 差缺补漏 + 交叉复核综合报告

> 审计日期: 2026-08-05
> 审计范围: 全库 ~52K 行 Go（HEAD = 6bedbfb，工作树干净；round-2 存档后无新 commit）
> 审计方法: AUDIT-METHODOLOGY §1.2 — 补缺 8 agent（protocol 包级 + goversion 交叉 + 6 组零覆盖包扫描）+ 1 修复方向复核 agent + 审计主循环人工读码核验
> 原始发现: round-3 agent 51 条（CRITICAL 1 / HIGH 2 / MEDIUM 23 / LOW 25）+ round-2 修复方向复核 14 项
> 存档: `dedup-index.txt`（round-2 全部 152 条索引）、`round3-workflow.js`（可复跑）

## 一、为什么需要第三轮（差缺的量化证据）

| 轮次 | 有发现的 Go 文件数 | 生产文件总数 | 零覆盖生产文件 |
|------|-------------------|-------------|---------------|
| 2026-08-full（93611d5 前全库） | 56 | 157 | — |
| 2026-08-round2（delta 聚焦） | 38 | 157 | 123 |
| 两轮并集 | 74 | 157 | **89** |

- round-2 的发现集中在 delta commit 触及的文件（cache/store.go、bridge.go、middleware/*、dnscrypt 等 38 个）；**89 个生产文件在两轮审计中零发现**——cmd/zjdns、config/、database/、internal/、ruleset/、zone/、server/handler/、server/resolver/dnssec/、server/upstream/ 等。
- round-2 有 2 个 agent 中断（03-protocol、25-goversion），本轮已补全。
- 结果：**89 个零覆盖文件中命中 51 条新发现，其中 1 CRITICAL / 2 HIGH**——"不全"的判断成立，且缺口主要在安全关键区（DNSSEC 验证链、递归应答校验）。

## 二、新发现 CRITICAL / HIGH（全部经审计主循环人工读码核验 CONFIRMED）

### R3-C1 — CRITICAL — `server/resolver/dnssec_chain.go:405`（同型 :272/:54）DNSKEY RRset 单 DS 摘要匹配即整体信任，缺 RFC 4035 §5.2 RRset 自签验证

**发现**: `VerifyDelegationDS`（dnssec/crypto.go:134）只做 DS 摘要 ↔ DNSKEY 逐条匹配；三处信任点（isDNSSECValid:405、ensureZoneDNSKEYs:272、isValidWithDNSSEC:54）在匹配成功后把**整个 dnskeyRecords 集合**存入 `chain.zoneDNSKEYs` / ZoneKeys 缓存，**从不验证 DNSKEY RRset 自身的 RRSIG**。RFC 4035 §5.2 要求：匹配 DS 的密钥必须签名整个 DNSKEY RRset——缺少该步，集合中任何额外注入的密钥都被信任。

**攻击链**（on-path 攻击者位于递归器与子区权威之间）:
1. 拦截 DNSKEY 查询响应，注入攻击者密钥 K2（连同真实 K1 一起返回）；
2. `VerifyDelegationDS` 用 K1 匹配父区 DS 摘要 → 成功 → 集合 {K1, K2} 全部入链；
3. `isAnswerSectionValid`（crypto.go）按答案 RRSIG 的 KeyTag 在集合中选密钥 → 攻击者用 K2 私钥签任意答案 → 验证通过；
4. AD=1 的伪造答案被缓存并下发给客户端。

**影响**: 对 on-path 攻击者（正是 DNSSEC 验证要防御的场景）完全伪造任意子区答案，静默缓存污染；root 区因 `ContainsRootKey` 交叉检查（:428）不受影响，非 root 子区全线暴露。

**修复**: DS 匹配成功后，用匹配到的密钥验证 DNSKEY RRset 的 RRSIG（`crypto.VerifyRRset(dnskeyRecords, dnskeyRRSIGs, matchedKey)`）——matchedKey 是 VerifyDelegationDS 的返回值（当前被 `_` 丢弃）；验证失败 → bogus。或仅信任 matchedKey 单密钥（而非整集合）。测试：构造含注入密钥 + 合法 DS 匹配的 DNSKEY 响应 → 断言拒绝。

### R3-H1 — HIGH — `server/resolver/nameserver.go:95` 递归路径无 question echo 校验（RFC 5452 §9.3）

**发现**: `queryNameserversConcurrent` 接受响应后只查 `result.Response.Rcode`，从不比较响应 Question 区与所发查询的 qname/qtype；`IsResponseValid`/`isAnswerSectionValid` 按 RRset owner 分组验证签名，也不要求 owner == 查询名。

**攻击**（on-path，同区任意签名响应重放）: 攻击者拦截对 `attacker.example.com` 的查询，重放先前捕获的 `bank.example.com` 的签名响应（RRSIG 由同一区密钥签发，验证通过）→ 该响应作为查询结果被缓存/下发（qname=attacker.example.com 下挂着 bank 的记录，AD=1）。zonecut.go:274 注释已自认 "IsResponseValid accepts any key in the slice" 的弱点，但 question echo 缺口未被覆盖。

**影响**: 签名区内任意名字的缓存投毒（重放真实数据，非伪造数据——攻击者无法自造签名，但可为受害查询注入其他名字的错误数据），TTL 内持续污染。

**修复**: 接受响应前校验 `len(response.Question) > 0 && dns.EqualName(response.Question[0].Header().Name, question.Name) && RRToType(question) 一致`；不匹配 → 丢弃（Put + 下个 NS）。同时对答案 RRset owner 与查询名做匹配断言。

### R3-H2 — HIGH — `config/load.go:113` DoH sdns:// stamp 静默产生永久失败的 upstream

**发现**: `resolveStamp` 用 `zstamp.ProtoToConfig(s.Proto)` 推导 protocol——DoH stamp 返回 `"doh"`（stamp.go），而配置/上游词汇表只认 `"https"`（validate.go:150 validProtocols 无 "doh"；upstream/client.go:256 分派 switch 也无 "doh" case → default "unsupported protocol: doh"）。且 load.go:38 `validateConfig` **先于** :42 `normalizeStamps` 运行——校验期 protocol 还是空串（合法），normalize 后才变成 "doh"，绕过了所有校验。`--generate` 生成的示例配置若含 DoH stamp 即中毒。

**影响**: 配置里任何 DoH stamp（`sdns://...doh...`）→ 该上游每个查询都以 "unsupported protocol: doh" 失败；多上游组内若 all-fail → SERVFAIL。静默失败，无启动期报错。

**修复**: `ProtoToConfig(ProtoDOH)` 返回 `config.ProtoHTTPS`（"https"），或 resolveStamp 内做 "doh"→"https" 映射；并调整 load 顺序为 normalizeStamps → validateConfig（或 validate 后二次校验）。CLI `--dnsstamp --encode --proto doh` 输出与 config 消费方的词汇表应统一。

## 三、新发现 MEDIUM 摘要（agent 报告，均已附代码证据；抽查核验 3 项）

| # | 位置 | 类别 | 摘要 |
|---|------|------|------|
| R3-M1 | server/protocol/tls/tls.go:254 | perf | **pre-packed 直发快路径在全部 TLS 家族监听器失效**——handler 以 isSecure=true 入链（tls.go:254/quic.go:272/https.go:129/dtls.go:177/tlcp.go:111/…），response.go:119 shouldAddEDNS 含 `qctx.IsSecure` → 快路径门（:58 `!shouldAddEDNS`）恒假，7/8 协议家族缓存命中全走 Unpack+重 Pack；f7e7f13 的头牌优化实际只在明文 UDP/TCP 生效（人工核验 ✅） |
| R3-M2 | server/protocol/dnscrypt/udp.go:59 | race | serveUDP/serveTCP 的 `s.wg.Add(1)` 无锁，Shutdown 在锁内 swap wg（server.go:384-385）——Add 与 Wait 竞态（人工核验 ✅） |
| R3-M3 | server/handler/middleware/chain.go:123 | security | ANY 与 Zone 匹配查询在 EDNS.pre（cookie 校验）之前短路——RFC 7873/9018 cookie 校验被绕过 |
| R3-M4 | server/handler/pending.go:59 | concurrency | LRU 淘汰 in-flight pendingCall → 跟随者被唤醒时拿到 nil 结果 → resolution.go 返回 nil → 查询静默丢弃 |
| R3-M5 | server/upstream/pool/tcp.go:200 | deadline-race | Exchange 的写 deadline 设置/归零在 writeMu 临界区外——并发 Exchange 相互擦除 deadline，阻塞写可超 9s 预算直至 60s idle timeout |
| R3-M6 | server/upstream/tls/quic.go:162 | context | doQUICQuery 流 I/O 无 ctx AfterFunc fail-fast（DoT/DTLS/DTLCP 均有），取消后 goroutine 阻塞至超时 |
| R3-M7 | zone/wire.go:75 | rfc | 通配符 zone 规则答案保留字面 `*.domain` owner 名，未替换为 QNAME |
| R3-M8 | zone/zone.go:535 | log-spam | match_tags 畸形时 Warnf 位于每查询热路径 |
| R3-M9 | server/handler/middleware/validation.go:34 | validation | wireNameLength 误解析 miekg v0.6.89 presentation 名：内嵌点标签被误 REFUSED、反斜杠字节处理错误 |
| R3-M10 | config/validate.go:180 | validation | 空/scheme 缺失的 https/http3/http-tlcp 地址通过校验，静默 dial ':443' |
| R3-M11 | cmd/zjdns/cli/sql.go:16 | validation | --sql（文档标注只读）在路径不存在时创建全新迁移完整的 SQLite 库 |
| R3-M12 | config/ddr.go:171 | rfc | DDR SVCB TargetName '.' at _dns.resolver.arpa —— RFC 9462 §4 明确 MUST NOT |
| R3-M13 | config/ddr.go:191 | rfc | resolver.arpa 未按本地服务区处理，非 SVCB 查询转发上游（RFC 9462 §6.4） |
| R3-M14 | server/resolver/dnssec/nsec.go:255 | rfc | NSEC3 covered-name NODATA 不要求覆盖记录的 Opt-Out 标志（RFC 5155 §8.5）——非 Opt-Out 区不完整证明被 fail-open 接受为 AD=1 |
| R3-M15 | server/resolver/dnssec/extract.go:189 | pool-leak | ZoneKeys 缓存命中不 ReleaseTTLOffsets——TTLOffsets 池泄漏族（mqtype/dns64/ns_addresses 已报）的新调用点，位于每次委派变化的热路径 |
| R3-M16 | internal/stamp/encode.go:130 | encode-parse | 编码器输出裸 IPv6 地址，包内自己的解析器拒绝（CLI encode → decode 不自洽） |
| R3-M17 | internal/stamp/stamp.go:235 | url | BuildDoHURL 在 ProviderName 带端口时产出非法 URL |
| R3-M18 | internal/dnscryptcrypto/pq.go:139 | panic | PQEncapsulate 缺 PQDecapsulate 同型的长度守卫——xwing.Encapsulate 对 len(pk) 错误 panic |
| R3-M19 | server/init.go:69 | config | wireZoneDynamicContent 按原始字符串匹配规则名，zone.LoadRules 做了 Canonical 化——永不匹配 |
| R3-M20 | server/defense/hopguard.go:96 | perf | trustedKeys(st) 参数在每次 hopguard 拒绝时无条件求值——拒绝路径分配+排序 |
| R3-M21 | server/handler/middleware/any.go:43 | observability | ANY/PTR 短路响应不进 query_stats/query_log |
| R3-M22 | internal/dnscryptcrypto/encrypted.go:357 | validation | 经典 Encrypt 路径缺 PQ 路径已有的 MaxDNSUDPPacketSize 超限守卫 |
| R3-M23 | internal/dnsutil/tcpframe.go:111 | bounds | WriteTCPMsg 对 >65535 的 msg.Data 静默回绕 2 字节长度前缀 |

## 四、新发现 LOW 摘要

| # | 位置 | 摘要 |
|---|------|------|
| R3-L1 | go.mod:3 | `go fix ./...` 全库零诊断（modernize 已全部应用） |
| R3-L2 | server/upstream/tls/https.go:131 | 5 处 `errors.As` 未用同文件已用的 `errors.AsType[T]` |
| R3-L3 | server/protocol/tls/server.go:347 | 14 处手写 `append([]T(nil), src...)` 可换 `slices.Clone` |
| R3-L4 | server/handler/prefetch.go:81 | 手写 6 行比较器可换 `cmp.Compare` |
| R3-L5 | database/db.go:38 | 包级 atomic 函数 + int32 未用 typed `atomic.Int32` |
| R3-L6 | edns/cookie.go:192 | 服务端 cookie SipHash MAC 非常量时间比较 |
| R3-L7 | zone/zone.go:204 | 通配符规则 + DynamicContent 注册不可达动态键，函数永不调用（死配置） |
| R3-L8 | ruleset/ruleset.go:39 | New() 双份堆叠 doc 注释 |
| R3-L9 | zone/zone.go:297 | Evaluate() 编号流程注释跳号 |
| R3-L10 | cmd/zjdns/cli/probe.go:79 | TLS probe 分支裸 net.Dial 无超时——黑洞目标挂死远超 probeDialTimeout |
| R3-L11 | cmd/zjdns/cli/sql.go:131 | RowsAffected 错误裸 `_` 丢弃无注释 |
| R3-L12 | cmd/zjdns/cli/probe.go:321 | probeIdleTimeout 把所有非超时读错误标为 "Connection closed by server" |
| R3-L13 | server/upstream/socks5/udp.go:268 | 64KB 池缓冲每次中继读全量 clear——每数据包 ~2-4us 无益 memset |
| R3-L14 | server/upstream/dnscrypt/client.go:214 | executeOnce 不回验响应 ID/question echo（M7 同族遗漏：DNSCrypt/DoH） |
| R3-L15 | server/upstream/pool/tcp.go:431 | WarmUp doc 声称替换死连接，实际容量满时直接 return（契约不符） |
| R3-L16 | server/upstream/socks5/tcp.go:21 | DialContext 在 ctx 无 deadline 时绕过 dialer 自带超时（潜在，当前调用方均有 deadline） |
| R3-L17 | server/protocol/tls/quic.go:269 | DoQ 流处理器 conn.Context().Done() 早退不归还池化请求消息 |
| R3-L18 | server/protocol/tlcp/http_tlcp.go:78 | TLCP DoH GET 用 base64url 编码长度而非解码后长度做 64KB 校验——49KB-64KB 合法查询被拒 |
| R3-L19 | server/protocol/tls/dtls.go:178 | DTLS/DTLCP 顺序调用 Put(query) 非 defer——ServeDNS panic 后池泄漏（§2.3 模板违规） |
| R3-L20 | server/protocol/tlcp/certs.go:72 | TLCP 自签叶证书 NotAfter 未钳制到 CA 过期时间 |
| R3-L21 | server/protocol/dnscrypt/server.go:128 | decodeWindows 错误裸 `_` 丢弃——损坏持久化状态被静默当空窗口 |
| R3-L22 | internal/dnscryptcrypto/certificate.go:270 | UnmarshalBinary "绝不留下部分填充证书" 契约在 PQ 路径被违反（注释 vs 代码） |
| R3-L23 | internal/dnsutil/tcpframe.go:100 | WriteTCPMsg 注释声称两次写入，代码单次合并写 |
| R3-L24 | cache/cache.go:134 | rebuildResponseWire 以第一个 0x00 字节定位 question 尾——QNAME 标签内合法 NUL 字节截断扫描，偏移表错位（store.go 的 dnsSkipName 正确，两副本行为分叉） |
| R3-L25 | cache/store.go:625 | evictIfNeeded `count < 0` 死分支——EntryCount 只增不减到负，与 round-2 人工笔记 M3 同型但未入 round-2 综合报告（本轮补录） |

（goversion agent 的 go.mod:3 结论：代码库现代性良好，`go fix` 零诊断——round-2 中断的 25 号维度补全后无 HIGH/MEDIUM 级发现。）

## 五、round-2 修复方向复核（verify agent，人工抽查一致）

| ID | 结论 | 修复方向 | 复核要点 |
|----|------|---------|---------|
| C1 | CONFIRMED | **partial** | 旧格式回退可行（zstd magic 检测 + 无偏移表）；但计划只提 `len(msgWire) >= 3` 守卫**不够**——还需 `numOffsets <= (len-3)/2` 边界校验，否则旧裸 wire 中 ID 高字节恰为 0x02 的 1/256 条目仍会越界 panic |
| C2 | CONFIRMED | yes | miekg Pack（msg.go:149-154）`Data = Data[:Len()]` 后从空字段重打包，确认清空；`len(m.Data) > 0` 直用方案充分——截断循环按真实 packet 长度度量，dnsutil.Truncate 只动字段、重 Pack 产出 TC=1 头+question 恰好符合 DNSCrypt §5.4.6；Normalize 对 pre-packed 是 no-op，无需额外改动 |
| H1 | CONFIRMED | yes | 链序/Resolution 只设 ResolutionResult/MQTYPE.post 早返回全链路坐实；外移方向需同步调 CacheStore 的 `Res != nil` 跳过逻辑与 forwarding 门 |
| H2 | CONFIRMED | **partial** | Unpack 重建 Answer/Pseudo 确认（msg.go:399/428）；另注意 merge 的 budget 用 `msg.Len()` 在 pre-packed 上按空字段低估——fix 需同时处理 budget 计算 |
| H3 | CONFIRMED | yes | :98 锁内 + :110 锁外双 Add，两路径各一 -1 → 删 :110 后净 0 |
| H4 | CONFIRMED | yes | miekg server.go:318 MsgOptionUnpackQuestion 确认；镜像 EDNS.pre 解包需注意 Pseudo 非空时跳过（防双解） |
| M1 | PARTIAL | yes | 不一致属实（state 无守卫 / buildState/deleteState 有）且 nil 接收者 `m.mu.Lock` 必 panic；但生产生命周期从不调用 upstream.Client.Close()（仅测试）→ **降级 LOW**（防御性修复仍值得做） |
| M2 | CONFIRMED | yes | ctx.Done 早退不归还 sg.last/prev/nonEDNS，错误路径显式归还 |
| M3 | CONFIRMED | yes | cert.go:83/52 裸 net.Dial，deadline 在 dial 后设置；UDP dial 不阻塞、TCP 受影响 |
| M4 | PARTIAL | yes | `_ = entry.Unpack()` 丢弃属实，但**损坏 wire 机制不可达**——Entry.Unpack（cache.go:103-116）失败时不赋值字段，sortAnswerByLatency no-op，原始 wire 原样服务 → **降级 LOW**（仅丢失延迟排序） |
| M5 | CONFIRMED | yes | 前台 TryGo 失败 done 永不关闭；定时器路径闭包阻塞的 `rc` 是**裸 refreshCtx（无 WithTimeout）**——泄漏到进程退出而非 10s，占 errgroup 槽位持续饿死刷新容量；修复：失败路径 close(done) |
| M6 | CONFIRMED | yes | entryRcode 只读 `[3]&0x0F` 低 4 位，扩展 rcode（OPT TTL 高字节）误判 |
| M7 | CONFIRMED | yes | TLCP/DTLS/DTLCP 三处无 ID 回验（tls.go:107、plain/tcp.go:114、quic 有） |
| M8 | CONFIRMED | yes | FLOWCHARTS 零覆盖 MQTYPE/querylog.clear/pre-packed/16-shard |

14 项中 12 项 CONFIRMED、2 项 PARTIAL（M1/M4 均为降级修正，无推翻）；C1/H2 的修复方向需补强（见上表）。

## 六、主题分析

1. **DNSSEC 验证完整性缺口集中在"RRset 整体性"检查**（R3-C1 + R3-H1 + R3-M14）：单密钥匹配即信任整集合、签名验证不绑定查询名/owner、NSEC3 证明 fail-open——三处都是"验证了存在性却未验证完整性/关联性"。这是本轮最严重主题，直接影响安全关键路径。
2. **pre-packed 直发优化的适配面被高估**（R3-M1 + round-2 C2/H2）：cache 层新格式引入后，协议层（DNSCrypt 加密、TLS 家族 isSecure 门、Response Unpack 路径）均未协同适配；f7e7f13 头牌优化实际只在明文 UDP/TCP 生效。
3. **stamp 生态不自洽**（R3-H2 + R3-M16/M17）：编码/解码/配置消费三方词汇表（doh vs https、IPv6 括号、URL 端口）各有一套规则，CLI encode → config 消费断裂。
4. **池纪律第三轮仍反复**（R3-M15 + R3-L17/L19）：TTLOffsets 新调用点、DoQ 早退、DTLS/DTLCP 非 defer Put——§2.3 TLS 模板未在 7 个协议家族完全落地。
5. **同步契约的系统性松懈**（R3-M2 + R3-M5 + round-2 H3）：Shutdown 与热路径的锁纪律在多个协议族不一致（wg swap 无锁 Add、deadline 归零在临界区外、refs 双 Add）。

## 七、Sprint 行动计划（与 round-2 未修项合并）

| Sprint | 范围 | 内容 |
|--------|------|------|
| **Sprint 1 (CRITICAL)** | R3-C1 + round-2 C1/C2 | DNSKEY RRset 自签验证（matchedKey 验证 + 测试）；cache.Get 格式标记 + numOffsets 边界；DNSCrypt encrypt pre-packed 直用 |
| **Sprint 2 (HIGH)** | R3-H1/H2 + round-2 H1-H4 | question echo 校验；DoH stamp 协议映射；MQTYPE 三处协同；bridge refs 去重 |
| **Sprint 3 (MEDIUM+LOW)** | 上表全部 | 池纪律（M15/L17/L19）、锁纪律（M2/M5）、stamp 词汇表统一、FLOWCHARTS 补图等 |

每 Sprint 后质量门禁：`go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt` → `go test -short ./...` → benchmark 对比基线（>15% 回归即回滚）。Sprint 1 的 R3-C1 修复后必须跑 `go test -short ./server/resolver/...` 的 DNSSEC 全套用例。

## 八、跨轮次未完成项

- round-2 的 M3（fetchCert net.Dial）修复方向已核验（DialContext），未修
- 89 个零覆盖文件中本轮 8 组 agent 已全部覆盖；剩余风险集中在测试文件（本轮未审 _test.go）
- `AUDIT-METHODOLOGY.md` §概述 的"历史记录表"从未建立（该节无表格）——建议补建或删除该句

**原始数据**: `docs/audit/2026-08-round3/round3-workflow.js`（可 `resumeFromRunId` 复跑）、`dedup-index.txt`

## 九、修复完成状态（2026-08-05，Sprint 1-4 全部执行完毕）

两轮审计发现全部修复完成，16 个 commit（`df11ee2`..`3dbe089`），每 commit 按发现编号组织：

| Sprint | 范围 | 结果 |
|--------|------|------|
| Sprint 1 (CRITICAL) | R3-C1（DNSKEY 自签验证，含 offline-KSK 绑定与 zonecut 参照实现修正）、C1（缓存格式兼容 + numOffsets 边界）、C2（DNSCrypt encrypt pre-packed） | 3 commit，9+6+2 测试 |
| Sprint 2 (HIGH) | H1+H2+H4（MQTYPE 链序重排三合一）、R3-H1（question echo 三路径）、R3-H2（DoH stamp → https）、H3（refs 双 Add） | 4 commit，测试均验证"修复前失败" |
| Sprint 3 (MEDIUM) | M2/M3/M5/M6/M7 + R3-M1~M15（含 R3-M3 被链序重排顺带修复） | 3 commit |
| Sprint 4 (MEDIUM+LOW) | 剩余 ~55 项按包批量（zone/stamp/internal/protocol/cmd/edns/config/upstream/cache/docs） | 6 commit |

**质量门禁**：每 Sprint 后 `go build && go fix && golangci-lint run && golangci-lint fmt && go test -short ./...` 全绿；最终门禁 0 lint 问题、全测试通过。
**Benchmark 回归**：刷新基线（107 条）；唯一 >15% 项（ClientExecuteQuery/UDP +406%）在审计前基线提交上复现相同数值 → 环境波动非回归；BuildDoHURL +56% 已优化至 +13%（噪声带内）。
**真实二进制测试**：`--config` 启动 + dig 实测——zone 精确规则 ✓、通配符 owner 重写 ✓（R3-M7 实测触发）、AA 位 ✓（resinfo）、ANY RFC 8482 ✓、CHAOS 端点 ✓、pre-packed 缓存命中 ✓、TCP 传输 ✓、日志零 panic。

**遗留清零**（后续 commit `3bd8997` 全部完成）：
- bridge TCP frame 池化（tcpFramePool——writeMu 临界区内同步写，Write 返回即可复用，移除每响应分配）
- wire 名称跳过统一为 `internal/dnsutil.SkipWireName`（bridge/cache 各自实现已删除，NUL 分歧根因消除）
- docs/rfc/ 补档 5 个代码引用缺档 RFC（3339/3986/5452/6763/9147，共 116 个）
