# 2026-08 第三轮审计 — 修复计划（差缺补漏 + 交叉复核）

> 修复时先读 `12-synthesis.md`（核验证据与人工确认）与 `dedup-index.txt`（round-2 全量索引，防重复修复）。
> 本计划 = round-3 新发现（R3-*）+ round-2 未修项（C1/C2/H1-H4/M1-M8，见 round2/00-plan.md 与 §五 复核修正）。
> 按 AUDIT-METHODOLOGY §2.1 分 Sprint；每 commit 主题行带发现编号；每 Sprint 后质量门禁 + benchmark 对比。

## Sprint 1 — CRITICAL（立即修复）

### R3-C1. `server/resolver/dnssec_chain.go:405/272/54` — DNSKEY RRset 缺自签验证（RFC 4035 §5.2）

- 修复：DS 匹配成功后用 `VerifyDelegationDS` 返回的 matchedKey（当前被 `_` 丢弃）验证 DNSKEY RRset 的 RRSIG——`crypto.VerifyRRset(dnskeyRecords, dnskeyRRSIGs, matchedKey)`；失败 → bogus（EDE 6），不入链不缓存。三处信任点（isDNSSECValid / ensureZoneDNSKEYs / isValidWithDNSSEC）统一收口到一个 helper（如 `verifyDNSKEYWithDS(dnskeyRecords, dnskeyRRSIGs, chain.childDS) ([]*dns.DNSKEY, error)`）。
- 备选（最小）：只把 matchedKey 单密钥放入 chain.zoneDNSKEYs，不信任集合其余成员（需检查 IsResponseValid 的密钥选择是否兼容单密钥）。
- 测试：`dnssec_chain_test.go` 构造"合法 K1 匹配 DS + 注入 K2 + 无 RRset 自签"的 DNSKEY 响应 → 断言拒绝；合法自签 → 接受。回归：现有 `TestDNSSECChain*` 全部通过。
- 注意：root 区路径（ContainsRootKey）不受影响，不要动；offline-KSK（verifyOfflineKSK/CDS/CDNSKEY）路径同样需自签验证——CDS/CDNSKEY 匹配后信任的 dnskeyRecords 也要过同一检查。

### C1. `cache/store.go:267` — Get 格式标记缺失（round-2，复核补强）

- 按 round2 计划实现旧格式回退（zstd magic 检测 + 无偏移表），**并补 numOffsets 边界**：`len(msgWire) < 3 → miss`；`numOffsets > (len(msgWire)-3)/2 → miss`（防旧裸 wire ID 高字节恰为 0x02 的 1/256 残留 + 新库损坏行）。
- 测试：`TestGetLegacyFormat`（zstd 裸 wire + 裸 wire 两种旧行，断言不 panic 且正确解包）+ 边界行（numOffsets 超大）。

### C2. `server/protocol/dnscrypt/crypto.go:29` — encrypt() 清空 pre-packed 响应（round-2，复核确认方案充分）

- 按 round2 计划：`encrypt()` 开头 `if len(m.Data) > 0 { packet = m.Data }` 跳过 Pack；截断循环逻辑无需改动（复核确认按真实 packet 长度度量，TC=1 重建行为符合 DNSCrypt §5.4.6）。Normalize 无需改动（对 pre-packed 为 no-op）。
- 测试：DNSCrypt UDP+TCP 缓存命中（pre-packed）+ 超预算截断两路集成测试。

## Sprint 2 — HIGH（下个发布周期）

### R3-H1. `server/resolver/nameserver.go:95` — question echo 校验（RFC 5452 §9.3）

- 修复：queryNameserversConcurrent 接受响应后、解析 rcode 前校验：`len(response.Question) == 1` 且 `dns.EqualName(response.Question[0].Header().Name, question.Name)` 且 `RRToType(question[0]) == question.Qtype`；不匹配 → `pool.DefaultMessage.Put(response)` + 记 Debug + 该 NS 尝试失败（继续下一个）。同型补到 forward.go / processUpstreamResponse（转发模式经 spoofguard 已有 ID 校验，question echo 补上对齐 RFC 5452）。
- 深度防御：`isAnswerSectionValid` 增加 RRset owner == 查询名断言（可先做第一层，owner 校验影响面大放 Sprint 3 评估）。
- 测试：构造"响应 question 与查询不同名"的响应 → 断言丢弃；正常响应 → 接受。

### R3-H2. `config/load.go:113` — DoH stamp 协议映射断裂

- 修复：`internal/stamp` 的 `ProtoToConfig(ProtoDOH)` 返回 `"https"`（与 config/upstream 词汇表一致）；同步检查 `protocolMatchesStamp` 的对照表（显式 "https" + DoH stamp 应匹配）。load.go 顺序评估：normalizeStamps 后二次校验 protocol ∈ validProtocols（防止未来同类"归一化后不合法"绕过）。
- 连带：`--dnsstamp --encode --proto doh` 的 CLI 帮助文案与 `--probe` 的协议名统一（doh→https 别名映射）。
- 测试：配置含 DoH stamp → 解析后 protocol == "https"、address == BuildDoHURL；`--probe --proto doh` 冒烟。

### H1/H2/H4. MQTYPE 三处协同（round-2，复核确认方向，补强点见下）

- H1：MQTYPE 链外移（或基于 ResolutionResult 合并），外移时同步调 CacheStore 的 `qctx.Res != nil` 跳过逻辑与 forwarding 门（`len(m.resolver.UpstreamServers()) > 0` 判定在 MQTYPE.pre 与外移后位置一致性）。
- H2：hit 路径 merge 产物防 Unpack 抹除——merge 写入 pre-packed Data 或 Response 对 Pseudo 非空 pre-packed 先合并后解包；**同时修复 merge 的 budget 计算**（pre-packed 上 `msg.Len()` 按空字段低估——改用 `len(msg.Data)` 或缓存 wire 长度）。
- H4：MQTYPE.pre 镜像 EDNS.pre 解包（`len(Pseudo)==0 → Options=0; Unpack()`），Pseudo 非空跳过（防双解）。
- 测试：AssembleChain 真实链 miss/hit 双路径集成测试（round-2 已列），断言 MQRESPONSE 与合并 RR 出现在最终 wire。

### H3. `server/bridge.go:110` — refs 双重 Add（round-2，复核确认方案）

- 删除 :110 的重复 `entry.refs.Add(1)`（保留 :98 锁内 Add + :115/:155 各一 -1 → 净 0）。
- 测试：请求完成后 `refs.Load() == 0` 断言；SERVFAIL 路径同断言。

## Sprint 3 — MEDIUM + LOW（文档/优化）

| # | 位置 | 修复 |
|---|------|------|
| R3-M1 | response.go:119 / 协议 handler | 从 shouldAddEDNS 移除 `qctx.IsSecure`（或快路径门改为按 clientWantsPad 判定）——恢复 TLS 家族 pre-packed 直发；需确认 AD 位由缓存 wire 携带（entry.Validated）且 ApplyToMessage 对 IsSecure 的 padding 用途被 clientWantsPad 覆盖 |
| R3-M2 | dnscrypt/udp.go:59, tcp.go:53 | serveUDP/serveTCP 的 `s.wg.Add(1)` 移入 Start 的 s.mu 临界区（或加锁）——消除与 Shutdown wg swap 的竞态 |
| R3-M3 | chain.go:123 | Any/Zone 短路前执行 cookie 校验（EDNS.pre 拆出 cookie 步骤或 Any 后置）——评估后修 |
| R3-M4 | pending.go:59 | LRU 淘汰 in-flight pendingCall 时以空结果唤醒跟随者改为拒绝/重查语义（避免静默丢查询） |
| R3-M5 | pool/tcp.go:200 | deadline 设置/归零移入 writeMu 临界区（或捕获旧值恢复） |
| R3-M6 | tls/quic.go:162 | doQUICQuery 加 `context.AfterFunc(ctx, stream.CancelRead/CancelWrite)`（对齐 tls.go:89 模式） |
| R3-M7 | zone/wire.go:75 | 通配符命中时用 QNAME 替换 `*.domain` owner 再 pack |
| R3-M8 | zone/zone.go:535 | match_tags 畸形解析 Warnf 降为 Debug（热路径） |
| R3-M9 | validation.go:34 | wireNameLength 按 miekg presentation 语义修复（内嵌点/转义） |
| R3-M10 | validate.go:180 | https/http3/http-tlcp 地址校验：空地址与缺 scheme 拒绝 |
| R3-M11 | cli/sql.go:16 | --sql 只读模式遇不存在路径报错（不创建库） |
| R3-M12/13 | ddr.go:171/191 | SVCB TargetName 修正 + resolver.arpa 本地应答 |
| R3-M14 | dnssec/nsec.go:255 | covered-name NODATA 要求 Opt-Out 标志（fail-closed） |
| R3-M15 | dnssec/extract.go:189 | ZoneKeys 命中后 ReleaseTTLOffsets（连同 dns64/mqtype/ns_addresses 已报点一并） |
| R3-M16/17 | stamp | 编码器 IPv6 加方括号；BuildDoHURL 端口处理 |
| R3-M18 | dnscryptcrypto/pq.go:139 | PQEncapsulate 补长度守卫 |
| R3-M19 | init.go:69 | 动态内容规则名 Canonical 化对齐 |
| R3-M20 | hopguard.go:96 | trustedKeys 延迟求值 |
| R3-M21 | any.go:43 | ANY/PTR 短路补 request 记录 |
| R3-M22 | encrypted.go:357 | 经典路径补 MaxDNSUDPPacketSize 守卫 |
| R3-M23 | tcpframe.go:111 | WriteTCPMsg 超 65535 返回错误（不静默回绕） |
| R3-L1-L24 | 见 synthesis §四 | 逐项小修（L14 ID 回验并入 M7 族；L17/L19 池纪律；L24 wire 扫描与 store.go 合并 dnsSkipName） |
| round-2 M1-M8 | 见 round2/00-plan.md + §五 修正 | M1/M4 按降级后 LOW 修；M5 失败路径 close(done)；M2/M3/M6/M7/M8 按原计划 |

## 门禁清单（每 Sprint 后）

```bash
go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt
go test -short ./...
# benchmark 对比（>15% 回归即回滚）
go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
```

Sprint 1 后额外：`go test -short ./server/resolver/... -run 'DNSSEC|Chain' -v`（R3-C1 回归面）。

## 提交规范提醒

- 每 commit 一类修复、主题行描述具体修复内容 + 发现编号（如 `fix: verify DNSKEY RRset self-signature with DS-matched key (R3-C1)`）。
- R3-C1 的三处信任点同根因可合并一次 commit；R3-M15 的池泄漏族（extract/dns64/mqtype/ns_addresses）同类可合并。
