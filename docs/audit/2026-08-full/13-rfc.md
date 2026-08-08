# 13-rfc.md — RFC 一致性交叉审计

Phase 2 CrossCut-RFC 审计：跨包 RFC 一致性扫描。范围：docs/rfc/ 存档完整性、代码 RFC 注释引用有效性、常量 vs RFC 推荐值、MUST/SHOULD 覆盖缺口、GUIDELINE.md 合规徽章准确性。所有结论均对照 `docs/rfc/` 中的 RFC 原文逐条核实。未修改任何文件。

## Findings

### MEDIUM

- [MEDIUM/rfc-compliance] server/handler/middleware/validation.go:113-115 — 显式 NXNAME(128) 查询返回 REFUSED，但 RFC 9824 §3.5 规定 "the DNS server MUST return a Format Error (response code FORMERR)"（EDE 30 可选） | risk: RFC 9824 感知客户端预期 FORMERR；MUST 条款未满足 | fix: qtype==NXNAME 分支改 RCODE=FORMERR（保留 EDE 30）；AXFR/IXFR 维持 REFUSED
- [MEDIUM/rfc-ttl] cache/store.go:990-1006（minTTL）— TTL 最高位置位（0x80000000–0xFFFFFFFF）被当作大正数并在 604800 秒处封顶，而 RFC 2181 §8 要求 "treat TTL values received with the most significant bit set as if the entire value received was zero" | risk: 攻击者可控的 MSB 置位 TTL 被缓存最长 7 天而非立即过期 | fix: 比较前将 TTL 规范化为 `ttl & 0x7FFFFFFF`（或 MSB 置位视为 0）
- [MEDIUM/archive] internal/dnscryptcrypto/pq.go:181 — 注释引用 "RFC 9443"（QUIC Version 2），docs/rfc/ 无 rfc9443.txt（违反规则 14/17：新 RFC 必须先存档）；且 DNSCrypt 规范本身对 client-magic 冲突引用的是 RFC 9000（draft-denis-dprive-dnscrypt.txt:1134 "in order to avoid confusion with the QUIC protocol [RFC9000]"） | risk: 引用不可验证、规范漂移 | fix: 存档 rfc9443.txt，或按规范原文改引 RFC 9000
- [MEDIUM/doc] docs/rfc/GUIDELINE.md:791 — "MUST: 不支持 EDNS 版本的响应 → FORMERR" 错误：RFC 6891 §6.1.3 要求 RCODE=BADVERS（"it MUST respond with RCODE=BADVERS"）；代码实现正确（server/handler/middleware/edns.go:53 返回 BadVers） | fix: 指南改为 BADVERS
- [MEDIUM/doc] docs/rfc/GUIDELINE.md:649 — RFC 6840 条目 "§5.3 放宽签名有效期检查 dnssec/nsec.go:139" 双重错误：RFC 6840 §5.3 是 "Private Algorithms"，无任何 6840 章节放宽签名有效期；nsec.go:139 实际是 NSEC3 祖先委托排除逻辑（正确引用为 §4.1） | fix: 更正章节号与文件位置
- [MEDIUM/doc] docs/rfc/GUIDELINE.md:1597（RFC 9824 条目）— 徽章 ✅ 但条目自身记录 "REFUSED + EDE 30" 拒绝 NXNAME，与 RFC 9824 §3.5 的 FORMERR MUST 相悖（见首条） | fix: 徽章降级为 ⚠️ 或修正行为
- [MEDIUM/doc+behavior] docs/rfc/GUIDELINE.md:717（RFC 6761 条目）— 徽章 ✅ 声称 "RFC 6761 允许解析器转发这些查询，行为合规"，但 RFC 6761 §6.3/§6.4 第 4 条：缓存 DNS 服务器 SHOULD NOT 查询权威解析 localhost/test 名，SHOULD 本地应答（回环地址/否定响应）；ZJDNS 无 localhost 特判，直接转发上游 | risk: localhost 应答依赖上游且泄漏查询 | fix: 本地应答 localhost（127.0.0.1/::1）或徽章降级 ⚠️

### LOW

- [LOW/comment] server/handler/middleware/any.go:34 — "RFC 8482 §2.1" 不存在：RFC 8482 无 §2.1（章节为 1.1/2/3/4.1-4.4/11.x）；合成 HINFO "RFC8482" 的规定在 §4.2 "Answer with a Synthesized HINFO RRset" | 行为正确，仅章节号错
- [LOW/comment] server/handler/middleware/edns.go:100,159 — 服务端对畸形 client cookie 返回 FORMERR 的行为引用 "RFC 7873 §5.3"，但 §5.3 是客户端侧 "Processing Responses"；服务端正确引用应为 §5.2.2（合法长度 8/16–40）与 §5.2.4（无效 server cookie → 按 §5.2.3 处理）
- [LOW/comment] server/resolver/dnssec/nsec.go:412 — "(RFC 4035 section 3.1.3, RFC 6840 section 5.3)" 两个引用均不指向否认证明验证：4035 §3.1.3 是服务器侧 NSEC 包含规则，6840 §5.3 是 Private Algorithms；正确引用为 RFC 4035 §5.4 "Authenticated Denial of Existence"
- [LOW/comment] server/resolver/dnssec/trust_anchor.go:118 — "RFC 7958 §3.2" 不存在（7958 章节为 2/2.1/2.1.1/2.2/2.3/3/3.1/4/5）；XML KeyTag 与密钥匹配的规定在 §2.1 "Hashes in XML"
- [LOW/comment] server/upstream/socks5/udp.go:48,123 — UDP ASSOCIATE 与中继行为引用 "RFC 1928 §6"，但 §6 是 "Replies"；UDP 中继流程在 §7 "Procedure for UDP-based clients"（0.0.0.0:0 请求分配中继为 §7 语境惯例）
- [LOW/comment] server/handler/middleware/validation.go:98 — 非 IN/CHAOS class 拒绝引用 "RFC 6895 §3.1"，§3.1 是 RRTYPE IANA 考虑；class 相关章节为 §3.2 "RR CLASS IANA Considerations"
- [LOW/rfc-compliance] server/resolver/dnssec/crypto.go:111-114 — RRSIG Expiration/Inception 用普通 `<`/`>` 比较，而 RFC 4034 §3.1.5 明确 "all comparisons involving these fields MUST use 'Serial number arithmetic', as defined in [RFC1982]" | risk: 仅 32 位时间戳回绕（2038/2106）附近判断错误 | fix: 复用 edns/cookie.go 的 compare1982 式序列号比较
- [LOW/rfc-compliance] server/protocol/tls/quic.go:205-228 — DoQ 服务端每流只读一条查询，不检测同流第二条查询；RFC 9250 §4.3.3 将 "a server receives more than one query on a stream" 列为协议错误（SHOULD 以 DOQ_PROTOCOL_ERROR 中止连接）| fix: 响应后检查流上残留数据并中止
- [LOW/doc] docs/rfc/GUIDELINE.md:648 — RFC 6604 行引用 "nameserver.go:78"，实际注释在 nameserver.go:124（内容本身正确）

## Checks performed

### 1. 存档完整性 — FAIL（1 处缺失）

从全部非测试 .go 文件提取 RFC 引用（`grep -rhoE 'RFC [0-9]{3,5}'`，另查 `RFC[0-9]+` 无空格形式），共 50 个不同编号：

| RFC | 存档 | RFC | 存档 | RFC | 存档 |
|---|---|---|---|---|---|
| 768 | ✓ | 1034 | ✓ | 1035 | ✓ |
| 1928 | ✓ | 1929 | ✓ | 1982 | ✓ |
| 2181 | ✓ | 3225 | ✓ | 3597 | ✓ |
| 3986 | ✓ | 4034 | ✓ | 4035 | ✓ |
| 4343 | ✓ | 5011 | ✓ | 5155 | ✓ |
| 5452 | ✓ | 6052 | ✓ | 6147 | ✓ |
| 6604 | ✓ | 6763 | ✓ | 6840 | ✓ |
| 6891 | ✓ | 6895 | ✓ | 6975 | ✓ |
| 7344 | ✓ | 7766 | ✓ | 7828 | ✓ |
| 7858 | ✓ | 7871 | ✓ | 7873 | ✓ |
| 7958 | ✓ | 8094 | ✓ | 8310 | ✓ |
| 8446 | ✓ | 8467 | ✓ | 8482 | ✓ |
| 8484 | ✓ | 8767 | ✓ | 8914 | ✓ |
| 9000 | ✓ | 9018 | ✓ | 9147 | ✓ |
| 9156 | ✓ | 9250 | ✓ | 9462 | ✓ |
| 9606 | ✓ | 9715 | ✓ | 9824 | ✓ |
| 10029 | ✓ | **9443** | **✗ 缺失** | | |

- `internal/dnscryptcrypto/pq.go:181` 引用 RFC 9443（QUIC Version 2，真实 RFC）→ docs/rfc/ 无 rfc9443.txt。
- 非代码引用的 GUIDELINE RFC（1348/1876/1995/1996/2065/2136/2537/2671/2782/2845/2915/2929/3110/3123/3339/3401-3403/3445/3596/4025/4255/4408/4509/4592/4635/4701/4892/5001/5077/5205/5702/5936/5966/6125/6605/6672/6725/6742/6761/6844/6944/7043/7314/7477/7553/7719/7830/8198/8427/8659/8777/8976/9077/9103/9114/9460/9461/9567/9660/9859）全部已存档。
- 三份 draft 均已存档：draft-denis-dns-stamps、draft-denis-dprive-dnscrypt、draft-dnsop-deleg。

### 2. RFC 注释引用有效性 — PASS（30 处抽查，6 处误引，均 LOW）

优先清单逐条对照 RFC 原文（grep 章节标题 + 关键段落）：

- 6891 §6.1.3（BADVERS ✓）、§6.2.2（EDNS 回退 ✓ nameserver.go:520）、§6.2.5（4096/1232 ✓）— 有效
- 7871 §6（选项格式/FORMERR ✓）、§7.3（响应回显 ✓）、§11.1（/24、/56 ✓）、§11.2（生日攻击 ✓）— 有效
- 7873 §5.2.2（合法长度 8/16–40 ✓）、§7.1（密钥默认 1 天 ✓）— 有效；§5.3 误用于服务端行为 ✗
- 9018 §4.3（1h/30min/5min ✓）、§4.4（SipHash-2-4 + 4/16 字节 IP ✓）— 有效
- 8914 §3、§4.1（code 0 带 ExtraText ✓）— 有效
- 8482 §2.1 ✗（应为 §4.2）；其余 ANY 行为正确
- 9156 §2.3（MAX_MINIMISE_COUNT=10/MINIMISE_ONE_LAB=4、比例分配、余数加末次 ✓ qname_minimise.go:68-128）— 有效
- 10029 §3.3（FORMERR 校验 ✓）、§3.4（合并/去重/TC 不扩展/空列表仍返回 ✓ mqtype.go:258）、§4（4 QTx ✓）— 有效
- 9824 §3.5（NXNAME 处理 — RCODE 偏差见 MEDIUM）、§5.1（NXDOMAIN 恢复 ✓）— 部分有效
- 6147 §5.1.7（TTL=min(A,SOA) 或 600 ✓）、§5.2（前缀长度 ✓）— 有效
- 6052 §2.1/§2.2（64:ff9b::/96、Figure 1 布局 ✓）— 有效
- 4034 §3.1.5（签名有效期 — 普通比较 ✗ 见 LOW）、§3.1.7（signer 匹配 ✓）— 部分有效
- 6840 §4.1（祖先委托 ✓）、§4.3（CNAME 位 ✓）— 有效；§5.3 ✗（nsec.go:412）
- 5155 §8.6/§9.2（Opt-Out AD 抑制 ✓）、§10.3（迭代 150 ✓）— 有效
- 5011 §2.1（REVOKE ✓ trust_anchor.go:39）— 有效
- 7766 §7（QNAME/QCLASS/QTYPE 匹配 ✓）— 有效
- 7858（ALPN "dot"、853 ✓）、8484 §4.1/§4.2.1（GET/POST、415 ✓）、§5.1（Cache-Control ✓）— 有效
- 9250 §4.2/§4.2.1/§4.3.1-4.3.3/§4.5（ID=0、长度前缀、0 长度→协议错误、oversized→DOQ_INTERNAL_ERROR ✓）— 有效（同流多查询见 LOW）
- 5452 §9.3（question echo ✓）、6604 §3（xNAME RCODE ✓）— 有效
- 6763 §6.1/§6.3/§6.4（TXT 格式 ✓）、6895 §3.1（opcode/元类型 ✓，class 误引 ✗）
- 1982 §2（序列号运算 ✓ compare1982/subtract1982 正确）— 有效
- 1928 §6/§7（RSV X'00' ✓；UDP 中继章节误引 ✗）、1929（认证格式 ✓）— 部分有效
- 7958 §3.2 ✗（应为 §2.1）；8767 §4（7 天 TTL 上限 ✓）/§6（stale 3 天 ✓）；8467（128/468 ✓）；7830（0x00 SHOULD、其他值 MAY — 随机填充合规 ✓）；7828（100ms 单位 ✓）；6975（DAU/DHU/N3U ✓）；9715 R3/R5（1400/1232 ✓）；8094（端口 8853 偏差已在指南已知偏离表）；9606（RESINFO ✓）

### 3. 常量 vs RFC 推荐值 — PASS（1 处偏差，其余一致）

| 常量 | 代码值 | RFC 推荐 | 结论 |
|---|---|---|---|
| DNS 端口 | 53 (defaults.go:10-11) | RFC 1035 | ✓ |
| DoT / DoQ 端口 | 853 (defaults.go:15-16) | RFC 7858 / 9250 | ✓ |
| DoH / DoH3 端口 | 443 (defaults.go:17-18) | RFC 8484 / 9114 | ✓ |
| DTLS 端口 | 8853 (defaults.go:19) | RFC 8094=853 | 已文档化偏差（指南"已知偏离"表） |
| DNSCrypt 端口 | 8443 (defaults.go:13) | draft SHOULD 443 | 已文档化偏差 |
| EDNS UDP 载荷 | 1232 / 递归 4096 (pool.go:27-28) | 6891 §6.2.5（4096 起点）、9715 R5（≤1400 为请求方推荐） | 1232 ✓；4096 为已文档化权衡 |
| 响应截断上限 | 1400 (defaults.go:243) | 9715 R3 推荐上限 1400 | ✓ |
| EDNS 最小 512 | dns.MinMsgSize 使用 (bridge.go:268, mqtype.go:190) | 6891 §6.2.5（<512 按 512） | ✓ |
| ECS 前缀 | /24、/56、scope 0 (ecs.go:21) | 7871 §11.1 | ✓ |
| Cookie 长度 | 8+16，最大 40 (cookie.go:52-53) | 7873 §5.2.2（8 或 16–40） | ✓ |
| Cookie 生命周期 | 1h/30min/5min (cookie.go:60-63) | 9018 §4.3 | ✓ |
| Cookie 密钥轮换 | 24h (defaults.go:166) | 7873 §7.1（默认 1 天） | ✓ |
| DNS64 前缀 | 64:ff9b::/96 (dns64.go:21, defaults.go:237) | 6052 §2.1 | ✓ |
| DNS64 前缀长度 | 32/40/48/56/64/96 (dns64.go:28) | 6052 Figure 1 | ✓ |
| DNS64 合成 TTL | min(A,SOA)，无 SOA 时 600 (dns64.go:66-95) | 6147 §5.1.7 | ✓ |
| MQTYPE QTx 上限 | 4 (defaults.go:246-247) | 10029 §4（"a limit of four QTx values would be appropriate"） | ✓ |
| NSEC3 迭代上限 | 150 (defaults.go) | 5155 §10.3（1024 位密钥） | ✓ |
| 入站 TTL 上限 | 604800 (defaults.go:51, store.go:1006) | 8767 §4（SHOULD ≤ 7 天） | ✓ |
| Stale 保留期 | 3 天 (defaults.go:48) | 8767 §6（建议 1–3 天） | ✓ |
| RRSIG 有效期比较 | 普通 `<` (crypto.go:111) | 4034 §3.1.5 MUST 序列号运算 | ✗ LOW |
| TTL MSB 置位 | 封顶 7 天 (store.go:1006) | 2181 §8（SHOULD 视为 0） | ✗ MEDIUM |
| 签名有效期 3 周上限 | 无该限制 | 4034 未规定 3 周（任务假设不成立） | 无偏差 |

### 4. MUST/SHOULD 覆盖缺口 — PASS（3 项高危实现核对）

(a) **DoQ (RFC 9250)**：2 字节长度前缀 ✓（quic.go 读写两侧）；每查询一流 ✓（客户端 OpenStream、服务端 AcceptStream 每流一查询）；0 长度 = DOQ_PROTOCOL_ERROR ✓（quic.go:213-216）；非零 Message ID = 协议错误 ✓（quic.go:244-247）；oversized 响应 → DOQ_INTERNAL_ERROR ✓（quic.go:314）；连接协议错误关闭 ✓（CloseWithError）。唯一缺口：同流第二条查询未检测（LOW，见上）。
(b) **DNSCrypt**：规范已存档（draft-denis-dprive-dnscrypt.txt）✓；24h 密钥轮换 MUST ✓（draft:1643）；查询 ≤4096 MUST ✓（draft:583）；§5.4.5 确定性填充 / §5.4.6-5.4.7 响应处理 / §11.9 PQ 降级保护均实现 ✓；端口 8443（SHOULD 443）已文档化偏差；RFC 9443 引用未存档（MEDIUM）。
(c) **EDNS Padding (RFC 7830/8467)**：请求 128 / 响应 468 块 ✓（defaults.go:234-235, edns.go:177-181）；客户端带 PADDING 选项 → MUST 填充响应 ✓（padding.go:37-38）；显式 opt-out（EDNS 无 PADDING）✓；填充字节随机（7830 §3 "Other values MAY be used" 合规）✓；仅加密传输填充（isSecureConnection 门控）✓（8467 "only applies if the DNS transport is encrypted"）。

### 5. GUIDELINE.md 徽章准确性 — FAIL（12 处抽查，4 处徽章/内容错误）

| GUIDELINE 条目 | 徽章 | 核实结果 |
|---|---|---|
| RFC 6891（791 行） | ✅ | ✗ "FORMERR" 应为 BADVERS（§6.1.3） |
| RFC 6840（649 行） | ✅ | ✗ "§5.3 放宽签名有效期" 章节不存在、位置错误 |
| RFC 9824（1597 行） | ✅ | ✗ NXNAME 应 FORMERR 却记录/实现 REFUSED |
| RFC 6761（717 行） | ✅ | ✗ "允许转发" 与 §6.3/§6.4 SHOULD NOT 相悖 |
| RFC 6604（648 行） | ✅ | ~ 引用行号漂移（78→124），内容正确 |
| RFC 8482 | ✅ | ✓ 行为正确（HINFO "RFC8482" TTL 3600） |
| RFC 8484 | ✅ | ✓ POST+GET、415、Cache-Control 均实现 |
| RFC 9250 | ✅ | ✓ 全部关键条款实现 |
| RFC 7873/9018 | ✅ | ✓ 常量与 §4.3/§4.4/§7.1 一致 |
| RFC 8767 | ✅ | ✓ 3 天 stale / 7 天 TTL 上限 |
| RFC 9156 | ✅ | ✓ 10/4 与比例分配算法正确 |
| RFC 10029 | ✅ | ✓ §3.3/§3.4/§4 全部落实 |
| RFC 5011/9077 | ⚠️ | ✓ 自评准确（REVOKE 检查实现，自动状态机未做） |
| RFC 9715 | ✅ | ✓ R3 截断 + 请求方 1232 |

## 汇总

- 50 个代码引用 RFC：49 个已存档，1 个缺失（RFC 9443）
- 7 MEDIUM（3 行为/合规 + 1 存档 + 3 文档），9 LOW（7 注释误引 + 2 行为）
- 0 CRITICAL，0 HIGH
