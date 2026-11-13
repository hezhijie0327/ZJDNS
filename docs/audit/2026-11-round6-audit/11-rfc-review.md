# Round 6 — RFC 引用与 docs/rfc/ 存档一致性审查

日期：2026-11-14。范围：全库 .go 引用 vs docs/rfc/ 存档、GUIDELINE.md 收录、README.md 索引、上游依赖库（codeberg.org/miekg/dns fork v0.6.134）新工作。只读分析 + 新增存档文件，未改任何代码与 GUIDELINE 正文。

---

## 1. 缺口表（代码引用 → 存档判定 → 处置）

| 编号 | 代码引用位置 | 判定 | 处置 |
|------|-------------|------|------|
| **rfc1002** | 不存在 | **误报**：`rfc1002` 是 `rfc10029`（RFC 10029 MQTYPE）的子串误匹配；精确 grep `RFC ?1002[^0-9]` 全库零命中 | 无需处理；rfc10029.txt 已存档且为最新 |
| **RFC 1918** | `internal/dns64/dns64.go:131`（WKP 合成排除 RFC1918/CGNAT 段的注释）、`internal/dns64/dns64_test.go:123`；GUIDELINE.md RFC 6147 条目内联引用（"WKP 下非全球 IPv4（RFC1918/CGNAT/保留段）不合成，2026-09 修复"） | **真实实现依赖**：DNS64 WKP 前缀合成的排除规则直接依据 RFC 1918 私有地址定义 | ✅ 已从 rfc-editor 存档 `docs/rfc/rfc1918.txt`（Address Allocation for Private Internets, BCP 5，9 页完整） |
| **draft-westerbaan-dnssec-mldsa** | `server/resolver/dnssec/crypto.go:310`（`nativelyVerified` 接受 `dns.MLDSA44`，fork 库内原生验证路径）、`server/resolver/dnssec/dnssec_test.go:313-347`（`TestVerifyRRset_MLDSA44`：alg 18、seed 派生密钥、DS SHA-384 链验证） | **真实实现依赖**：ML-DSA-44 后量子 DNSSEC 签名验证已进入 resolver DNSSEC 路径。datatracker 确认**尚未出版为正式 RFC**（rev 04，expires 2027-02-12，Cloudflare/Google，individual I-D） | ✅ 已从 datatracker 存档 `docs/rfc/draft-westerbaan-dnssec-mldsa.txt`（rev 04，2026-08，9 页完整）。出版正式 RFC 后应替换为 rfc{N}.txt |
| **RFC 8906** | 无直接代码引用。但：ZJDNS 服务器侧 EDNS 行为（EDNSMiddleware parse-then-validate、MQTYPE 8 个 FORMERR 用例、上游对 unknown EDNS option 的 SERVFAIL → 无选项重试、RFC 6891 §6.2.2 EDNS-free 重试）即 RFC 8906（BCP 231）所规范的服务器响应结构要求；且上游 fork 2026-11 刚落地 "edns0 compliance: remaining tests from 8906"、"atomdns: implement rest of 8906"、"dns: cap edns0 option we parse" | **建议存档**：ZJDNS 通过 fork 库消费 EDNS 行为，fork 的 edns0-compliance 基准即 RFC 8906；ZJDNS 自身 EDNS 中间件的合规性审计也需要该基准 | ✅ 已从 rfc-editor 存档 `docs/rfc/rfc8906.txt`（A Common Operational Problem in DNS Servers: Failure to Communicate, BCP 231） |
| **atomdns** | 非 IETF 文档 | datatracker 查无 atomdns draft —— 它是 fork 内置的全功能 DNS server（`cmd/atomdns`），8906 合规的实现载体，不是协议规范 | 无需存档；RFC 8906 已覆盖其规范依据 |
| 版本核对：RFC 9715 | `docs/rfc/rfc9715.txt` = "IP Fragmentation Avoidance in DNS over UDP"（Fujiwara/Vixie，2025-01，Informational），无 obsoletes | ✓ 最新版 | 无需处理 |
| 版本核对：RFC 10029 | `docs/rfc/rfc10029.txt` = "DNS Multiple QTYPEs"（ISC），正式 RFC | ✓ 最新版，已存档 | 无需处理 |
| 版本核对：RFC 9563 | 已存档，2024-12 Informational（CNNIC），代码 8 处引用 | ✓ | 无需处理 |
| 版本核对：4 个 draft | draft-denis-dns-stamps-02、draft-denis-dprive-dnscrypt-11（代码引用 -10/-11，存档为最新 -11）、draft-dnsop-deleg-00（2024-07 过期后再无更新，即最新）、draft-vixie-dnsext-dns0x20-00（唯一版本） | ✓ 均为 datatracker 最新 rev | 无需处理 |

**正向缺口结论**：全部 .go 引用（含测试，62 个 RFC 编号 + 2 个 draft）中仅 RFC 1918 与 draft-westerbaan-dnssec-mldsa 未存档，均已补齐；rfc1002 为误报。

---

## 2. 反向缺口（存档了但 .go 从未引用）

64 个存档文件（含本轮新增后总数 132 个 .txt）中，未在任何 .go 文件引用的有 63 个（新增 3 个除外后的既有集合），分类如下：

**a) GUIDELINE.md 已收录（61 个）** —— 历史/背景/工具链参考，非代码直引，保留即可：
1348 1876 1995 1996 2065 2136 2537 2671 2782 2845 2915 2929 3110 3123 3401 3402 3403 3445 3596 4025 4033 4255 4408 4592 4635 4701 4892 5001 5077 5205 5702 5936 5966 6125 6605 6672 6725 6742 6761 6844 6944 7043 7314 7477 7553 7719 8427 8446 8499 8659 8777 8976 9077 9103 9114 9276 9460 9461 9471 9567 9660 9859

**b) 仅 docs/audit/ 引用（1 个）**：
- **RFC 5280** — X.509 证书；`docs/audit/2026-09-full-audit/08-crosscut.md` C-L2 条目（"RFC 5280/8624 未镜像 → ✅ 存档"）。tlcp/certs.go、dnssec/crypto.go 间接依赖 X.509 语义。保留。

**c) 全库零引用（1 个）** —— 唯一真正的"未引用"项：
- **RFC 9853** — "Return Routability Check for DTLS 1.2 and 1.3"（UniBw M.）。与 ZJDNS 的 DTLS/DTLCP 上游支持相关，但代码、GUIDELINE、docs 均未引用。判定：历史遗留（DTLS 工作时的背景参考）。**标注"未引用"，不删除**。

---

## 3. 本轮新增存档文件清单（docs/rfc/）

| 文件 | 来源 | 说明 |
|------|------|------|
| `docs/rfc/rfc1918.txt` | https://www.rfc-editor.org/rfc/rfc1918.txt | Address Allocation for Private Internets（BCP 5, 1996-02）；DNS64 WKP 排除规则依据。命名/内容与上游逐字节核对 |
| `docs/rfc/rfc8906.txt` | https://www.rfc-editor.org/rfc/rfc8906.txt | A Common Operational Problem in DNS Servers: Failure to Communicate（BCP 231, 2020-09）；EDNS 服务器响应合规基准 |
| `docs/rfc/draft-westerbaan-dnssec-mldsa.txt` | https://datatracker.ietf.org/doc/id/draft-westerbaan-dnssec-mldsa-04.txt | Module-Lattice Digital Signature Algorithm for DNSSEC（rev 04，2026-08；ML-DSA-44 alg 18、DS SHA-384）；`dns.MLDSA44` 验证路径依据。遵循既有 draft 命名约定（无版本后缀，README 表内注版本） |

完整性核对：三个文件均含标准页脚（rfc1918 至 [Page 9]、mldsa 至 [Page 9]）、正文完整、与 datatracker/rfc-editor 一致。

---

## 4. GUIDELINE.md 待补条目（仅标题行 + 概述，正文未动）

三个新存档在 GUIDELINE.md 中均无独立条目（RFC 1918 仅在 RFC 6147/DNS64 条目内联引用；RFC 8906、ML-DSA 全文无提及）。建议新增（置于对应 RFC 编号顺序处）：

1. `## RFC 1918 — Address Allocation for Private Internets  [RFC 1918: Best Current Practice (BCP 5)]  ✅`
   一句话：私有 IPv4（10/8、172.16/12、192.168/16）与共享地址段定义；DNS64 WKP（64:ff9b::/96）合成跳过非全球单播地址的规范依据（现状可保持内联于 6147 条目，独立条目便于审计追溯）。

2. `## RFC 8906 — A Common Operational Problem in DNS Servers: Failure to Communicate  [RFC 8906: Best Current Practice (BCP 231)]  ✅`
   一句话：服务器对未知 RR 类型/EDNS 版本/EDNS 选项等"结构异常"查询必须应答而非丢弃的合规矩阵；ZJDNS EDNSMiddleware、MQTYPE FORMERR 用例与上游 unknown-option 无选项重试的审计基准；上游 miekg/dns fork 2026-11 edns0-compliance 工作的依据。

3. `## draft-westerbaan-dnssec-mldsa-04 — Module-Lattice Digital Signature Algorithm for DNSSEC  [Internet-Draft, rev 04, expires 2027-02-12]  ✅`
   一句话：ML-DSA-44（alg 18）DNSSEC 公钥/RRSIG/DS（SHA-384）编码；`dns.MLDSA44` 原生验证（`nativelyVerified`）与 `TestVerifyRRset_MLDSA44` 的依据；⚠️ 仍是 I-D 非 RFC，出版后需替换为正式编号。

---

## 5. 规范化建议

### 5.1 README.md 索引缺 13 条（高优先，纯文档改动）
目录 132 个 .txt，README "File Index" 仅 119 条。缺失：
- 既有 10 条：`draft-vixie-dnsext-dns0x20.txt`、`rfc5280.txt`、`rfc8020.txt`、`rfc8624.txt`、`rfc8998.txt`、`rfc9276.txt`、`rfc9471.txt`、`rfc9520.txt`、`rfc9563.txt`、`rfc9853.txt`
- 本轮新增 3 条：`rfc1918.txt`、`rfc8906.txt`、`draft-westerbaan-dnssec-mldsa.txt`（注 `draft-westerbaan-dnssec-mldsa-04`）

（按任务约束本轮只增 RFC 文本、未改 README；建议下轮补齐。）

### 5.2 README "Update" 刷新脚本覆盖不全（低优先）
`docs/rfc/README.md` 末尾的刷新循环只覆盖 rfc*.txt + denis 两份 draft，缺 `draft-dnsop-deleg.txt`、`draft-vixie-dnsext-dns0x20.txt`、新增的 `draft-westerbaan-dnssec-mldsa.txt`。建议补齐（或注明 draft 手工刷新）。

### 5.3 GUIDELINE 引用但未存档的 RFC（15 个，按需补档）
| RFC | GUIDELINE 用途 | 判定 |
|-----|---------------|------|
| 7983（QUIC/UDP 首字节分路）、9287（grease QUIC bit）、9369（QUIC v2）、8900（IP 分片系统性脆弱性，9715 的威胁背景） | QUIC/分片行为规则 | 半实现依赖（quic-go fork 行为）——若做 QUIC 合规审计建议补档 7983/8900 |
| 8145（信任锚传送） | root-anchors.xml 获取方式 | 参考性；7958 已存档覆盖主线 |
| 7250（Raw Public Keys）、7918（False Start）、7924（Cached Info） | eTLS fork TLS 合规清单（MUST/SHOULD 项） | ZJDNS .go 零引用；依赖库层面，可不补 |
| 7464（JSON Text Sequences） | stats 流式输出提及 | 代码未使用该格式，可不补 |
| 8945（TSIG） | ⚪ 明确"不启用" | 不补 |
| 1706、1886、4697、7208、7450 | RR 历史/顺带提及 | 不补 |

### 5.4 命名一致性（✅ 无需改动）
- 全部符合 `rfc{NUMBER}.txt`（无前导零，如 rfc768.txt）与 `draft-{name}.txt`（无版本后缀）；GUIDELINE 内以 `-NN` 版本号标注，README 表内 draft 行注版本 —— 现有约定自洽。
- 特例核对：`rfc768.txt` 无标准 "Request for Comments" boilerplate（1980 年原版排版如此，与上游逐字节一致 5896B）；`rfc1929.txt` 3568B 为真实大小（与上游一致）。非损坏，无需处理。

---

## 6. 上游依赖库动态（codeberg.org/miekg/dns，go.mod v0.6.134）

2026-11 近期提交与本审查直接相关：
- `edns0 compliance: remaining tests from 8906` (#1204)、`atomdns: implement rest of 8906` (#1201)、`edns0 compliance` (#1198) —— 库与内置 atomdns server 对齐 RFC 8906
- `dns: cap edns0 option we parse` (#1217) —— EDNS 选项解析上限加固
- `Rename msg.Z to msg.Flags`、`Msg: allow Pack without compression` —— API 变化，升级 fork 时注意

结论：RFC 8906 存档（本轮已补）使 ZJDNS 在下次升级 fork 时有据可依；建议升级后复核 EDNSMiddleware 对 8906 合规用例（未知选项容忍、BADVERS、unknown-RR-type NOERROR/NOTIMP 语义）的行为。

### 参考来源
- [miekg/dns — Codeberg](https://codeberg.org/miekg/dns)（atomdns 说明与近期提交）
- [draft-westerbaan-dnssec-mldsa — IETF Datatracker](https://datatracker.ietf.org/doc/draft-westerbaan-dnssec-mldsa/)（rev 04，未出版 RFC）
