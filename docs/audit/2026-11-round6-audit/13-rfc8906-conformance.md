# RFC 8906（BCP 231）合规验证报告（2026-11-14）

用户问"RFC 我们需要对齐吗？"——对 3 份新存档逐一核实：RFC 1918（DNS64 已在用，仅补档）、ML-DSA draft（已实现 rev 04 语义）、**RFC 8906 需要系统验证**——EDNS 容忍语义/FORMERR/未知选项重试都在其矩阵内但从未对照过。用 raw-packet 探针（/tmp 构造，14 用例）对活服务器实测。

## 结果：14/14 PASS（1 个真实 bug 已修复）

| # | 用例 | 8906 要求 | 实测 | 判定 |
|---|------|-----------|------|------|
| 0 | A 查询（sanity） | 应答 | NOERROR | PASS |
| 1 | TYPE1000 未知类型 | 应答不丢弃（§8.1.2） | **修复前 SERVFAIL（出站包 QDCOUNT=0 被上游丢弃）→ 修复后 NOERROR** | **FIXED** |
| 2,3 | opcode=2/12 | NOTIMP（§3.1.4） | NOTIMP | PASS |
| 4-6 | CD=1 / AD=1 / 保留位 | 应答不丢弃（§3.1.3） | NOERROR | PASS |
| 7,8 | EDNS version=1/127 | BADVERS 扩展 rcode（§3.2.2/6891 §6.1.3） | BADVERS（header 低 4 位=0 + OPT TTL ext-rcode=1） | PASS |
| 9 | 未知 EDNS option 65535 | 忽略该选项照常应答（§3.2.3） | NOERROR | PASS |
| 10 | QR=1 查询 | 丢弃或 FORMERR（§3.1.3） | DISCARD | PASS |
| 11 | QDCOUNT=0 | FORMERR（§3.1.3 矩阵） | FORMERR | PASS |
| 12 | QDCOUNT=2 | FORMERR 或丢弃 | DISCARD | PASS |
| 13 | UDP size=512 + 大应答 | 不超通告尺寸/TC（§3.2.5） | TC + wire ≤512 | PASS |

## 修复的 bug：未知 TYPE 转发整体失效（HIGH）

**现象**：TYPE1000/9999/65280/65535（含 RFC 6895 私用段）查询全部 SERVFAIL——上游（223.5.5.5 直测 NOERROR 空答）明明应答，我们 18s 读超时后 SERVFAIL。

**根因**（dump 上游抓包实锤）：fork 的 `dnsutil.SetQuestion` 对 `TypeToRR` 没有的类型**返回 nil 且不设置问题节**（compat.go 文档写明）。`BuildQueryMsg`（handler/handler.go）与 MQTYPE 无选项重试（resolver/ns_concurrent.go）都忽略了返回值 → 出站查询 **QDCOUNT=0 + 孤立 OPT**（另带 0x4000 杂散 Z 位）→ 真实上游静默丢弃 → 超时。

**修复**：`internal/dnsutil.SetQuestionAny`——SetQuestion 失败时以 `&dns.RFC3597{Hdr, RFC3597:{RRType}}` 构造问题节（fork 的 unpack 对未知类型正是生成该表示；实测 Pack 往返保真、`RRToType`=原类型）。两个调用点切换。回归测试：`TestBuildQueryMsgUnknownType`（1000/65280/65535 三档出站 wire 断言）+ `TestEDNSMiddleware_RawVersionBADVERS`（raw wire → BADVERS 端到端，钉住 EnsureFullUnpack 不丢 Version）。

**影响面**：所有未知/未分配 RR 类型的转发与递归（8906 §8.1.2 明确"IANA 不太可能分配 TYPE1000"正是测试载体）；顺带修复了未知 type 的 MQTYPE optionless 重试。

## 探针自身的教训（方法论补充素材）

1. **扩展 RCODE**：BADVERS=16 在 header 低 4 位是 0，真值在响应 OPT TTL 最高字节——只读 header 会把 BADVERS 误判成 NOERROR。
2. **手工构造 DNS 包**：ARCOUNT 必须与附加节匹配，否则 fork 解包报 "N more octets" 丢弃（服务器行为完全正常，探针报 NO RESPONSE 的假象）。
3. EDNS TTL 布局：ext-rcode(31..24) | version(23..16) | DO(15) | Z(14..0)。
