# 文档/流程图/注释审计 — 22 findings: 6M/16L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| T1 | MED | AGENTS.md:298 | spoofguard 行为描述与代码相反(不再 reject) | ✅ |
| T2 | MED | ARCHITECTURE.md:78, FLOWCHARTS.md:843 | 池上限 4/32 vs 实际 8/512 三方矛盾 | ✅ |
| T3 | MED | AGENTS.md:139,352, README.md:18 | 基线 -benchmem 矛盾;基线文件补齐 | ✅ |
| T4 | MED | config.example.json:158-162 | fallback 上游缺 server_name → 示例配置自身校验失败 | ✅ |
| T5 | MED | DEBUG.md:529-555 | spoofguard 测试期望已删除的日志行/行为 | ✅ |
| T6 | MED | FLOWCHARTS.md | 缺:fallback 上游、共享端口 demux、DNSCrypt replay bound、批量 fan-out、MQTYPE 重试 | ✅ |
| T7 | LOW | AGENTS.md:135 | 116→115 benchmarks | ✅ |
| T8 | LOW | AGENTS.md:355 | 117→119 RFC 文件 | ✅ |
| T9 | LOW | AGENTS.md:309 | ProtocolSettings 漏 HTTPTLCP | ✅ |
| T10 | LOW | AGENTS.md:225 | defense/ 目录描述错位(spoofguard/splitguard 在 upstream;漏 capsguard) | ✅ |
| T11 | LOW | ARCHITECTURE.md:321,326 | 引用不存在文件 tlcp/sharedudp.go;packetBufPool→PacketBufPool | ✅ |
| T12 | LOW | ARCHITECTURE.md:241 | dnscrypt_state 残留表名 | ✅ |
| T13 | LOW | FLOWCHARTS.md:236 | cache key 不含 dnssec(与 PendingKey 混淆) | ✅ |
| T14 | LOW | FLOWCHARTS.md:591 | TLD probe 2s → 1s | ✅ |
| T15 | LOW | README.md:12, AUDIT-METHODOLOGY.md:363 | 18 维度→20;27 前缀→28 | ✅ |
| T16 | LOW | dnscrypt/persist_file.go:1 | "Package dnscryptstate" 错名 | ✅ |
| T17 | LOW | dnscrypt/server.go:91-106 | New godoc 错挂 newKeyEntry | ✅ |
| T18 | LOW | plain/udp.go:161 | 注释引用不存在的 PackQuery | ✅ |
| T19 | LOW | rfc/GUIDELINE.md:979 | RFC 9018 Secret 轮换 30min 行错误 | ✅ |
| T20 | LOW | rfc/GUIDELINE.md:1545 | RESINFO exterr 列表与代码不符 | ✅ |
| T21 | LOW | README.md:225,76,123 | DB Schema 表述;capsguard 缺失 | ✅ |
| T22 | LOW | DEBUG.md:251-255 | 共享端口表漏 http3/dnscrypt 复用 | ✅ |
