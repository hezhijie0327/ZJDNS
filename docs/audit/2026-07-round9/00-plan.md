# Round 9 — RFC 合规审计 (2026-07-31)

审计范围：7 个 RFC/草案，逐行比对实现代码。方法：读 RFC → 读实现 → 逐项比对 MUST/SHOULD/协议常量 → 报告违规 + 修复。

## 审计清单

| RFC | 领域 | 发现 | HIGH | 状态 |
|-----|------|------|------|------|
| RFC 8914 | EDE 错误传递 | 10 | 1 | ✅ 已修复 |
| RFC 8484 §5.1 | DoH Cache-Control | 1 | 0 | ✅ 已修复 |
| RFC 8767 | Serve-Stale | 5 | 0 | ✅ 已修复 |
| RFC 9156 | QNAME Minimisation | 4 | 2 | ✅ 已修复 |
| RFC 7871 | ECS | 4 | 2 | ✅ 已修复 |
| RFC 9250 | DoQ | 7 | 0 | ✅ 已修复 |
| draft-dnscrypt | DNSCrypt 加密 | 14 | 2 | ✅ 已修复 |

## 已验证合规（之前审计发现已修复）
- DNSCrypt C1 (sharedKeyCache race) ✅
- DNSCrypt C2 (WaitGroup swap) ✅
- Zero-pk replay ✅
- 上游 EDE 跨查询竞态 ✅

## 修复优先级
1. HIGH (7): EDE-A, QM-1, QM-2, ECS-1, ECS-2, DNS-A, DNS-D
2. MEDIUM (14)
3. LOW (16)
