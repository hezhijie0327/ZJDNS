# RFC 合规审计报告

审计日期: 2026-07-28
审计范围: 8 个协议，48 个 RFC 条款

## 总览

| 协议 | RFC | 合规 | ⚠️ 部分 | ❌ 缺失 | 评级 |
|------|-----|------|---------|---------|------|
| **Plain DNS** | 1035 + 7766 | 22 | 5 | 3 | B+ |
| **DoT** | 7858 + 8310 | 17 | 2 | 7 | B |
| **DoH** | 8484 | 18 | 3 | 1 | A- |
| **DoH3** | 9114 + 8484 | 14 | 2 | 0 | A |
| **DoQ** | 9250 | 12 | 6 | 5 | B- |
| **DTLS** | 8094 | 13 | 3 | 4 | B- |
| **DNSCrypt** | draft-denis | 37 | 1 | 1 | A+ |
| **TLCP/DTLCP** | GB/T 38636 | 12 | 3 | 0 | A- |

## 跨协议系统性问题

### 1. 服务端 DoS 防护缺失（影响 Plain DNS, DTLS, DoQ）
- 无每 IP 连接数限制
- 无握手速率限制
- 无应用层空闲超时（Plain TCP 服务端）

### 2. PMTU 处理缺失（影响 DTLS, DTLCP, DoQ）
- 无路径 MTU 发现
- 无 1280 字节默认 MTU 假设
- 大响应可能被静默丢弃

### 3. 消息大小限制不一致（影响 DoQ, DoT）
- DoQ 服务端限制 8190 字节（规范要求 65535）
- DoT 服务端限制 8190 字节（规范要求 65535）

### 4. 高级 TLS 特性缺失（影响 DoT, DTLS）
- SPKI 固定 (RFC 7858 §4.2)
- DANE TLSA 认证 (RFC 8310 §8)
- OCSP Stapling (RFC 8094 §9)
- 原始公钥 (RFC 7250)

## 协议详细发现

### DoT (RFC 7858 + RFC 8310)

**❌ 缺失 (7):**
- RFC 7858 §4.2: SPKI 密钥固定
- RFC 8310 §8: DANE TLSA 认证
- RFC 8310 §9: 原始公钥 (RFC 7250)
- RFC 8310 §9: TLS False Start
- RFC 8310 §9: 缓存信息扩展
- RFC 7858 §3.1: 失败服务器跟踪
- RFC 7858 §3.4: TCP 快速打开

**⚠️ 部分 (2):**
- 消息大小限制 8190（规范 65535）
- 非池化路径双 Write（长度+消息分离）

### DoH (RFC 8484)

**❌ 缺失 (1):**
- §5.1: 客户端必须处理 Age 头计算 DNS TTL

**⚠️ 部分 (3):**
- Cache-Control 始终 max-age=0（非基于 TTL）
- Content-Type 错误返回 400 而非 415
- 客户端无差异化 HTTP 错误处理

### DoQ (RFC 9250)

**❌ 缺失 (5):**
- §4.3.1: 事务取消 (STOP_SENDING)
- §4.3.2: 事务错误 (RESET_STREAM with DOQ_INTERNAL_ERROR)
- §4.5: 0-RTT 非重放事务检查（客户端+服务端）
- §4.6: 消息大小限制 65535（当前 8190）
- §4.1.1: 客户端无端口 53 禁止检查

### DoH3 (RFC 9114)

**⚠️ 部分 (2):**
- SETTINGS_MAX_FIELD_SECTION_SIZE 未配置
- 服务端 EnableDatagrams 无必要配置

### DTLS (RFC 8094)

**❌ 缺失 (4):**
- §5: PMTU 处理完全缺失
- §3.3: 服务端无每 IP 并发连接限制
- §9: OCSP Stapling 缺失
- §9: 握手泛滥防护缺失

### DNSCrypt (draft-denis-dprive-dnscrypt)

**❌ 缺失 (1):**
- §10: Anonymized DNSCrypt relay（设计选择，SOCKS5 替代）

**⚠️ 部分 (1):**
- §11.7.3: Ticket 密钥轮换（固定 ticket key）

### Plain DNS (RFC 1035 + RFC 7766)

**❌ 缺失 (3):**
- §6.2.3: 服务端 TCP 空闲超时缺失
- §6.2.2: 服务端无每客户端连接限制
- §7: QNAME/QCLASS/QTYPE 响应验证缺失

### TLCP/DTLCP (GB/T 38636 + GM/T 0128)

**⚠️ 部分 (3):**
- DTLCP 同步连接处理（gotlcp 库限制）
- 加密证书 KeyUsage 应为 KeyAgreement
- ALPN 值讨论（dot vs tlcp）

## 优先级修复建议

### Sprint 1 — MUST 违规（应立即修复）
1. DoQ §4.6: 消息大小限制改为 65535
2. DoQ §4.5: 添加 0-RTT 非重放事务检查
3. DoH §5.1: 客户端 Age 头处理
4. DNSCrypt §11.7.3: 文档化 ticket key 策略

### Sprint 2 — SHOULD 违规（高优先级）
5. DTLS §5: PMTU 处理和 1280 默认假设
6. Plain DNS §6.2.3: 服务端空闲超时
7. DoH §5.1: 基于 TTL 的 Cache-Control
8. Plain DNS §6.2.2: 每客户端连接限制

### Sprint 3 — 增强（后续迭代）
9. SPKI/DANE/原始公钥支持
10. OCSP Stapling
11. 服务端 DoS 防护（速率限制）
