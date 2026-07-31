# DNSCrypt Draft 审计

## 发现
| # | 严重度 | 位置 | 描述 | 状态 |
|---|--------|------|------|------|
| A | HIGH | `crypto.go:66-71` | 轮换重叠期用错密钥加密 | ✅ 已修复 |
| D | HIGH | `state.go:168-179` | pqdnscrypt:true 时静默降级 | ✅ 已修复 |
| B | MED | `crypto.go:37-60` | TCP 响应可超 4096 字节 | 📝 已知 |
| C | MED | `client.go:175-196` | UDP TC 不重试 TCP | 📝 已知 |
| E | MED | `state.go:112-121` | 证书查询从不填充 | 📝 已知 |
| F | MED | `crypto.go:55-62` | KEM 密文跨查询复用 | 📝 已知 |
| G | MED | `server.go:126-135` | Ticket 密钥从不轮换 | 📝 已知 |
| H | LOW | `crypto.go:102-107` | 重叠期 ticket 无法验证 | 📝 已知 |
| I | LOW | `server.go:426-428` | PQ fit 检查可超调 | 📝 已知 |
| J | LOW | `client.go:146-158` | Ticket 过期未限证书过期 | 📝 已知 |
| K | LOW | `dns.go:22-39` | PQ 开销少算 2 字节 | 📝 已知 |
| L | LOW | `defaults.go:13` | 非默认端口 8443 | 📝 已知 |
| M | LOW | `server.go:223,241` | Start-after-Shutdown 密钥轮换死锁 | 📝 已知 |

## 已验证合规
- 证书格式 (§5.5) ✅
- ClientMagic 约束 ✅
- 密钥交换 (§6) ✅
- AEAD (§7/§13) ✅
- Nonce 构造 (§4/§8) ✅
- PQ 密钥派生 (§11.4) ✅
- 恢复 (§11.7) ✅
- UDP 反放大 (§5.4.6) ✅
- 密钥轮换 (§8.2/§9) ✅
- TCP 帧 (§5.4.4) ✅
