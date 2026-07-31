# RFC 8484 (DoH) + RFC 8767 (Serve-Stale) 审计

## DoH (RFC 8484 §5.1)
| # | 严重度 | 位置 | 描述 | 状态 |
|---|--------|------|------|------|
| 1 | MED | `https.go:171` | Cache-Control max-age=0 硬编码 | ✅ 已修复 |
| 4 | LOW | `https_dns.go:26-86` | DoH 客户端忽略 Age 头 | 📝 已知 |

## Serve-Stale (RFC 8767)
| # | 严重度 | 位置 | 描述 | 状态 |
|---|--------|------|------|------|
| 2 | MED | `ttl.go:24-36` | Stale TTL 循环倒计时 | ✅ 已修复 |
| 3 | MED | `store.go:303-321` | TTL=0 记录被缓存 | ✅ 已修复 |
| 5 | LOW | `store.go:317-318` | 7 天 TTL 上限仅用于保留 | 📝 已知 |
| 6 | LOW | `forward.go:249-293` | 刷新接受不检查 AA 位 | 📝 已知 |
