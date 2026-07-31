# RFC 9156 (QNAME) + RFC 7871 (ECS) + RFC 9250 (DoQ) 审计

## QNAME Minimisation (RFC 9156)
| # | 严重度 | 位置 | 描述 | 状态 |
|---|--------|------|------|------|
| QM-1 | HIGH | `qname_minimise.go:14-59` | 增量 vs 累积标签重复查询 | 📝 待修复 |
| QM-2 | HIGH | `recursive.go:182-186` | NXDOMAIN 返回为 NOERROR | 📝 待修复 |
| QM-3 | LOW | `qname_minimise.go:116-125` | MAILA/MAILB 缺失 | 📝 已知 |
| QM-4 | LOW | `recursive.go:182-186` | 最小化 NXDOMAIN 暴露全名 | 📝 已知 |

## ECS (RFC 7871)
| # | 严重度 | 位置 | 描述 | 状态 |
|---|--------|------|------|------|
| ECS-1 | HIGH | `edns.go:107` | 响应 Scope 始终为 0 | 📝 待修复 |
| ECS-2 | HIGH | `store.go:325-370` | 缓存按请求前缀分桶 | 📝 待修复 |
| ECS-3 | MOD | `ecs.go:26-43` | 响应 ECS 未验证 | 📝 已知 |
| ECS-4 | LOW | `ecs.go:26-43` | 畸形 ECS 无 FORMERR | 📝 已知 |

## DoQ (RFC 9250)
| # | 严重度 | 位置 | 描述 | 状态 |
|---|--------|------|------|------|
| DoQ-2 | MOD | `quic.go:172-253` | STOP_SENDING/RESET_STREAM 忽略 | 📝 已知 |
| DoQ-3 | MOD | `quic.go:232-238` | 0-RTT NOTIFY 被拒绝 | 📝 已知 |
| DoQ-1a | LOW | `quic.go:276` | >65535 长度前缀未检查 | 📝 已知 |
| DoQ-1b | LOW | `edns.go:100` | DoQ 消息中 UDPSize 1232 | 📝 已知 |
| DoQ-4 | LOW | `quic.go:172-253` | 协议错误静默忽略 | 📝 已知 |
