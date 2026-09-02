# Defense 审计 (server/defense + 调用点) — 9 findings: 1C/4M/4L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| S1 | CRITICAL | defense/poisonguard.go:86-113 | hasSig 仅存在性检查:未签名区伪造 RRSIG 即豁免 poisonguard;最小化查询名下 TLD probe 不设防 → 注入 A 进缓存 | ✅ |
| S2 | MED | upstream/client.go:176-190 | (=U6) capsDowngrade 计数丢更新 | ✅ |
| S3 | MED | poisonguard.go:116-118 | 注入拒绝路径无条件求值 rr.String()(攻击者可控分配压力) | ✅ |
| S4 | MED | client.go:153-165, poisonguard.go:179-188 | ExecuteQuery/classifyRoot godoc 错挂 | ✅ |
| S5 | MED | upstream/plain/client.go:24 | hopguardWarned sync.Map 递归+代理场景无界增长 | ✅ |
| S6 | LOW | plain/udp.go:326-341 | (=U5) ID 不还原 | ✅ |
| S7 | LOW | plain/udp.go:514-695 | executeUDPMultiRead 生产不可达且已漂移 | ✅ 收敛 |
| S8 | LOW | client.go:221,252-270 | 0x20 降级偏离 §6.4(累计计数无衰减窗) | ✅ 连续失配计数 |
| S9 | LOW | hopguard.go:164-216 | %8 阈值/冗余条件/Should 谓词带副作用 | ✅ |
