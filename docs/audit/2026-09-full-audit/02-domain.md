# Domain 审计 (config/cache/edns/zone/ruleset) — 16 findings: 2H/4M/10L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| D1 | HIGH | cache/store.go:693,701 | Set 在 pool.Put 后读 msg.Data → DNSSEC flag 永假;DO=0 客户端收到未过滤 RRSIG/NSEC | ✅ |
| D2 | HIGH | cache/cache.go:258-262, latency_spill.go:67-71 | OnEvict 在 lrumap 锁内同步 spill.Put(WriteAt);Compact 期间全缓存冻结 | ✅ |
| D3 | MED | cache/store.go:428 vs 700-709 | 写方 15 位偏移计数 vs 读方 ≤255 拒绝 → >255 RR 条目永久 miss | ✅ |
| D4 | MED | config/validate.go:389,404-424 | dnscrypt 只注册 udp 冲突项,监听也绑 TCP;TCP-443 组成员死代码 | ✅ |
| D5 | MED | cache/stats.go:56-73 | FlushDB 逐条 spill 落盘后立刻截断文件(2000 次无用 syscall 且持锁) | ✅ |
| D6 | MED | cache/cache.go:286-309 | Flush 持 entries 锁做逐条磁盘 IO(关机窗口全局停顿) | ✅ |
| D7 | LOW | cache/statsjournal.go:1 | "Package statsjournal" 在 package cache | ✅ |
| D8 | LOW | cache/store.go:435-438 | 损坏条目每 Get 一次 Warn 且永不清理 | ✅ |
| D9 | LOW | config/config.go:127-128 | CacheSettings 文档首行重复 | ✅ |
| D10 | LOW | zone/parse.go:107 | 文件规则 match tag 解析错误被静默丢弃(变全匹配) | ✅ |
| D11 | LOW | edns/ede.go:6-8 | EDE 注册表注释过期(0-29 已分配错) | ✅ |
| D12 | LOW | cache/store.go:596-722 | Set 恒返回 0 的 int64(SQLite 残留) | ✅ |
| D13 | LOW | ruleset/ruleset.go:81-86 | 每 IP 规则二次 ParseCIDR | ✅ |
| D14 | LOW | zone/zone.go:46,376 | Result.cachable 死字段 | ✅ |
| D15 | LOW | cache/cache.go:268-281 | Close 非幂等 | ✅ |
| D16 | LOW | cache/stats.go:267-268 | UpdateLatency 先置 flag 后验 IP(非 IP 永久启用无效排序探测) | ✅ |
