# Handler 审计 (server/handler/*) — 15 findings: 1H/3M/11L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| H1 | HIGH | handler/pending.go:104-112 | DoJoin leader panic 不 Done → pending key 永久毒化(follower 60s 挂起,LRU 刷新永不驱逐) | ✅ |
| H-M1 | MED | middleware/cache_lookup.go:128 | 默认 stale 刷新路径缺 refreshGroup nil 守卫(门永不释放) | ✅ |
| H-M2 | MED | handler/response.go:56-90 + cache/store.go:439-446 | 损坏 BLOB 的 TTL 偏移值/wire 长度未校验 → serve 路径 panic → 静默丢查询 | ✅ |
| H-M3 | MED | middleware/dns64.go:43,91-104 | CNAME 链无 AAAA 时不合成(RFC 6147 §5.1.5);合成时 Validated 残留 → AD 误置 | ✅ |
| H-L1 | LOW | dns64.go:65, mqtype.go:308 | 过期命中丢 TTLOffsets 未归还池 | ✅ |
| H-L2 | LOW | cache_lookup.go:317 | refreshCacheEntry 缺 nil refreshCtx 守卫 | ✅ |
| H-L3 | LOW | mqtype.go:98 | 冗余循环变量拷贝 | ✅ |
| H-L4 | LOW | mqtype.go:352-403 | mergeRRs O(n²) 每对 2 次 rr.String() | ✅ |
| H-L5 | LOW | middleware/edns.go:20 | EDNS.config 死字段 | ✅ |
| H-L6 | LOW | middleware/zone.go:35-46 | isDestructiveChaosName 每调用重建常量串 | ✅ |
| H-L7 | LOW | cache_lookup.go:25 | 注释引用已删 CacheEntry 字段 | ✅ |
| H-L8 | LOW | handler/handler.go:158-163 | 链错误统计缺 qname/qtype/延迟 | ✅ |
| H-L9 | LOW | cache_lookup.go:75-77 | 冷却被未启动的刷新白白消耗 | ✅ |
| H-L10 | LOW | middleware/validation.go:130-135 | wire 名无效被误记为 unsupported qtype | ✅ |
| H-L11 | LOW | cache_store.go:103-112 | ECS mismatch SERVFAIL 是唯一不入统计的结果 | ✅ |
