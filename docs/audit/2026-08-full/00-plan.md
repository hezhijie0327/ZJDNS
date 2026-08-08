# 00-plan.md — 2026-08 全库审计修复计划

按 AUDIT-METHODOLOGY.md §2 分三个 Sprint。Sprint 内按 §2.2 优先级：单字符/单行修复 → 模式匹配修复 → 逻辑重写 → 死代码删除。每个修复一个 commit，主题行用 `<type>: <具体修复> (<ID>)`（§3.5）。

**每个 Sprint 完成后**：`go test -short ./...` + benchmark 基线对比（§3.3，必须 `-benchmem`；H7/H10 涉及 pre-packed 直发路径，任何新增分配即契约破坏）。

---

## Sprint 1 — CRITICAL（立即修复）

| ID | 修复内容 | 类型 | 建议 commit |
|----|----------|------|-------------|
| **C1** | `server/upstream/plain/udp.go` — 快速返回路径（:604-606）与 `collectEDNSCandidate` TTL-confident 路径（:734-736）在 `Put(s.prev/s.last)` 后立即置 nil；`executeUDPCollect` 收养块（:274-276）改为只在非 nil 时 Put。三处 `s.prev`/`s.last`/`s.nonEDNS` 统一置 nil 纪律 | 单行 ×3（模式） | `fix: nil s.prev/s.last after Put in spoofguard fast paths (C1)` |
| **C2** | `server/upstream/dnscrypt/state.go:103-105` — `state()` 在 `c.cacheMu.Lock()` 后检查 `c.cache == nil` 直接返回错误（仿 `deleteState`/`buildState`） | 单行 | `fix: nil-guard cache in dnscrypt state() before Close race (C2)` |
| **C3** | `server/handler/middleware/cache_store.go:49` — 门卫改 `if qctx.Res != nil { return err }`（去掉 CacheServed/ZoneMatched 条件，二者都有 Res 兜底）；`zone.go:156-160` 恢复问题名改写（`qd.Header().Name = zoneResult.Domain`）或删除死分支 + `restoreDomain` 链 | 逻辑重写 | `fix: zone records-less rules drop queries — gate CacheStore on Res only (C3)` |

**Sprint 1 验证**：`go test -short ./...` 全绿；手动测试 `*.example.com` 无记录规则 + `ZJDNS.cache.clear` + DNSCrypt 上游关停；benchmark 基线对比。

---

## Sprint 2 — HIGH（下个发布周期）

| ID | 修复内容 | 类型 |
|----|----------|------|
| **H1** | `internal/pending/pending.go:246` — 超时分支只返回 `ErrTimeout`（不读 `existing.Err`），消除竞争且语义更正确 | 单行 |
| **H2** | `cache/store.go FlushDB` + `stats.go` — DELETE 前先 `cacheWriter.Flush()`/`statsWriter.Flush()` 并清空 `s.pending`（或把 clear 路由进 writer goroutine） | 逻辑重写 |
| **H3** | `cache/batch_writer.go:58` — `run()` 首行加 `defer zdnsutil.HandlePanic("Cache batch writer")` | 单行（模板） |
| **H4** | `server/protocol/tls/dtls.go:138-140` — `ErrShortBuffer` 不再 `continue`：计数超限断开连接，或 `SetReadDeadline` 后跳过该记录（pion 不消费 → 需显式推进） | 逻辑重写 |
| **H5** | `server/protocol/tlcp/dtlcp.go:211-229` — `s.serverGroup.Go()` 移出 `l.mu` 临界区（先快照连接，锁外 Go） | 模式 |
| **H6** | `server/protocol/dnscrypt/server.go:90-103` — 配置加载时校验 `len(privKey) == ed25519.SeedSize`（64B），错误即报配置错误 | 单行 |
| **H7** | `server/bridge.go:276 truncateWire` — 改写入新缓冲（truncate 路径罕见，复制免费），不再原地改 `response.Data` | 单行 |
| **H8** | `server/resolver/recursive.go:191` — `truncated := response.Truncated` 在 `Put` 前捕获，`QueryResult` 用局部变量 | 单行 |
| **H9** | `server/upstream/plain/udp.go:260` — collect 路径门改 `len(pkt.Data) < 12`（与多读路径 :479 对齐），或 `processPacket` 内先验长度 | 单行 |
| **H10** | `cache/store.go:272-275,464-470` — pending 读穿路径的 `buildEntry` 返回**复制**的 wire（`slices.Clone`），断开与 `pendingEntry.msgWire` 的别名；顺带修复 ID/TTL patch 污染 | 逻辑重写（注意 0 B/op 契约：复制仅在 pending 读穿路径） |
| **H11** | `middleware/cache_lookup.go:192-234` — done 成功分支补 `m.store.Set(qname, qtype, qclass, ecsOpt, dnssecOK, qr.Answer, qr.Authority, qr.Additional, qr.Validated, qr.Rcode)`（与 timer 路径 :251-277 对齐） | 单行 |

**Sprint 2 验证**：`go test -race -short ./...`；H4 用 >8192B DTLS 记录回归测试；H9 用 2–9 字节伪造数据报回归测试；H10/H7 后跑 `BenchmarkServerProcessQuery` 确认无 alloc 回归。

---

## Sprint 3 — MEDIUM（57）+ LOW（78）

按维度分组，每维度一次提交。完整清单见各报告，以下为每报告的关键 MEDIUM 索引：

### 文档（12 MEDIUM，10-docs.md）— `docs:` 提交
- CLAUDE.md 管道顺序（实际链 Response→EDNS→MQTYPE→CacheStore→Validation→Zone→Any→CacheLookup→PTR→DNS64→Resolution，:263-279）
- CLAUDE.md `AsyncStatsWriter` → `BatchWriter`（:226,314）；27 前缀 vs "23 前缀"（CLAUDE.md:338 vs AUDIT-METHODOLOGY.md:354）
- FLOWCHARTS.md：9→11 层（:30）、整体架构图缺 MQTYPE/Any、EDNS 错位（:9）、ORDER BY 过期（:117）
- BENCHMARK.md dnsperf zone 配置格式失效（:40-45，改用 LOADTEST.md:59-61 数组格式）
- README.md 九表→十表（:89）；DEBUG.md resolver_info 键不存在（:217）；DEBUG.md grep 模式失效（:697）
- ARCHITECTURE.md `pqResumedSharedKey`→`PQResumedSharedKey`（:251）；GUIDELINE.md 统计重算（:33-53）

### RFC（7 MEDIUM + 9 LOW，13-rfc.md）— `fix:`/`docs:` 提交
- `validation.go:113-115` NXNAME 改 FORMERR + EDE 30（RFC 9824 §3.5 MUST）——同时修正 GUIDELINE.md 9824 ✅ 徽章
- `cache/store.go:990-1006` TTL MSB-set 按 RFC 2181 §8 视作 0 处理
- 存档 `docs/rfc/rfc9443.txt`（或 pq.go:181 改引 RFC 9000，与 DNSCrypt 草案一致）
- GUIDELINE.md 6891（BADVERS）、6840（§5.3→§4.1）、6761（localhost 转发）条目修正
- 6 处 LOW 章节错引（any.go §2.1→§4.2、edns.go 7873 §5.3 等）

### 日志前缀（01-foundation）— `fix:` 提交
- `dnsutil.go:215` `LogHandshake` 去掉硬编码 `"TLS: "` 前缀（双重前缀 + TLCP/DTLCP 误标）

### 池/内存（01-foundation、06-handler）— `fix:` 提交
- `lrumap Delete/CompareAndDelete` 补 OnEvict 调用（:136,166，防御性——当前调用方安全）
- `mqtype.go:273-276`、`dns64.go:62-70` TTLOffsets 泄漏 → 失败路径也 Release
- `zone.go:96`/`any.go:50`/`ptr.go:61` 改用 `cache.AcquireRequestRecord` 池

### 缓存正确性（02-domain、06-handler）— `fix:` 提交
- `validateDDR` IPv4 漏检（`To16()` 非 nil 陷阱）→ 按 `ip4 := ip.To4()` 判断
- resinfo `exterr` 列表回归（补 1,7,12,22,30，删 2,5,9,11,13,14,19）
- `cache_lookup.go:204-222` 前台刷新重建补 `qr.Rcode`/EDE/DNS64；mqtype/dns64 次级查询补 `isExpired` 处理
- `cache_store.go:114-121` ECS 不匹配 SERVFAIL 补日志

### 防御算法（07-defense）— `fix:` 提交（需 fuzz/边界测试，§4.2）
- hopguard Feed 移到 ID/长度校验 + spoofguard 接受之后（学习期防固定 TTL 洪水取胜）
- hopguard 武装后 TTL 漂移恢复路径：拒绝 TTL 概率性入直方图或连续拒绝解除武装
- poisonguard `classifyTLD`：携带有效 RRSIG 的数据 RRset 豁免

### 协议（03-protocol）— `fix:` 提交
- DoT/TLCP 连接 Shutdown 唤醒（仿 DNSCrypt :392 `SetReadDeadline(time.Unix(1,0))`）
- `tlcp/certs.go` leaf NotAfter 钳制（对齐 `tls/certs.go`）
- DTLCP dispatcher 缓冲 1232→8192（或按 RFC 8094 65535）；`demuxPacketConn.ReadFrom` 加 `io.ErrShortBuffer`
- `http_tlcp.go` Content-Type 错 → 415
- DNSCrypt `ResetKeys`/`updateKeys` 去重（互斥或统一入口）

### 上游（04-upstream）— `fix:`/`perf:` 提交
- DoQ 错误处理区分 `context.Canceled`（不淘汰健康连接）；0-RTT 重试二次失败也不留池
- `pool/udp.go` collect-mode 等待者唤醒；不可达 `!ok` 分支
- per-query `SystemCertPool()` Clone + config Clone 上提至 dial 时（perf）
- dnscrypt `readUDPWithCancel`/`readPrefixedWithCancel` 两个 goroutine 补 HandlePanic（client.go:328,350）

### 生命周期（08-top）— `fix:` 提交
- `tasks.go:299` `shutdownServer` 加 `sync.Once`
- pprof 绑定失败降级（仿 initPprof 自身 skip-on-error）
- `--sql` 模式互斥补 `runSQL`；`--sql` 真只读（migrate 前置守卫或 `--rw` 才 migrate）
- loadtest：`elapsed` 按实际窗口计时、`-workers 0`/`-seconds 0` 校验、3 个 goroutine 补 HandlePanic

### LOW 汇总（78 个）
- 魔法数字（probe.go `Timeout: 100`、validation.go `255`、mqtype.go `64` 等）→ 命名常量
- 未注释 `_` 丢弃（dnssec_chain.go:241/333/593/624、zonecut.go:312、nameserver.go:481/587）→ 补注释
- 重复代码（ns_addresses.go:108-112/251-253 重复 TryProbeNSAddrs）
- 注释过期（forward.go:357-361 等）与 RFC 章节误引（13-rfc 6 处）
- godoc 缺口（EncodeTicketPlaintext、dns64.Synthesize 等 36 处，34 处为接口实现豁免）
- debug 日志格式、日志前缀补充（UDPPOOL×2、DOH×1 未列入 27 前缀）

---

## 执行顺序建议

1. **Sprint 1 三刀先切**（C1/C2/C3 互不依赖，可并行）→ 立即验证
2. Sprint 2 按依赖：H8/H1/H9/H3/H6 是单行，先做；H7+H10 一起做（同根因）；H4/H5 独立；H2/H11 涉及缓存，做完整轮缓存测试
3. Sprint 3 文档批次先行（成本最低、刷完立即减少误报），再按上表维度推进
4. 每 Sprint 结束跑 `docs/benchmark/benchmark-baseline.txt` 对比（`-benchmem`），回归判定按 §3.3 表
