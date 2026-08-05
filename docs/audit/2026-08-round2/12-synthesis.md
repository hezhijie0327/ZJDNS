# 2026-08 第二轮全库审计 — 综合报告（快速存档版）

> 审计日期: 2026-08-05
> 审计范围: 全库 ~52K 行 Go；重点为 93611d5（上轮审计修复）之后的 12 个 commit（v3.11.7–v3.11.14）：RFC 10029/9824/9606/9715/8482/6975、pre-packed wire 直发、ECS 单轮查询、TTL-offset 池、TCP 写入分片、SQLite 驱动切换 modernc
> 审计方法: AUDIT-METHODOLOGY §1.2 — Phase 1 包级 7 agent + Phase 2 交叉 19 agent（**24/26 完成，2 个未完成见 HANDOVER.md**）+ 审计主循环人工读码核验
> 原始发现: 152 条（CRITICAL 10 / HIGH 20 / MEDIUM 49 / LOW 73），去重后核心问题如下。原始数据: `raw-phase12.jsonl`

## 一、CRITICAL / HIGH 发现（全部经人工读码核验 CONFIRMED）

### C1 — CRITICAL — `cache/store.go:267` Get 无格式标记校验 → 升级后旧缓存条目越界 panic

**9 个 agent 独立确认（domain/arch/validation/mem/perf/locks/errc/panic/comment）+ 人工确认。**

- Get() 无条件按 `cacheFormatPrePacked` (0x02) 解析 `msgWire[1:3]` 为 TTL offset 表，**从不检查 `msgWire[0] == 0x02`**。
- v3.11.11 及更早 Set 存 `zdnsutil.Compress(msg.Data)`（zstd 裸 wire，无前缀）或裸 wire（≤v3.11.10）。
- zstd 帧头字节 1-2 = `0xB52F` = 46383 → `AcquireTTLOffsets(46383)` → 循环 `msgWire[3+i*2:]` **越界 panic**；裸 wire（DNS ID 随机字节）同样。
- **影响窗口**: 升级后最长 7 天（TTL）+ 3 天（stale）= **10 天内命中旧条目即 panic**（HandlePanic 恢复 → 查询丢弃）。
- 证据: `git show 5256aec^:cache/store.go`；`git show ba1f78c:cache/store.go`。
- **修复**: Get 检查 `msgWire[0] != 0x02` 时按旧格式解析（zstd magic 检测 + 解压、无 offset 表）；或迁移时清旧条目。

### C2 — CRITICAL — `server/protocol/dnscrypt/crypto.go:29` encrypt() 无条件 Pack() 清空 pre-packed 直发响应

**panic 维度 agent 发现 + 人工核验机制。**

- `encrypt()` 对 handler 返回的响应无条件 `m.Pack()`；pre-packed 直发响应（Data 完整、Answer/Ns/Extra 为 nil）经 miekg v0.6.89 `Len()`（只算 RR 区，msg.go:609-629）→ `cap(Data) >= l` 分支 `Data = Data[:l]` **截断** → 重建为仅 header+question 的**空 NOERROR**。
- DNSCrypt `udpResponseWriter.WriteMsg`（udp.go:41-49）/TCP 同型直接 `encrypt(m)`——**唯一未适配 pre-packed 的协议路径**（bridge.go 的 UDP/TCP 有 `len(response.Data) == 0` 守卫跳过 Pack）。
- **影响**: DNSCrypt 监听器上每次缓存命中响应被静默清空（客户端收到空应答/NOERROR 无记录）。
- **修复**: encrypt 前 `if len(m.Data) > 0 { 使用 m.Data 作为 packet }` 或先 Unpack 再 Pack。

### H1 — HIGH — `server/handler/middleware/mqtype.go:78` 递归模式缓存 miss 路径 MQTYPE merge 不执行

**3 个 agent 确认（server-02/deadcode-02/errc-02）+ 人工确认。**

- 链顺序 Response→CacheStore→MQTYPE→…→Resolution；miss 时 Resolution 只设 `qctx.ResolutionResult`，MQTYPE post 时 `qctx.Res == nil`（:78 早返回）→ merge 永不执行。
- RFC 10029 §3.4 "MUST return MQTYPE-Response" 违反；§5 客户端把无 MQRESPONSE 的响应视为无效。
- **修复**: merge 移到 CacheStore 外侧（或基于 ResolutionResult 构建）。

### H2 — HIGH — `mqtype.go:180-196` + `response.go:73` 缓存命中路径 merge 产物被 Unpack 抹掉

**3 个 agent 确认（deadcode-03/errc-03/rfc-01）+ 人工确认。**

- 命中路径 Res 为 pre-packed（Data 非 nil、RR 区 nil）；merge 追加 Answer/Pseudo 后，Response 中间件 `shouldAddEDNS=true`（请求带 MQQUERY）→ `Unpack()` → miekg msg.go:160/428 **重建** Answer/Pseudo → 合并 RR 与 MQRESPONSE 全部丢失。
- **修复**: merge 后置（Response finalize 前重新打包），或直接改写 pre-packed Data。

### H3 — HIGH — `server/bridge.go:98,110` refs 双重 Add → sweep 死代码 → tcpWriteMu 无界增长（H1 修复回归）

**12 个 agent 交叉确认（server-01/regression-01/goroutine-01/bridge-01/resource-01/validation-02/context-01/mem-02/deadcode-01/locks-01/panic-03/comment-02）+ 人工确认。**

- f7e7f13（v3.11.13）shard 化时把 H1 修复（9f6001c）的锁内 `refs.Add(1)` 复制成两份（:98 锁内 + :110 锁外），goroutine/SERVFAIL 各只有一个 `defer Add(-1)` → 每请求净 +1 → `sweepTCPWriteMu`（tasks.go:137）永不删除 → 每 TCP 客户端连接一条永久 entry（含 channel），进程生命周期无界增长。
- **修复**: 删除 :110 的重复 Add。

### H4 — HIGH — `server/handler/middleware/mqtype.go:56` 明文 UDP/TCP 上 MQTYPE-Query 不可见（Pseudo 为空）

**server 维度 agent 发现 + 人工核验 miekg server.go:318。**

- miekg/dns v0.6.89 `Server.serveDNS` 硬编码 `r.Options = MsgOptionUnpackQuestion`（server.go:318，只解 question）；plain 监听器（plain/udp.go:25, tcp.go:32 用 `dns.Server`）请求到达链时 `Req.Pseudo` 为空。
- MQTYPE.pre（链第 3 层）在 EDNS.pre（第 7 层，完整解包处）**之前**执行 → `findMQQUERY` 永远返回 hasMQ=false → **明文 UDP/TCP 上 MQTYPE 校验（FORMERR）与合并全部不可达**。转发透传不受影响（resolution.go 在 EDNS 之后）。
- 综合 H1/H2/H4：**RFC 10029 客户端功能仅转发模式可用；递归模式全线失效（明文不可见 + miss 不合并 + hit 被抹）**。
- **修复**: MQTYPE.pre 镜像 EDNS.pre 的 `if len(Pseudo)==0 { Options=0; Unpack() }`。

## 二、MEDIUM 摘要（人工核验 CONFIRMED 2 项）

| # | 位置 | 类别 | 摘要 | 核验 |
|---|------|------|------|------|
| M1 | upstream/dnscrypt/state.go:104 | resource | `state()` 读 `c.cache` 无 nil 守卫，Close() 置 nil（client.go:277-284）后查询在 lrumap nil 接收者上 panic——H5 同类模式的保留实例（同文件 buildState/deleteState 均有守卫） | ✅ |
| M2 | upstream/plain/udp.go:166 | pool-leak | `executeUDPMultiRead` ctx.Done 早退不归还已收集的池化候选（sg.last/prev/nonEDNS），错误路径 214-223 显式归还——first-win 取消场景每查询泄漏 1-2 池项 | ✅ |
| M3 | upstream/dnscrypt/cert.go:83 | context | `fetchCertOverTCP/UDP` 裸 `net.Dial`（无 ctx），connect 阻塞可超查询预算 2-13 倍（对端丢 SYN 时） | 待 |
| M4 | cache/store.go:314 | validation | `_ = entry.Unpack()` 错误丢弃（latency 排序路径，部分填充 → rebuild 损坏 wire） | ✅（同人工 M2） |
| M5 | middleware/cache_lookup.go:247 | goroutine | serveExpiredWithRefresh 前台 TryGo 失败时 done 永不关闭，定时器路径的第二个 TryGo 闭包 select 等待 `<-done` 直到 refreshCtx 超时（DefaultBackgroundTimeout） | 待 |
| M6 | mqtype.go:269 | rfc | `entryRcode` 只读 `ResponseWire[3]&0x0F` 低 4 位——扩展 rcode（≥16）条目被误判 NOERROR，RCODE 匹配检查失效 | ✅（同人工 M1） |
| M7 | upstream/tlcp/tlcp.go:89 | validation | exchangeOverTLCP 不回验响应 ID（tls.go:107-110 同型校验缺失，DTLS/DTLCP 同缺） | 待 |
| M8 | config/chaos.go querylog.clear | docs | FLOWCHARTS.md 对新增功能（MQTYPE/RFC 10029/querylog.clear/pre-packed）**零覆盖**（26 图均无） | ✅ |

其余 40 余条 MEDIUM/LOW（lrumap OnEvict 覆盖语义、注释残留、TLCP 证书、常量等）见 `raw-phase12.jsonl`，修复时逐项确认。

## 三、主题分析

1. **RFC 10029 客户端功能全线失效**（H1+H2+H4 同根因）：中间件链位置（CacheStore 内侧）、pre-packed 直发路径、EDNS 解包时序三处交互未协同。测试只覆盖 fake-next 孤立形态，未覆盖真实管线（miss/hit 双路径）。
2. **pre-packed 直发格式的协议适配不完整**（C2 + H2）：cache 层引入新格式后，DNSCrypt 加密路径与 Response 的 Unpack 路径未同步适配。
3. **H1 修复回归**（H3）：shard 重构复制了 refs.Add——上轮审计修复后的重构未回归测试（无 "refs 归零" 断言）。
4. **升级兼容性缺失**（C1）：新存储格式未做读侧兼容（0x02 标记检查），旧库直接 panic。
5. **关闭路径竞态**（M1）：H5 修复（删 proxyDialers=nil）未推广到 dnscrypt 的 cache=nil。

## 四、Sprint 行动计划

| Sprint | 范围 | 内容 |
|--------|------|------|
| **Sprint 1 (CRITICAL)** | C1, C2 | Get 格式标记兼容、DNSCrypt encrypt pre-packed 适配 |
| **Sprint 2 (HIGH)** | H1-H4 | MQTYPE 链位置/Unpack 时序/EDNS 解包、bridge refs 去重 |
| **Sprint 3 (MEDIUM+LOW)** | M1-M8 等 | dnscrypt nil 守卫、spoofguard 池归还、DialContext、FLOWCHARTS 更新 |

每 Sprint 后质量门禁：`go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt` → `go test -short ./...` → benchmark 对比基线。

## 五、未完成项（转 HANDOVER.md）

- 2/26 agent 未完成（protocol 包级 + 1 个交叉维度）
- C2 的 DNSCrypt 调用链到达性最终确认（机制已确认：Len()/Pack() 截断行为）
- M3/M5/M7 逐项核验
- 152 条原始发现的完整去重与 LOW 清单

**原始发现数据**: `docs/audit/2026-08-round2/raw-phase12.jsonl`（24 agent / 152 条）
**逐 agent 存档**: `docs/audit/2026-08-round2/agents/`（26 个文件，`01-foundation.md` ~ `26-flowcharts.md`；`03-protocol`/`25-goversion` 为未完成占位）
**人工核验笔记**: `docs/audit/2026-08-round2/_manual-verification.md`
