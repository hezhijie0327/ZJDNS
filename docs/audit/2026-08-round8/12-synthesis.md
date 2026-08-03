# 综合审计报告 — 2026-08 Round 8

审计日期: 2026-08-03
审计范围: 154 个非测试 Go 文件（+78 测试文件用于语义验证），18 个审计维度，全新从零审计（不参考历史报告）
审计方式: 7 组并行逐文件审计（14 份子报告）+ 交叉维度机械扫描 + 主审计员人工验证关键发现

## 总体概览

| 严重程度 | 数量 | 说明 |
|----------|------|------|
| **CRITICAL** | **5** | 数据损坏、panic、安全绕过、静默功能丢弃 |
| **HIGH** | **12** | 竞态、goroutine/fd 泄漏、死锁、防御失效 |
| **MEDIUM** | **38** | 维护性、边际正确性、次优分配、日志质量 |
| **LOW** | **57** | 文档、微优化、代码异味、注释 |
| **总计** | **112** | 全部必须修复（严重度决定顺序，不决定是否修复） |

## CRITICAL 发现（5 个，全部经主审计员代码验证）

| # | 位置 | 类别 | 描述 |
|---|------|------|------|
| **C1** | `server/protocol/dnscrypt/udp.go:81,88,118` | pool-corruption | **池双重归还**：三处显式 `pool.DefaultBuffer.Put(buf)` 与第 65 行 `defer` Put 叠加（闭包捕获 buf 变量）。路径 118（`isStarted()` 循环退出）在**每次优雅关停**必然触发；81/88 在关停/读错误时大概率触发。同一 8KB 缓冲进入 sync.Pool 两次 → 两个并发 `Get()` 返回同一数组 → 双写同一缓冲区 → 跨客户端 DNS 数据损坏。第 63-64 行注释声称"Single deferred Put covers every exit path"——显式 Put 本应在加 defer 时删除。修复：删除 81、88、118 行显式 Put。 |
| **C2** | `server/resolver/dnssec/trust_anchor.go:132-133` | nil-deref | `dnskey.ToDS(kd.DigestType)` 对非 SHA 摘要类型（GOST/0 等）或畸形公钥返回 **nil**，随后 `ds.Digest` 裸解引用 → **启动崩溃**。同文件 crypto.go:149-155 的 `VerifyDelegationDS` 有 `computedDS == nil` 守卫，此处遗漏。触发条件：root-anchors.xml 被篡改/损坏或 IANA 换用新摘要算法。修复：`if ds == nil { continue }`。 |
| **C3** | `server/upstream/dnscrypt/state.go:126` + `server/upstream/tlcp/http_tlcp.go:54` | nil-deref | **Close 置 nil 后查询路径无守卫**：`Client.Close()` 将 `c.cache`/`c.httpClient` 置 nil，但 `state()`/`ExecuteHTTPTLCP` 在无守卫下 `Get(key)` → nil 指针解引用 panic。触发窗口：SIGTERM 常规关停期间 in-flight 查询（DNSCrypt UDP→TCP fallback 在 GFW 环境每查询必发生，重新进入 state()）。同文件 buildState/deleteState 有守卫、tls/https.go:44 有守卫——跨协议一致性遗漏。修复：补 nil 检查（或 Close 不置 nil 改用 Clear()）。 |
| **C4** | `server/resolver/dnssec_chain.go:74-91, 415-423` | security-bypass | **根 DNSKEY 信任锚定缺失**：`isValidWithDNSSEC` 与 `isDNSSECValid` 的根域分支仅 `SelfVerifyDNSKEY`（集合内自签名即通过——攻击者自生成密钥对可平凡构造），**缺少** `ContainsRootKey` 信任锚交叉校验。`ensureZoneDNSKEYs`（:300-303）有该校验且注释自述："Without this cross-check, a MITM of the root DNSKEY query could inject a self-signed key set and forge the whole chain of trust"。三处根域验证点两处缺锚定 → MITM 根 DNSKEY 响应即伪造整条 DNSSEC 链（并 `CacheZoneKeys` 持久污染缓存）。修复：两处补 `ContainsRootKey` 检查，与 ensureZoneDNSKEYs 对齐。 |
| **C5** | `server/handler/middleware/zone.go:85` | silent-drop | **ZoneResult 无条件赋值**：第 85 行 `qctx.ZoneResult = &zoneResult` 先于所有分支执行；fall-through 路径（matched + NOERROR + 无记录 → 委托下游）带着已非 nil 的 ZoneResult → CacheStore（cache_store.go:38）跳过响应构建 → Response（response.go:32）`Res==nil` 直接返回 → **客户端静默无响应（超时）**。可达性（两条路径）：(a) 动态 zone 规则（`DynamicContent != nil`）无条件存 qtype=0 sentinel（zone.go:222-230），非配置 qtype 查询命中 sentinel；(b) 记录内容全部构建失败（如 `1 999.999.999.999`）的规则仍被 store（parse.go:66-70, wire.go:104-133）。第 81-84 行注释精确描述了此危害但与代码矛盾（git 历史显示注释加入时赋值位置未动）。修复：赋值移入两个实际构建响应的分支内。 |

## HIGH 发现（12 个）

| # | 位置 | 类别 | 描述 |
|---|------|------|------|
| **H1** | `cache/ptr.go:47-52, 87` | data-race | **PTR 索引共享切片竞态**（4 份子报告独立确认 + 主审计员验证）：`lrumap.Get` 返回的切片共享底层数组。`updatePtrIndex` 锁外 `append(old, owner)` 就地写共享数组（与 `ReverseLookup` 锁外遍历竞态；两个并发 updatePtrIndex 同一 IP 时 owner 映射互相覆盖丢失）；`cleanupPtrIndex` 的 `kept := keys[:0]` 在 Range 锁内就地压缩（锁挡不住已在锁外遍历旧切片头的 ReverseLookup）。违反 §6.1-3"修改前必须复制"。修复：`append(slices.Clone(old), owner)` + 复制式过滤。 |
| **H2** | `server/handler/pending.go:119-139` | data-race | **Done/OnEvict 竞态**（主审计员 + Foundation + Handler×2 确认）：(a) 数据竞争——淘汰恰在 `evicted.Load()==false` 检查与 `call.result = cloneQueryResult(result)`（:137，锁外）之间发生时，与 OnEvict（锁内）的 `call.result = evictedResult()`（:70）写-写竞争；(b) ABA——Get 取到淘汰后新 leader 存入的新 pendingCall，`Delete(key)` 误删新 call 并以其结果关闭，去重失效 + 结果串线。修复：`CompareAndDelete(key, call)` 替换 Get+检查+Delete（CAD 成功即保证未淘汰）。 |
| **H3** | `server/bridge.go:49-64` + `server/tasks.go:137-159` | data-race | **tcpWriteMu sweep 竞态**：LoadOrStore 创建条目（refs=0, lastAccess=0 < cutoff）与 `refs.Add(1)`（:64）之间存在窗口，清扫器（删除条件 `lastAccess < cutoff && refs == 0`）可删除该条目 → 请求在已脱离 map 的条目上写 writeMu → 下一请求重建新 writeMu → **两个写入者并发写同一 TCP 流**，长度前缀帧交错损坏。tasks.go:140-144 注释承认设计意图但保护不完整。修复：预构造 `refs.Add(1)` 的条目再 LoadOrStore；或 sweep 增加 `lastAccess != 0` 条件。 |
| **H4** | `server/defense/hopguard.go:97-99` + `server/upstream/plain/udp.go:230-235` | defense | **Feed 契约被调用方违反**（Defense×2 + POC 对照确认）：docstring 声称"仅 spoofguard 确认 clean 的 TTL 进入直方图"，但 udp.go:231 在 Validate 之前、ID 校验之前、长度检查之前**无条件 Feed**，且 :246-248 确认 clean 后**再次** Feed（双重计数，学习期减半至 ~16 样本）。GFW 固定 TTL 洪水可经 `rebuildTrusted` 晋升为 trusted 基线 → hopguard 使能的上游 UDP 永久 DoS。POC（docs/poc/hopguard/main.go:184-186）只在 `!isGFW` 时 feed——三处证据（docstring/POC/调用方）中调用方与设计相悖。修复：Feed 移到 ID 校验 + spoofguard 采纳之后。 |
| **H5** | `server/defense/poisonguard.go:167-172` | defense | **classifyTLD 误杀合法委派记录**（主审计员验证）：classifyRoot:154 有 `(NS||DS) && isTLD(name)` 委派豁免，classifyTLD 无对应分支——TLD 服务器对子域 DS 查询返回 DS 记录（标准行为）被判 `VerdictPoisoned` → 响应整体丢弃 → `verifyNoDSInParent`/`resolveZoneCut` 的 DS 查询全部失败 → **签名域 DNSSEC 链断裂 SERVFAIL**（poisonguard:true 与 DNSSEC 组合下所有签名域）。修复：`(rrtype==DS||NS) && IsSubDomain(zone, name)` 返回 Clean。 |
| **H6** | `server/protocol/tls/dtls.go:130-140` | resource-exhaustion | **DTLS 空闲连接永不关闭**（Protocol×2 + 主审计员验证）：读超时错误 `Timeout()==true` → `IsTemporaryError` true → `continue` → 重新 SetReadDeadline → 无限续期循环 → 永久占用 errgroup 槽位（限额 1024）+ goroutine + 会话存储。注释（:122-124）声称"deadline fires → connection is closed"与代码矛盾。**tlcp/dtlcp.go:321-327 已修复同类 bug**（注释自述 "a timeout was being classified as temporary and the loop spun"）。攻击者 1024 个僵尸连接 DoS 整个 TLS 协议族。修复：仿 tlcp 加 `errors.As(err,&ne) && ne.Timeout() → return`。 |
| **H7** | `server/protocol/tls/server.go:198-280` | deadlock | **Start 部分启动失败永久死锁**（主审计员验证）：errgroup 的 `g.Wait()` 等待所有 goroutine；某协议启动失败触发 ctx cancel 后，DoT/DoH/DTLS goroutine 若阻塞在无 ctx 感知的 `ln.Accept()`（tls.go:62、https.go:70、dtls.go:82），`<-ctx.Done()` 永不执行 → Wait 永不返回 → errChan 永无消息 → **进程启动失败时挂死**（DoQ/DoH3 的 `Accept(s.ctx)` 可退出，不对称）。修复：错误路径先关闭已绑定 listener 再返回。 |
| **H8** | `server/handler/middleware/response.go:77-79` | data-race | **修改共享默认 ECS 对象**（Handler×2 + 主审计员验证）：客户端无 ECS 时 `ecsOpt` 来自 `ECSForQType`（edns/ecs.go:47-73）返回的**共享单例**（atomic.Load 指针，无拷贝）；:78 `ecsOpt.ScopePrefix = ...` 每查询热路径无锁写 → 并发查询 read-write/write-write 竞态 + 跨查询污染（A 的 scope 改变 B 的缓存分区行为，RFC 7871 §7.3.1 scope=0 全局缓存被破坏）。该写还是"有害空操作"（ApplyToMessage 硬编码 Scope）。修复：`ecs := *ecsOpt; ecs.ScopePrefix = ...; ecsOpt = &ecs` 或删除该行。 |
| **H9** | `server/handler/middleware/dns64.go:86-92` | data-race | **共享 ResolutionResult 并发改写**：singleflight followers 共享同一个克隆结果（pending.go:137 只克隆一次），DNS64 中间件在各自 goroutine 中并发写 `qr.Answer/Authority/Additional/Validated`，与 CacheStore.buildSuccess 并发读竞态；同模式 cache_store.go:123 `CapValidatedTTL` 对共享 RR 头原地写 TTL（dnssec/nsec.go:474）。触发：DNS64 开启 + 并发相同 AAAA 查询（A-only 域名）。修复：改写前 per-goroutine 拷贝，或在 Done 分发时按 follower 数克隆。 |
| **H10** | `server/upstream/socks5/tcp.go:48` + 6 个调用方 | goroutine-leak | **手工 dial 路径无 I/O 期限（系统性根因）**：`socks5.DialContext` 握手后 `SetDeadline(time.Time{})` 清除全部 deadline（注释称"调用方管理 I/O 超时"），但所有调用方均未恢复：`plain/tcp.go exchangeViaProxy`、`plain/udp.go exchangeViaProxyUDP`、`tls/tls.go exchangeOverTLS`、`tlcp/tlcp.go exchangeOverTLCP`、`tls/dtls.go`（握手+读）、`tlcp/dtlcp.go`（读）——`Read` 完全不观察 ctx（net 包 Read 只在有 deadline 时响应取消）→ 停滞对端（丢包/无 RST）时**永久阻塞**，每次故障查询泄漏 goroutine + fd。9s `context.WithTimeout` 契约失效。修复模板已存在：`dnscrypt/cert.go:63-68`（AfterFunc + deadline）推广到全部 6 处。 |
| **H11** | `server/upstream/tls/http3.go:167-178` | fd-leak | **quic.Dial 失败 pconn 未关闭**：代理路径 `quic.Dial(ctx, pconn, ...)` 失败时 UDP PacketConn 泄漏。同包 quic.go:56-63 有注释"quic-go 不接管失败 dial 的 PacketConn——不要泄漏 UDP socket"并做了 `_ = pconn.Close()`，http3.go 缺失同模式。修复：错误路径照抄 quic.go 关闭。 |
| **H12** | `server/resolver/nameserver.go:43-45, 47-62` | use-after-put | **baseMsg 池消息提前归还**：`defer pool.DefaultMessage.Put(baseMsg)`（:45）先于 `cancel()`（:32）执行；`g.Go` 在 `SetLimit(min(len,6))` 下排队，主流程收到首个响应提前返回后，排队 goroutine 启动读取**已被 Put（清零或被池复用改写）**的 baseMsg → 向权威服务器发送空 Question 或跨查询数据（**跨查询数据泄露**）。根服务器（26 地址）路径必现。修复：Put 移入 g.Wait 之后的 goroutine，或每个 goroutine 从不可变 question 构造消息。 |

## 按包组分布

| 包组 | CRITICAL | HIGH | MEDIUM | LOW | 总计 |
|------|----------|------|--------|-----|------|
| Foundation（internal/*，35 文件） | 0 | 1* | 8 | 11 | 20 |
| Domain（config/cache/edns/zone/ruleset/stats，24 文件） | 0 | 1* | 8 | 25 | 34 |
| Protocol（server/protocol/*，22 文件） | 1 | 2 | 13 | 11 | 27 |
| Upstream（server/upstream/*，24 文件） | 1 | 3 | 9 | 9 | 22 |
| Resolver（server/resolver/*，17 文件） | 2 | 1 | 5 | 3 | 11 |
| Handler（server/handler/*，16 文件） | 1 | 3 | 6 | 10 | 20 |
| Defense+Server+CLI（16 文件） | 0 | 2 | 4 | 14 | 20 |
| 交叉扫描（Phase 2，跨包） | 0 | 1* | 2 | 2 | 5 |
| **合计（去重后）** | **5** | **12** | **38** | **57** | **112** |

\* H1/H2 跨 Domain+Foundation，统计在主要归属组。

## 系统性根因模式

### 1. 共享可变状态跨并发写（3 CRITICAL/HIGH 同源）
H1（PTR 切片共享底层数组）、H2（pendingCall.result 锁外写）、H8（共享 ECS 单例写）、H9（singleflight 共享结果原地改写）——项目已有"克隆"意识（cloneQueryResult、slices.Clone 契约），但共享边界之后的消费方仍原地改写。**修复纪律：从 lrumap.Get / atomic.Load / singleflight 分发取出的对象，任何字段写之前必须先拷贝。**

### 2. 池归还纪律（C1 + 2 MEDIUM）
dnscrypt/udp.go 加 defer 时未删旧显式 Put（注释已声明意图）；protocol 四处的 response==query 身份未一致处理（quic.go 有守卫但顺序错——先 Put 后 Pack；tls.go 双 defer 无守卫；dtls.go/dtlcp.go Put(query) 先于 sendXxxResponse）；resolver 的 baseMsg 共享 + 提前 Put（H12）；nameserver 第二个成功响应滞留缓冲通道。**修复纪律：先响应后 Put；身份守卫；单一所有权。**

### 3. 防御算法状态机（H4 + H5）
hopguard 的"仅 clean 内容入直方图"契约被调用方无门控 Feed + 双重 Feed 破坏；poisonguard 的 classifyTLD 缺委派豁免（classifyRoot 有）。**修复后必须补测试：hopguard "GFW TTL 不进入直方图"、poisonguard "TLD 返回子域 DS → Clean"。**

### 4. 注释与代码脱节（C4、C5、H4、H6）
四处注释精确描述了正确设计而代码从未实现/已偏离：zone.go:81-84（"ZoneResult is set ONLY on the branches..."）、hopguard.go:97-99（"Only trusted DNS content..."）、dtls.go:122-124（"deadline fires → connection is closed"）、dnssec_chain.go:296-299（"Without this cross-check..."——该处另一分支有实现）。**根因：安全/不变量声明写在注释里却没有以代码形式强制执行。**

### 5. 跨协议一致性（H6、H7、H10、H11、C3）
同一缺陷在多个协议处理器中重复出现，且对照实现已修复：tlcp/dtlcp.go 修了超时循环而 tls/dtls.go 漏；quic.go 修了 pconn 泄漏而 http3.go 漏；https.go 有 nil 守卫而 tlcp/http_tlcp.go、dnscrypt/state.go 漏；tls.go 系有 accept 退避而 dtls.go、dnscrypt/tcp.go 漏。**修复纪律：修复一个协议 bug 后，全局搜索同模式到所有协议处理器。**

### 6. Close 置 nil 竞态（C3）
upstream/client.go:312-315 已确立"不置 nil、靠 lrumap 并发安全"的正确模式，三个子客户端（tls/tlcp/dnscrypt）未遵循。**修复纪律：Close 只清资源（Range+CloseIdleConnections），不置 nil 字段。**

### 7. 热路径分配与日志刷屏（MEDIUM 群）
zone exactKey 每查询最多 34 次 Sprintf、edns padding 双重 Pack + CSPRNG、cache ecsFallbackCandidates 每查询切片、root_hints 文件缺失每查询 Error、warmup 无效 proxy 每查询 Warn、dns64 A 查询失败每查询 Warn——违反"每查询一条日志"与零分配纪律。

### 8. 存储层专项
lrumap 整体质量高（OnEvict 锁内调用契约、LoadOrStore、权重预算、版本门禁 + .bak + 原子写均正确），但暴露三个问题：(a) 派生索引的读-改-写非原子（H1——lrumap 无原子 Update API，需调用方克隆）；(b) OnEvict 在写锁内执行 O(索引规模) 全表扫描（store.go:93 → ptr.go:86，MEDIUM）；(c) `load()` decode 中途失败不备份且保留部分状态（与 zstd 损坏/版本不匹配三个路径的 Backup 行为不一致，MEDIUM）。

## 修复路线图

### Sprint 1 — CRITICAL（5 个，立即修复）
| # | 修复 | 工作量 |
|---|------|--------|
| C1 | 删 dnscrypt/udp.go 三处显式 Put（单行级） | S |
| C2 | trust_anchor.go 补 `ds == nil` 检查（单行级） | S |
| C5 | zone.go 赋值移入两个响应分支（约 10 行） | S |
| C4 | dnssec_chain.go 两处补 ContainsRootKey（约 10 行） | M |
| C3 | state.go/http_tlcp.go 补 nil 守卫（单行级 ×2） | S |

### Sprint 2 — HIGH（12 个，下个发布周期）
1. H1 ptr.go 克隆修复（slices.Clone ×2）—— 附 -race 测试
2. H2 pending.go CompareAndDelete —— 附并发测试
3. H6 dtls.go 超时检查（对照 tlcp 单行）
4. H10 无期限 I/O：抽 `setConnDeadline(ctx, conn)` 辅助函数推广 6 处（以 dnscrypt/cert.go 为模板）
5. H12 nameserver.go baseMsg 生命周期重排
6. H4 hopguard Feed 门控
7. H5 poisonguard classifyTLD 委派豁免
8. H8/H9 共享对象拷贝（ECS、ResolutionResult）
9. H3 bridge sweep 竞态（预构造 refs 或 lastAccess 守卫）
10. H11 http3 pconn 关闭
11. H7 tls/server.go Start 错误路径关 listener

### Sprint 3 — MEDIUM + LOW（95 个，后续）
按 §7 系统性根因分批：日志降级/去重、常量提取、文档同步（含 FLOWCHARTS.md 域名重写描述）、`_` 丢弃注释补全、死代码删除（zone rewrite 机制、ErrDrop、detectRequestProtocol、statsSaver.file、Server.stats/cacheStore、dns64 ExtractIPv4 等）、lrumap load 备份对齐、stamp 编码长度校验、persist 解压上限、dtls_session Get 深拷贝、nsec rrset key 对齐 rrsetKey 等。

## 质量门禁（修复后）

- [ ] `go build ./...` 零编译错误
- [ ] `go fix ./... && golangci-lint run && golangci-lint fmt` 零警告
- [ ] `go test -short ./...` 全部通过
- [ ] `go test -race ./server/...` 零竞态（H1/H2/H8/H9 修复验证）
- [ ] Benchmark 回归检测：`go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt`，对比旧基线 >15% 变慢即回归
- [ ] 新测试：hopguard 喂入语义、poisonguard TLD DS、PTR 并发 -race、pending 淘汰并发、DTLS 空闲超时、zone 动态规则非配置 qtype、DNSCrypt 关停无双重归还
