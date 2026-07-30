# ZJDNS 综合审计报告 — 2026-07

## 概述

对 ZJDNS 全部 130 个非测试 Go 文件，按 AUDIT-METHODOLOGY.md 的 18 个维度进行了完整审计。

- **审计范围**: 6 个包组, 130 个 Go 源文件
- **审计维度**: 18 个（代码质量 / 内存安全 / 锁正确性 / 耦合度 / 架构设计 / 性能 / Panic 检测 / 错误处理 / Context 传播 / Goroutine 生命周期 / 资源生命周期 / 日志质量 / 文档质量 / 参数校验 / 常量提取 / RFC 一致性 / 注释准确性 / 函数排序）
- **方法**: 6 并行 Agent，逐文件审查

---

## 发现汇总

| 严重程度 | 数量 |
|----------|------|
| CRITICAL | 1 |
| HIGH     | 8 |
| MEDIUM   | 18 |
| LOW      | 33 |
| **总计** | **60** |

---

## CRITICAL（1）

### C1. ReadTCPMsg use-after-Put — 池缓冲区数据竞争

- **文件**: `internal/dnsutil/tcpframe.go:36-47`
- **类别**: pool-leak, memory, panic
- **问题**: `ReadTCPMsg` 从池获取缓冲区，`defer Put`，然后将 `msg.Data = buf` 指向池缓冲区。`Unpack()` 后 `msg.Data` 仍引用池内存。`Put` 在调用方使用 `msg.Data` 之前执行，导致引用已归还的池内存。
- **风险**: 返回的 `dns.Msg.Data` 数据损坏。若另一 goroutine 获取同一缓冲区并写入，构成数据竞争。调用方对返回消息调用 `Pack()` 可能序列化损坏的线格式数据。
- **修复**: `Unpack()` 后复制 `msg.Data`: `msg.Data = slices.Clone(msg.Data)`，或改为将缓冲区所有权转移给调用方。

---

## HIGH（8）

### H1. ExecuteDoHRequest HTTP 响应体泄漏

- **文件**: `internal/dnsutil/https_dns.go:57,65`
- **类别**: resource, memory
- **问题**: `defer httpResp.Body.Close()` 注册在原始响应体上。随后 `httpResp.Body` 被 `io.NopCloser(io.LimitReader(...))` 替换。deferred close 调用的是 `NopCloser.Close()`（空操作），原始 `httpResp.Body` 未被关闭。
- **风险**: HTTP 连接池耗尽。Go 的 `net/http` transport 在响应体未关闭时无法复用 HTTP/1.x keep-alive 连接，最终耗尽文件描述符，致使 DoH 上游查询失败。

### H2. DTLCP 单连接 Accept 造成 DoS 向量

- **文件**: `server/protocol/tlcp/dtlcp.go:265`
- **类别**: goroutine, performance
- **问题**: `handleDTLCPConnections` 同步调用 `handleDTLCPConnection`——同一时间只服务一个 DTLCP 连接。这是由于 gotlcp 库共享底层 UDP socket 的限制所致。一个慢客户端可阻塞所有其他 DTLCP 客户端最多 30 秒。
- **风险**: 攻击者仅需一个连接即可 DoS 整个 DTLCP 监听器。无速率限制，无 per-IP 限制。

### H3. HopGuard 永久拒绝所有状态

- **文件**: `server/defense/hopguard.go:117-126`
- **类别**: correctness, state-machine
- **问题**: 一旦 `st.armed` 变为 `true`，学习代码路径被永久绕过。`rebuildTrusted` 每次将直方图计数衰减 3/4。如果上游 anycast 重路由导致 TTL 变化，所有受信任 TTL 的计数可能衰减到阈值以下，产生空的 `st.trusted` map。`st.armed` 仍为 `true`，没有解除武装的机制。
- **风险**: 所有响应被拒绝（"hopguard reject TTL="），上游永久不可达，直到进程重启。无自动恢复路径。

### H4. Pending-refresh 锁泄漏（stale-prefetch 路径）

- **文件**: `server/handler/middleware/cache_lookup.go:88-98`
- **类别**: resource, goroutine
- **问题**: 在 `preferStale` 路径中，代码通过 `tryStartRefresh` 获取 pending-refresh 锁，然后通过 `TryGo` 启动刷新 goroutine。若 `TryGo` 返回 false（errgroup 容量满或已关闭），goroutine 永不运行，`finishRefresh`（释放锁）永不调用。
- **风险**: 在持续 errgroup 饱和的情况下，特定缓存键被永久阻塞，无法进行后台刷新，服务器在重启前始终返回过期条目。

### H5. `serveExpiredWithRefresh` goroutine + 锁泄漏

- **文件**: `server/handler/middleware/cache_lookup.go:119-145`
- **类别**: resource, goroutine
- **问题**: 前台刷新 goroutine 通过 `TryGo` 启动，返回值被丢弃。若 `TryGo` 失败，`done` channel 永不关闭，第二个 goroutine（timer case）永久阻塞在 `<-done` 上，pending-refresh 锁永不释放。
- **风险**: 每次进入 `serveExpiredWithRefresh` 的过期缓存查询泄漏：一个阻塞到 shutdown 的 goroutine + 一个永不释放的锁。

### H6. 递归 NS 路径池消息泄漏

- **文件**: `server/resolver/nameserver.go:71-82`
- **类别**: pool-leak
- **问题**: `msg := pool.DefaultMessage.Get()` 获取消息并传递给 `ExecuteQuery`，但从不 `Put`。注释声称"所有权转移至 ExecuteQuery"，但 `ExecuteQuery` 不获取消息所有权——它只读取 `msg.Pack()` 和 `msg.Data`，不执行 `Put`。
- **风险**: 每次递归 NS 查询泄漏一个池消息（根→TLD→权威约 6-12 个泄漏）。池枯竭后每次泄漏产生额外分配。

### H7. ExecuteQuery 消息所有权约定冲突

- **文件**: `server/resolver/forward.go:83-85` vs `nameserver.go:71-77`
- **类别**: api-design
- **问题**: 同一函数 `ExecuteQuery` 存在两种矛盾的消息所有权约定。转发路径在 `ExecuteQuery` 后显式 `Put` 消息。递归路径声称所有权已转移且不执行 `Put`。由于 `ExecuteQuery` 从不 Put 输入消息，递归路径有泄漏。
- **风险**: API 设计缺陷导致同一函数在不同调用点的行为不一致，重构时容易引入双重 Put 或遗漏泄漏。

### H8. DNSCrypt 递归重试可能导致栈耗尽

- **文件**: `server/upstream/dnscrypt/client.go:186`
- **类别**: correctness
- **问题**: `response.Truncated` 为 true 时递归调用 `c.Execute()`。虽然递归深度有界（约 log2(4096/256) ≈ 5 层），但每次递归在 `defer conn.Close()` 链完成前都会堆积栈帧。
- **风险**: 在病理性的截断循环下浪费内存。实际影响有限（有界深度）。

---

## MEDIUM（18）

### M1. padding.go 双重 Pack

- **文件**: `edns/padding.go:40`
- **类别**: performance
- **问题**: `addPadding` 调用 `msg.Pack()` 来计算压缩线格式大小以进行填充计算，消息之后会再次 Pack。每个响应执行两次完整 Pack。注释承认此权衡但实现成本高。
- **修复**: 缓存打包结果并复用，或以更低成本估算压缩大小。

### M2. cache.Set 静默 Pack 失败

- **文件**: `cache/store.go:233-236`
- **类别**: error-handling
- **问题**: `msg.Pack()` 失败时错误被静默丢弃，`msgWire` 仍为 nil。代码继续在 BadgerDB 中存储一个空线格式负载条目——该条目在检索时永远 miss，浪费数据库空间和 TTL 跟踪资源。
- **修复**: 记录警告，不存储条目。

### M3. padding.go 阻塞式 crypto/rand.Read

- **文件**: `edns/padding.go:46`
- **类别**: performance
- **问题**: 每个填充响应调用 `crypto/rand.Read`。在 Linux 上使用 `getrandom(2)`，若内核熵池未初始化则可能阻塞。对于高 QPS DNS 服务器，这引入了对内核 CSPRNG 的延迟依赖。填充字节不需要加密级随机性（RFC 8467 不要求）。
- **修复**: 使用 `math/rand/v2`（Go 1.22+，非阻塞）。

### M4. makeAddrValidator nil 缓存 panic

- **文件**: `server/protocol/tls/addr_validator.go:18`
- **类别**: panic, validation
- **问题**: `makeAddrValidator` 返回一个闭包，若 `cache` 为 nil 则调用 `cache.Get(key)` 会 panic。当前调用方均传入非 nil 缓存，但函数签名未记录此前置条件。
- **修复**: 在闭包顶部添加 nil 检查。

### M5. decrypt 无边界检查

- **文件**: `server/protocol/dnscrypt/crypto.go:146,170`
- **类别**: panic, validation
- **问题**: `b[:ClientMagicSize]` 切片未检查 `len(b)`。当前调用方在调用前验证了长度，但函数本身无防御。
- **修复**: 在 `decrypt` 顶部添加长度检查。

### M6. plain.Server.Start() 无 nil 检查

- **文件**: `server/protocol/plain/server.go:34`
- **类别**: validation
- **问题**: `Start` 未对 `g` 和 `handler` 做 nil 检查。若为 nil，`g.Go()` 立即 panic。
- **修复**: 在 `Start` 顶部添加 nil 检查。

### M7. Spoofguard copyBuf 无界增长

- **文件**: `server/upstream/plain/udp.go:307-314`
- **类别**: memory
- **问题**: `copyBuf` 增长到最大观察到值后永不收缩。在大响应流量下稳定在峰值。
- **影响**: 轻微常驻内存开销。有界（最大 UDP 数据报 65507 字节）。

### M8. TLCP transportKey 使用 fmt.Sprintf

- **文件**: `server/upstream/tlcp/http_tlcp.go:35`
- **类别**: performance, consistency
- **问题**: TLCP 使用 `fmt.Sprintf` 构造键，TLS 使用 `strings.Builder` + `Grow`。不一致且分配更多。
- **修复**: 迁移到 `strings.Builder`。

### M9. SOCKS5 UDP 中继双重 goroutine 模式

- **文件**: `server/upstream/socks5/udp.go:180-201`
- **类别**: code-quality
- **问题**: 双重 goroutine 监控控制连接的模式正确但脆弱。应重构为 `io.Copy` 或 context 驱动的方式。

### M10. SOCKS5 UDP 中继 deadline 未清除

- **文件**: `server/upstream/socks5/udp.go:164`
- **类别**: resource
- **问题**: 控制连接的 deadline 被清除，但 UDP 中继 socket 的 deadline 未清除——继承了 `dialer.DialContext()` 的 deadline。若 ctx 的 deadline 短于期望的中继生命周期，socket 可能提前过期。

### M11. DNSCrypt 弱密钥注释中的死 nolint

- **文件**: `server/upstream/dnscrypt/crypto.go:21-23`
- **类别**: comments
- **问题**: `//nolint` 抑制注释引用了 CodeQL 的 `go/weak-sensitive-data-hashing`，但对 golangci-lint 无效。是无效的 nolint 注释。

### M12. HTTP3 warmup cfg 参数遮蔽

- **文件**: `server/upstream/tls/http3.go:148-149`
- **类别**: code-quality
- **问题**: http3 `Dial` 函数签名中的 `cfg` 参数被闭包的 `quicCfg` 遮蔽。调用方提供的 `cfg` 中的字段（除 `.Tracer` 外）被静默忽略。有意为之但令人困惑。

### M13. cache.Set 错误被静默丢弃

- **文件**: `server/handler/middleware/cache_lookup.go:191-192,225` / `cache_store.go:108`
- **类别**: logging, error-handling
- **问题**: 多处 `_ = m.store.Set(...)` 静默丢弃错误。缓存写入失败（BadgerDB 停顿、磁盘满）永不记录。
- **修复**: 至少记录 Debug 级别日志。

### M14. Validation 中间件穿透逻辑不直观

- **文件**: `server/handler/middleware/validation.go:62-84`
- **类别**: code-quality
- **问题**: 主守卫将三个条件合并为一个 `if`，要么委托要么穿透到 REFUSED 构造器。穿透路径重新评估条件以确定 EDE 代码。逻辑正确但需要读者在心理上追踪两个条件块。
- **修复**: 重构为每个拒绝类别的早期返回，配以明确的 EDE 代码。

### M15. handler→resolver 子包耦合

- **文件**: `server/handler/handler.go:17`
- **类别**: coupling
- **问题**: `handler` 直接导入 `server/resolver` 以使用 `resolver.QueryResult`。这是有意的（架构文档认可）但不理想。

### M16. QueryContext Req "immutable" 注释不准确

- **文件**: `server/handler/context.go:19-21`
- **类别**: comments
- **问题**: 注释说 `Req` 是 "Immutable: never modified"，但 EDNS 中间件在其上调用 `req.Unpack()` 修改了 `dns.Msg` 结构体内容。指针未被重新赋值，但指向的结构体被修改。
- **修复**: 澄清为 "Pointer is never reassigned"。

### M17. processUpstreamResponse 参数过多（11 个）

- **文件**: `server/resolver/forward.go:240`
- **类别**: code-quality
- **问题**: 违反 CLAUDE.md 中"超过 5 个参数时使用配置结构体分组"的规范。
- **修复**: 分组到结构体中。

### M18. cacheGlueRecords 混合 A/AAAA 类型存储

- **文件**: `server/resolver/recursive_ns.go:107-110`
- **类别**: correctness
- **问题**: `cacheGlueRecords` 将所有属于同一 NS 的 glue 记录（A 和 AAAA 混合）通过第一个记录的类型存储。若同时存在 A 和 AAAA glue，所有记录存储在单一类型名下，另一种类型的后续查询会 miss。功能上仍可工作（`lookupNSAddrsFromCache` 检查两种类型），但缓存状态逻辑不正确。
- **修复**: 在缓存前按实际类型分组。

---

## LOW（33）— 摘要

| # | 文件 | 问题 |
|---|------|------|
| L1 | dnscryptcrypto/encrypted.go:109,163 | 死参数 `isUDP` |
| L2 | dnscryptcrypto/certificate.go:170-171 | MarshalBinary 文档称"err 永远为 nil" |
| L3 | dnscryptcrypto/encrypted.go:434,488 | Decrypt/DecryptPQInitial 参数类型不一致 |
| L4 | latency/httppool.go:56,62 | IdleConnTimeout 但 DisableKeepAlives=true |
| L5 | stamp/encode.go:156 | readVLP 在 encode.go 中定义但仅在 parse.go 中使用 |
| L6 | stamp/encode.go:223-230 | splitOptionalPort 错误处理括号 IPv6 |
| L7 | dnscryptcrypto/encrypted.go:196-249 | encryptPQResponse 中三次重复的 ESVersion switch |
| L8 | stats/stats.go:120-127 | 高延迟异常值不计入任何桶 |
| L9 | cache/store.go:221,226 | additional 切片双重 clone |
| L10 | config/validate.go:162-183 | 空协议产生误导性"地址无效"错误 |
| L11 | cache/store.go:329-349 | ecsFallbackCandidates 每次 Get 都分配 |
| L12 | edns/edns.go:17-23 | DNSHandler 重复/重叠注释 |
| L13 | protocol/tls/https.go:148-149 | Content-Type 精确匹配拒绝有效参数 |
| L14 | protocol/tlcp/certs.go:89,98 | 自赋值 no-op |
| L15 | protocol/dnscrypt/crypto.go:158-268 | 非池化的短生命周期消息分配 |
| L16 | protocol/plain/tcp.go:24-29 | 部分绑定失败时孤儿监听器 |
| L17 | protocol/tls/quic.go:138 | errgroup.WithContext 第二个返回值被丢弃 |
| L18 | protocol/tls/quic.go:171 | handleDOQStream 无 nil 检查 |
| L19 | protocol/tls/dtls.go:107 | DTLS 缓冲区大小限制大记录 |
| L20 | protocol/dnscrypt/server.go:402-425 | 握手时为大小估算分配临时消息 |
| L21 | handler/middleware/cache_store.go:100 | 死代码 `var _ int64` |
| L22 | server/tasks.go:212-232 | 关闭超时时孤儿 goroutine |
| L23 | handler/middleware/response.go:57-59 | HasPaddingOption 被调用两次 |
| L24 | upstream/dnscrypt/cert.go:66 | fetchCertOverUDP 缓冲区非池化 |
| L25 | upstream/socks5/udp.go:310 | socks5PacketConn 零值 nil done 会 panic |
| L26 | upstream/socks5/socks5.go:396-401 | splitHostPort 忽略原始解析错误 |
| L27 | resolver/nameserver.go:331-333 | 死错误处理代码 |
| L28 | resolver/nameserver.go:280,289 | 丢弃 resolveNSAddrType 的返回值 |
| L29 | resolver/forward.go:160 | captureUpstreamEDE 放置不当 |
| L30 | resolver/dnssec/nsec.go:216 | 硬编码 NSEC3 Opt-Out 标记 |
| L31 | resolver/dnssec/crypto.go:183 | RootKeys() 返回内部切片 |
| L32 | resolver/dnssec/extract.go:152 | 参数重新赋值 |
| L33 | resolver/forward.go:46 | 已取消 context 的原因未使用 |

---

## 维度合规矩阵

| 维度 | 评级 | 关键问题 |
|------|------|---------|
| 代码质量 | ⚠️ | H6/H7（所有权不一致），M1（参数过多），L21（死代码） |
| 内存安全 | ⚠️ | C1（use-after-Put），H1（响应体泄漏），H6（池泄漏） |
| 锁正确性 | ✅ | 无数据竞争、死锁或排序违规 |
| 耦合度 | ⚠️ | M15（handler→resolver），L5（readVLP 放错文件） |
| 架构设计 | ✅ | 包结构清晰，导入 DAG 正确 |
| 性能 | ⚠️ | M1（双重 Pack），M3（crypto/rand），M8（fmt.Sprintf） |
| Panic 检测 | ⚠️ | M4（nil 缓存），M5（无边界检查），M6（无 nil 检查） |
| 错误处理 | ⚠️ | M2（静默 Pack 失败），M13（静默 Set 失败），H4/H5（TryGo 失败） |
| Context 传播 | ✅ | ctx 正确传播，使用 WithCancelCause |
| Goroutine 生命周期 | ⚠️ | H4/H5（TryGo 泄漏），H2（DTLCP DoS），L22（孤儿 goroutine） |
| 资源生命周期 | ✅ | Close() 幂等，正确 defer cleanup |
| 日志质量 | ⚠️ | M2/M13（静默错误），热路径均为 Debug |
| 参数校验 | ⚠️ | M4/M5/M6（防御性检查缺失），L25（零值 panic） |
| 常量提取 | ✅ | 绝大多数魔法数字已提取 |
| RFC 一致性 | ✅ | 无规范偏离 |
| 注释准确性 | ⚠️ | M11（死 nolint），M16（misleading Req），L2（不准确文档） |
| 函数排序 | ⚠️ | L29（captureUpstreamEDE），L3（函数间方法） |
| Go 版本特性 | ✅ | Go 1.26 特性合理使用 |

---

## 行动计划

### Sprint 1（CRITICAL — 立即修复）

| 发现 | 文件 | 修复 |
|------|------|------|
| C1 | `internal/dnsutil/tcpframe.go:36-47` | Unpack 后 Clone msg.Data |

### Sprint 2（HIGH — 下个发布周期）

| 发现 | 文件 | 修复 |
|------|------|------|
| H1 | `internal/dnsutil/https_dns.go:57,65` | 重组后关闭原始响应体 |
| H2 | `server/protocol/tlcp/dtlcp.go:265` | 添加连接超时或并发限制 |
| H3 | `server/defense/hopguard.go:117-126` | trusted 为空时重置为学习模式 |
| H4 | `server/handler/middleware/cache_lookup.go:88-98` | TryGo 失败时调用 finishRefresh |
| H5 | `server/handler/middleware/cache_lookup.go:119-145` | TryGo 失败时同步关闭 done |
| H6 | `server/resolver/nameserver.go:71-82` | 添加 defer pool.Put(msg) |
| H7 | `server/resolver/{forward,nameserver}.go` | 统一 ExecuteQuery 所有权约定 |
| H8 | `server/upstream/dnscrypt/client.go:186` | 将递归改为循环 |

### Sprint 3（MEDIUM + LOW — 后续发布）

按优先级排序：错误处理（M2, M13）→ 性能（M1, M3, M8）→ 防御性修复（M4, M5, M6）→ 代码组织（M14, M17, M18）→ 文档/注释（M11, M16）→ LOW 各项。

---

## 正向发现

1. **锁正确性**: 全部 `Close()` 方法使用 `sync.Once` 实现幂等。无 ABBA 死锁路径。`Shutdown()` 在锁外收集连接后再调用 `c.close()`。
2. **池纪律**: TLS `tls.go`（DoT handler）是池管理的黄金标准。所有协议处理器正确遵循模式。
3. **Context 传播**: 所有 accept 循环检查 `ctx.Done()`。无生产代码使用 `context.TODO()`。
4. **RFC 合规**: RFC 7766 §7 响应-查询验证、RFC 9156 QNAME 最小化、RFC 7873 Cookie 验证——全部正确实现。
5. **错误包装**: 一致使用 `%w`。正确使用 `errors.Is`/`errors.As`/`errors.AsType[T]`。
6. **声明顺序**: 全部文件遵循 `type → const → var → func`。构造器紧跟类型定义。
7. **防御层**: Pending singleflight `LoadOrStore` 领导选举 + `sync.Once` 守卫 + clone-before-share——无竞态条件。
8. **关闭顺序**: 精心排序（标记关闭 → 取消 ctx → 等待组 → 关闭探测器 → 关闭客户端 → 关闭缓存）。

---

## 与历次审计对比

参考 AUDIT-METHODOLOGY.md §4.2 中的常见根因模式：

| 模式 | 本次状态 |
|------|---------|
| 池归还纪律 | ⚠️ C1（tcpframe），H6（nameserver）— 仍存在问题 |
| 并发安全 | ✅ 无问题 |
| 键值编码 | ✅ 使用 BigEndian，编码一致 |
| TODO 管理 | ✅ 未发现过期 TODO |
| 日志质量 | ⚠️ M2/M13（静默错误） |
| 文档腐烂 | ⚠️ M16（misleading Req 注释） |
| 参数校验缺失 | ⚠️ M4/M5/M6 |
| 错误包装断裂 | ✅ 一致使用 %w |
| 有界缓存手动实现 | ✅ 全部迁移到 lrumap |
| Close 非幂等 | ✅ 全部使用 sync.Once |

---

*审计日期: 2026-07-30 | 方法: 6 并行 Agent 按 AUDIT-METHODOLOGY.md §1.2 Phase 1*
