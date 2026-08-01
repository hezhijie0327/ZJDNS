# 2026-08 Open Code Review — 修复计划

来源: `01-open-code-review-report.md` — 193 文件, 384 条评论, ~2h9m OCR 深度审查。

## 严重度分布

| 严重度 | 数量 | 说明 |
|--------|------|------|
| CRITICAL | 2 | DTLCP 握手无超时; Offline-KSK 绕过密码学认证 |
| HIGH | 78 | 65 bug + 13 security |
| MEDIUM | 181 | 140 bug + 20 security + 14 maintainability + 1 perf + 1 test + 其他 |
| LOW | 123 | 59 maintainability + 47 bug + 8 perf + 4 security + 4 doc + 5 other |

## 修复原则

1. **全部修复, 无一跳过** (CLAUDE.md §0) — 严重度只决定调度顺序。
2. **按批次提交**, 每批独立可验证, 先提交安全类, 后功能性, 最后工具链/文档。
3. 每批完成后: `go build ./... && go test ./... -short && go fix ./... && golangci-lint run && golangci-lint fmt`。
4. 提交信息遵循现有风格 (`fix: ...` / `refactor: ...`), 批量提交前呈现给用户审查。
5. 修复后逐条对照报告回查, 确保无遗漏。

---

## 批次 1 — 安全 CRITICAL (先行, 单独提交)

### 1a. DTLCP 握手无期限 → 单客户端永久阻塞整个 DTLCP 服务
- **报告位置**: `server/protocol/tlcp/dtlcp.go:180-181` [security · critical]
- **修复**: `readFirstDatagram` 消费首包后, 在 `conn.Handshake()` 前对 `bpc`/共享 socket 设置握手 deadline (如 `DefaultDTLSIdleTimeout`), `defer conn.SetDeadline(time.Time{})` 清除。
- **验证**: 测试一个只发 ClientHello 后静默的客户端不会挂起 accept 循环。

### 1b. Offline-KSK 回退绕过 DNSSEC 密码学认证
- **报告位置**: `server/resolver/dnssec_chain.go:188-193` [security · critical]
- **修复**: 移除或严格改造 `verifyOfflineKSK` 路径 — CDS/CDNSKEY 响应未做 RRSIG 验证, 16-bit key tag 碰撞 (2^16) 即可伪造。要求: (a) 验证 CDS/CDNSKEY 的 RRSIG 且签名者本身经认证; (b) 或直接删除回退。`isDNSSECValid` 中 `rrsigKeyTagMatchesDS && r.verifyOfflineKSK` 分支同步处理。
- **验证**: 单测 — 伪造 key tag 碰撞 + 重放公共 DS digest 的响应必须判 bogus。

**提交**: `fix: security — DTLCP handshake deadline + remove offline-KSK crypto bypass`

---

## 批次 2 — DNSSEC 信任链完整性 (server/resolver/dnssec/*, dnssec_chain.go, zonecut.go)

报告 Top Issue #1: "DNSSEC 校验可以把未认证/伪造数据认证为有效"。约 22 条。

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 2.1 | `dnssec/validate.go:21-25` | HIGH | 移除"存在 DNSSEC 记录即 validated"回退 — 只有 `IsResponseValid` 可确认; AD 位伪造同样不可信 |
| 2.2 | `dnssec_chain.go:123-126` | HIGH | 无 DS 时要求认证过的 NSEC/NSEC3 否定证明才能判 insecure; 用哨兵错误区分 bogus/insecure, 不折叠为 (false,nil) |
| 2.3 | `dnssec_chain.go:504` | HIGH | `Recursive.lastEDECode` 数据竞争 → 改为随 `dnssecChain`/`QueryResult` 传递, 删除 `DNSSECEDECode()` 的共享读 |
| 2.4 | `dnssec_chain.go:227-230` | MEDIUM | 删除 `parentDNSKEYs` 回退 (只在 root→TLD 首层正确) 或在验证前从 `zoneDNSKEYs` 更新 |
| 2.5 | `dnssec/crypto.go:128-131` | MEDIUM | DS 匹配与 SelfVerifyDNSKEY 不要求 SEP 位; 遍历所有 key, SEP 仅作 tie-break |
| 2.6 | `dnssec/crypto.go:297-303` | HIGH | `anyValidated` → 要求所有 RRset 验证成功; 无 RRSIG 的 RRset 判失败 (RFC 6840 §4.1 清 AD) |
| 2.7 | `dnssec/crypto.go:108-111` | LOW | VerifyRRset 增加 `RRSIG.SignerName == DNSKEY owner` 显式检查 |
| 2.8 | `dnssec/nsec.go:342-344` | HIGH | Opt-Out 证明是**有效**的 (RFC 5155 §9.2 只抑制 AD 位) — 返回成功并抑制 AD, 不返回 ErrBogusSignature; 只检查证明实际用到的 NSEC3 |
| 2.9 | `dnssec/nsec.go:318-320` | MEDIUM | 不静默改写 iterations (改了哈希输入永远不匹配) — 返回明确"不支持的 NSEC3 参数"错误, fail closed |
| 2.10 | `dnssec/nsec.go:237` | MEDIUM | 检查 next-closer 覆盖记录的 Opt-Out Flags; 按 §8.4/§8.5 过滤 |
| 2.11 | `dnssec/nsec.go:66-70` | MEDIUM | NSEC NODATA 增加通配符祖先 case: owner 为 `*.`+ancestor 且 bitmap 无 QTYPE/CNAME |
| 2.12 | `dnssec/extract.go:165-170` | MEDIUM | 删除死代码 TTL 循环, 在 Set 前对 key 副本 clamp TTL 到 DefaultDNSKeyCacheTTL |
| 2.13 | `dnssec/extract.go:198` | LOW | trust anchor 返回深度拷贝 (`k.Clone()`), 不共享 `c.rootKeys` 指针 |
| 2.14 | `dnssec/extract.go:43` | LOW | 用 `dns.IsSubDomain` 双向比较替代 `strings.EqualFold` (处理转义/大小写) |
| 2.15 | `dnssec/extract.go:149-153` | MEDIUM | NSEC lower==upper (Next Domain == owner) 时按 RFC 4034 §4.1 处理: `return loName != 0` |
| 2.16 | `dnssec/trust_anchor.go:68-69` | MEDIUM | 解析 `ValidFrom`, 未到期 key 跳过; `ValidUntil` 解析失败 fail closed |
| 2.17 | `dnssec/trust_anchor.go:98-99` | LOW | 校验 `dnskey.KeyTag() == kd.KeyTag` 且 DS digest 与重建 key 匹配, 不符则拒绝 |
| 2.18 | `zonecut.go:37-43` | HIGH | signer == fqZone 视为 in-zone (`dns.EqualName || IsBelow`), 否则 in-zone 记录全被剥离 |
| 2.19 | `zonecut.go:156-164` | HIGH | 缓存/使用子域 DNSKEY 集前用 DS 匹配的 key 做 `SelfVerifyDNSKEY` 验证整个 RRset 自签名 |
| 2.20 | `zonecut.go:96-97` | HIGH | DS 向 parent 侧服务器查询 (并要认证否定), DNSKEY 向 child 侧查询 — 不能同侧 |
| 2.21 | `zonecut.go:68-71` | MEDIUM | 选择**最深**祖先 signer 而非第一个 (混合签名响应时第一个可能错) |
| 2.22 | `zonecut.go:32-36` | MEDIUM | 签名区内无匹配 RRSIG 的记录不通过 — 拒绝或降级 Validated |

**验证**: 现有 DNSSEC 测试全绿 + 新增: 伪造 DNSKEY 注入测试、Opt-Out 域 (com) NXDOMAIN 测试、NSEC 通配符 NODATA 测试。

**提交**: `fix: DNSSEC chain-of-trust integrity (validated-fallback, offline-KSK, zone-cut auth)` — 可与 1b 合并或分两次。

---

## 批次 3 — 数据竞争与共享可变状态

报告 Top Issue #2。约 12 条 + 关联修复。

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 3.1 | `stats/stats.go:288-291` | HIGH | `Reset()` 的 `*c = Collector{}` 非原子 → 逐字段 `Store(0)` (含 latCounts/rCode/latTotal), 或 atomic.Pointer 快照交换 |
| 3.2 | `server/init.go:70` | HIGH | `.cache.clear`/`.stats.clear` 的 `statsCollector.Reset()` 与查询 goroutine 的 `Record()` 并发 → 依赖 3.1 修复后自动消除 |
| 3.3 | `server/init.go:72-75` | MEDIUM | `cache.clear` 顺带清空统计 — 移除 `statsCollector.Reset()` 调用 |
| 3.4 | `server/protocol/dnscrypt/crypto.go:126` | HIGH | `s.ticketKey`/`ticketKeyID`/`prev*` 写入持 `s.mu` 而 PQ 路径无锁读 → `RLock` 快照后传本地副本给 PQSealTicket/PQOpenTicket |
| 3.5 | `server/tasks.go:124-126` + `server/bridge.go:46` | HIGH | tcpWriteMu sweep 删除在用条目 → 写串行化破坏、帧交错。增加 in-flight refcount (或 `len(entry.capacity)==0` 检查), 仅在零引用时删除; 同时 `lastAccess` 在每次请求更新 |
| 3.6 | `internal/lrumap/lru.go:82-85` | HIGH | `Set` 不 defer Unlock → OnEvict panic 永久锁死; `Range` 持锁回调 → 快照或文档化"回调不得重入/阻塞" |
| 3.7 | `internal/lrumap/lru.go:33-36` | MEDIUM | `OnEvict` 无同步赋值 → 构造参数或 `SetOnEvict` 持锁赋值 |
| 3.8 | `internal/lrumap/dtls_session.go:24` + `:17` | MEDIUM | `Set` 深拷贝 `ID`/`Secret` (否则 OnEvict 清零会抹掉握手在用缓冲); 之后配置 OnEvict 清零 DTLS 主密钥 |
| 3.9 | `server/upstream/dnscrypt/state.go:157-158` | HIGH | `ephemeralKeys` 在 buildState 发布后写入且不持 `state.mu` → 传入 buildState 在 `cache.Set` 前设置; 同一 addr|provider 二次复用共享 state 的 knobs 问题一并处理 (缓存 key 含 ephemeral_keys/pqdnscrypt) |
| 3.10 | `server/upstream/warmup.go:48` | LOW | `s := &servers[i]` 指向调用方数组 → 拷贝为局部值再取地址 |
| 3.11 | `server/upstream/client.go:305` | LOW | `Close()` 无同步置 nil `proxyDialers` → mutex/atomic 保护 |
| 3.12 | `stats/stats.go:181` | LOW | `Stats()` 非一致快照 → 文档化或 atomic.Pointer 不可变快照 |

**验证**: `go test -race ./stats/... ./internal/lrumap/... ./server/...`。

**提交**: `fix: data races on shared resolver/server state (stats.Reset, ticket keys, tcpWriteMu sweep)`

---

## 批次 4 — 缓存层错误答案与 TTL 语义 (cache/, internal/ttl/, 相关 handler)

报告 Top Issue #5。约 18 条。

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 4.1 | `cache/lifecycle.go:127-130` | HIGH | `LatencyLastProbe` 返回真实存储时间戳 (值中追加时间戳或利用 ExpiresAt), 否则 probe 间隔逻辑永远是死代码 |
| 4.2 | `cache/lifecycle.go:46` | MEDIUM | ptr_map 反查 TTL 恒为 stale TTL → 用 `item.ExpiresAt()` 或持久化写入时间戳计算剩余 TTL |
| 4.3 | `cache/lifecycle.go:34-37` | LOW | View/ValueCopy 错误吞掉 → 传播 callback 错误 (至少 Warn) |
| 4.4 | `cache/lifecycle.go:90` | LOW | `db.Update` 错误丢弃 → `log.Warnf` |
| 4.5 | `cache/cache.go:167-173` | MEDIUM | ProcessRecords 快路径返回共享 backing storage → 调用方可变时克隆 (或 ClampTTL 克隆/操作副本) |
| 4.6 | `cache/cache.go:106-108` | LOW | value 超 uint32 静默截断 → clamp: `uint32(min(value, ^uint32(0)))` |
| 4.7 | `cache/store.go:80-85` | HIGH | Badger `Item.Value` 回调外失效 → `item.ValueCopy(nil)` |
| 4.8 | `cache/store.go:233-237` | HIGH | OPT TTL 非 TTL (RFC 6891) → TTL 计算/调整前 strip OPT |
| 4.9 | `cache/store.go:377-386` | MEDIUM | stripOPT 原地压缩破坏调用方 backing array → 分配新 slice |
| 4.10 | `cache/ptr.go:42-43` | LOW | dedup key 用 `dns.CanonicalName` 规范化 (RFC 4343) |
| 4.11 | `database/keys.go:107-111` | LOW | e:ip: 命名空间碰撞 (EntryKey qname 以 "ip:" 开头) → 移出或扫描时排除非 ptr 键 |
| 4.12 | `database/keys.go:131-135` | LOW | EncodePtrMapValue 负值 clamp 到 [0, MaxInt32] |
| 4.13 | `database/db.go:67-71` | MEDIUM | 内存模式走 `defaultDiskOptions("", opt).WithInMemory(true)`, 应用全部内存 knobs |
| 4.14 | `internal/ttl/ttl.go:24-28` | LOW | 边界统一: `remaining >= 0` 视为 fresh, 精确到期返回 0 |
| 4.15 | `internal/ttl/ttl.go:21-23` | LOW | 注释与实现对齐 (常量 stale TTL per RFC 8767 §4), 或实现文档化的递减 |
| 4.16 | `internal/ttl/ttl.go:90` | MEDIUM | 周期环绕重置为全 TTL → 单调递减 clamp 0 (zone 静态响应若故意, 注释说明) |
| 4.17 | `server/handler/response.go:36-37` | MEDIUM | cache.Entry 无 Rcode → 持久化 Rcode 并在命中时恢复 (NXDOMAIN 不再变 NODATA) |
| 4.18 | `server/handler/middleware/cache_lookup.go:172-173` | HIGH | 前台刷新成功不写回 cache (缺 `m.store.Set`) + 刷新后未清 `qctx.EDE` (stale EDE 泄漏) — 两条一起修 |
| 4.19 | `server/handler/middleware/cache_lookup.go:67-69` | MEDIUM | prefetch TryGo 拒绝时未调用 finishRefresh → pendingRefreshes 永久占用; 两处 TryGo 失败分支对齐 |
| 4.20 | `server/handler/middleware/cache_store.go:171-172` | MEDIUM | cache 救回的错误记录成 SERVFAIL → 记录实际响应的 rcode (RcodeSuccess) |

**验证**: 反查 TTL 单测、OPT TTL=0 缓存单测、NXDOMAIN 缓存往返单测、probe 间隔单测。

**提交**: `fix: cache correctness (reverse TTL, OPT handling, refresh write-back, negative rcode)`

---

## 批次 5 — 协议解析器崩溃/损坏输入 (stamp, edns, dnscryptcrypto, pool)

报告 Top Issue #8。约 40 条。

### 5a. internal/stamp/ — 解析器 OOB + 编码丢失 (9 条)
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `stamp.go:130-132` | HIGH | Parse 每次读 length-byte 前重新校验 `pos < binLen` (hashes/provider-name/path) |
| `stamp.go:121-123` | MEDIUM | 放宽 DNSCrypt (44B) 与 relay (2B) 最小长度到格式下限 |
| `stamp.go:220-223` | MEDIUM | 无端口 Address 时用 ProviderName 构造 URL、IPv6 加括号、默认 443 |
| `encode.go:196-201` | HIGH | `splitOptionalPort` 处理裸 IPv6: 先剥括号 + net.ParseIP 再 colon 拆分 |
| `encode.go:140-141` | HIGH | `appendBootstrapIPs` 空列表补 `0x00` VLP 终止符 (与 appendHashes 对齐) |
| `encode.go:113-121` | HIGH | hostname 为空时把端口并入 hostname, 不丢弃 |
| `encode.go:162-164` | MEDIUM | addr 端口段过 `validatePort` 校验 |
| `stamp.go:92-94` | LOW | 修正 Parse 的 doc comment (当前错误描述 parsePlainDNS) |
| `stamp.go:190-192` | LOW | 修正 ProtoConfig 注释 (实际返回 "dnscrypt-relay"/"odoh-relay"/"odoh") |

### 5b. edns/ — 4 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `ecs.go:230-233` | MEDIUM | SourcePrefix > len(Address)*8 时返回 false (不 panic) |
| `ecs.go:142-144` | MEDIUM | 自动检测失败返回 error / 记录日志, 不再静默 no-op |
| `edns.go:101-102` | MEDIUM | 响应 DO 位镜像查询 (isRequest 才设 Security); 增加 dnssecOK 参数 |
| `edns.go:104-111` | LOW | ECS 地址无效时跳过选项 (addrToNetip 无效 → ecs=nil) |

### 5c. edns/padding.go — 3 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `padding.go:20-28` | HIGH | 用 `req.UDPSize != 0` 判定 EDNS 存在; 空选项列表 = 显式 opt-out 不 pad |
| `padding.go:43-44` | MEDIUM | `paddingDataSize >= 0` 补空 PADDING 选项对齐块边界 |
| `padding.go:40-41` | MEDIUM | `msg.Pack()` 错误检查 → 失败返回 0 跳过 padding |

### 5d. internal/dnscryptcrypto/ — 23 条 (PQ 证书/报文预算)
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `certificate.go:346` | MEDIUM | Sign/MarshalBinary 校验 `len(PqPublicKey) == PQPublicKeySize` |
| `certificate.go:204-211` | MEDIUM | 全部校验通过后才填充结构体 (失败不清残留) |
| `certificate.go:196-199` | MEDIUM | 严格长度相等检查 (CertByteLength / PQCertByteLength) |
| `dns.go:23-37` | MEDIUM | MinMsgSize 下限移入 EDNS/TCP 分支, 报文预算分支不抬升截断阈值 |
| `dns.go:106` | MEDIUM | 写 2 字节前缀前 `len(b) > dns.MaxMsgSize` 返回错误 |
| `keys.go:21-23` | LOW | 冒号分隔校验或文档化宽松规范化 |
| `proto.go:91` | MEDIUM | `ResolverMagic` 改 `[ResolverMagicSize]byte` |
| `proto.go:102` | LOW | `PQESVersion` 从 `XWingPQ` 派生, 单一事实源 |
| `proto.go:57` | LOW | 开销常量交叉引用注释 + 编译期断言 `EDNSSize >= MinResponseOverhead(XWingPQ)` |
| `proto.go:143-149` | LOW | 未知 construction 默认取更大 PQ 开销 (fail closed) |
| `encrypted.go:339-341` | MEDIUM | PQ 大小上限 `!q.IsTCP` 才应用 |
| `encrypted.go:541-543` | MEDIUM | 解析 ticket 后强制 payload 最小长度 `>= TagSize+MinDNSPacketSize` |
| `encrypted.go:413` | LOW | 初始 PQ 路径 TCP 时用 PadTCP (镜像 resumed 路径) |
| `encrypted.go:303-309` | LOW | controlLen==0 时清 `r.PQControl` |
| `encrypted.go:454-457` | LOW | 经典路径无条件从 ClientPk 派生 sharedKey (不信任预置值) |
| `encryption.go:117-118` | MEDIUM | Pad 输出真正受 MaxDNSUDPPacketSize 约束 (min 上限 - QueryOverhead) |
| `encryption.go:105-106` | LOW | 注释公式与实现对齐 |
| `encryption.go:61-62` | LOW | PadResponse/PadResponseWithin nil 检查 |
| `string.go:37-40` | MEDIUM | `dddToByte` 拒绝 >255 与截断转义 |
| `string.go:45-47` | LOW | 删除 C 风格转义 (\t/\r/\n), 按 DNS 惯例 \X = 字面 X |
| `pq.go:57-59` | MEDIUM | PQCertContext 长度守卫 (不足返回 nil) |
| `pq.go:118-120` | HIGH | PQDecapsulate 校验 ct/sk 长度, 返回 error (circl 会 panic) |
| `pq.go:269-274` | MEDIUM | DecodeTicketPlaintext 返回 esVersion/peHash, 绑定校验进 API |
| `pq.go:242-245` | LOW | 删除 PQClientMagic 死代码 (与 cert 派生矛盾) |
| `xsecretbox.go:89-93` | LOW | 捕获 `hash.Sum` 返回值再拷贝 |
| `xsecretbox.go:65-67` | LOW | 传播 chacha20 错误, 修正过时注释 |

### 5e. cmd/zjdns/cli/probe.go — 5 条 (Quick Wins)
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `probe.go:143-145` | HIGH | newQuery/PTR 辅助设 `Rrtype: dns.TypeA / dns.TypePTR` |
| `probe.go:224` | HIGH | `resp.ID < uint16(probePipelineNumQueries)` 才写 seen, 防越界 panic |
| `probe.go:221-223` | HIGH | 单调性检查检测乱序 (lastID 追踪) |
| `probe.go:287-294` | MEDIUM | `net.Error.Timeout()` 视为"仍存活继续等", 仅 io.EOF 判定服务端关闭 |
| `probe.go:63-65` | LOW | `net.Dialer{Timeout: ...}` 快速失败 |

### 5f. internal/pool — 2 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `pool.go:34-39` | LOW | DoQ 错误码常量移到 `internal/doq` 共享包, pool 脱离 quic-go 依赖 |
| `pool.go:112-115` | LOW | `NewBuffer` size<0 clamp 到 0 |

**验证**: 新增 stamp fuzz/边界单测; PQ 证书畸形输入单测; `go test -race ./internal/dnscryptcrypto/...`。

**提交**: `fix: parser hardening (stamp OOB, ECS prefix, DNSCrypt PQ bounds, probe panics)`

---

## 批次 6 — 配置层 (config/)

报告 Top Issue #4/#6。22 条。

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 6.1 | `config.go:216-219` | HIGH | TLS 证书校验: 先查 tlsEnabled 再要求完整证书 — 当前 IsEnabled()==false 提前返回 |
| 6.2 | `config.go:211-214` | MEDIUM | TLCP 同款: tlcpEnabled 优先检查 |
| 6.3 | `config.go:198-200` | MEDIUM | 单个 DNSCrypt key (公/私) → 校验错误"必须成对提供" |
| 6.4 | `chaos.go:42-46` | HIGH | `.cache.clear`/`.stats.clear` 无认证即可远程触发 — **已核实: 当前不存在 127.0.0.1 限制** (chaos.go 规则无 Match tags; zone.go evalDynamic 无客户端 IP 检查), 任何可达任一监听器的客户端都能执行 → 修复: 按用户预期实现 loopback-only (127.0.0.1/::1 或 Match tag 白名单) |
| 6.5 | `chaos.go:29-31` | MEDIUM | 追加规则前检查 cfg.Zone 是否已有同名规则 |
| 6.6 | `chaos.go:28` | LOW | 用固定 slice 遍历替代 map 随机序 |
| 6.7 | `chaos.go:35` | LOW | 用 DNS-aware TXT 引号工具替代 strconv.Quote (非 ASCII 主机名) |
| 6.8 | `defaults.go:89` | MEDIUM | 对齐 DefaultRecursiveResolveTimeout (30s) 与 DefaultHTTPServerWriteTimeout (10s): 提高写超时覆盖递归预算或降低递归超时 |
| 6.9 | `load.go:150-153` | HIGH | DoH stamp → ProtoHTTPS ("https") 映射 (ProtoToConfig/protocolMatchesStamp/resolveStamp 三处) |
| 6.10 | `load.go:33-34` | MEDIUM | 先 `NewDefaultServerConfig()` 再 Unmarshal (补齐默认值) |
| 6.11 | `load.go:16-18` | MEDIUM | 空路径配置也走 enrich 管道 (addChaosRecord + DDR) — 两条路径行为一致 |
| 6.12 | `ecs.go:140` | HIGH | 移除 `PreferIPv4` 的 `omitzero` (false→true 往返 bug) |
| 6.13 | `ecs.go:45-47` | HIGH | `e.Address.Mask(mask)` nil 防护; IPv4 先规整为 4 字节 |
| 6.14 | `ecs.go:44` | MEDIUM | SourcePrefix 超地址宽度 → clamp 或显式错误 |
| 6.15 | `ecs.go:190-192` | LOW | 删除孤儿注释 (描述未实现行为) |
| 6.16 | `ddr.go:168-169` | MEDIUM | SVCB TargetName 用 domain (当前硬编码 '.', 证书/附加记录不一致) |
| 6.17 | `ddr.go:60-62` | LOW | 空协议集防御性提前返回 |
| 6.18 | `ddr.go:191-193` | LOW | 每条规则 `slices.Clone` Answer/Additional |
| 6.19 | `ddr.go:73-81` | MEDIUM | dohpath 端点做与 domain 同级的非法字符校验 (引号/反斜杠/URL) |
| 6.20 | `validate.go:0-0` | MEDIUM | IPv6 校验拒绝 IPv4 (`ip.To4() != nil` 即拒绝) + 修正错误消息 |
| 6.21 | `validate.go:424-426` | MEDIUM | tlcpEnabled 增加 `|| proto.DTLCP != ""` |
| 6.22 | `validate.go:172-183` | MEDIUM | DoH/DoH3/HTTP-TLCP 地址: URL 形式要求 scheme+host, 否则 host:port 形式 |

**验证**: 配置加载往返测试 (omit 字段默认值、ecs 往返、DoH stamp 端到端)。

**提交**: `fix: config validation gaps (TLS/TLCP certs, DoH stamps, ECS round-trip, chaos rules)`

---

## 批次 7 — 服务器监听器生命周期 (server/protocol/*)

报告 Top Issue #7 (泄漏) + 跨切面"shutdown races"。约 25 条。

### 7a. plain — 5 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `plain/server.go:39-42` | MEDIUM | 启动错误路径关闭已建 listeners; ctx 取消真正关闭 listener |
| `plain/server.go:47` | MEDIUM | 协议 server slice 加锁或 Shutdown 前同步填充; Shutdown 等待同一 errgroup |
| `plain/server.go:47-54` | MEDIUM | Shutdown 收集并返回各 dns.Server 错误 |
| `plain/server.go:35-37` | LOW | Start 返回 error 替代 panic (nil group/handler) |
| `plain/server.go` (tasks.go:171 关联) | LOW | 15s drain 超时失败需可观察 — plain.Shutdown 返回首错 |

### 7b. dnscrypt — 7 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `tcp.go:40` | HIGH | 写响应/握手前 `SetWriteDeadline` (WritePrefixed 两处) |
| `tcp.go:86-87` | LOW | wg.Add 在 spawn 前完成; shutdown 期接受检查 `isStarted()` |
| `tcp.go:105` | MEDIUM | SetReadDeadline 失败 → 日志 + 关连接 |
| `udp.go:130-139` | HIGH | 截断后重验 `len(truncated.Data) <= len(b)`, 超限丢弃 (§10.3 保证) |
| `udp.go:62-64` | MEDIUM | 单 `defer pool.DefaultBuffer.Put(buf)` 覆盖全部退出路径 (panic-safe) |
| `generate.go:229-232` | MEDIUM | 持久化 resolver seed, 双证书同 seed 派生 |
| `generate.go:211-213` | MEDIUM | `net.SplitHostPort` 校验端口数值/非空 (裸 IPv6 现被误解析) |

### 7c. tlcp — 9 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `dtlcp.go:180-181` | CRITICAL | 已在批次 1a |
| `dtlcp.go:294-300` | HIGH | `net.Error.Timeout()` 视为断连; accept 循环不继承过期 deadline; 临时错误退避 |
| `dtlcp.go:260-262` | HIGH | 每次响应前刷新写 deadline (现在固定 30s 到期拆线) |
| `tlcp.go:42-47` | MEDIUM | 统计成功绑定的 listener 数, 0 时返回错误 |
| `certs.go:70` | HIGH | 证书填充 DNSNames/IPAddresses (SAN), 接受 host/IP 参数 |
| `certs.go:73-74` | HIGH | 加密证书独立 key usage (KeyAgreement\|KeyEncipherment\|DataEncipherment) |
| `certs.go:105-108` | MEDIUM | 返回/持久化自签 CA 并加入链 |
| `http_tlcp.go:33` | HIGH | ALPN 改 `http/1.1` (该 http.Server 不解析 HTTP/2) |
| `http_tlcp.go:40` | MEDIUM | 增加 `ReadTimeout: config.DefaultHTTPServerReadTimeout` (Slowloris) |
| `server.go:83-86` | LOW | 握手日志去掉硬编码 "client" 或移到有 RemoteAddr 的 accept 处 |

### 7d. tls — 8 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `tls.go:266` | HIGH | 16-bit 长度前缀前 `len(respBuf) > dns.MaxMsgSize` → 截断 TC 或丢弃 |
| `tls.go:62-76` | MEDIUM | 预握手连接占用共享 errgroup 槽位 → 专用 per-protocol 上限/短预握手 deadline |
| `addr_validator.go:26-31` | HIGH | 返回值反转 → 缓存命中 true, 未命中插入后 false |
| `addr_validator.go:9-11` | HIGH | 原始 IP 白名单可投毒且条目无时间过期 → token 验证 (握手完成才白名单) + 时间过期真正读时间戳 |
| `http3.go:86-88` | HIGH | QUIC 连接无上限 → semaphore/max-conns 准入 |
| `https.go:137-140` | MEDIUM | GET 先 base64 解码再比对 DefaultDOHMaxRequestSize |
| `https.go:175-178` | LOW | short write 保留原错误 (`%w`) |
| `quic.go:250-261` | MEDIUM | deferred Put 增加 `response != req` 身份守卫防双 Put |

**验证**: DTLCP/DTLCP E2E (docs/debug/DEBUG.md 的 TLCP/DTLCP 测试), DoH slowloris 测试, `go test -race ./server/protocol/...`。

**提交**: `fix: listener lifecycle (deadlines, shutdown, cert SANs, QUIC admission)`

---

## 批次 8 — 递归解析器 (server/resolver/)

报告热点模块 #1。约 20 条 (DNSSEC 部分已在批次 2)。

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 8.1 | `nameserver.go:190-201` | HIGH | select 后非阻塞 drain resultChan — NOERROR 与 errgroupDone 同时就绪时不再丢有效响应 |
| 8.2 | `nameserver.go:76-79` | HIGH | buildMsg 副本拷贝 `Pseudo` (ECS 等选项当前静默丢失) |
| 8.3 | `nameserver.go:71-76` | MEDIUM | 池化内存别名 (Put 前异步消费者未完成) → 深拷贝或延迟 Put |
| 8.4 | `root_hints.go:49-54` | HIGH | sync.Once 缓存永久失败 → mutex + 失败重试加载 |
| 8.5 | `root_hints.go:77-80` | MEDIUM | dns.New 失败行 Debug 日志 |
| 8.6 | `root_hints.go:97-102` | LOW | hints map key 统一小写 |
| 8.7 | `forward.go:214-230` | HIGH | 多标签 CIDR 过滤 OR→AND 语义: 每个预过滤 tag 必须满足 (negate 现在被短路) |
| 8.8 | `forward.go:273` | LOW | EDE 归属竞态 → captureUpstreamEDE 返回值直接进 QueryResult, 不重载共享 atomic |
| 8.9 | `resolver.go:275-278` | MEDIUM | concurrencyLimit 跨层非单调 (13→7, 21→8) → 连续公式或 clamp 不低于上一档 |
| 8.10 | `resolver.go:198-206` | MEDIUM | **已核实: 无 reload 机制** — `upstream.store()` 仅一个调用点 (resolver.go:209, ConfigureServers, 启动期一次) → 修复方向为简化: `upstreamSet` 的 atomic.Pointer 换成普通字段 (write-once), 消除"暗示支持 reload"的死复杂度; 防御标志的 `\|\|` 累积逻辑保留现状 |
| 8.11 | `ns_addresses.go:89-90` | MEDIUM | 根服务器地址全局按延迟排序 (当前 AAAA 恒被压后 + map 随机序) |
| 8.12 | `ns_addresses.go:99-102` | LOW | 收集数 < hints 数时合并 allRootAddrs() |
| 8.13 | `ns_addresses.go:125-126` | LOW | getRootServers 每查询重读缓存 → memoize + 周期刷新 |
| 8.14 | `probe/probe.go:112-113` | MEDIUM | 依赖 4.1 (LatencyLastProbe 修好后间隔逻辑复活) |
| 8.15 | `probe/probe.go:106-107` | MEDIUM | 只探测 stale IP (needProbe 列表), 不全量重探 |
| 8.16 | `probe/probe.go:123-124` | MEDIUM | 单飞 key 含 IP 集/ECS; 删除死参数 ecsResponse |
| 8.17 | `probe/probe.go:143` | LOW | 重命名 probeAndReorder → probeAndUpdateLatency + 注释修正 |
| 8.18 | `recursive_ns.go:86-95` | MEDIUM | cache/glue 未覆盖的 NS 独立解析后合并, 不短路 |
| 8.19 | `recursive_ns.go:42-45` | LOW | cache 循环 seen-set 防重复 NS; 最终地址去重 |
| 8.20 | `recursive.go:97-102` | MEDIUM | root 分支 VerdictPoisoned 也走 TCP 重启 (与主循环一致) |
| 8.21 | `recursive.go:339-344` | LOW | 收集链上所有 CNAME (参与链的 owner), 不丢中间 CNAME |
| 8.22 | `qname_minimise.go:102-115` | LOW | 比例阶段 hold back 1 label, 全 QNAME 只在 stepsTaken >= minimisationCount 暴露 |
| 8.23 | `qname_minimise.go:24-29` | LOW | labelsToAdd<=0 返回 fqZone (root 返回 "."), 不返回空 QNAME |
| 8.24 | `defense/hopguard.go:94-97` | MEDIUM | Feed 学习契约失效: 调用点 (upstream/plain/udp.go) 对每个包都 Feed (含 GFW 注入) → 只在 spoofguard-clean 后 Feed, 或强化提升规则 (候选必须是 mode 本身, 非 >= mode/4) |
| 8.25 | `defense/hopguard.go:117-121` | LOW | 重建仅按样本数触发 → 结合时间衰减, 低流量上游也能收敛 |
| 8.26 | `defense/poisonguard.go:111-114` | LOW | IsPoisonedByTLD 豁免 root-server 域名与 TLD apex (与 classifyRoot/classifyTLD 一致) |
| 8.27 | `defense/poisonguard.go:83-86` | MEDIUM | Validate 同时检查 owner 为查询名祖先的 Answer (注入 DNAME 逃逸) |
| 8.28 | `defense/poisonguard.go:81-86` | LOW | 遍历 Answer 前 nil RR 检查 |

**验证**: 递归集成测试 + 根服务器排序单测; `go test ./server/resolver/...`。

**提交**: `fix: recursive resolver correctness (root hints retry, fan-out select race, qname-minimisation)`

---

## 批次 9 — handler 管道 (server/handler + middleware)

约 22 条。

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 9.1 | `middleware/zone.go:50-51` | HIGH | `ZoneMatched` 只在真正短路的合成响应分支设置 — matched-but-empty 情况转普通委托, 否则查询静默丢弃 |
| 9.2 | `middleware/dns64.go:38-40` | HIGH | 用 `qd.Qtype` 结构体字段 (Question 无 Header/RRToType) |
| 9.3 | `middleware/dns64.go:40-42` | HIGH | CNAME-only 链不抑制合成 — 检查 `hasAAAA` 而非 `len(Answer)>0` |
| 9.4 | `middleware/dns64.go:61-66` | MEDIUM | A 查询失败 → Warn 日志并传播错误 (不静默变 NODATA) |
| 9.5 | `middleware/dns64.go:0-0` | MEDIUM | 合成后清 `qr.Validated` (或传播 aqr.Validated) — NODATA 的认证状态不能安到合成 AAAA 上 |
| 9.6 | `middleware/resolution.go:52-55` | MEDIUM | resolver 返回 nil / 被逐出 follower → 构建 SERVFAIL 响应, 不静默无响应 |
| 9.7 | `middleware/resolution.go:49-51` | MEDIUM | 单飞工作函数用 server-scope ctx (非首调用者 ctx); follower 等待时 select 自身 ctx |
| 9.8 | `middleware/edns.go:50-56` | MEDIUM | FORMERR 响应清 `qctx.ECSOpt` + 从 req.Pseudo 移除 SUBNET (不回显畸形选项) |
| 9.9 | `middleware/edns.go:57-60` | MEDIUM | ParseCookie 区分 absent/malformed, 畸形 → FORMERR; bad-cookie 助手 8 字节守卫 |
| 9.10 | `middleware/response.go:64-67` | MEDIUM | EDNS 门控用真实请求 OPT 证据 (`req.Security || req.UDPSize != 0 || len(req.Pseudo)>0`), 去掉 `qctx.IsSecure` |
| 9.11 | `middleware/response.go:132-136` | MEDIUM | restoreDomain 重命名带 RRSIG 的 RRset → 剥离受影响 RRSIG/NSEC、清 AD, 或 DNSSEC 记录存在时跳过 restore |
| 9.12 | `middleware/response.go:74` | LOW | qctx.TCPKeepalive 从未赋值 → 实现解析 RFC 7828 选项或删除死条件 |
| 9.13 | `middleware/validation.go:62` | MEDIUM | 用 `dns.PackDomainName` 量线格式长度 ≤255 |
| 9.14 | `middleware/validation.go:47` | LOW | QDCOUNT != 1 直接 FORMERR (防 Question[1] 走私) |
| 9.15 | `middleware/chain.go:124` | MEDIUM | `deps.ZoneEvaluator != nil &&` 守卫 (文档承诺可选) |
| 9.16 | `middleware/chain.go:22-23` | LOW | Stats 加入必填字段文档或 nil 检查 |
| 9.17 | `handler.go:153-158` | MEDIUM | err != nil 且 Res 已填充 → 日志 + 记录 error 统计, 不静默返回部分响应 |
| 9.18 | `handler/response.go:21-23` | MEDIUM | 无 question 时也拷贝 Id/Opcode (FORMERR 否则 Id=0 客户端丢弃) |
| 9.19 | `handler/pending.go:58` | HIGH | 逐出时发布合成错误; Done 按指针验证归属; 结果发布与逐出同步 |
| 9.20 | `handler/pending.go:88-93` | LOW | timer drain 用非阻塞 select (Go 1.23+ 无缓冲语义) |
| 9.21 | `handler/prefetch.go:78-82` | MEDIUM | 先逐出已过冷却期的条目; 保留逐出时间戳让冷却期继续生效 |
| 9.22 | `handler/prefetch.go:49-51` | LOW | ShouldStart 内联软上限 |
| 9.23 | `handler/prefetch.go:18-22` | LOW | 零值可用 (lazy init) 或文档化禁止零值 |
| 9.24 | `handler/context.go:55` | MEDIUM | 增加 `Responded bool` 完成标志区分部分/最终响应 (或哨兵错误) |
| 9.25 | `handler/context.go:37-38` | LOW | bool+pointer 对折叠为单指针字段 (nil=false) |
| 9.26 | `handler/context.go:60-61` | LOW | 增加 `EffectiveName()` 访问器 |
| 9.27 | `handler/context.go:23` | LOW | `ClientAddr()` 访问器返回非 nil |
| 9.28 | `middleware.go:64-66` | LOW | 文档化 ErrDrop 必须 `%w` 包装 |
| 9.29 | `middleware.go:55` | LOW | 接口参数名对齐实现 / 布尔聚成 options struct |
| 9.30 | `middleware.go:39` | LOW | 文档化 matchedTags 只读契约 |
| 9.31 | `middleware/zone.go:22` | LOW | 删除未使用的 cache 字段 |

**验证**: DNS64 CNAME 链、QDCOUNT>1、无 question FORMERR、单飞逐出测试。

**提交**: `fix: middleware pipeline (DNS64 synthesis, singleflight eviction, EDNS gating, zone fall-through)`

---

## 批次 10 — 上游客户端 (server/upstream/)

报告热点模块 #2。约 35 条。

### 10a. dnscrypt 客户端 — 9 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `cert.go:58-60` | HIGH | `DialContext` + `context.AfterFunc(ctx, SetDeadline)` 中断阻塞 I/O |
| `cert.go:66-67` | HIGH | 缓冲扩到 DefaultDNSCryptUDPSize; 满缓冲视为截断错误 (TCP 回退) |
| `cert.go:43-45` | MEDIUM | TCP 回退失败 → 返回错误, 不返回截断的 UDP 响应 |
| `crypto.go:87-88` | LOW | crypto/rand.Read 错误传播 |
| `crypto.go:48-49` | MEDIUM | resume secret 从本查询 key 派生, 不读可变 `state.sharedKey` |
| `client.go:29-31` | MEDIUM | maxTCRetries 从初始值推导 (或 7), 保证 4096 与 TCP 回退可达 |
| `client.go:147-150` | LOW | 纯 I/O 错误不清 state (仅解密错误清) |
| `state.go:188-191` | MEDIUM | PQ-only 时无条件派生 X25519 对 (State 永远携带真实 key) |
| `state.go:212` | MEDIUM | `expires = min(now+TTL, selectedCert.NotAfter)` |
| `state.go:38-39` | LOW | 删除死字段 ewmaQuerySize |

### 10b. plain — 4 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `client.go:27-36` | LOW | timeout 字段未用 → 用于 multi-read maxDeadline 或删除 |
| `client.go:27-28` | LOW | New 校验 nil 依赖或文档化非 nil 契约 |
| `tcp.go:102-104` | MEDIUM | 验证 `response.ID == msg.ID` (现覆盖而非校验) |
| `udp.go:333-335` | MEDIUM | 用 `resp.IsEdns0() != nil` 判定 EDNS (ARCOUNT 非 OPT 证据) |

### 10c. pool — 4 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `quic.go:105-108` | MEDIUM | 拨号前锁内检查 p.closed |
| `quic.go:183-187` | MEDIUM | Put 前检查连接活性 (conn.Context().Err()) |
| `quic.go:171-174` | LOW | 释放锁后再 CloseWithError |
| `tcp.go:0-0` | MEDIUM | readLoop 投递前 RLock 重验 inflight 注册, 防止取消竞态泄漏 pooled msg |
| `tcp.go:407-410` | LOW | WarmUp `len(conns) >= maxConns` 直接返回 (不再浪费拨号) |

### 10d. socks5 — 7 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `udp.go:72-75` | HIGH | 锁内取 udpConn, nil 返回错误 |
| `socks5.go:274` | LOW | 预检放宽到 `len(b) < 4` (ATYP 可读即可) |
| `socks5.go:398` | MEDIUM | 括号 IPv6 无端口剥括号再走默认端口 |
| `socks5.go:386` | MEDIUM | `len(host) > 255` 拒绝 (不截断字节) |
| `socks5.go:450` | MEDIUM | skipAddress 不解析域名; readAddress 用连接 deadline 替代 context.Background |
| `udp.go:81-84` | MEDIUM | 无 ctx deadline 时应用 d.timeout (拨号+协商) |
| `udp.go:137-141` | MEDIUM | 非 IP 代理主机解析后再定 relay |
| `udp.go:244-248` | LOW | 截断时复制前缀返回 n=len(p) 或文档化丢弃 |

### 10e. tlcp 客户端 — 5 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `client.go:70-72` | MEDIUM | DTLCP 配置镜像 ServerName + CurvePreferences (SM2) |
| `client.go:49` | MEDIUM | 空 CertPool → 支持加载 SM2 CA 或文档化强制 skip_tls_verify |
| `client.go:57-62` | LOW | VerifyConnection 检查失败返回 error, 文档化 logging-only |
| `http_tlcp.go:33-35` | MEDIUM | 校验 scheme == https 且 host 非空 (防明文降级) |
| `http_tlcp.go:66-69` | HIGH | `CheckRedirect: http.ErrUseLastResponse` (防查询泄漏/SSRF) |
| `http_tlcp.go:46` | LOW | 缓存 key 用规范化 URL |
| `tlcp.go:25` | MEDIUM | 握手后强制 `NegotiatedProtocol == "dot"` |

### 10f. tls 客户端 — 8 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `client.go:232-235` | HIGH | QUIC pool/config 缓存 key 含 identity (addr\|serverName\|skipVerify\|proxy) |
| `client.go:248-253` | MEDIUM | WarmUp 拨真实 server.Address (poolKey 含 proxy 会解析失败) |
| `client.go:253` | MEDIUM | quic.Dial 失败关闭 pconn (泄漏 UDP socket) |
| `https.go:33-35` | HIGH | `parsedURL.Hostname()` 再 JoinHostPort (IPv6 双括号) |
| `https.go:40` | MEDIUM | Close 置 nil 后 Execute 路径 nil 检查 |
| `https.go:52-57` | MEDIUM | lrumap 增加 `CompareAndDelete` 原子化 Get→比较→Delete |
| `http3.go:90-98` | HIGH | Err0RTTRejected 处理不限于 isCached 分支 (reset+重建) |
| `http3.go:115-122` | HIGH | 仅 QUIC/连接级错误才驱逐 transport; caller 取消/HTTP 错误不驱逐 |
| `http3.go:40-44` | MEDIUM | RLock 不覆盖网络 I/O (只保护 closed 标志) |
| `dtls.go:91` | LOW | uint16 截断前显式长度检查 |
| `quic.go:79-85` | MEDIUM | Err0RTTRejected → 从池移除、新拨号、再重试 |

### 10g. client.go / warmup.go — 4 条
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `client.go:191-196` | LOW | dispatch switch: 未知协议返回错误 (fail closed, 不落 UDP) |
| `client.go:294-297` | LOW | tlcpClient 增加 Close (关 LRU 缓存客户端) |
| `client.go:265-266` | LOW | DTLS→TLS 回退用新鲜 `context.WithTimeout` |
| `warmup.go:29-30` | MEDIUM | 日志 redact proxy URL + 不缓存失败 dialer (nil 不入 LRU) |
| `warmup.go:64-65` | LOW | WarmUpHTTPS/HTTP3 接收 ctx |

**验证**: 上游集成测试 + `go test -race ./server/upstream/...`; DoQ/DoH3 0-RTT 拒绝测试。

**提交**: `fix: upstream clients (pool races, redirects, identity-keyed QUIC cache, fallback ctx)`

---

## 批次 11 — server 核心 (server.go, init.go, tasks.go, bridge.go)

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 11.1 | `server.go:87-91` | HIGH | `database.Open` 后所有错误路径 `defer func(){ if !ok { db.Close() } }` (BadgerDB 目录锁泄漏) |
| 11.2 | `server.go:314-317` | MEDIUM | 协议 init 错误语义: 文档说非致命但实现 abort → 按文档 warn+continue 或 fail-fast+清理已建 listener |
| 11.3 | `server.go:372-377` | MEDIUM | pprof handler 404 → 注册 `/debug/pprof/` (net/http/pprof 或专用 mux) |
| 11.4 | `tasks.go:86-87` | LOW | 首次 refreshECSOnce 前检查 backgroundCtx.Done() |
| 11.5 | `bridge.go:104-105` | LOW | tcpSem 等待加超时 → SERVFAIL (不无限占 per-client slot) |
| 11.6 | `init.go:55-57` | MEDIUM | FlushDB 错误不回显到 TXT 应答 (log 细节 + 通用 error=flush-failed) |

(3.2/3.3 init.go 统计竞态在批次 3; 3.5 tasks.go sweep 在批次 3。)

**提交**: `fix: server core (db leak on init failure, pprof, init error semantics)`

---

## 批次 12 — internal/ 工具包

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 12.1 | `dnsutil/clientip.go:12-13` | MEDIUM | typed-nil 检查 (*net.TCPAddr)(nil) |
| 12.2 | `dnsutil/clientip.go:16-21` | MEDIUM | 显式 `*net.IPAddr` case |
| 12.3 | `dnsutil/bind.go:32-37` | MEDIUM | 按 IP 去重 |
| 12.4 | `dnsutil/bind.go:23-26` | MEDIUM | 接口枚举失败 Warn |
| 12.5 | `dnsutil/bind.go:14` | MEDIUM | port "0"/"" 前置拒绝 |
| 12.6 | `dnsutil/bind.go:27-31` | LOW | 类型 switch 支持 *net.IPAddr |
| 12.7 | `dnsutil/download.go:70-75` | HIGH | 临时文件 + `os.Rename` 原子替换 (部分下载不再被当作有效信任材料) |
| 12.8 | `dnsutil/download.go:50-56` | MEDIUM | 不安全权限 → 拒绝加载 (fail closed) |
| 12.9 | `dnsutil/keepalive.go:18` | LOW | 消除常量重复 (注入或一致性测试) |
| 12.10 | `dnsutil/https_dns.go:47-48` | LOW | 克隆 URL + RawQuery + String() |
| 12.11 | `dnsutil/https_dns.go:114-116` | MEDIUM | DoH 只接受 QUERY opcode |
| 12.12 | `dnsutil/dnsutil.go:112-120` | MEDIUM | 先 EvalSymlinks 再 Clean (symlink 路径穿越) |
| 12.13 | `dnsutil/dnsutil.go:159-162` | LOW | ExtractIPString 加 IsValid 守卫 |
| 12.14 | `dnsutil/tcpframe.go:34-36` | LOW | 删除不可达守卫或文档化 close-required 契约 |
| 12.15 | `dns64/dns64.go:49-53` | HIGH | `v4Offset()` 按前缀长度 (RFC 6052 §2.2), u octet 清零 |
| 12.16 | `dns64/dns64.go:57-62` | MEDIUM | IsSynthesized 校验 u octet == 0 + 正确槽位 |
| 12.17 | `dns64/dns64.go:73-78` | MEDIUM | 合成 gated on Validated bool; 剥离非 A 记录/RRSIG (RFC 6147 §5.5) |
| 12.18 | `ipdetect/ipdetect.go:60-64` | MEDIUM | 非 2xx 状态码返回 nil |
| 12.19 | `ipdetect/ipdetect.go:74-77` | MEDIUM | 拒绝非公网地址 (private/loopback/link-local) |
| 12.20 | `latency/httppool.go:80-82` | MEDIUM | Close 前 drain in-flight probes (refcount/WaitGroup) |
| 12.21 | `latency/httppool.go:51-53` | LOW | client.Timeout 防御性设置 |
| 12.22 | `latency/httppool.go:38-40` | LOW | get() 返回 (nil, error) 显式契约 |
| 12.23 | `latency/prober.go:76-82` | MEDIUM | 有界 worker pool (min(n,cap) workers + channel) |
| 12.24 | `latency/probes.go:268` | MEDIUM | CheckRedirect: ErrUseLastResponse + 验证最终响应属于探测 IP |
| 12.25 | `latency/probes.go:262` | LOW | 删除 Host 覆盖或改 net.JoinHostPort 括号形式 |
| 12.26 | `ipttl/ipttl.go:32-33` | MEDIUM | 按 socket 域选 family; 无控制消息显式错误 |
| 12.27 | `log/log.go:211-216` | HIGH | 组件过滤作用于渲染后消息 (动态前缀 `%s: %s` 不再被静默丢弃) |
| 12.28 | `log/log.go:295-303` | LOW | 空组件列表归一为 nil (契约: nil = 不过滤) |
| 12.29 | `pending/pending.go:56-63` | MEDIUM | 满 map 泄漏 key → eviction/TTL 或指标 |
| 12.30 | `pending/pending.go:49-51` | LOW | Start 零值 nil guard 清晰 panic 或 lazy init |
| 12.31 | `siphash/siphash.go:11-13` | MEDIUM | nil key panic (勿静默零密钥 MAC) |
| 12.32 | `siphash/siphash.go:36-38` | LOW | sipRound 辅助函数消除 8 份重复 (编译器内联) |

**验证**: `go test -race ./internal/...`; dns64 前缀向量测试 (RFC 6052 各前缀)。

**提交**: `fix: internal utils (download atomicity, dns64 offsets, clientip, log filtering)`

---

## 批次 13 — ruleset + zone

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 13.1 | `ruleset/ruleset.go:69-71` | HIGH | domain 规则 key 与 Match 查找一致 (tldPlusOne 或 Match 走后缀) — 当前多标签规则永不匹配 |
| 13.2 | `ruleset/ruleset.go:117-119` | LOW | `!tag` 空集 → `(false, true)` 与 `(true, true)` 对齐或文档化 |
| 13.3 | `ruleset/iptrie.go:87-90` | MEDIUM | IPv6 规则泄漏到 IPv4 匹配 (::/0 规则给 8.8.8.8) — 深度 >= 96 才收集或分根 |
| 13.4 | `ruleset/iptrie.go:71` | LOW | insert 去重 tag (slices.Contains) |
| 13.5 | `zone/parse.go:88-91` | HIGH | 裸 "."/"*." 头重置全部解析状态; ". rcode=3" 属性解析 |
| 13.6 | `zone/parse.go:139-143` | MEDIUM | 先查 sc.Err() 再 flush; 加载原子性 |
| 13.7 | `zone/parse.go:0-0` | MEDIUM | tokenize 处理 `\"` 转义引号 |
| 13.8 | `zone/zone.go:162-169` | HIGH | 通配符动态规则 key 剥 `*.` 前缀 (当前永不匹配) |
| 13.9 | `zone/zone.go:355-360` | HIGH | dynamicEntry 存储 matchTags/rcode/authority/additional 并在 evalDynamic 生效 |
| 13.10 | `zone/zone.go:341-352` | MEDIUM | 动态过滤不匹配时落到普通 exact/wildcard 匹配 |
| 13.11 | `zone/zone.go:165` | MEDIUM | 畸形 match tag 返回错误 (勿静默变成 match-all) |
| 13.12 | `zone/wire.go:95-98` | HIGH | RFC3597 回退设 Rrtype + 要求真正 `\# len hex` 内容, 否则记录级错误 |
| 13.13 | `zone/wire.go:69-72` | MEDIUM | 相对记录名拼接到 zone domain |
| 13.14 | `zone/wire.go:23-27` | MEDIUM | Pack 错误至少日志 |
| 13.15 | `zone/wire.go:35-39` | LOW | Unpack 失败 Warn |

**验证**: zone 加载测试 (裸 "." 头、通配符动态规则、转义引号、`. rcode=3`)。

**提交**: `fix: zone evaluator and ruleset (wildcard dynamics, rule key spaces, parser state)`

---

## 批次 14 — CLI (cmd/zjdns)

| # | 位置 | 严重度 | 修复要点 |
|---|------|--------|----------|
| 14.1 | `cli/parse.go:103-105` | HIGH | ParseFlags 返回非零退出码 (解析失败/命令失败), main `os.Exit`; `-h`/`--version` 保持 0 |
| 14.2 | `cli/parse.go:108-113` | MEDIUM | 特殊模式互斥校验 (最多一个 of version/generate-config/dnsstamp/probe; 最多一个 probe 模式), 冲突打印错误 |
| 14.3 | `cli/generate.go:33-36` | HIGH | 生成时代生成 DNSCrypt key pair (不再内嵌静态私钥) |
| 14.4 | `cli/dnsstamp.go:30-32` | MEDIUM | ODoH-target 解码保留 Path (折叠进 Address) 或返回错误 |
| 14.5 | `cli/dnsstamp.go:64-66` | MEDIUM | odoh-target 带 `--stamp-addr` 显式拒绝 |
| 14.6 | `cli/dnsstamp.go:88-91` | LOW | 空路径报错/文档化; odoh-relay 同样规范化 |
| 14.7 | `banner.go:20-20` | LOW | `{version}` 占位符 + strings.ReplaceAll (防 `%` 破坏) |
| 14.8 | `version.go:20-23` | LOW | 元数据逐项独立拼接 (部分 provenance 也显示) |
| 14.9 | `main.go:24` | LOW | banner 写失败 stderr 诊断 |
| 14.10 | `main.go:45-48` | LOW | `run() error` 结构让 defers 可执行 |

**验证**: 手测 `--generate-config`/`--probe` 失败退出码; `--version --generate-config` 冲突报错。

**提交**: `fix: CLI exit codes, DNSCrypt example keygen, ODoH stamp round-trip`

---

## 批次 15 — 脚本 + CI + Docker + 文档 + 杂项

### 15a. scripts/ (12 条)
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `bump-version.sh:21` | HIGH | GNU `\s` → POSIX `[[:space:]]*` (macOS BSD grep) |
| `bump-version.sh:24-26` | HIGH | CURRENT 校验 `^[0-9]+\.[0-9]+\.[0-9]+$` 再算数 |
| `bump-version.sh:39` | MEDIUM | 替换后 `grep -q` 验证; 转义点号; README badge 加 `g` + 验证 |
| `bump-version.ps1:14` | MEDIUM | 锚定版本声明模式 + 校验 + 解析失败 throw |
| `bump-version.ps1:33` | MEDIUM | `[regex]::Escape($Current)` |
| `bump-version.ps1:34-35` | MEDIUM | 替换后验证 + 显式 `-Encoding UTF8` |
| `bump-version.ps1:13` | LOW | `$PSScriptRoot` 锚定路径 |
| `install-hook.sh:8` | MEDIUM | `git rev-parse --git-path hooks/pre-commit` (worktree) |
| `install-hook.sh:15-16` | MEDIUM | 备份现有 hook |
| `install-hook.sh:10-13` | MEDIUM | 仓库上下文预检 |
| `install-hook.ps1:9-12` | MEDIUM | Write-Host + exit 1 (Write-Error 会提前终止) |
| `install-hook.ps1:7` | MEDIUM | `git rev-parse --git-path` + 创建 hooks 目录 |
| `install-hook.ps1:14` | MEDIUM | 现有 hook 备份 |
| `pre-commit:24-26` | HIGH | 先验证 staged 无未暂存修改再格式化 (防无关改动被扫进提交) |
| `pre-commit:23` | MEDIUM | NUL 分隔迭代文件名 (空格/通配符) |
| `pre-commit:15-18` | MEDIUM | 只对 staged Go 文件跑格式化/检查; lint 二进制前置检查 |

### 15b. .github/ (9 条)
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `workflows/deps.yml:31-34` | HIGH | Actions 固定完整 commit SHA (有 secrets 权限的) |
| `workflows/deps.yml:6-8` | MEDIUM | 最小 permissions 块 (contents/pull-requests: write) |
| `workflows/deps.yml:28-29` | MEDIUM | PR 前 `go build/vet/test` 门禁 |
| `workflows/deps.yml:20-21` | MEDIUM | `@latest` 替代 `@main`/`@develop` 移动分支 |
| `workflows/deps.yml:8-10` | LOW | timeout-minutes |
| `workflows/main.yml:6-8` | LOW | concurrency group |
| `workflows/main.yml:15` | MEDIUM | CONTAINTER_TAG 拼写; latest 标签策略 (run_number) |
| `workflows/main.yml:19` | HIGH | 移除 continue-on-error (防单平台 manifest 发布) |
| `workflows/main.yml:57` | LOW | docker buildx 缓存 |
| `workflows/main.yml:121-122` | HIGH | `imagetools create -t :${digest}` (digest 引用非法) |
| `.gitignore` (4 条) | LOW | `.env*` + 例外; `**/dist/`, `bin/`, `build/`; coverage.* ; *.sqlite |
| `.golangci.yml` (4 条) | LOW/MEDIUM | gosec/makezero 空块; enable-all 裁剪; `default-signifies-exhaustive: false`; perfsprint 收窄 |
| `LICENSE:3` | HIGH | ⛔ **用户决定: 许可保持不变, 跳过此修复** — Apache-2.0 + Commons Clause 的法律不一致风险保留 (记录在案) |
| `Dockerfile:1` | MEDIUM | 固定 Go 版本 1.26 |
| `Dockerfile:7` | MEDIUM | COPY + .dockerignore |
| `Dockerfile:13` | HIGH | CA bundle 校验 SHA-256 或从固定镜像复制 |
| `Dockerfile:39` | MEDIUM | 非 root USER + /etc/passwd |

### 15c. docs/ (7 条)
| 位置 | 严重度 | 修复 |
|------|--------|------|
| `debug/routedns/dtls-client.toml:10` | MEDIUM | CA 移出 /tmp (root-only 目录) |
| `debug/routedns/dtls-client.toml:8-9` | MEDIUM | 证书加 `-addext subjectAltName=IP:127.0.0.1` 或加 server-name |
| `debug/routedns/dtls-client.toml:11` | LOW | 删除冗余 bootstrap-address |
| `debug/dnscrypt/proxy-classic-ephemeral.toml:9` | LOW | 加注释引用 server config + 重新生成 stamp 的工具 |
| `debug/dnscrypt/proxy-classic-ephemeral.toml:4` | LOW | log_level 1 |
| `debug/dnscrypt/proxy-classic-ephemeral.toml:2` | LOW | 注释警示 127.0.0.1 勿放宽 |
| `debug/dnscrypt/proxy-classic-ephemeral.toml:6` | LOW | 注释警示性能开销 |
| `dependabot.yml` (2 条) | LOW | 拆分分组 / 忽略 major |

**提交**: `chore: scripts/CI hardening` / `chore: Dockerfile and docs fixes`。LICENSE 问题单独向用户确认后处理。

---

## 验证总纲

1. 每批: `go build ./... && go test ./... -short && go fix ./... && golangci-lint run && golangci-lint fmt` (零警告)。
2. 竞态批次: `go test -race` 覆盖相关包。
3. 回归: 基准测试对比 `docs/benchmark/benchmark-baseline.txt` (`go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort`)。
4. 端到端: `docs/debug/DEBUG.md` 的 TLCP/DTLCP/DNSCrypt E2E 用例; `./zjdns --probe` 各模式。
5. 完成后逐条对照 `01-open-code-review-report.md` 的 384 条评论回查, 确认零遗漏; 更新 `01-open-code-review-report.md` 头部或本文件添加完成标记。

## 建议提交顺序 (15 个提交)

1. `fix: security — DTLCP handshake deadline + remove offline-KSK crypto bypass` (批次 1)
2. `fix: DNSSEC chain-of-trust integrity` (批次 2)
3. `fix: data races on shared resolver/server state` (批次 3)
4. `fix: cache correctness` (批次 4)
5. `fix: parser hardening` (批次 5)
6. `fix: config validation gaps` (批次 6)
7. `fix: listener lifecycle` (批次 7)
8. `fix: recursive resolver correctness` (批次 8)
9. `fix: middleware pipeline` (批次 9)
10. `fix: upstream clients` (批次 10)
11. `fix: server core` (批次 11)
12. `fix: internal utils` (批次 12)
13. `fix: zone evaluator and ruleset` (批次 13)
14. `fix: CLI exit codes and example keygen` (批次 14)
15. `chore: scripts/CI/Docker hardening + docs` (批次 15)

每个提交前呈现 diff 给用户审查 (CLAUDE.md §9)。
