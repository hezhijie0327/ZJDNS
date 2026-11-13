# ZJDNS Round 6 Foundation 审计报告(只读,仓库未修改)

审计员:Foundation 组。范围:`internal/*` 全部 20 个包(log, pool, ttl, dnsutil, stats, ipdetect, latency, pending, stamp, lrumap, ktls, demux, ipttl, doq, dns64, dnscryptcrypto, resolv, siphash, topk, spillfile)。其中 **spillfile 属 Domain 组重叠范围**,本组仅从 Foundation 视角(锁/IO/池)复核,标注为重叠。

## 前置:Round 5 已修复项状态确认

| Round 5 编号 | 状态 | 证据 |
|---|---|---|
| F-1 HIGH(MSG_PEEK 嗅探自旋) | **已修复** | e1207ac1(零进度退避 + POLLRDHUP)+ bce1518c(RDHUP 后 re-peek、零窗排水)。复核 `internal/demux/sniff_peek.go`:部分头部停留时 poll 唤醒后 `n == prev` 触发 1ms→50ms 指数退避;FIN 带尾数据场景 re-peek 后正确返回 `ErrUnexpectedEOF`。无残留自旋路径 |
| F-2 LOW(Control 注释夸大) | **已修复** | sniff_peek.go 注释已改为 "fresh off Accept with no other reader" 论据 |
| F-3 LOW(ktls/limit.go 声明顺序) | **未修复**(Round 5 标注可选) | 不重复计入,见文末备注 |

`go vet ./internal/...` 干净;`go test ./internal/... -short -count=1` 全绿(20 包)。

## 发现

### F1 | LOW | 协议合规 / 预算数学 | internal/dnscryptcrypto/encryption.go:111-122 + encrypted.go:266-293

**问题**:经典(XChacha20Poly1305)DNSCrypt 客户端查询的 UDP 大小预算在明文 ≥ 3968 字节时被突破。`encryptPadding` 将目标 padding 长度钳制到 `MaxDNSUDPPacketSize - QueryOverhead`(4096−68=4028),但 `Pad`(encryption.go:23)内部会取 `max(minLen, roundup64(len+1))` 重新对齐到 64 字节边界 —— 4028 不是 64 的倍数,而 `roundup64(len+1)` 在 len≥3968 时为 ≥4032,反向覆盖了钳制值:

```
len=3967 → padded=4028 → 密封线宽=52+4028+16=4096  ✓(恰好)
len=3968 → padded=4032 → 密封线宽=4100            ✗
len=5000 → padded=5056 → 密封线宽=5124            ✗ 无上界
```

(算术已用独立程序按源码逐行移植复现,输出如上。)同时 `EncryptedQuery.Encrypt` 的经典路径(encrypted.go:266-293)在 XchachaSeal 之后**没有** `len(query) > MaxDNSUDPPacketSize` 检查 —— 该检查只存在于 PQ 分支(encrypted.go:260-262),所以超大经典查询不会被 `ErrQueryTooLarge` 拦截而是原样发出。

**风险**:上游客户端(`server/upstream/dnscrypt/client.go` executeOnce)对 msgData 无预检;一个 ≥3968 字节的明文查询(如携带巨型 OPT 的伪造客户端查询被转发)会产出 >4096 的 UDP 数据报 → IP 分片,违背 DNSCrypt/DoT Flag Day 的查询预算意图,并可能在丢弃分片的网络上造成该查询永久失败。无内存安全问题(纯长度数学,AEAD 完整)。

**修复建议**(二选一或组合):
- `encryptPadding` 的钳制值向下取 64 对齐:`minWire` 钳制用 `(MaxDNSUDPPacketSize-QueryOverhead) &^ 63`(=3968),并当 `roundup64(len+1) > 3968` 时直接返回错误;
- 更简单:在经典分支复用 PQ 分支的密封后检查 `if !q.IsTCP && len(query) > MaxDNSUDPPacketSize { return ErrQueryTooLarge }`。

### F2 | LOW | 性能 / 锁粒度 | internal/lrumap/lru.go:194-206(Len)、lru.go:292-306(Range)

**问题**:`Len()` 用写锁(`m.mu.Lock`)读 `m.len`,`Range` 用写锁遍历链表。二者只需 `RLock`:`m.len` 与链表指针仅在写锁内变更,读侧并发无任何写竞争。Round 5 曾以"既有小疵、本轮未变更"提及但未计入;本轮计入。

**风险**:`cache/stats.go:139`(`FormatLines` 每次 `.stats` CHAOS 查询)、`EntryCount`、cache flush / delegation snapshot 的 `Range` 均走此路径。频次低(控制面/周期任务),但 sharded map 的 `Len` 会逐 shard 拿写锁,在统计查询与写入高峰重叠时造成不必要的串行化。量级小,纯性能洁癖项。

**修复建议**:`Len` 与 `Range` 改 `RLock/RUnlock`(回调重入约束不变 —— 无论哪种锁,fn 回调进 map 都死锁)。

### F3 | LOW | 性能 / 热路径分配 | internal/dnscryptcrypto/encrypted.go:266-268(经典查询构建)

**问题**:`EncryptedQuery.Encrypt` 经典路径从 nil 起步 `query = append(query, q.ClientMagic[:]...)` → `ClientPk`(32B)→ `Nonce` 半区(12B),连续 3 次扩容(8→40→52 的 growslice),随后 `XchachaSeal` 再做一次大 append。对照:同文件响应路径 `EncryptedResponse.Encrypt`(encrypted.go:118)已预分配 `make([]byte, 0, ResolverMagicSize+NonceSize)`。

**风险**:每条 DNSCrypt 上游查询多付 2-3 次小分配。非最高热路径(DNSCrypt 上游占比有限),量级小但修复是一行。

**修复建议**:`query = make([]byte, 0, QueryOverhead+默认padding预算)` 起步(或至少 `ClientMagicSize+KeySize+NonceSize/2`)。

### F4 | LOW | 性能 / 锁内 IO | internal/spillfile/compact.go:50-85(Warm)【与 Domain 组重叠】

**问题**:`Warm` 在 `s.mu.Lock(); defer Unlock()` 内完成**全部** sorted-region 块读(`ReadAt` 每块一次 pread,行 60-74)**以及** top-N 的 wire 读(行 79-85)—— 与本包自己确立的"元数据在锁内、pread 在锁外"纪律(Get/Entries/Indexed/EntryCount 均已外提)相悖。持锁时长 = 全文件顺序扫描,期间所有 Get/Put/Indexed 排队。

**风险**:当前三个调用方(`cache/spill.go:30`、`cache/latency_spill.go:52`、`server/resolver/delegation_snapshot.go:162`)均为启动路径,运行期影响为零;但该函数是导出 API 且文档未声明"仅限启动调用",一旦被运行期复用(如重建/预热任务)会把整个 store 串行化在磁盘延迟后。附带说明:同包 `Put`(spillfile.go:239-254)也在 `mu` 内做 `WriteAt`,但 spill 写入由单一 AsyncWriter goroutine 串行化、失败回滚复杂度是真实约束,该设计可辩护,不计为发现。

**修复建议**:按 `Entries` 的协议重构 —— 锁内快照 `tailMap` 副本 + `sparse` 切片头 + `fref`,锁外做块读与 wire 读。

## 深审通过(无发现)的要点

- **demux**:R5 修复后的 peekHeader 逐行复核(退避/RDHUP/re-peek 语义正确);`looksLikePlainDNSQuery` 结构闸门与字节掩码逐位核对;`bufferedConn.Read` 缓冲重放与短读语义;queue push/Close 双检竞态(R5 已闭合);sniff 信号量 try-acquire + HandlePanic + defer 释放。
- **ipttl**:`cmsgTTL` 平台 cmsg_len 差异(Linux size_t vs BSD socklen_t)、level/type 偏移、`l >= hdrLen+1` 载荷边界、单读者纪律注释,均正确;capture_other.go 零值防御到位。
- **pool**:Message.Put 容量级路由(2048 类独占)与全部 11 处 AcquireWire/ReleaseWire 调用点抽查(cache/entries.go、handler/response.go、resolve.go、cache_lookup/store、ns_addresses)无双重归还;tcpReadBufPool/dtlsFrameBufPool 的 detach-then-Put 与 frameOK 分支正确。
- **pending**:Token 语义、CompareAndDelete 防陈旧 leader、eviction 回调 Once 竞争、Join 定时器排水、panic 发布-重抛顺序,全部正确(R5 深审结论维持)。
- **stats/topk**:组合计数槽数组索引边界(130/56 槽,最大索引 129/55)、rcode 折叠(bucket 0-24 vs 计数 0-6 的双轨设计有注释)、topk 分片 nil-hashKey 落 shard 0、Timer 排水。RecordRequest 池化记录先清后还。
- **dnscryptcrypto 其余**:XchachaSeal/Open 手写 AEAD 与 x/crypto 构造一致、常数时间比较、verify-before-decrypt;PQ 控制块剥离的 `PQMinControlBlockLen(11) ≥ len(PQControlMagic)(4)` 使 `packet[2:6]` 切片永不越界;ParsePQResumedHeader 双重最小长度闸门;证书 Unmarshal 定长校验先于字段填充。
- **stamp**:LP/VLP 全部边界(`readVLP` 的 `1+length > binLen-pos`、`^0x80` 位运算)、normaliseStampAddr 的 IPv6 括号/端口歧义、BuildDoHURL 的 provider 带端口迁移;parseSecure 的 `bin[9]` 裸读由 Parse 层 min-len 常量(≥13)守护 —— 有命名常量且注释说明防漂移。
- **dnsutil**:FoldCase 类型覆盖表与 presentation 回退的两遍零分配扫描;TruncateWire 的 OPT 保留 + ARCOUNT 修正;PackStreamFrame 别名/拷贝分支;SkipWireName 指针双字节边界;clientip XFF 右行左走 + 单值头拒逗号;HandlePanic 零分配快路径。
- **latency**:probeMu 对 Add/Wait 的互斥、callWg/probeWg 双组、panic 时 sem 释放与 Done 顺序(LIFO 使 Done 先于 recover);icmp 随机 ID/seq + 源 IP 校验;httpPool 关闭语义。
- **log/resolv/dns64/siphash/doq/ttl/ipdetect**:锁无关发布(componentFilter 原子指针)、TimeCache Once 停止;resolv 的 singleflight 重检 + WithoutCancel;k Maxwell;RFC 6052 六种前缀布局逐字节核对;SipHash-2-4 与参考实现一致;dns64 WKP 非全局 IPv4 拒绝。

## 备注(Round 5 遗留未修复、非新发现)

- ktls/limit.go 声明顺序(R5 F-3,LOW 可选):`NewLimitListener` 与 `limitListener` 之间仍隔 `limitConn` 及其方法。纯风格,维持"可不修"结论。

## 汇总表

| 编号 | 严重程度 | 类别 | 位置 | 摘要 |
|---|---|---|---|---|
| F1 | LOW | 协议合规/预算数学 | internal/dnscryptcrypto/encryption.go:111-122, encrypted.go:266-293 | 经典 DNSCrypt UDP 查询明文 ≥3968B 时 Pad 重对齐突破 4096 预算(4100B+),且经典路径缺 PQ 路径的密封后大小检查 |
| F2 | LOW | 性能/锁粒度 | internal/lrumap/lru.go:194-206, 292-306 | Len/Range 用写锁,RLock 即可(R5 已提及未计入) |
| F3 | LOW | 性能/热路径分配 | internal/dnscryptcrypto/encrypted.go:266-268 | 经典查询构建从 nil append 三连扩容;响应路径已有预分配可对照 |
| F4 | LOW | 性能/锁内 IO | internal/spillfile/compact.go:50-85 【Domain 重叠】 | Warm 全程持 mu 完成所有块读与 wire 读,违背本包读外提纪律;当前调用方均为启动路径 |

无 CRITICAL/HIGH/MEDIUM 发现。internal 层整体质量高:R5 修复经复核无回归,池纪律、锁序、边界检查在抽查中未见新漏洞。
