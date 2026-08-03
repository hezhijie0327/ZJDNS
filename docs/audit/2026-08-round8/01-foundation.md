# Foundation 组审计 — internal/* 基础层（35 文件，双份独立审计合并）

## HIGH

### H2: server/handler/pending.go:119-139 — Done/OnEvict 竞态（跨包，见综合报告 H2）
- `Done()` 的 `evicted.Load()==false` 检查与 `call.result = cloneQueryResult(result)`（:137，lrumap 锁外）之间，OnEvict（锁内）可写入 `call.result = evictedResult()`（:70）并 close——写-写数据竞争；ABA：Get 取到淘汰后新 leader 存入的新 call，`Delete(key)` 误删新 call。
- 修复：`p.sets.CompareAndDelete(key, call)` 替换 Get+检查+Delete。

## MEDIUM

### M1: internal/lrumap/lru.go:456-467 — `load()` decode 中途失败不备份且保留部分状态
- `DecodeKey`/`DecodeValue` 出错时直接 `return 0, err`，此前已 `m.Set` 的条目留在 map 中，文件原样保留——下一次 `Save()` 用部分数据**静默覆盖原文件且无 .bak**。与 zstd 损坏/文件过短/版本不匹配三个路径（均 `persist.Backup`）不一致；EnablePersist godoc（:355-357）声称"corrupt file 后以 empty map 继续"，与部分加载的实际行为矛盾（cacheCodec.DecodeKey 对截断返回 io.ErrUnexpectedEOF，路径可达）。
- 修复：decode 失败路径同样 `persist.Backup(path)`；godoc 改为如实描述。

### M2: internal/lrumap/lru.go:259 — CompareAndDelete 对不可比较 V 运行时 panic
- `any(e.val) == any(val)` 在 V 为 slice/map/func 时 panic。本项目自身就有 `Map[string, []entryKey]`（PTR 索引）——未来对该 map 调用 CompareAndDelete 即崩。当前三个调用方（*http.Client、int64）安全。
- 修复：godoc 注明 "V must be comparable" 或运行时防御。

### M3: internal/lrumap/dtls_session.go:43-50 — Get 返回浅拷贝，OnEvict 清零抹掉 in-flight 会话
- Set 深拷贝（:34-35）但 Get 浅拷贝——条目被淘汰时 OnEvict（:21-23）`clear(sess.Secret); clear(sess.ID)` 清零共享数组，抹掉并发 Get 结果/进行中握手的关键材料。文件自身 doc 注释（:29-32）声称"eviction zeroing must not wipe memory still referenced by an in-flight handshake or a concurrent Get result"——保证不存在。
- 修复：Get 也深拷贝（slices.Clone ×2），或按注释如实描述。

### M4: internal/persist/persist.go:62-69 — zstd 解压无输出上限（解压炸弹）
- `dec.DecodeAll(raw, nil)` 按内容分配任意大小输出；Load 在版本检查**之前**全量解压。高压缩比损坏/篡改文件可解压出数 GB → 启动 OOM。
- 修复：`zstd.WithDecoderMaxMemory` 或基于文件大小的倍数上限，超限走现有 Backup 路径。

### M5: internal/stamp/encode.go — 编码路径无长度校验，byte(len(x)) 静默截断
- `plainString`/`dnsCryptString`/`encodeSecure` 等对 addr/providerName/path 直接 `byte(len(...))` 截断；`appendHashes`/`appendBootstrapIPs` 对 >127 字节元素 `vlen |= 0x80` 损坏。各处 nolint 注释声称 "bounded to 255"/"VLP length ≤ 127"——**注释与代码不符，不存在任何边界检查**。`--dnsstamp --encode` 用户输入超长时产出损坏 stamp。
- 修复：编码前校验长度并返回错误。

### M6: internal/dnscryptcrypto/encryption.go:118-128 — encryptPadding 4096 上限钳位差一轮 64 对齐
- 钳位到 `MaxDNSUDPPacketSize-QueryOverhead`（4028）后 `Pad` 内部 roundup64 再向上取整 → 实际 wire ∈ [4112, 4180]，**超过 4096 反分片上限 16-84 字节**。PQ 路径有事后检查（encrypted.go:351-353），经典路径（Encrypt）没有——静默违规（DNSCrypt §5.4.2 预算被破坏）。
- 修复：钳位值向下取 64 的倍数（3968），或 `min(roundUp(len+1), 预算)`。

### M7: internal/dnscryptcrypto/certificate.go:199-248 — "failed parse never leaves a partially populated certificate" 文档与实现不符
- `unmarshalPQ` 先拷贝 Signature/PqPublicKey/ClientMagic（:267-272），**之后**才做 client-magic 校验（:271-273）——失败返回时证书部分填充；复用同一 Certificate 先解 PQ 再解 classical 时旧 PQ 字段残留。
- 修复：校验前移到赋值前，或修正文档。

### M8: internal/dnscryptcrypto/proto.go:92,97,110 — 导出的可变 var 数组是虚假不可变保证
- `ResolverMagic`/`CertMagic`/`PQESVersion` 导出且可变，注释声称"fixed array so external callers cannot mutate"——任何包 `ResolverMagic[0] = 0xFF` 合法可编译，全局协议损坏。
- 修复：非导出数组 + 只读访问器。

## LOW（11 项）

| 位置 | 描述 |
|------|------|
| lru.go:281 | `Clear()` 按 `m.cap` 全量预分配，与 New 的 `min(cap, 1024)` 有界预分配不一致——大容量 map 清理时内存尖峰。 |
| lru.go:173-179 | 权重预算更新路径不执行淘汰（`totalWeight` 可长期超 maxWeight，直到新 key 插入）——字节预算不变量可被持续突破（有界，单值最大增量）。 |
| dnscrypt/server.go:440-441,509-510 | `sharedKeyCache.Clear()` 后立即整体 `lrumap.New(...)` 重建——双重清空冗余（新 map 与清空后旧 map 状态相同）。 |
| dns64/dns64.go:97-133 | `ExtractIPv4`/`IsSynthesized` 无生产调用方（仅测试使用）——死代码。 |
| ttl/ttl.go:13-14 | `NowUnix` 文档注释句子截断（"This is an exported var so that test packages" 未写完）。 |
| stamp/stamp.go:254 | 悬空注释 "// String encodes the stamp back to an sdns:// URI."，String() 定义在 encode.go 且无 godoc。 |
| latency/probes.go:125 | 行内注释重复粘贴两次（"deadline advisory..." ×2）。 |
| latency/prober.go:71 | `ProbeIPsLatency` 未检查 nil ctx（`measureIPLatency` 直接 `WithTimeout(nil)` panic）；New 有 nil 保护此函数没有。 |
| dns64/dns64.go:27,135 | `New`/`Synthesize`/`ExtractIPv4` 无 godoc。 |
| dnscryptcrypto/pq.go | 14 个导出函数无 godoc（HKDFSHA256/PQDeriveSharedKey/PQEncapsulate/...）。 |
| dnscryptcrypto/string.go:56-58 | `unescapeChar` 是无操作函数（return b 原样返回），唯一作用是把注释伪装成函数。 |
| latency/probes.go:111,163,166,274 | `_ = conn.Close()`/`SetDeadline` 无丢弃原因注释。 |

## 已排除疑点（有代码证据安全）

- internal/pool：Message.Put 整结构清零（*msg = dns.Msg{}）——"池复用数组"是**错误**认知，数组随即释放给 GC；Buffer cap 不变量正确。
- internal/dnscryptcrypto/dns.go：Normalize UDP 预算用 PQ 51 字节保守上限正确；ReadPrefixed/WritePrefixed 边界完整。
- internal/dnscryptcrypto/encrypted.go：非对称路径长度守卫、PQ 控制块剥离边界、nonce 生成语义正确。
- internal/dnscryptcrypto/keys.go、pq.go：HKDF 参数位置语义正确；PQ 票据 prevKey 旋转逻辑正确。
- internal/dnsutil：ReadTCPMsg pool 归还纪律正确（Unpack 后 slices.Clone 脱离池缓冲）；WriteTCPMsgSegmented 零写守卫；DownloadFile 原子写。
- internal/doq：QUICCodeErrorReserved=0xd098ea5e 符合 RFC 9250 §4.3。
- internal/log：TimeCache goroutine 有 recover + 幂等 Stop。
- internal/latency/prober.go：probeWg Add/Wait 互斥协议正确（22fc4eb 修复后）、信号量 panic 不泄漏槽位。
- internal/latency/httppool.go：get/create 同一锁内，无重复创建。
- internal/persist/manager.go：SaveAll 失败不阻断、快照在锁外。
- internal/siphash：SipHash-2-4 常数与轮数对照参考实现正确。
- internal/stamp/parse.go、stamp.go：VLP 循环必然前进、全部越界守卫；ODoH Target 无 bootstrap VLP 与 draft §4.6.1 一致（已排除）。
- internal/pending：纯 Group 正确。
