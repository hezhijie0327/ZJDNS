# panic 审计

> agent: `a77fae83d7d3b549d`

发现数: 5

## panic-01 — CRITICAL

- **位置**: `cache/store.go:267`
- **类别**: validation
- **摘要**: Get() 解析 msg_wire 时不检查格式标记 0x02，v3.11.12 之前写入的旧格式条目（裸 zstd，无头部）导致切片越界 panic
- **描述**: Get()（cache/store.go:267-273）无条件把 msgWire[1:3] 当作 numOffsets 解析，从不检查 msgWire[0] == cacheFormatPrePacked（0x02 常量定义于 :50 但从未被读取）。旧格式（git show 93611d5:cache/store.go:340 `msgWire := zdnsutil.Compress(msg.Data)` 即 v3.11.7~v3.11.11 写入的裸 zstd 数据，无头部）条目经升级后仍在 entries 表中：zstd magic 0x28 B5 2F FD → numOffsets = uint16(msgWire[1:3]) = 46383 → wireStart = 3 + 92766 = 92769 > 实际条目长度（压缩后通常 100~2000 字节）→ :273 `wire := msgWire[wireStart:]` 直接 slice-bounds panic；同时 :268 AcquireTTLOffsets(46383) 每次命中分配 ~92KB。数据库层无启动清理（FlushDB 仅 CHAOS 端点触发，migrations 因 database.Version 从不赋值而不执行——round-1 H8 未修），因此升级后每条旧缓存命中必 panic。panic 在 bridge.go:59 HandlePanic 处被恢复，请求被整体丢弃——而 CacheLookup 先于 Resolution 执行，旧行永远不会被刷新替换，缓存域名在驱逐压力前永久不可解析。
- **风险**: 带旧 cache.db 升级到 v3.11.12+ 后，所有旧缓存条目命中即 panic、查询超时，缓存功能整体失效；每次命中额外 92KB 分配加重 GC。
- **修复**: Get() 解析前检查 `len(msgWire) < 3 || msgWire[0] != cacheFormatPrePacked` → 视为 miss（返回 nil,false,false），让 Set 路径用新格式替换旧行；或升级时一次性清理 entries 表。同时在 :269 后加 `if wireStart > len(msgWire) { return nil, false, false }` 防御损坏数据。

## panic-02 — CRITICAL

- **位置**: `server/protocol/dnscrypt/crypto.go:29`
- **类别**: memory
- **摘要**: DNSCrypt encrypt() 无条件 m.Pack() 截断 pre-packed 直发 wire，缓存命中响应被静默清空为仅 header+question 的空 NOERROR
- **描述**: miekg fork 的 Pack()（msg.go:163）在 cap(m.Data) >= Len() 时复用并截断 m.Data：`m.Data = m.Data[:l]`（l = Len()，仅按 Question/Answer/Ns/Extra/Pseudo 字段计算）。pre-packed 快速路径（middleware/response.go:58-68）只设置 qctx.Res.Data（完整 wire）、Answer/Ns/Extra 保持 nil，返回时直接 Put 到协议层。dnscrypt server.go:651 以 isSecure=false 调用 Handler.ServeDNS → qctx.IsSecure=false → shouldAddEDNS=false（无 EDNS 选项、非 DNSSEC 条目、非 debug）→ 快速路径激活 → resp.Data = 完整预打包 wire 到达 encrypt() → :29 `m.Pack()` 将 Data 截断为 header+question（ANCOUNT=0）并覆写 → 客户端收到 NOERROR 但零答案。TLS/DTLS/DoH/DoQ/TLCP 处理器（tls.go:260 等）同样无条件 Pack()，但只因传入 isSecure=true 强制走 Unpack 路径（Data 被置 nil，response.go:87）才幸免——bridge.go:192 已按 `len(Data)==0` 跳过 pack，DNSCrypt 是唯一裸奔入口。
- **风险**: DNSCrypt 客户端的全部缓存命中（无 EDNS 选项客户端）收到空 NOERROR 响应，可解析域名表现为无答案，静默数据丢失；加密后无法被客户端察觉为格式错误。
- **修复**: encrypt() 仿照 bridge.go:192：`if len(m.Data) == 0 { err = m.Pack() }`（Data 已存在时直接使用）；或在 dnscrypt server.go:651 传 isSecure=true 使中间件走 Unpack 路径。其余协议处理器（tls.go:260、dtls.go:194、https.go:179、quic.go:298、tlcp.go、http_tlcp.go:103）应加同样的 Data 跳过保护，消除依赖 IsSecure 的隐式耦合。

## panic-03 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: TCP write-registry refcount 双重 +1（:98 与 :110）仅单次 -1，每请求净 +1，sweep 永不过期、条目无界增长（round-1 H1 修复不完整，regression）
- **描述**: bridge.go:98 与 :110 各执行一次 `entry.refs.Add(1)`（两处注释完全相同，:106-109 是旧代码占位注释的复制残留），而退出路径只有 :115（SERVFAIL）与 :155（goroutine）各一次 `refs.Add(-1)`。计数：正常路径 +1(98)+1(110)-1(155) = 恒 +1；SERVFAIL 路径 +1(98)+1(110)-1(115) = 恒 +1。tasks.go:137 的 sweep 要求 `refs.Load() == 0` 才删除——refs 永不为 0，sweep 全部跳过，每个 TCP 连接的 tcpWriteEntry（含 writeMu + capacity 两个 channel）在 tcpWriteShards 中永久累积，进程生命周期内无界增长。这正是 round-1 H1 的问题（综合报告 H1：refcount 永不归零），本次 shard+锁重构（f7e7f13）封堵了 TOCTOU 却留下了重复增量，修复不完整。
- **风险**: 长时间运行的服务器在 TCP 连接翻腾下内存无界增长（每连接 2 个 channel + 结构体），sweep 成为死代码；Go race detector 无法捕获，需真实流量才能暴露。
- **修复**: 删除 :106-110 的重复 refs.Add(1) 块（保留锁内 :98 的增量即可）；建议补断言测试：请求完成后 entry.refs.Load() == 0。

## panic-04 — MEDIUM

- **位置**: `server/handler/middleware/mqtype.go:180`
- **类别**: rfc
- **摘要**: 递归模式缓存命中时 MQTYPE 合并结果被 response.go 的 Unpack 覆盖丢弃：合并 RR 与 MQRESPONSE 均丢失，RFC 10029 §3.4 静默失效
- **描述**: 缓存命中时 CacheLookup 先设 qctx.Res = buildFromPrePacked（Data=完整 pre-packed wire，Answer/Ns/Extra=nil）。MQTYPE.merge 随后执行 `msg.Answer = mergeRRs(msg.Answer, qr.Answer)`（:180）并 `msg.Pseudo = append(msg.Pseudo, &dns.MQRESPONSE{...})`（:195）——但 msg.Data 仍是旧 wire。Response 中间件（最外层）判定 shouldAddEDNS=true（请求带 MQTYPE-Query → len(Req.Pseudo)>0），跳过直发路径进入 :73 `qctx.Res.Unpack()`——miekg Unpack（msg.go:160）`m.Answer, m.Ns, m.Extra, m.Pseudo = ...[:0]` 全部重置——合并的附加 RRset 与 MQRESPONSE 选项被整体丢弃，客户端只收到普通主响应且无 MQRESPONSE 回执，违反 RFC 10029 §3.4（服务器 MUST 返回 MQTYPE-Response）。仅递归模式缓存命中路径受影响（转发模式由上游处理，miss 路径 msg.Data=nil 不受影响）。
- **风险**: RFC 10029 新特性在递归模式的常见路径（缓存命中）上完全静默失效，客户端请求 NS+DS 合并却只得到主类型且无完成信号，误导依赖 MQRESPONSE 的客户端。
- **修复**: merge() 开始时若 msg.Data != nil（pre-packed），先 `msg.Data = nil` 并在 merge 后由 Pack 重建；或在 merge 后重新执行 buildFromPrePacked 式的 wire 重建（重建时把合并 RR 与 MQRESPONSE 一并打包）。

## panic-05 — MEDIUM

- **位置**: `server/handler/middleware/dns64.go:57`
- **类别**: pool-leak
- **摘要**: 4 处 cache.Get() 调用只 Unpack 不释放池内 TTLOffsets，pre-packed 条目的 TTL-offset 池对象每次命中泄漏
- **描述**: cache.Get()（store.go:268）为 pre-packed 条目从 ttloOffsetsPool 取得 TTLOffsets 切片，唯一释放点是 handler/response.go:67 buildFromPrePacked 中的 cache.ReleaseTTLOffsets。以下调用点直接 entry.Unpack() 使用后既不调用 ReleaseTTLOffsets 也不走 buildFromPrePacked：middleware/dns64.go:57、middleware/mqtype.go:204、resolver/ns_addresses.go:239（lookupCachedRRs，:243 Unpack）、resolver/dnssec/extract.go:189（ZoneKeys，:193 Unpack）。每次命中漏还一个池对象（cap ≤16 的 []uint16，sync.Pool 对象 GC 前驻留），高频 DNS64 AAAA miss 回退与 MQTYPE 合并查询下池周转率持续下降，退化为每命中一次堆分配。
- **风险**: 池对象泄漏导致池命中率下降、热路径分配增加（每 Get 一次 ~32 字节堆分配），违背池化优化的初衷。
- **修复**: 在上述 4 个调用点使用完毕后调用 cache.ReleaseTTLOffsets(entry.TTLOffsets)（注意与 rebuildResponseWire 已释放的路径不冲突——Get 内 latency 路径已替换为新建切片，直接释放 entry.TTLOffsets 幂等）；或在 Get() 返回池切片的契约注释中强制所有调用方释放。

