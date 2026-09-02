# 2026-09 全项目审计 — 修复计划

原则:发现即修复。每个 Sprint 后跑质量门禁;全部完成后 benchmark 对比 + E2E(docs/debug)。

## Sprint 1 — CRITICAL + HIGH

| ID | 严重度 | 位置 | 问题 | 修复 | 状态 |
|----|--------|------|------|------|------|
| S1 | CRITICAL | server/defense/poisonguard.go:86-113 | 仅凭 RRSIG 存在即豁免 poisonguard(GFW 可伪造 RRSIG 绕过) | 传入 zoneSigned(链上有已验证 DNSKEY/DS)才豁免 | ✅ |
| D1 | HIGH | cache/store.go:693,701 | Set 在 pool.Put 归零后再读 msg.Data → DNSSEC flag 永假,DO=0 过滤失效 | Put 前捕获 wire 计算 hasDNSSEC | ✅ |
| F1 | HIGH | internal/spillfile/spillfile.go:506-619 vs 846-863 | Get/Indexed 锁外 ReadAt 与 Compact close/reassign 竞态 | ReadAt 纳入临界区 | ✅ |
| P1 | HIGH | server/protocol/tlcp/dtlcp.go:159-165 | standalone DTLCP accept 裸 channel send,Close 并发 → panic 杀死监听 | 导出 Send() 守卫方法并改用 | ✅ |
| P2 | HIGH | server/protocol/dnscrypt/udp.go:189 | processUDPPacket 对 <8B 共享端口数据报 b[:8] 越界 panic → 客户端黑洞 | 入口 MinDNSPacketSize 守卫 | ✅ |
| P3 | HIGH | server/protocol/shared/udp.go:707-755, manager.go:124 | 共享 UDP 每客户端 goroutine 无界 + Manager SetLimit 死代码 + Shutdown 不清扫 dcState | 有界组 + 并发上限 + 关闭清扫 | ✅ |
| U1 | HIGH | server/upstream/pool/{tcp,udp,raw,quic}.go Acquire | 死连接过滤不递减 p.total → 上漂 → 驱逐风暴 | 过滤时同步递减 | ✅ |
| U2 | HIGH | pool/{tcp,udp,raw}.go dialAndAdd | 死替换分支不 p.total++ → 下漂 → 全局上限失效 | 补递增 | ✅ |
| U3 | HIGH | pool/quic.go Put | Put 不 total++、不设 lastUsed、绕过全局上限 | 补齐三件 | ✅ |
| U4 | HIGH | upstream/tls/http3.go:175-193, tls/client.go:272-290 | 代理 DoH3/WarmUpQUIC 缺 conn.Context().Done() 释放 pconn → SOCKS5 relay 泄漏 | 复制 ExecuteQUIC 钩子 | ✅ |
| H1 | HIGH | server/handler/pending.go:104-112 | DoJoin leader panic 不 Done → key 永久毒化,follower 60s 挂起 | recover 后 Done(错误结果) 再 reraise | ✅ |
| D2 | HIGH | cache/cache.go:258-262, cache/latency_spill.go:67-71, resolver/delegation_snapshot.go:174-213 | OnEvict/Range 在 lrumap 锁内同步磁盘写;Compact 期间全缓存停顿 | 有界异步落盘队列 + 单 writer goroutine | ✅ |

## Sprint 2 — MEDIUM(摘要,全文见分区报告)

代码类:F2 spillfile maxKeyLen 越界;F4 demux DetectTCPProtocol 文档/代码矛盾;F5 FoldCase 无条件序列化(0x20 关闭时纯浪费);P-M1 共享 DoH3 流上限 65535/无 IdleTimeout;P-M2 DoH3 accept 循环重复;P-M3 TLCP 监听失败静默跳过;P-M4 DTLS/DTLCP response 重复+截断丢 OPT;P-M5 TLCP DoT 热路径分配;P-M6 TCP demux sniff goroutine 无界;D3 TTL 偏移表 >255 RR 永久 miss;D4 dnscrypt TCP 端口冲突矩阵缺项;D5 FlushDB 先写后截断;D6 Flush 锁内 IO;R3 NS 解析 depth 重置 0;R4/R5 DNSSEC Canonical/KeyTag 分配;S2/U6 capsguard 计数丢更新;S3 poisonguard Debugf 未门控;S4 两个 godoc 错挂;S5 hopguardWarned 无界;U5/S6 spoofguard ID 不还原;U7 DoQ 超时即拆连接;U8 无 ctx dial;U9 五处重复 unpack;U10 dnscrypt fallback 不看取消;H-M1 refresh gate nil 守卫;H-M2 损坏 BLOB 可 panic serve 路径;H-M3 DNS64 CNAME 链不合成;X3 demux 队列 Close 不排水;X4 共享 UDP Shutdown 泄漏 drain goroutine(并入 P3);C-M1 ECS mismatch Warn 刷屏;C-M2 CHAOS 拒绝 Warn 刷屏;C-M3 损坏缓存条目 Warn 刷屏且不自治愈;C-M4 BADCOOKIE 不填充(RFC 8467);E1 NewHandler 8 参数。
文档类:T1 spoofguard 表述相反;T2 池上限三处矛盾;T3 benchmem 基线矛盾;T4 config.example.json 缺 server_name;T5 DEBUG.md spoofguard 日志过期;T6 流程图缺口(fallback/共享端口/replay bound/批量 fan-out/MQTYPE 重试)。

## Sprint 3 — LOW(批量)

godoc 错挂/过期注释/包文档错名(F9/F10/F12/R6/S4/T16/T17)、死代码(F3 demux udp.go、F16、E2/E3、L5-L7、D12/D14、R7/R8)、常量命名(F13/F14/U14/S9/L6)、errors.Is/AsType 一致化(E4/E5)、slices.Sort 迁移(E6/E7/R15)、`_` 丢弃注释(R9/U17/L8)、日志细节(D8/D16/L1-L11)、注释措辞(F11/U11-U13/U12/U16/R10/R11/R12/T18)、池排水(X3/L5/F8)、L1 truncateWire 越界防御、L2-L10 其他、文档 T7-T22。

## 验证

1. `go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt` 零警告
2. `go test -short ./...` + `go test -race -short ./server/... ./cache/...` 全绿
3. 新增回归测试:D1(DNSSEC flag 落盘)、F1(Compact 并发 Get)、P2(短数据报)、U1-U3(total 守恒)、H1(panic 后 key 自愈)、D2(落盘异步化不丢条目)、H-M2(损坏 BLOB)
4. benchmark 对比基线(allocs 零回归)
5. E2E:docs/debug/DEBUG.md — loopback 14 协议、共享端口、MQTYPE 两场景、DNSSEC、defense 六配置、upstream 外网、pprof-dual 泄漏复核
