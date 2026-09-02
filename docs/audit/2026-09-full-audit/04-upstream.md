# Upstream 审计 (server/upstream/*) — 19 findings: 4H/6M/9L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| U1 | HIGH | pool/{tcp,udp,raw,quic}.go Acquire | 惰性死连接过滤重写 conns[key] 不减 p.total → 单调上漂 → 驱逐风暴 | ✅ |
| U2 | HIGH | pool/{tcp,udp,raw}.go dialAndAdd | 死替换分支 append 不 p.total++ → 下漂 → 全局上限失效 | ✅ |
| U3 | HIGH | pool/quic.go:280-313 | Put 不 total++/不设 lastUsed/绕过全局上限;每次 Remove→Put 循环累积 | ✅ |
| U4 | HIGH | tls/http3.go:175-193, tls/client.go:272-290 | 代理 DoH3 Dial 与 WarmUpQUIC 缺 Context().Done() 关闭 pconn → SOCKS5 relay 2fd+1goroutine/连接泄漏 | ✅ |
| U5 | MED | plain/udp.go:338-339 | collect 死连接路径返回 sg.last 未还原 originalID | ✅ |
| U6 | MED | upstream/client.go:176-190 | noteCapsMismatch 非原子读改写 → 丢更新延迟降级 | ✅ |
| U7 | MED | tls/quic.go:124-128 | 任何非取消错误(含超时)即 Remove 共享 QUIC conn → 同连查询全灭 + 拨号风暴 | ✅ |
| U8 | MED | plain/udp.go:546 | 原始 UDP 回退 net.Dial 无 ctx | ✅ |
| U9 | MED | plain/udp.go:812-946 | 五处重复 unpack-and-stage 块 | ✅ |
| U10 | MED | upstream/client.go:317-343 | DNSCrypt TCP fallback 不看 context.Canceled;UDP 错误被覆盖 | ✅ |
| U11 | LOW | upstream/client.go:164-165 | capsDisabled godoc 错挂 ExecuteQuery | ✅ |
| U12 | LOW | tls/http3.go:86 | "Close() nils the map" 与实际相反 | ✅ |
| U13 | LOW | pool/raw.go:196-198 | "close() closes resultChs" 描述错误 | ✅ |
| U14 | LOW | client.go:133, socks5/udp.go:313,389, tls/dtls.go:218, plain/udp.go:789, quic.go:302 | 魔法数字 | ✅ |
| U15 | LOW | pool/udp.go:100-144 | acquire 清/Put vs release 不清,不一致 | ✅ |
| U16 | LOW | plain/udp.go:389-393,1005-1013 | pickBestTTL 返回 lastTTL 即使选中 prev | ✅ |
| U17 | LOW | socks5/udp.go:158, socks5.go:501-503 | `_ =` 无注释;nil err 用 %w | ✅ |
| U18 | LOW | dnscrypt/state.go:76-107 | adjustQuerySize 陈旧 EWMA 可回退并发升级(良性) | ✅ 注释 |
| U19 | LOW | plain/udp.go:178,292 | 每查询 2 字节 string key 分配 | ✅ |
