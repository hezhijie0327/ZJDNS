# Protocol 审计 (server + protocol/* + cmd) — 19 findings: 3H/6M/10L

| ID | 严重度 | 位置 | 问题 | 状态 |
|----|--------|------|------|------|
| P1 | HIGH | protocol/tlcp/dtlcp.go:159-165 | standalone DTLCP accept 裸 channel send;握手失败/idle 关闭并发 → panic 杀死整个监听(78b23d6 漏修路径) | ✅ |
| P2 | HIGH | protocol/dnscrypt/udp.go:189 | processUDPPacket 无长度守卫,共享端口 1 字节数据 b[:8] 越界 panic → 该源地址 DNSCrypt-UDP 永久黑洞 | ✅ |
| P3 | HIGH | protocol/shared/udp.go:707-755, manager.go:124-125 | 共享 UDP 每客户端 goroutine 无界(Server.backgroundGroup 无 SetLimit,Manager 的 SetLimit 死代码);伪造源洪水 → goroutine/内存耗尽 | ✅ |
| P-M1 | MED | protocol/tls/server.go:541-547 | 共享 DoH3 用 DefaultMaxIncomingStreams(65535) 且无 IdleTimeout — 7939c64 只修了独立路径 | ✅ |
| P-M2 | MED | protocol/tls/http3.go:79-161 | DoH3 accept 循环逐行重复两份(M1 即漂移实例) | ✅ |
| P-M3 | MED | protocol/tlcp/tlcp.go:44-46, http_tlcp.go:28-30 | 监听失败仅 Warn+continue,零监听也返回 nil(违背 fail-fast 策略) | ✅ |
| P-M4 | MED | protocol/tls/dtls.go:207-244, tlcp/dtlcp.go:273-318 | sendDTLS/DTLCPResponse 95% 重复;每响应分配;截断丢 OPT(违背 RFC 6891 §6.2.5) | ✅ |
| P-M5 | MED | protocol/tlcp/tlcp.go:120,156 | TLCP DoT 读/写不池化(每查询 ≥3 堆分配,pre-packed 直发契约失效) | ✅ |
| P-M6 | MED | demux/tcp.go:120 | sniff goroutine 每连接一个、10s 窗口无并发上限(静默连接洪水绕过 LimitListener) | ✅ |
| P-L1 | LOW | server/bridge.go:322-351 | truncateWire questionEnd 可越 len(wire)(cap>len 时静默发送陈旧字节) | ✅ |
| P-L2 | LOW | protocol/dnscrypt/persist.go:16 | StateStore 文档引用已删 *database.DB | ✅ |
| P-L3 | LOW | protocol/shared/udp.go:262-398 | 三种 ReadFrom 短缓冲语义不一致(ErrClosed/silent copy/ErrShortBuffer) | ✅ |
| P-L4 | LOW | protocol/shared/udp.go:587,612 | 8192 读缓冲静默截断 >8192 数据报 | ✅ 文档化 |
| P-L5 | LOW | protocol/shared/udp.go:191-198 | Close 不排水 Ch,≤32 个池缓冲被 GC(池效率) | ✅ |
| P-L6 | LOW | server/server.go:380 | 死 `_ = http3PortShared` 语句 | ✅ |
| P-L7 | LOW | protocol/tlcp/http_tlcp.go:130-133,52 | 无 Cache-Control;ErrServerClosed 直比 | ✅ |
| P-L8 | LOW | shared/manager.go:162-189, tls/server.go:319-351 | 关闭路径 `_ =` 无注释 | ✅ |
| P-L9 | LOW | tls/certs.go:109-115, tlcp/certs.go:129-135 | leafNotAfter 双份复制 | ✅ |
| P-L10 | LOW | protocol/tlcp/dtlcp.go:172 | 导出函数裸类型断言 | ✅ |
