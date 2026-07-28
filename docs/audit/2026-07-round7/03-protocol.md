# Protocol 层审计报告 (Phase 1)

审计范围: `server/protocol/{plain,tls,tlcp,dnscrypt}` (24 个源文件, 4 个子包)
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 2 | sharedKeyCache data race、wg.Go() + WaitGroup swap 竞态 |
| HIGH | 4 | DNSCrypt pool bypass、DTLCP 单客户端瓶颈、TLCP DoH nil 响应、ReadTCPMsg pool 缺失 |
| MEDIUM | 6 | workerCap 顺序、冗余 HandlePanic、WriteTimeout 缺失、pool 生命周期 |
| LOW | 4 | 无操作赋值、error 包装、defer 一致性、plain goroutine 追踪 |

**共 16 个发现** (2 CRITICAL, 4 HIGH, 6 MEDIUM, 4 LOW)

## CRITICAL

### C1: DNSCrypt sharedKeyCache data race — decrypt() 和 rotateKeys() 之间

- **文件**: `server/protocol/dnscrypt/crypto.go:180-189` + `server/protocol/dnscrypt/server.go:331`
- **类别**: `race/data-race`
- **描述**: `decrypt()` 访问 `s.sharedKeyCache.Get()/Set()` 无锁保护。`rotateKeys()` 在 `s.mu.Lock()` 下重新赋值 `s.sharedKeyCache = lrumap.New[...](2000)`。decrypt() 中的读与 rotateKeys() 中的写未同步，在指针上创建 data race。
- **风险**: Go race detector 会标记此问题。在极少数情况下（32位架构），可能读到损坏的指针。
- **修复**: 在 decrypt() 中将 sharedKeyCache 与 keys 一起快照：`cacheSnapshot := s.sharedKeyCache`。

### C2: DNSCrypt wg.Go() 绕过 WaitGroup swap 模式

- **文件**: `server/protocol/dnscrypt/server.go:260`
- **类别**: `goroutine-lifecycle`
- **描述**: Go 1.26 的 `sync.WaitGroup.Go()` 内部调用 Add(1)/Done()。Shutdown() 原子交换 WaitGroup（`prevWg := s.wg; s.wg = &sync.WaitGroup{}`），但 serveUDP/serveTCP 在交换前可能调用新 wg 的 Go()，导致 goroutine 追踪到新 WaitGroup 上而 Shutdown 只等待 prevWg。
- **风险**: 竞态相关的 goroutine 泄漏，延长 shutdown 窗口。
- **修复**: 在 serveUDP/serveTCP 热路径中加读锁序列化 wg 交换。

## HIGH

### H1: DNSCrypt decrypt() 绕过 message pool

- **文件**: `server/protocol/dnscrypt/crypto.go:158,194,267`
- **类别**: `performance`
- **描述**: 三处分配 `msg = &dns.Msg{}` 而非 `pool.DefaultMessage.Get()`。每个解密查询产生新的堆分配。
- **风险**: 高负载下 GC 压力增加。
- **修复**: benchmark 验证 pool ownership 语义后改用 pool。

### H2: TLCP DTLCP 同步处理器是单客户端瓶颈

- **文件**: `server/protocol/tlcp/dtlcp.go:264-266`
- **类别**: `performance/DoS`
- **描述**: `handleDTLCPConnections()` 同步调用 `handleDTLCPConnection(conn)`（gotlcp 库限制）。单个慢客户端阻塞所有 DTLCP 流量。
- **风险**: DTLCP 端口上的简单 DoS 向量。
- **修复**: 文档说明为已知限制；新连接到达时已有连接正在服务时添加警告日志。

### H3: TLCP DoH handler nil 响应静默返回 200

- **文件**: `server/protocol/tlcp/http_tlcp.go:95-97`
- **类别**: `error-handling`
- **描述**: ServeDNS() 返回 nil 时，serveDOH() 返回 nil 不写 HTTP 响应。Go HTTP server 写默认 200 OK 空 body，误导客户端。
- **风险**: 客户端收到误导性 200 OK 空 body。
- **修复**: resp == nil 时返回 `http.StatusInternalServerError`。

### H4: ReadTCPMsg 分配 new(dns.Msg) 而非 pool

- **文件**: `internal/dnsutil/tcpframe.go:36`
- **类别**: `performance/cross-protocol`
- **描述**: TLCP DoT handler 使用 ReadTCPMsg（每查询分配一次）而 TLS DoT handler 正确使用 pool.DefaultMessage.Get()。
- **风险**: 每 TLCP/DTLCP 查询多一次分配。
- **修复**: 添加 pooled 变体或让调用方自行管理 pool。

## MEDIUM (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| M1 | `dnscrypt/udp.go:100-105` | workerCap 满时多余的 Get/Put 循环 — 应先检查再获取 buffer |
| M2 | `tlcp/tlcp.go:82,87` | 冗余 HandlePanic（外层和内层都有） |
| M3 | `tls/quic.go:163,172` | 冗余 HandlePanic（同 M2） |
| M4 | `tlcp/http_tlcp.go:38-43` | TLCP DoH server 缺少 WriteTimeout |
| M5 | `dnscrypt/server.go:368-498` | handleHandshake 脆弱的 nil 技巧 — pool 生命周期分离 |
| M6 | `tls/dtls.go:114-116` | SetReadDeadline 失败时 continue 而非 return — 无退避 |

## LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `tlcp/certs.go:89,98` | big.Int 自赋值无操作 |
| L2 | `tls/quic.go:235-236` | respondQUIC %w 包装浪费 — 调用方不展开 |
| L3 | `tls/quic.go:238-240` | pool.Put defer 在 if 块内 — 不一致 |
| L4 | `plain/server.go:34-39` | plain goroutine 未追踪到 errgroup |
