# Upstream 层审计报告 (Phase 1)

审计范围: `server/upstream/*` (18 个源文件, 6 个子包)
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 2 | DoQ 代理地址错误、DNSCrypt deleteState nil 指针竞态 |
| HIGH | 4 | DoH/DoH3 连接泄漏、LRU 传输器清理不完整、QUIC 0-RTT 泄漏、DNSCrypt 过早解锁 |
| MEDIUM | 3 | 池死连接清理、SOCKS5 清理幂等性、LRU Evict 缺失 |
| LOW | 5 | 字符串构建器、端口处理、已弃用 API、池清除、写入超时 |

**共 14 个发现** (2 CRITICAL, 4 HIGH, 3 MEDIUM, 5 LOW)

## CRITICAL

### C1: DoQ+代理地址错误 — poolKey 用作拨号地址

- **文件**: `server/upstream/tls/quic.go:31-54`
- **类别**: `bug`
- **描述**: 配置 SOCKS5 代理时，poolKey 包含服务器地址和代理 URL（如 `"1.1.1.1:853|socks5://..."`），但该 poolKey 被传递给 dialQUIC 闭包作为 addr 参数，然后传递给 `net.ResolveUDPAddr("udp", addr)` 和 `quic.DialAddrEarly()`。导致地址解析失败。
- **风险**: 配置了代理的 DoQ 上游服务器 100% 失败。
- **修复**: dialQUIC 闭包中使用 `server.Address` 而非 poolKey 进行实际拨号。

### C2: DNSCrypt deleteState nil 指针竞态与 Close()

- **文件**: `server/upstream/dnscrypt/state.go:226-231` + `client.go:217-224`
- **类别**: `race`
- **描述**: deleteState() 无锁调用 `c.cache.Delete()`，Close() 在锁下将 `c.cache = nil`。并发 Close + Execute 导致 nil `*lrumap.Map` 上调用方法 → panic。
- **风险**: 服务器关闭期间无条件 panic。
- **修复**: deleteState 中添加 cacheMu 锁 + cache nil 检查。

## HIGH

### H1: DoH/DoH3 传输器未关闭空闲连接

- **文件**: `server/upstream/tls/https.go:50-64`
- **类别**: `resource`
- **描述**: LRU 逐出时 OnEvict 调用 CloseIdleConnections() 而非 Transport.Close()。活跃 TCP 连接保持打开。
- **风险**: TIME_WAIT 状态下的 TCP 连接泄漏。
- **修复**: OnEvict 中取消 Transport context 以强制清理。

### H2: 非池化 DoQ 路径 Err0RTTRejected 连接泄漏

- **文件**: `server/upstream/tls/quic.go:89-95`
- **类别**: `resource`
- **描述**: quic-go DialAddrEarly 返回 (conn, Err0RTTRejected) 时连接可用但代码将任何非 nil error 视为拨号失败，不关闭连接就返回。
- **风险**: 每次 0-RTT 拒绝泄漏一个 QUIC 连接。
- **修复**: 检查 conn != nil 且 err == Err0RTTRejected 时使用连接。

### H3: DNSCrypt PQ 控制块过早解锁

- **文件**: `server/upstream/dnscrypt/client.go:144-156`
- **类别**: `lock`
- **描述**: PQResumeSecret 推导失败时，锁在 else 分支执行前被过早释放，并发 Execute 可能读到陈旧的 state 字段。
- **风险**: 锁边缘情况导致不一致的 state。
- **修复**: 重构为 defer unlock 模式。

### H4: 旧 DoT/DoH 传输器 LRU 逐出未完全清理

- **文件**: `server/upstream/tls/client.go:81-85`
- **类别**: `resource`
- **描述**: OnEvict 只调用 CloseIdleConnections/Close，不取消底层 context。活跃连接泄漏直到 HTTP/2 goroutine 自行超时。
- **风险**: 长期运行的代理中 TCP 连接不定增长。
- **修复**: 存储带可取消 context 的 wrapped http.Client。

## MEDIUM (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| M1 | `dnscrypt/client.go:31-32` | State 缓存无 OnEvict — 旧状态在 GC 前保持内存 |
| M2 | `pool/quic.go:88-94` | 死连接被丢弃时不调用 close() |
| M3 | `socks5/udp.go:206-218` | cleanupLocked 缺少 ctrlConn nil 守卫 |

## LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `tlcp/http_tlcp.go:35` | 缓存键用 fmt.Sprintf 而非 strings.Builder |
| L2 | `dnscrypt/cert.go:46,77` | FetchCert 无默认端口 |
| L3 | `plain/udp.go:49-54` | spoofguardBufPool clear 时机可优化 |
| L4 | `tls/https.go:110` | net.Error.Temporary() 已弃用 — 总是返回 false |
| L5 | `pool/tcp.go:180-181` | writeBuf 无写入超时 |
