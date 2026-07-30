# Protocol 层审计报告 — `server/protocol/*`

## 审计范围

21 个源文件：`plain/`, `tls/`, `tlcp/`, `dnscrypt/`

## 发现

### HIGH

#### H1. DTLCP 单连接 Accept 造成 DoS 向量

- **文件**: `server/protocol/tlcp/dtlcp.go:265`
- **类别**: goroutine, performance
- **问题**: `handleDTLCPConnections` 同步调用 `handleDTLCPConnection`——同一时间只服务一个 DTLCP 连接。gotlcp 库共享底层 UDP socket 的限制。一个慢客户端可阻塞所有其他 DTLCP 客户端最多 `DefaultDTLSIdleTimeout`（30s）。
- **风险**: 攻击者仅需一个连接即可 DoS 整个 DTLCP 监听器。
- **修复**: 添加连接超时或并发限制。

### MEDIUM

#### M1. makeAddrValidator nil 缓存 panic

- **文件**: `server/protocol/tls/addr_validator.go:18`
- **类别**: panic, validation
- **问题**: 闭包调用 `cache.Get(key)` 但未 nil 检查 cache。当前调用方传入非 nil 缓存，但函数签名未记录此前置条件。
- **修复**: 添加 nil 检查。

#### M2. decrypt 无边界检查

- **文件**: `server/protocol/dnscrypt/crypto.go:146,170`
- **类别**: panic, validation
- **问题**: `b[:ClientMagicSize]` 切片未检查 `len(b)`。当前调用方验证了长度，但函数无防御。
- **修复**: 在 `decrypt` 顶部添加 `len(b) < ClientMagicSize` 检查。

#### M3. plain.Server.Start() 无 nil 检查

- **文件**: `server/protocol/plain/server.go:34`
- **类别**: validation
- **问题**: 未对 `g` 和 `handler` 做 nil 检查。nil 时 `g.Go()` 立即 panic。
- **修复**: 在 `Start` 顶部添加 nil 检查。

### LOW

#### L1. Content-Type 精确匹配拒绝有效参数

- **文件**: `server/protocol/tls/https.go:148-149`
- **类别**: rfc
- **修复**: 使用 `strings.HasPrefix` 代替精确匹配。

#### L2. errgroup.WithContext 返回值被丢弃

- **文件**: `server/protocol/tls/quic.go:138`
- **类别**: context
- **修复**: 命名变量代替 `_`。

#### L3. 自赋值 no-op

- **文件**: `server/protocol/tlcp/certs.go:89,98`
- **类别**: code-quality
- **修复**: 移除 self-assignment 行。

#### L4. 非池化短生命周期消息分配

- **文件**: `server/protocol/dnscrypt/crypto.go:158-268`
- **类别**: performance
- **修复**: 切换到池化消息。

#### L5. 部分绑定失败时孤儿监听器

- **文件**: `server/protocol/plain/tcp.go:24-29`
- **类别**: resource
- **修复**: 失败时关闭已打开的监听器。

#### L6. handleDOQStream 无 stream nil 检查

- **文件**: `server/protocol/tls/quic.go:171`
- **类别**: panic
- **修复**: 添加 nil 检查。

#### L7. DTLS 缓冲区大小限制大记录

- **文件**: `server/protocol/tls/dtls.go:107`
- **类别**: performance
- **修复**: 显式处理 `io.ErrShortBuffer`。

#### L8. 握手时为大小估算分配临时消息

- **文件**: `server/protocol/dnscrypt/server.go:402-425`
- **类别**: performance
- **修复**: 在密钥轮换时预计算和缓存大小。

### 维度合规

| 维度 | 状态 |
|------|------|
| Goroutine 生命周期 | ⚠️ H1 |
| Panic 检测 | ⚠️ M1, M2, M3, L6 |
| 性能 | ⚠️ L4, L7, L8 |
| 资源生命周期 | ⚠️ L5 |
| RFC 一致性 | ⚠️ L1 |
| 代码质量 | ⚠️ L3 |
| 其余 | ✅ |
