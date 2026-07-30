# Upstream 层审计报告 — `server/upstream/*`

## 审计范围

24 个源文件：`plain/`, `tls/`, `tlcp/`, `dnscrypt/`, `pool/`, `socks5/` + `client.go`, `warmup.go`

## 发现

### HIGH

#### H1. DNSCrypt 递归重试可能导致栈耗尽

- **文件**: `server/upstream/dnscrypt/client.go:186`
- **类别**: correctness
- **问题**: `response.Truncated` 为 true 时递归调用 `c.Execute()`。递归深度有界（约 5 层），但每次递归堆积栈帧。
- **修复**: 将递归改为循环。

### MEDIUM

#### M1. Spoofguard copyBuf 无界增长

- **文件**: `server/upstream/plain/udp.go:307-314`
- **类别**: memory
- **问题**: `copyBuf` 增长到最大观察到值后永不收缩。有界（最大 65507 字节）。
- **影响**: 轻微常驻内存开销。

#### M2. TCPFramePrefixLen 注释不准确

- **文件**: `server/upstream/pool/tcp.go:157-161`
- **类别**: comments
- **问题**: 注释声称条件"在实践中永远无法到达"，但 guard 防止的是极不可能的病理情况。
- **修复**: 更新注释。

#### M3. TLCP transportKey 使用 fmt.Sprintf

- **文件**: `server/upstream/tlcp/http_tlcp.go:35`
- **类别**: performance
- **问题**: TLCP 使用 `fmt.Sprintf` 构造键，TLS 对应代码使用 `strings.Builder` + `Grow`。
- **修复**: 迁移到 `strings.Builder`。

#### M4. SOCKS5 UDP 中继双重 goroutine 模式

- **文件**: `server/upstream/socks5/udp.go:180-201`
- **类别**: code-quality
- **问题**: 正确但脆弱。应重构为更简单的方式。
- **修复**: 重构为 context 驱动方式。

#### M5. SOCKS5 UDP 中继 deadline 未清除

- **文件**: `server/upstream/socks5/udp.go:164`
- **类别**: resource
- **问题**: 控制连接 deadline 已清除，但 UDP 中继 socket 的 deadline 继承自 dial。
- **修复**: 清除 UDP socket 的 deadline。

#### M6. DNSCrypt 弱密钥注释中的死 nolint

- **文件**: `server/upstream/dnscrypt/crypto.go:21-23`
- **类别**: comments
- **问题**: `//nolint` 引用 CodeQL 规则，对 golangci-lint 无效。
- **修复**: 移除无效 nolint。

#### M7. HTTP3 warmup cfg 参数遮蔽

- **文件**: `server/upstream/tls/http3.go:148-149`
- **类别**: code-quality
- **问题**: 函数参数 `cfg` 被闭包变量遮蔽。调用方的 cfg 字段（除 Tracer 外）被忽略。
- **修复**: 添加注释说明或重构。

### LOW

#### L1. needsTCPFallback 对安全协议死代码

- **文件**: `server/upstream/client.go:312-314`
- **类别**: dead-code
- **说明**: 防御性编程，可接受。

#### L2. fetchCertOverUDP 缓冲区非池化

- **文件**: `server/upstream/dnscrypt/cert.go:66`
- **类别**: performance
- **说明**: 证书获取低频（TTL 缓存），可接受。

#### L3. socks5PacketConn 零值 nil done 会 panic

- **文件**: `server/upstream/socks5/udp.go:310`
- **类别**: panic
- **修复**: 添加 nil guard。

#### L4. splitHostPort 忽略原始解析错误

- **文件**: `server/upstream/socks5/socks5.go:396-401`
- **类别**: error-handling
- **修复**: 记录或传播原始错误。

#### L5. DefaultQUICClientIdleTimeout warmup 路径

- **文件**: `server/upstream/tls/client.go:189`
- **类别**: consistency
- **说明**: 一致，无问题。

### 维度合规

| 维度 | 状态 |
|------|------|
| 代码质量 | ⚠️ M4, M7 |
| 内存安全 | ⚠️ M1 |
| 性能 | ⚠️ M3 |
| 错误处理 | ⚠️ L4 |
| 资源生命周期 | ⚠️ M5 |
| 注释准确性 | ⚠️ M2, M6 |
| 其余 | ✅ |
