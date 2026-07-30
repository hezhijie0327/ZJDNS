# Foundation 层审计报告 — `internal/*` + `stats`

## 审计范围

33 个源文件：`internal/dns64/`, `internal/dnscryptcrypto/`, `internal/dnsutil/`, `internal/ipdetect/`, `internal/ipttl/`, `internal/latency/`, `internal/log/`, `internal/lrumap/`, `internal/pending/`, `internal/pool/`, `internal/siphash/`, `internal/stamp/`, `internal/ttl/`, `stats/`

## 发现

### CRITICAL

#### C1. ReadTCPMsg use-after-Put — 池缓冲区数据竞争

- **文件**: `internal/dnsutil/tcpframe.go:36-47`
- **类别**: pool-leak, memory, panic
- **问题**: `ReadTCPMsg` 从 `tcpReadBufPool` 获取缓冲区（L36），`defer Put`（L37），然后将 `msg.Data = buf` 指向池缓冲区（L43）。`Unpack()` 后 `msg.Data` 仍引用池内存。`Put` 在调用方使用 `msg.Data` 之前执行，导致引用已归还的池内存。
- **风险**: 返回的 `dns.Msg.Data` 数据损坏。若另一 goroutine 获取同一缓冲区并写入，构成数据竞争。调用方对返回消息调用 `Pack()` 可能序列化损坏的线格式数据。
- **修复**: `Unpack()` 后 `msg.Data = slices.Clone(msg.Data)`，或改为将缓冲区所有权转移给调用方。

### HIGH

#### H1. ExecuteDoHRequest HTTP 响应体泄漏

- **文件**: `internal/dnsutil/https_dns.go:57,65`
- **类别**: resource, memory
- **问题**: `defer httpResp.Body.Close()`（L57）注册在原始响应体上。L65 `httpResp.Body` 被 `io.NopCloser(io.LimitReader(...))` 替换。deferred close 调用的是 `NopCloser.Close()`（空操作），原始 `httpResp.Body` 永不关闭。
- **风险**: HTTP 连接池耗尽。Go `net/http` transport 在响应体未关闭时无法复用 keep-alive 连接，最终耗尽文件描述符。
- **修复**: 重组 Body.Close()，确保原始响应体被关闭。

### MEDIUM

#### M1. 死参数 `isUDP`

- **文件**: `internal/dnscryptcrypto/encrypted.go:109,163`
- **类别**: dead-code
- **问题**: `EncryptedResponse.Encrypt` 和 `encryptPQResponse` 接收 `isUDP bool` 参数但从不读取。UDP/TCP 区分已由 `maxWireLen > 0` 检查处理。
- **修复**: 从两个函数中移除 `isUDP` 参数并更新调用方。

#### M2. MarshalBinary 文档不准确

- **文件**: `internal/dnscryptcrypto/certificate.go:170-171`
- **类别**: docs
- **问题**: 文档注释说"err is always nil"，但函数签名返回 `error`。error 返回是 `encoding.BinaryMarshaler` 接口要求的。
- **修复**: 更新注释说明 error 仅因接口要求而存在。

#### M3. Decrypt/DecryptPQInitial 参数类型不一致

- **文件**: `internal/dnscryptcrypto/encrypted.go:434,488`
- **类别**: api-design
- **问题**: `Decrypt` 接收 `[KeySize]byte`（固定数组），`DecryptPQInitial` 接收 `[]byte`（切片）。不对称。
- **修复**: 统一参数类型。

#### M4. IdleConnTimeout 但 DisableKeepAlives=true

- **文件**: `internal/latency/httppool.go:56,62`
- **类别**: inefficiency
- **问题**: 非 HTTP3 transport 同时设置 `DisableKeepAlives: true` 和 `IdleConnTimeout`。DisableKeepAlives 为 true 时空闲连接永不复用，IdleConnTimeout 为空操作。
- **修复**: 移除 IdleConnTimeout。

### LOW

#### L1. readVLP 定义在 encode.go 但仅在 parse.go 中使用

- **文件**: `internal/stamp/encode.go:156`
- **类别**: ordering
- **修复**: 移动到 parse.go。

#### L2. splitOptionalPort 错误处理括号 IPv6

- **文件**: `internal/stamp/encode.go:223-230`
- **类别**: correctness
- **修复**: 从括号 IPv6 提取端口时追加 `]`。

#### L3. encryptPQResponse 重复 ESVersion switch

- **文件**: `internal/dnscryptcrypto/encrypted.go:196-249`
- **类别**: code-quality
- **修复**: 提取为单个守卫。

#### L4. stats 高延迟异常值不计入任何桶

- **文件**: `stats/stats.go:120-127`
- **类别**: correctness
- **修复**: >10s 的值计入最后一个桶。

#### L5. EncryptedQuery.Encrypt 先构建再检查大小

- **文件**: `internal/dnscryptcrypto/encrypted.go:339-345`
- **类别**: inefficiency
- **修复**: 构建前检查大小。

### 维度合规

| 维度 | 状态 |
|------|------|
| 代码质量 | ⚠️ M1（死参数） |
| 内存安全 | ❌ C1（use-after-Put） |
| 锁正确性 | ✅ |
| 性能 | ⚠️ L5 |
| Panic 检测 | ❌ C1 |
| 错误处理 | ✅ |
| Context 传播 | ✅ |
| 资源生命周期 | ❌ H1（响应体泄漏） |
| RFC 一致性 | ✅ |
| 常量提取 | ✅ |
