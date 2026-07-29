# 27 · 交叉分析：参数校验

> 审计 Agent：Phase 2a · Validation
> 范围：全项目 nil/空/零值、ParseIP 判 nil、_ 丢弃错误


# ZJDNS 参数校验审计报告

## 审计维度

| 维度 | 搜索方法 | 范围 |
|------|----------|------|
| 1 | 导出函数 `func [A-Z]` 检查 nil/空/零值参数 | 全仓库非 `_test.go` |
| 2 | `net.ParseIP` / `net.ParseCIDR` 结果判 nil | 全仓库非 `_test.go` |
| 3 | `_ =` / `_, _` 丢弃的 error 有无注释 | 全仓库非 `_test.go` |
| 4 | `func(_, name string)` 废弃参数 | 全仓库非 `_test.go` |
| 5 | 裸类型断言 `.(Type)` 无 comma-ok | 全仓库非 `_test.go` |

---

## 维度 1: 导出函数未校验 nil/空/零值参数

### 1.1 `cache/async_writer.go:33` — NewAsyncStatsWriter 未校验 db 和 bufferSize

**严重程度:** LOW

**问题:** `NewAsyncStatsWriter(db *database.DB, bufferSize int)` 没有判 `db == nil` 也没有判 `bufferSize <= 0`.

```go
func NewAsyncStatsWriter(db *database.DB, bufferSize int) *AsyncStatsWriter {
    w := &AsyncStatsWriter{
        ch:       make(chan RequestRecord, bufferSize),
        ...
        db:       db,
    }
```

如果 `bufferSize <= 0`，`make(chan RequestRecord, 0)` 创建无缓冲 channel，异步写入会阻塞（生产行为改变）。如果 `db == nil`，`run()` 中对 `w.db` 的后续调用会 panic。

**风险:** `bufferSize <= 0` 导致异步 stats 写入阻塞；`db == nil` 导致 panic。

**修复建议:** 添加参数校验：
```go
if db == nil {
    panic("cache/async_writer: nil database")
}
if bufferSize <= 0 {
    bufferSize = config.DefaultAsyncStatsBufferSize
}
```

### 1.2 `server/handler/pending.go:132` — DoJoin 的 fn 回调可空

**严重程度:** MEDIUM

**问题:** `DoJoin` 接受 `fn func() *resolver.QueryResult` 但未判 nil。

```go
func (p *PendingRequests) DoJoin(... fn func() *resolver.QueryResult) *resolver.QueryResult {
    if qr, follower := p.Join(...); follower {
        return qr
    }
    result := fn()   // nil fn → panic
    ...
}
```

**风险:** 调用方传入 nil 回调导致 panic。

**修复建议:** 添加 `if fn == nil { panic("pending: nil fn") }`。

### 1.3 `server/resolver/resolver.go:233` — ShuffleSlice 接受 nil slice

**严重程度:** LOW

**问题:** 泛型函数 `ShuffleSlice[T any](slice []T)` 没有处理 nil slice。虽然 Go 中 `rand.Shuffle(len(slice), ...)` 在 `len(nil) == 0` 时安全，但这是一个依赖隐式行为的不安全模式。

**风险:** 低。nil slice 不会 panic，但函数应明确处理。

**修复建议:** 添加 `if len(slice) == 0 { return }` 提前返回。

### 1.4 `server/upstream/dnscrypt/client.go:204` — state() 两个返回值都丢弃

**严重程度:** LOW

**问题:**
```go
_, _ = c.state(ctx, addr, providerName, publicKey, server, server.Protocol == config.ProtoDNSCryptTCP)
```
`state()` 返回 `(*dnscryptcrypto.SharedKey, error)`，两者全部丢弃，且**无注释说明原因**。

**风险:**共享密钥计算错误被静默忽略，后续 DNSCrypt 加密/解密使用 nil key 将 panic。

**修复建议:** 要么使用一个返回值（如 `key`）要么添加注释说明为什么丢弃。

---

## 维度 2: `net.ParseIP` / `net.ParseCIDR` 结果未判 nil

代码库中所有 `net.ParseIP` / `net.ParseCIDR` 调用都已检查（共 30+ 处）。以下异常位置经过人工验证为**可接受**（设计上支持 nil IP）：

### 2.1 `server/bridge.go:110,146` — ParseIP 结果直接传给 ServeDNS

**严重程度:** 无（设计上可接受）

**问题:** `net.ParseIP(dnsutil.RemoteIP(w))` 的结果未判 nil 直接传给 `s.handler.ServeDNS(req, ..., false, ...)`。

**分析:** `net.IP` 是 slice 类型，nil 是合法值。`ServeDNS` 在 `clientIP` 为 nil 时使用 `net.IPv4(0,0,0,0)` 作为回退。这是设计意图，非 bug。

### 2.2 `server/protocol/tlcp/http_tlcp.go:93` — ParseIP 结果未判 nil

**严重程度:** 无（设计上可接受）

**分析:** `host, _, _ := net.SplitHostPort(r.RemoteAddr)` 提取的 host 可能是域名（非 IP），`net.ParseIP(host)` 返回 nil。nil IP 传给 `ServeDNS` 是合法的——已有注释说明。

### 2.3 `server/protocol/tls/https.go:116` — ParseIP 结果未判 nil

**严重程度:** 无（设计上可接受）

**分析:** 在 `if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil { clientIP = net.ParseIP(host) }` 中，即使 `SplitHostPort` 成功，host 可能不是 IP（IPv6 加括号的情况已移除）。nil IP 传给 `ServeDNS` 是合法值。

### 2.4 `internal/dnsutil/clientip.go:21` — ParseIP 结果未判 nil

**严重程度:** 无（设计上可接受）

**分析:** 函数文档明确写 "Returns nil for unknown or nil addresses"。返回 nil 是协议的一部分。

---

**结论：维度 2 无需要修复的缺陷。所有 `net.ParseIP` 调用要么显式判 nil，要么以 nil 作为合法 sentinel 值。**

---

## 维度 3: 丢弃 error 缺少注释说明

### 3.1 CRITICAL: 无注释且可能隐藏真实错误的丢弃

#### 3.1.1 `server/upstream/dnscrypt/client.go:204` — 丢弃共享密钥计算错误

**严重程度:** CRITICAL

**问题:**
```go
_, _ = c.state(ctx, addr, providerName, publicKey, server, server.Protocol == config.ProtoDNSCryptTCP)
```
`state()` 返回 `(*dnscryptcrypto.SharedKey, error)`。如果共享密钥计算失败（如密钥类型不匹配），后续加密/解密操作使用 nil SharedKey 将导致 panic。**无任何注释说明为什么丢弃 error。**

**风险:** DNSCrypt 加密路径上的静默数据损坏和 panic。

**修复建议:** 捕获 key 或者至少添加注释 `//nolint // error: shared key computation failure is non-recoverable here; will manifest as encryption panic`。

#### 3.1.2 `edns/padding.go:46` — 丢弃 rand.Read 错误

**严重程度:** MEDIUM

**问题:**
```go
_, _ = rand.Read(paddingBytes)
```
无注释。虽然 `crypto/rand.Read` 在 linux/*bsd 上几乎从不失败，但按 Go 标准库文档它确实可能返回 error。同仓库 `server/upstream/dnscrypt/crypto.go:85` 有注释 `// _ = error: crypto/rand.Read never fails on modern kernels`，此处缺少对应注释。

**风险:** 极低。但如果运行在资源受限环境（如 Linux container with no /dev/urandom），可能产生可预测的 padding。

**修复建议:** 添加注释 `// _ = error: crypto/rand.Read never fails on modern kernels`。

### 3.2 MEDIUM: 无注释但风险较低的丢弃

#### 3.2.1 `cmd/zjdns/cli/probe.go:178` — 丢弃 rand.Read 错误

**严重程度:** MEDIUM

**问题:**
```go
_, _ = rand.Read(b[:])
```
无注释。用于生成随机域名，不影响正确性，但应添加注释解释原因。

**修复建议:** 添加注释 `// _ = error: crypto/rand.Read never fails on modern kernels`。

#### 3.2.2 `cmd/zjdns/cli/probe.go:69` — 丢弃 SplitHostPort 的错误

**严重程度:** LOW

**问题:**
```go
serverName, _, _ := net.SplitHostPort(host)
```
无注释。端口和 error 同时丢弃。

**修复建议:** 可添加注释说明 `_ = port, _ = error: host always in host:port form from URL parsing`。

#### 3.2.3 `server/upstream/socks5/udp.go:186` — 丢弃 Read 错误用于控制通道

**严重程度:** LOW

**问题:**
```go
_, _ = ctrlConn.Read(buf[:])
```
无注释。这是关闭控制连接的一个 side-channel 信号读取，错误是无意义的。但缺少注释。

**修复建议:** 添加注释 `// _ = error: control read is a close signal; any error means connection closed`。

### 3.3 HIGH: 常见模式但无注释的 `_ =` 批量

以下文件中有大量 `_ = db.View(...)`、`_ = db.Update(...)`、`_ = item.Value(...)`、`_ = conn.Close()`、`_ = conn.SetDeadline(...)` 等调用**缺少注释**。这些虽然是惯用模式（BadgerDB View/Update 返回 error 通常只在事务开始时失败，已经通过 `IsClosed()` 过滤；close/setDeadline 错误是 cleanup best-effort），但项目中有已完成注释的对照示例：

**有注释的示例（良好实践）：**
- `internal/dnsutil/keepalive.go:27-28`: `// _ = error: non-fatal — connection is still usable`
- `internal/latency/probes.go:125`: `// _ = error: deadline advisory, benign on closed conn`
- `internal/latency/probes.go:122`: `// _ = error: best-effort cleanup close`

**缺少注释的位置（建议补充）：**

| 文件 | 行号 | 缺少注释的表达式 |
|------|------|-----------------|
| `cmd/zjdns/cli/probe.go` | 82,86,90 | `_ = tcpConn.Close()` — 错误处理时的 cleanup close |
| `cmd/zjdns/cli/probe.go` | 172,243,272 | `defer func() { _ = conn.Close() }()` |
| `cmd/zjdns/cli/probe.go` | 186,205,248,274,288 | `_ = conn.Set*Deadline(...)` |
| `database/db.go` | 62 | `_ = bdb.Close()` — 初始化失败时的 cleanup close |
| `database/db.go` | 149 | `_ = db.entrySeq.Release()` — Close 时释放 sequence |
| `database/keys.go` | 347 | `_ = putBytesLE(...)` — 最后一个字段，偏移量未使用 |
| `database/keys.go` | 360 | `additional, _ = getBytesLE(...)` — 错误意味着数据截断 |
| `ruleset/ruleset.go` | 72,92,142 | `_ = e.db.View(...)` — 迭代计数/加载，不会失败（db 已初始化） |
| `cache/store.go` | 86,200 | `_ = c.db.View(...)` — 初始化后不会失败 |
| `cache/store.go` | 206 | `_ = item.Value(...)` — 仅在事务中调用 item，不会失败 |
| `cache/stats.go` | 45,60,163,183,355,371 | `_ = c.db.Update/View(...)` — 同上 |
| `cache/stats.go` | 73,107,191 | `_ = item.Value(...)` — 同上 |
| `cache/stats.go` | 114 | `_ = txn.Set(...)` — QueryStats 是 best-effort |
| `zone/zone.go` | 265,274,331,362 | `_ = e.db.View(...)` / `_ = item.Value(...)` |
| `zone/parse.go` | 35 | `defer func() { _ = f.Close() }()` |
| `internal/latency/probes.go` | 111 | `_ = conn.Close()` — TCP probe cleanup |
| `internal/latency/probes.go` | 163,166,272 | ICMP/HTTP probe cleanup |
| `server/protocol/tlcp/server.go` | 209 | `_ = srv.Shutdown(ctx)` |
| `server/protocol/tlcp/tlcp.go` | 29,30,88,93 | KeepAlive/ReadDeadline/close |
| `server/protocol/tlcp/dtlcp.go` | 96,110,182 | `_ = conn.Close()` — cleanup close |
| `server/protocol/tls/server.go` | 304,310,315,331 | `_ = t.Close()` / `_ = srv.Shutdown(ctx)` |
| `server/protocol/tls/quic.go` | 64,124,144,147,154,164,184,193,196,207,216,223 | QUIC cleanup close/deadline/streamGroup |
| `server/protocol/tls/http3.go` | 60 | `_ = conn.Close()` |
| `server/protocol/tls/tls.go` | 76,97,98,115,166 | TLS cleanup close/keepalive/deadline |
| `server/protocol/dnscrypt/server.go` | 174,183,186,193,196,246 | cleanup close |

**严重程度:** MEDIUM（批量）。

**风险:** 长期维护时新开发者可能不清楚为什么 error 被丢弃，导致后续修改时错误地开始处理 error 或引入额外复杂性。

**修复建议:** 对高风险丢弃（db.Update/View、item.Value、txn.Set）添加 `// _ = error: [具体原因]` 注释；对 cleanup close/setDeadline 可选择性添加。参考 `internal/dnsutil/keepalive.go` 的注释风格。

---

## 维度 4: `func(_, name string)` 废弃参数

### 4.1 回调/接口实现的废弃参数（可接受）

所有 `func(_, name)` 模式均出现在 LRU map eviction 回调和 pool dial 回调中：

| 文件 | 行号 | 函数签名 |
|------|------|----------|
| `server/upstream/client.go:115` | `func(_ string, d *socks5.Dialer)` | LRU evict，`_` 是 key |
| `server/upstream/tlcp/client.go:36` | `func(_ string, client *http.Client)` | LRU evict，`_` 是 key |
| `server/upstream/tls/quic.go:38` | `func(dialCtx context.Context, _ string)` | dial callback，`_` 是 pool key |
| `server/upstream/tls/http3.go:148` | `func(ctx context.Context, _ string, tlsCfg ...)` | dial callback，`_` 是 addr |
| `server/upstream/tls/client.go:81,86` | `func(_ string, client *http.Client)` | LRU evict，`_` 是 key |

**结论：** 全部是接口实现中的废弃参数（LRU eviction key 不需要用），且 `quic.go:38` 已有注释解释。**无需要修复的问题。**

### 4.2 需要删除的废弃参数

未发现。仓库中使用 `_` 参数的函数全是接口实现或回调，没有应删除的废弃命名参数。

**严重程度:** 无。

---

## 维度 5: 裸类型断言 `.(Type)` 无 comma-ok

### 5.1 CRITICAL: `server/tasks.go:116` — `key.(string)` 无 comma-ok

**严重程度:** CRITICAL

**问题:**
```go
stale = append(stale, key.(string))
```
`s.tcpWriteMu.Range(func(key, value any) bool { ... })` 中的 `key` 是 `any` 类型。如果 `LoadOrStore` 存入的 key 的类型在后续版本中改变（或 mutate），这行会直接 panic。

```go
// 上下文 lines 114-116:
entry, ok := value.(*tcpWriteEntry)   // ← 有 comma-ok
if !ok || entry.lastAccess.Load() < cutoff {
    stale = append(stale, key.(string))  // ← 无 comma-ok！
}
```

**风险:** `tcpWriteMu` 是 `*lrumap.Map[string, *tcpWriteEntry]`，但 `Range` 的 `key` 参数类型是 `any`。如果 key 类型由于重构变成非 string（如 `net.IP`），这一行会在运行时 panic。

**修复建议:** 使用 comma-ok 模式：
```go
if keyStr, ok := key.(string); ok {
    stale = append(stale, keyStr)
}
```

### 5.2 MEDIUM: `server/protocol/dnscrypt/server.go:355` — 裸 `.(ed25519.PublicKey)`

**严重程度:** MEDIUM

**问题:**
```go
rc.PublicKey = dnscryptcrypto.HexEncodeKey(s.signingSK.Public().(ed25519.PublicKey))
```
`signingSK` 是 `ed25519.PrivateKey`，其 `Public()` 返回 `crypto.PublicKey` 接口。这里直接强制断言为 `ed25519.PublicKey` 无 comma-ok。

**风险:** 虽然 `ed25519.PrivateKey.Public()` 的 stdlib 实现确实返回 `ed25519.PublicKey`，但如果后续代码使用包装类型或 mock 对象（如测试），会 panic。

**修复建议:** 使用 comma-ok 模式：
```go
pk, ok := s.signingSK.Public().(ed25519.PublicKey)
if !ok {
    return nil, errors.New("signing key is not Ed25519")
}
rc.PublicKey = dnscryptcrypto.HexEncodeKey(pk)
```

### 5.3 已验证安全的位置

下表所有位置都已使用 comma-ok 模式：

| 文件 | 行号 | 表达式 |
|------|------|--------|
| `server/bridge.go:37` | `w.RemoteAddr().(*net.TCPAddr)` | 用于判断 TCP/UDP，无需值 |
| `server/bridge.go:47` | `entryI.(*tcpWriteEntry)` 含 comma-ok | 安全 |
| `server/tasks.go:114` | `value.(*tcpWriteEntry)` 含 comma-ok | 安全 |
| `internal/lru*` (批次) | 所有池分配都用 comma-ok | 安全 |
| `server/protocol/*` (批次) | 所有类型断言都有 `, ok` | 安全 |
| `server/resolver/*` (批次) | 所有 RR 类型断言都有 `, ok` | 安全 |

---

## 问题汇总

| ID | 分类 | 严重程度 | 文件 | 行 | 描述 |
|----|------|---------|------|----|------|
| 1.1 | 参数未校验 | LOW | `cache/async_writer.go` | 33 | `bufferSize <= 0` 和 `db == nil` 未检测 |
| 1.2 | 参数未校验 | MEDIUM | `server/handler/pending.go` | 123 | `DoJoin` 的 `fn` 回调未判 nil |
| 1.3 | 参数未校验 | LOW | `server/resolver/resolver.go` | 253 | `ShuffleSlice` 未显式处理 nil slice |
| 1.4 | 参数未校验 | LOW | `server/upstream/dnscrypt/client.go` | 204 | `state()` 两返回值全丢弃，无注释 |
| 3.1.1 | error 丢弃 | CRITICAL | `server/upstream/dnscrypt/client.go` | 204 | 静默丢弃共享密钥错误，后续 DNSCrypt 加密会 panic |
| 3.1.2 | error 丢弃 | MEDIUM | `edns/padding.go` | 46 | `rand.Read` 错误无注释（同项目有对照） |
| 3.2.1 | error 丢弃 | MEDIUM | `cmd/zjdns/cli/probe.go` | 178 | `rand.Read` 错误无注释 |
| 3.2.2 | error 丢弃 | LOW | `cmd/zjdns/cli/probe.go` | 69 | `SplitHostPort` 错误无注释 |
| 3.2.3 | error 丢弃 | LOW | `server/upstream/socks5/udp.go` | 186 | 控制通道 Read 错误无注释 |
| 3.3 | error 丢弃 | MEDIUM | ~50 处 | 多个 | 大量 `_ = db.View/Update/Close/SetDeadline` 无注释 |
| 5.1 | 裸类型断言 | CRITICAL | `server/tasks.go` | 116 | `key.(string)` 可能 panic |
| 5.2 | 裸类型断言 | MEDIUM | `server/protocol/dnscrypt/server.go` | 355 | `.(ed25519.PublicKey)` 无 comma-ok |

---

## 优先级建议

**立刻修复（CRITICAL）：**
1. `server/tasks.go:116` — 裸类型断言 → panic 风险
2. `server/upstream/dnscrypt/client.go:204` — 丢弃共享密钥错误 → 加密路径损坏

**高优先级（MEDIUM + 实际影响）：**
3. `server/protocol/dnscrypt/server.go:355` — 裸类型断言（虽 stdlib 保证，但代码素质问题）

**中优先级（MEDIUM）：**
4. `server/handler/pending.go:123` — `fn` nil 未校验
5. `edns/padding.go:46` — `rand.Read` 无注释
6. `cmd/zjdns/cli/probe.go:178` — `rand.Read` 无注释

**低优先级（LOW）：**
7. `cache/async_writer.go:33` — bufferSize 校验
8. 50+ 处 `_ =` 无注释（可分批添加）
9. `server/resolver/resolver.go:253` — nil slice 处理