# 37 · 交叉分析：Go 版本特性

> 审计 Agent：Phase 2b · GoVersion
> 范围：go.mod 版本特性采用、stdlib 替代手写模式、go fix 覆盖


Now I have all the data. Let me compile the complete audit report.

---

## Go 版本特性审计报告

**Go 版本**: `1.26.4` (来自 `go.mod`)
**`go fix ./...`**: 无输出 —— 所有 Go 现代化工具已应用

---

### 发现 1: `errors.AsType[T]` 未使用 (低严重度)

**Go 1.26 新增** `errors.AsType[T](error) (T, bool)`，可替代 `errors.As()` + 前置 `var` 声明。当前代码库有 **11 处** `errors.As()` 调用，其中 **5 处有独立的 var 声明**可被消除：

**1a.** `/Users/hezhijie/Downloads/ZJDNS/cmd/zjdns/cli/probe.go:156`
```go
var netErr net.Error
if errors.As(err, &netErr) && netErr.Timeout() {
```
→ `if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {`

**1b.** `/Users/hezhijie/Downloads/ZJDNS/internal/dnsutil/dnsutil.go:218`
```go
var ne net.Error
if errors.As(err, &ne) && ne.Timeout() {
```
→ 同上

**1c.** `/Users/hezhijie/Downloads/ZJDNS/server/handler/middleware/cache_store.go:183`
```go
var dnsErr *resolver.DNSSECError
if errors.As(queryErr, &dnsErr) {
```
→ `if dnsErr, ok := errors.AsType[*resolver.DNSSECError](queryErr); ok {`

**1d.** `/Users/hezhijie/Downloads/ZJDNS/server/protocol/tls/dtls.go:125`
```go
var netErr net.Error
if errors.As(err, &netErr) && netErr.Timeout() {
```
→ 同 1a

**1e.** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/plain/udp.go:183`
```go
var netErr net.Error
if errors.As(err, &netErr) && netErr.Timeout() {
```
→ 同 1a

**1f.** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/tls/https.go:105`
```go
var netErr net.Error
if errors.As(err, &netErr) && netErr.Timeout() {
```
→ 同 1a

**1g.** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/tls/https.go:110`
```go
var opErr *net.OpError
if errors.As(err, &opErr) && opErr.Temporary() {
```
→ `if opErr, ok := errors.AsType[*net.OpError](err); ok && opErr.Temporary() {`

**1h–1k.** `/Users/hezhijie/Downloads/ZJDNS/server/upstream/tls/http3.go:205,213,218,223`
```go
var qAppErr *quic.ApplicationError
if errors.As(err, &qAppErr) { ... }

var qIdleErr *quic.IdleTimeoutError
if errors.As(err, &qIdleErr) { ... }

var resetErr *quic.StatelessResetError
if errors.As(err, &resetErr) { ... }

var qTransportError *quic.TransportError
if errors.As(err, &qTransportError) && qTransportError.ErrorCode == quic.NoError { ... }
```
→ 全部可替换为 `errors.AsType[T]`

| 风险 | 修复建议 |
|------|----------|
| 低。`errors.As()` 有效，无功能缺陷。仅代码风格现代化 | 将每处 `var x T; errors.As(err, &x)` 替换为 `x, ok := errors.AsType[T](err)` |

---

### 发现 2: `strings.CutPrefix` 替代 HasPrefix + 硬编码下标 (低严重度)

Go 1.21 起有 `strings.CutPrefix(s, prefix) (string, bool)`。3 处使用了 `HasPrefix` + **硬编码长度** 子切片，去掉魔术数字可提高可维护性：

**2a.** `/Users/hezhijie/Downloads/ZJDNS/zone/parse.go:112-113`
```go
if strings.HasPrefix(f, "rcode=") {
    if n, err := strconv.Atoi(f[6:]); err == nil {
```
→ `if rest, ok := strings.CutPrefix(f, "rcode="); ok { if n, err := strconv.Atoi(rest); err == nil {`

**2b.** `/Users/hezhijie/Downloads/ZJDNS/zone/parse.go:116-117`
```go
} else if strings.HasPrefix(f, "match=") {
    curTags = f[6:] // store raw, validated at query time
```
→ `} else if rest, ok := strings.CutPrefix(f, "match="); ok { curTags = rest`

**2c.** `/Users/hezhijie/Downloads/ZJDNS/internal/stamp/stamp.go:95-96`
```go
if !strings.HasPrefix(stampStr, stampPrefix) {
    return nil, ErrNotAStamp
}
bin, err := base64.RawURLEncoding.Strict().DecodeString(stampStr[len(stampPrefix):])
```
→ 
```go
rest, ok := strings.CutPrefix(stampStr, stampPrefix)
if !ok {
    return nil, ErrNotAStamp
}
bin, err := base64.RawURLEncoding.Strict().DecodeString(rest)
```

| 风险 | 修复建议 |
|------|----------|
| 低。功能正确，但硬编码 `6` 和 `len(stampPrefix)` 弱化了意图表达 | 改为 `CutPrefix`，消除魔术数字 |

**注意**: 剩余 7 处 `strings.TrimPrefix`/`TrimSuffix` 调用（`ruleset.go:251,252,258`、`validate.go:231`、`ddr.go:62`、`poisonguard.go:177`）不需要布尔返回值，不适合改为 `CutPrefix`/`CutSuffix`，保持现状即可。

---

### 发现 3: `slices.Backward` 用于反向迭代 (信息性)

**3a.** `/Users/hezhijie/Downloads/ZJDNS/internal/siphash/siphash_test.go:88`
```go
for i := len(msg) - 1; i >= 0; i-- {
    last |= uint64(msg[i]) << (i * 8)
}
```
→ `for i, b := range slices.Backward(msg) { last |= uint64(b) << (i * 8) }`

| 风险 | 修复建议 |
|------|----------|
| 极低。测试文件，非关键路径 | 可选改为 `slices.Backward` |

**3b.** `/Users/hezhijie/Downloads/ZJDNS/server/resolver/resolver.go:257`（Fisher-Yates 洗牌）
```go
for i := len(slice) - 1; i > 0; i-- {
    j := rand.IntN(i + 1)
    slice[i], slice[j] = slice[j], slice[i]
}
```
不适合改为 `slices.Backward` —— 需要索引 `i` 进行元素交换，且循环跳过 `i==0`。保持现状。

---

### 发现 4: `slices` 包其他 API 使用情况 (无问题)

| API | 状态 | 说明 |
|-----|------|------|
| `slices.Reverse` | 未使用，但无可替换的手写模式 | 无发现 |
| `slices.Replace` | 未使用 | 无发现 |
| `slices.Delete` | 未使用 | 无发现 |
| `slices.Insert` | 未使用 | 无发现 |
| `slices.Contains` | **已使用** (10+处) | 合规 |
| `slices.Clone` | **已使用** | 合规 |
| `slices.SortStableFunc` | **已使用** | 合规 |
| `slices.Sort` | **已使用** | 合规 |
| `maps` 包 | 非测试代码中未使用 | 无手动 map copy 模式需更换 |

---

### 发现 5: `new(expr)` 指针简化 (无发现)

Go 1.26 的 `new(expr)`（对任意表达式取指针）在代码库中 **没有适用场景**。现有的 `new(T)` 调用全部是标准类型分配（`new(dns.Msg)`、`new(big.Int)` 等），无 `v := expr(); return &v` 模式可替换。

---

### 总结

| 类别 | 发现数 | 最高严重度 |
|------|--------|-----------|
| `errors.AsType[T]` 未使用 | 11 处 | 低 |
| `strings.CutPrefix` 替代 | 3 处 | 低 |
| `slices.Backward` | 1 处（测试） | 信息性 |
| `new(expr)` | 0 | - |
| `slices.Reverse/Replace/Delete` | 0 | - |
| `go fix` 未应用 | 0 | - |
| **总计** | **15 处** | **低** |

代码库整体对 Go 1.21–1.26 特性的采用程度良好：`slices.SortStableFunc`、`slices.Clone`、`slices.Contains`、`rand.IntN`、`maps.Copy`（测试中）等均已使用。`go fix` 报告无残留现代器。建议优先处理 **发现 2**（消除魔术数字）和 **发现 1**（消除样板 var 声明），**发现 3** 可忽略或仅对测试文件选择性处理。