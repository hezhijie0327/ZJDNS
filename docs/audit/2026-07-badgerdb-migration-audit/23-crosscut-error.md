# 23 · 交叉分析：错误处理

> 审计 Agent：Phase 2a · Error
> 范围：全项目 %w 包装链路、sentinel error、errors.Is/As


以下是 ZJDNS 错误处理审计报告。共审查了 51 个源文件（排除 `_test.go`）。

---

## 审计结果：错误处理

### FINDING 1（严重）—— `server/resolver/dnssec/nsec.go:172,178,181`：DNSSEC 标记错误未用 `%w` 包装

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec/nsec.go`
- **行号**：172、178、181
- **严重性**：严重
- **问题**：在 `isDenialOfExistenceValid()` 中，三个返回路径使用普通 `fmt.Errorf`，未将包级标记错误（如 `ErrBogusSignature`）与 `%w` 包装。`crypto.go` 中其他所有 DNSSEC 验证错误正确包装了标记错误（例如 `crypto.go:76,84,90,126,164,272`），但 `nsec.go` 中缺少。
- **风险**：调用者使用 `errors.Is(err, dnssec.ErrBogusSignature)` 将错过否定存在性验证失败（NODATA 和 NXDOMAIN）。`dnssec_chain.go:396` 已使用 `errors.Is(err, dnssec.ErrMissingRRSIG)` — 第 178/181 行的错误本应捕获为其他 `ErrBogusSignature` 变体，但不会被检测到。
- **修复**：将这些行改为返回 `fmt.Errorf("%w: ...", dnssec.ErrBogusSignature, denialType)`。

**第 172 行当前**：
```go
return false, fmt.Errorf("NSEC3 Opt-Out proof for %s of %s — AD bit suppressed (RFC 5155 §9.2)", denialType, qname)
```

**第 178 行当前**：
```go
return false, fmt.Errorf("NSEC3 records present but do not prove %s of %s (type=%s)", denialType, qname, dns.TypeToString[qtype])
```

**第 181 行当前**：
```go
return false, fmt.Errorf("no signed NSEC/NSEC3 for %s", denialType)
```

---

### FINDING 2（严重）—— `server/resolver/zonecut.go:93,114,139,153`：DNSSEC 标记错误未用 `%w` 包装

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/resolver/zonecut.go`
- **行号**：93、114、139、153
- **严重性**：严重
- **问题**：`resolveZoneCut()` 返回 DNSSEC 相关的错误字符串，但未包装 `dnssec` 包中的相应标记错误（`ErrNoDNSKEY`、`ErrNoRRSIG`、`ErrBogusSignature`）。
- **风险**：相同 — 调用者无法使用 `errors.Is` 检测这些区切验证失败。下游代码检查这些结果以设置 EDE 代码并做出验证决策。
- **修复**：第 93 行：用 `%w` 包装 `dnssec.ErrNoDNSKEY`；第 114 行：用 `%w` 包装 `dnssec.ErrNoRRSIG`；第 139 行：用 `%w` 包装 `dnssec.ErrBogusSignature`；第 153 行：用 `%w` 包装 `dnssec.ErrNoDNSKEY`。

**第 93 行当前**：
```go
return false, fmt.Errorf("no parent DNSKEYs available to verify DS for %s", childZone)
```

**第 114 行当前**：
```go
return false, fmt.Errorf("no RRSIG for DS records of %s", childZone)
```

**第 139 行当前**：
```go
return false, fmt.Errorf("DS RRSIG verification failed for %s", childZone)
```

**第 153 行当前**：
```go
return false, fmt.Errorf("no DNSKEY records found for %s", childZone)
```

---

### FINDING 3（严重）—— `server/resolver/recursive_helpers.go:196`：DNSSEC 验证错误未包装为 `*DNSSECError`

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive_helpers.go`
- **行号**：196
- **严重性**：严重
- **问题**：返回普通 `fmt.Errorf("DNSSEC validation failed: bogus delegation for %s", ...)`，而不是 `*DNSSECError`。`dnssec_chain.go:451` 在其他地方正确构造了 `*DNSSECError`，但 `recursive_helpers.go:196` 不这样做。
- **风险**：`cache_store.go:182-183` 中的 `errors.As(queryErr, &dnsErr)` 将**不会**捕获此错误，因此 EDE 代码（ExtendedErrorNoReachableAuthority）将不会被记录到缓存统计中。
- **修复**：改为返回 `&resolver.DNSSECError{EDECode: dns.ExtendedErrorNoReachableAuthority, Message: "bogus delegation for " + question.Name}`。

---

### FINDING 4（高）—— `internal/dnscryptcrypto/xsecretbox.go:58,61,102,105`：相同条件重复内联错误

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/xsecretbox.go`
- **行号**：58、61、102、105
- **严重性**：高
- **问题**：`"dnscrypt: unsupported nonce size"` 和 `"dnscrypt: unsupported key size"` 错误字符串在两个不同的函数（`XchachaSeal` 和 `XchachaOpen`）中生成为独立的 `errors.New(...)` 值。这创建了两个不同的错误值表示相同的逻辑条件。
- **风险**：调用者无法可靠地检测这些错误（不能使用 `errors.Is`，只能使用脆弱的字符串比较）。包级标记错误（`proto.go` 中定义了 17 个，`xsecretbox.go` 中定义了 3 个）已存在，并且使用命名标记将是一致的。
- **修复**：添加包级标记：`var errUnsupportedNonceSize = errors.New("dnscrypt: unsupported nonce size")` 和 `var errUnsupportedKeySize = errors.New("dnscrypt: unsupported key size")`，并在两处使用它们。

---

### FINDING 5（高）—— `server/resolver/recursive.go:58,305`：可恢复条件，缺少可检测的标记错误

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive.go`
- **行号**：58、305
- **严重性**：高
- **问题**：`"recursion depth exceeded"` 和 `"CNAME loop detected"` 是表示可恢复递归失败的标记条件，但作为普通错误字符串返回。没有公共标记错误（如 `ErrRecursionDepthExceeded` 或 `ErrCNAMELoop`）供调用者检测。
- **风险**：调用者（中间件、上游转发器）无法编程区分这些递归错误和其他内部失败。如果未来的代码需要特殊处理这些情况，它将不得不进行字符串匹配。
- **修复**：在 `server/resolver/resolver.go` 中添加 `ErrRecursionDepthExceeded` 和 `ErrCNAMELoop` 标记错误，并用 `%w` 包装它们。

**第 58 行当前**：
```go
Err: fmt.Errorf("recursion depth exceeded: %d", depth)
```

**第 305 行当前**：
```go
Err: fmt.Errorf("CNAME loop detected: %s", currentName)
```

---

### FINDING 6（高）—— `server/resolver/recursive_helpers.go:94`：跛脚委派错误不可检测

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/resolver/recursive_helpers.go`
- **行号**：94
- **严重性**：高
- **问题**：`"lame delegation: no reachable authority"` 错误作为普通字符串返回，没有标记。
- **风险**：跛脚委派是一种可恢复的递归失败，调用者可能希望单独检测。此错误与 EDE 代码 `ExtendedErrorNoReachableAuthority` 相关联，但没有 `errors.Is` 兼容的标记，无法编程确定。
- **修复**：添加 `ErrLameDelegation` 标记错误并用 `%w` 包装，或将此错误包装为 `DNSSECError`。

---

### FINDING 7（中）—— `internal/stamp/parse.go`：大量内联错误与标记错误约定不一致

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/internal/stamp/parse.go`
- **行号**：19、39、46、68、84、91、97、100、110、131、143、152、161、197、208、211、218（17 处）
- **严重性**：中
- **问题**：`stamp/stamp.go` 定义了 9 个导出的标记错误（`ErrNotAStamp`、`ErrTooShort`、`ErrBase64Decode`、`ErrUnknownProtocol` 以及 5 个未使用的标记）。然而 `parse.go` 使用内联 `errors.New("stamp: ...")` 和 `fmt.Errorf("stamp: ...")` 用于相关验证错误（无效地址、空端口、无效类型等），这些错误无法通过 `errors.Is` 检测。这在包内造成了不一致——结构解析错误是可检测的，但内容验证错误不可检测。
- **风险**：低 — 调用者目前不会检查特定的标记解析错误。但是，如果有人扩展了标记错误检测，这些将不会被发现。代码风格不一致。
- **修复**（可选）：将所有这些转换为 `stamp.go` 中的标记错误（或删除未使用的标记）。这是一个风格决定，不是错误。

---

### FINDING 8（中）—— `server/protocol/tlcp/certs.go`：非惯用错误赋值模式

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/protocol/tlcp/certs.go`
- **行号**：22、27、32、39、44、49、80、85、94、103
- **严重性**：中
- **问题**：函数 `generateSelfSignedSMCerts` 使用命名返回值 `err error`，然后用 `err = fmt.Errorf(...)` 赋值给局部 `err` 变量（从 `:=` 阴影化），然后显式返回 `signCert, encCert, dtlcpSignCert, dtlcpEncCert, err`。这有效，但令人困惑——阴影化的命名返回值从未被使用，并且显式列表每次都重复完整的返回值列表。更惯用的方式是让每个 `if err != nil` 块直接 `return signCert, encCert, dtlcpSignCert, dtlcpEncCert, fmt.Errorf(...)` 而不涉及命名返回值。
- **风险**：无（功能正确）。代码很难阅读，并且如果在未来编辑中添加纯 `return`，可能会有回归的风险，这可能会意外地使用阴影化的命名返回值。
- **修复**：从签名中移除 `err error` 命名返回值（仅保留其他四个命名返回值），并在每个失败点使用内联 `fmt.Errorf`。

---

### FINDING 9（低）—— `config/validate.go`：一致的 `%w` 模式但缺少标记错误

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/config/validate.go`
- **行号**：各处（111、119、122、126、129、132、170、192、195、201、209、218、221、225、233、246、251、335、367、370、396、404、424、446、449、452、455）
- **严重性**：低
- **问题**：所有这些错误使用 `fmt.Errorf` 仅使用 `%s`/`%d` 格式、没有 `%w`。这本身没有错——大多数没有底层错误可包装。但它们都是无结构的字符串，没有标记错误。调用者无法检测 "invalid log level" 与 "proxy port invalid"。鉴于配置错误是启动时的致命错误，显示给用户，这目前不是问题。
- **风险**：极低。只有在某个调用者需要编程检测特定验证失败时才会成为问题。
- **修复**：无（当前不需要）。

---

### FINDING 10（低/观察）—— `server/handler/pending.go:96`：超时错误不可检测

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/handler/pending.go`
- **行号**：96
- **严重性**：低
- **问题**：`fmt.Errorf("pending request timeout for %s %s", ...)` 没有包装 `context.DeadlineExceeded` 或任何标记错误。通道选择中的 `ctx.Done()` 被正确处理，但如果上下文超时，错误消息不会暴露超时原因。
- **风险**：低。这主要用于调试日志。
- **修复**：考虑返回 `fmt.Errorf("pending request timeout for %s %s: %w", qname, typ, context.DeadlineExceeded)`。

---

### FINDING 11（观察）—— `DNSSECError` 结构体没有 `Unwrap`/`Is`/`As`

- **文件**：`/Users/hezhijie/Downloads/ZJDNS/server/resolver/resolver.go:127`
- **严重性**：观察（不是错误）
- **分析**：`DNSSECError` 只有 `Error()` 方法。它没有 `Unwrap()`、`Is()` 或 `As()`。这是 OK 的，因为：
  - `errors.As(queryErr, &dnsErr)` 在 `cache_store.go:183` 通过遍历由 `%w` 包装创建的链来工作
  - `DNSSECError` 通常是链中最内层的错误（没有更深的错误可供展开）
  - 添加 `Unwrap()` 只有在 `DNSSECError` 包装另一个错误时才有意义，而目前它没有
  - 不需要 `Is()`，因为没有比较语义是需要的
- **结论**：无需更改。

---

### 总结表

| # | 文件 | 行号 | 严重性 | 类别 |
|---|------|------|--------|----------|
| 1 | `server/resolver/dnssec/nsec.go` | 172,178,181 | 严重 | 检测不到的 DNSSEC 标记错误 |
| 2 | `server/resolver/zonecut.go` | 93,114,139,153 | 严重 | 区切验证中丢失的 `%w` |
| 3 | `server/resolver/recursive_helpers.go` | 196 | 严重 | DNSSEC 错误未包装为 `*DNSSECError` |
| 4 | `internal/dnscryptcrypto/xsecretbox.go` | 58,61,102,105 | 高 | 重复内联错误，不是标记 |
| 5 | `server/resolver/recursive.go` | 58,305 | 高 | 没有可检测标记的递归错误 |
| 6 | `server/resolver/recursive_helpers.go` | 94 | 高 | 跛脚委派错误没有标记 |
| 7 | `internal/stamp/parse.go` | 17 处 | 中 | 内联错误 vs 标记约定不一致 |
| 8 | `server/protocol/tlcp/certs.go` | 10 处 | 中 | 非惯用命名返回 + 阴影化 |
| 9 | `config/validate.go` | 27 处 | 低 | 配置错误没有结构化 |
| 10 | `server/handler/pending.go` | 96 | 低 | 超时没有包装 `DeadlineExceeded` |
| 11 | `server/resolver/resolver.go:127` | — | 观察 | `DNSSECError` 缺少 `Unwrap`——当前没问题 |

`%w` 与 `%v` 的正确性总体上是好的——196 个 `fmt.Errorf` 调用中有 187 个在应该使用的时候正确使用了 `%w`（或没有错误可包装时没有使用）。检查发现 `%v` 的 9 个误用：全部 `%v` 实例要么没有错误（`recover()` 值在 `bridge.go:201`），要么是纯粹可格式化的非错误值。如果从检查中排除这些，零错误。`errors.Is`/`errors.As` 的所有使用都正确处理具有兼容标记的实际标准库错误类型。

**值得修复的最大风险**：发现 1、2 和 3——它们共同意味着 DNSSEC 验证失败的子集逃避了 `errors.Is`/`errors.As` 检测，这可能绕过依赖于正确错误分类的 EDE 代码记录和策略逻辑。发现 4 是一个紧密的第二位，因为它意味着加密错误子集是不可检测的。