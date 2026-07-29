# 36 · 交叉分析：函数排序

> 审计 Agent：Phase 2b · Ordering
> 范围：全项目 decorder 合规、构造函数位置、方法聚合、146 文件 AST 分析


现在我有足够的数据来编译报告。以下是完整的审计结果。

---

## ZJDNS 函数排序审计报告

范围：146 个非测试 Go 源文件，通过 `go/parser` AST 分析。

---

### 1. 声明顺序（type → const → var → func）

**结论：0 处违规。** `decorder` linter（`golangci-lint` 的一部分）声明顺序规则被正确执行。所有 146 个文件都保持 `type` → `const` → `var` → `func` 的顺序。✅

---

### 2. New* 构造函数与类型定义分离

发现指定类型的 `New*` 构造函数由于中间分布了其他函数/方法而未紧随类型定义的 4 个实例。

#### SEVERE: `internal/log/log.go` — `TimeCache` / `NewTimeCache`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/log/log.go` |
| **类型行号** | 第 41 行 `type TimeCache struct` |
| **构造函数行号** | 第 317 行 `func NewTimeCache() *TimeCache` |
| **间距** | 定义了 20 个函数/方法（整个 Logger 接口 + 四个包级帮助函数 + `sanitizeLogMessage`） |
| **风险** | 读者在阅读 TimeCache 类型后（第 41 行）会期望立即看到其构造函数。相反，他们需要翻越 274 行的 Logger 代码才能找到 `NewTimeCache`（第 317 行）和 `TimeCache` 方法（第 345、361 行）。此外，`DefaultTimeCache` 变量在第 80 行声明，远早于 `NewTimeCache`——虽然对于包级变量来说属于正常的 Go 初始化顺序，但从阅读角度来说会令人困惑。 |
| **修复建议** | 将整个 `TimeCache` 相关代码（`DefaultTimeCache` 变量、`NewTimeCache`、`Now()`、`Stop()`）移到一起，紧跟在 `type TimeCache` 之后，在 Logger 声明块之前。 |

#### MODERATE: `server/upstream/pool/tcp.go` — `ConnPool` / `NewConnPool`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/upstream/pool/tcp.go` |
| **类型行号** | 第 53 行 `type ConnPool struct` |
| **构造函数行号** | 第 324 行 `func NewConnPool(maxConns, maxPipe int)` |
| **间距** | 7 个函数/方法（`newConn`、`Conn.Exchange`、`Conn.readLoop`、`Conn.close`、`Conn.IsFull`、`Conn.IsDead`） |
| **风险** | `ConnPool` 类型在第 53 行定义，但其构造函数在第 324 行才出现。所有 `Conn` 方法（95-319 行）排在中间，将 `ConnPool` 的类型与构造函数及所有 `ConnPool` 方法（340-522 行）分隔开。这迫使读者在发现 `ConnPool` 时扫描整个文件来找到其构造函数。 |
| **修复建议** | 将 `NewConnPool` 移到 `ConnPool` 类型定义（第 53 行附近）之后，`const dnsIDMask` 之前。或者，将 `Conn` 类型和其方法提取到单独的 `conn.go` 文件中。 |

#### MODERATE: `server/upstream/pool/quic.go` — `QUIC` / `NewQUIC`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/upstream/pool/quic.go` |
| **类型行号** | 第 26 行 `type QUIC struct` |
| **构造函数行号** | 第 67 行 `func NewQUIC(maxConns int)` |
| **间距** | 3 个方法（`QUICConn.close`、`QUICConn.isDead`、`QUIC.decDialing`） |
| **风险** | 类似于 tcp.go——`QUICConn` 的帮助方法将 `QUIC` 类型（第 26 行）与其构造函数（第 67 行）分隔开。 |
| **修复建议** | 将 `NewQUIC` 移到 `QUIC.decDialing` 方法之前，紧跟在类型和连接器变量之后。 |

#### LOW: `internal/pool/pool.go` — `Buffer` / `NewBuffer`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/pool/pool.go` |
| **类型行号** | 第 17 行 `type Buffer struct` |
| **构造函数行号** | 第 112 行 `func NewBuffer(size, poolSize int)` |
| **间距** | 3 个函数（`NewMessage`、`Message.Get`、`Message.Put`） |
| **风险** | 轻微。这是一个小文件（155 行），很容易阅读。但构造函数与其类型的分离降低了紧密耦合。 |
| **修复建议** | 将 `NewBuffer` 移到第 17 行 Buffer 类型定义之后，在第 22 行 Buffer 常量和第 34 行 QUIC 错误常量之间；将 `NewMessage` 移到 `Message` 类型定义之后。 |

---

### 3. 方法分散

发现 12 个文件中出现了具有相同接收者的方法被无关的独立函数插入或相互穿插的情况。

#### MODERATE: `cache/stats.go` — 接收者 `Cache`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/cache/stats.go` |
| **范围** | 7 个方法，跨度 337 行（第 29–366 行） |
| **分隔函数** | `upsertQueryStats`（第 100 行）、`parseStatsKey`（第 303 行）、`readNulString`（第 329 行） |
| **风险** | 这三个独立函数是 `RecordRequest` 和 `Stats` 使用的辅助函数，但它们被放在方法声明之间，而非之前或之后。`Cache` 方法布局：`RecordRequest`（第 29 行）→ `upsertQueryStats`（第 100 行）→ `ReverseLookup`（第 53 行）→ `FlushDB`（第 120 行）→ `Clear`（第 145 行）→ `Stats`（第 156 行）→ `parseStatsKey`（第 303 行）→ `readNulString`（第 329 行）→ `UpdateLatency`（第 348 行）→ `LatencyLastProbe`（第 366 行）。布局不规则——`ReverseLookup` 出现在第 53 行，在 `RecordRequest` 的方法体开始之前。 |
| **修复建议** | 按逻辑分组重构：`RecordRequest` + 辅助函数（`upsertQueryStats`、`parseStatsKey`、`readNulString`）作为一个块；`ReverseLookup` 在其自己的块中；`FlushDB` + `Clear`；`Stats`；`UpdateLatency` + `LatencyLastProbe`。这些辅助函数应该从方法之间移到文件末尾。 |

#### MODERATE: `server/resolver/dnssec/nsec.go` — 接收者 `CryptoValidator`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec/nsec.go` |
| **范围** | 7 个方法，跨度 172 行（第 16–188 行） |
| **分隔函数** | `matchesNSECDenial`（第 56 行）、`matchesNSEC3Denial`（第 120 行）、`nsec3HashName`（第 145 行） |
| **风险** | 非方法函数被放在调用它们的 CryptoValidator 方法之间。模式：`verifyNSEC` → `verifyNSECRecord` → `matchesNSECDenial`（独立）→ `verifyNSEC3` → `verifyNSEC3Record` → `matchesNSEC3Denial`（独立）→ `nsec3HashName`（独立）→ `isDenialOfExistenceValid` → `isNXDOMAINValid` → `isNODATAValid`。这些辅助函数是独立函数（无接收者），但被穿插在方法之间，打破了方法分组。 |
| **修复建议** | 将 `matchesNSECDenial`、`matchesNSEC3Denial` 和 `nsec3HashName` 移到文件末尾，在所有 CryptoValidator 方法之后。或者，将它们分组在一个 "Helper functions" 注释块中，放在方法之前或之后。 |

#### MODERATE: `zone/zone.go` — 接收者 `Evaluator`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/zone/zone.go` |
| **范围** | 9 个方法，跨度 346 行（第 79–425 行） |
| **分隔函数** | `extractMatchTagsFromZoneKey`（第 390 行）、`parseZoneKeyTypeClass`（第 406 行） |
| **风险** | 模式：`Evaluate`（第 217 行）→ `queryExact`（第 260 行）→ `queryWildcardBatch`（第 307 行）→ `scanWildcardSuffix`（第 346 行）→ `extractMatchTagsFromZoneKey`（独立，第 390 行）→ `parseZoneKeyTypeClass`（独立，第 406 行）→ `evalDynamic`（方法，第 425 行）。两个独立函数（被 queryExact/scanWildcardSuffix 使用）在 `scanWildcardSuffix` 和 `evalDynamic` 之间。 |
| **修复建议** | 将这两个独立函数移到 `evalDynamic` 方法之后（文件末尾），放在 LoadRules/Evaluate/wildcard 组之后。 |

#### LOW: `edns/ecs.go` — 接收者 `Handler`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/edns/ecs.go` |
| **行号** | 第 132–135 行 |
| **分隔函数** | `isECSOptionEqual`（第 132 行） |
| **风险** | 轻微。这个小型独立函数出现在方法之间，但它被 `detectVia` 使用，而 `detectVia` 是最后一个方法——所以只有 1 个方法在它后面。 |
| **修复建议** | 将其移到文件末尾属于可选项但值得鼓励的做法。 |

#### LOW: `edns/edns.go` — 接收者 `Handler`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/edns/edns.go` |
| **行号** | 第 143–159 行 |
| **分隔函数** | `addrToNetip`（第 143 行） |
| **风险** | 轻微。一个独立帮助函数将 `GenerateServerCookie` 和 `IsServerCookieValid` 委托方法与 `ApplyToMessage` 分开。 |
| **修复建议** | 将 `addrToNetip` 移到 `ApplyToMessage` 之前或文件末尾。 |

#### LOW: `internal/stamp/encode.go` — 接收者 `DNSStamp`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/stamp/encode.go` |
| **行号** | 第 35 行 |
| **分隔函数** | `newStampHeader`（第 35 行） |
| **风险** | 轻微。`String()` 是第一个方法，`newStampHeader` 是它使用的帮助函数——这些函数被放在其他方法之前，而不是文件末尾。 |
| **修复建议** | 将 `newStampHeader` 移到文件末尾，放在 `encodeSecure` 之后。 |

#### LOW: `internal/log/log.go` — 接收者 `TimeCache`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/log/log.go` |
| **行号** | 第 350–357 行 |
| **分隔函数** | `NowUnix`、`NowUnixNano` |
| **风险** | 轻微。这两个包级函数被放在 `TimeCache.Now()` 和 `TimeCache.Stop()` 之间。 |
| **修复建议** | 这是 `#1 TimeCache 分离` 问题的一部分——一次整体重构即可解决。 |

#### LOW: `server/server.go` — 接收者 `Server`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/server.go` |
| **行号** | 第 184–200 行 |
| **分隔函数** | `SetRootFilesDir`（第 184 行）、`isRecursiveMode`（第 190 行） |
| **风险** | 轻微。这两个包级独立函数被放在 `initQueryClient` 和 `initDNSResolver` 方法之间。 |
| **修复建议** | 将 `SetRootFilesDir` 移到文件末尾的独立函数部分（或者更好的是，移到 `init.go` 中）并将 `isRecursiveMode` 移到 `initDNSResolver` 之后。 |

#### LOW: `server/resolver/ns_addresses.go` — 接收者 `Recursive`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/resolver/ns_addresses.go` |
| **行号** | 第 106 行 |
| **分隔函数** | `allRootAddrs`（第 106 行） |
| **风险** | 轻微。一个独立函数将 `getRootServers` 和 `lookupNSAddrsFromCache` 方法分开。 |
| **修复建议** | 将 `allRootAddrs` 移到 `lookupNSAddrsFromCache` 之后。 |

#### LOW: `server/resolver/forward.go` — 接收者 `Resolver`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/resolver/forward.go` |
| **行号** | 第 160 行 |
| **分隔函数** | `captureUpstreamEDE`（第 160 行） |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

#### LOW: `server/resolver/dnssec_chain.go` — 接收者 `Recursive`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/resolver/dnssec_chain.go` |
| **行号** | 第 267 行 |
| **分隔函数** | `rrsigKeyTagMatchesDS`（第 267 行） |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

#### LOW: `server/resolver/nameserver.go` — 接收者 `Recursive`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/resolver/nameserver.go` |
| **行号** | 第 349 行 |
| **分隔函数** | `domainNamesEqual`（第 349 行） |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

#### LOW: `server/upstream/tls/https.go` — 接收者 `Client`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/upstream/tls/https.go` |
| **行号** | 第 82、103 行 |
| **分隔函数** | `transportKey`（第 82 行）、`shouldRetryHTTP`（第 103 行） |
| **风险** | 轻微。这两个函数将 `ExecuteHTTPS` 和 `createDOHClient` 分开。 |
| **修复建议** | 将独立帮助函数移到文件末尾。 |

#### LOW: `internal/dnscryptcrypto/encrypted.go` — 接收者 `EncryptedQuery`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/encrypted.go` |
| **行号** | 第 535 行 |
| **分隔函数** | `ParsePQResumedHeader` |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

#### LOW: `internal/dnscryptcrypto/proto.go` — 接收者 `CryptoConstruction`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/proto.go` |
| **行号** | 第 143 行 |
| **分隔函数** | `MinResponseOverhead` |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

#### LOW: `ruleset/ruleset.go` — 接收者 `Engine`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/ruleset/ruleset.go` |
| **行号** | 第 118 行 |
| **分隔函数** | `splitRuleSetKey` |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

#### LOW: `server/upstream/pool/quic.go` — 接收者 `QUIC`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/server/upstream/pool/quic.go` |
| **行号** | 第 67 行 |
| **分隔函数** | `NewQUIC` |
| **风险** | 轻微；这是已在 `#2 构造函数放置` 中记录的同一条目。 |

#### LOW: `internal/dnscryptcrypto/certificate.go` — 接收者 `Certificate`

| | |
|---|---|
| **路径** | `/Users/hezhijie/Downloads/ZJDNS/internal/dnscryptcrypto/certificate.go` |
| **行号** | 第 322 行 |
| **分隔函数** | `isClientMagicValid` |
| **风险** | 轻微。 |
| **修复建议** | 将其移到文件末尾。 |

---

### 4. 文件末尾的游离声明

两个非测试文件以非函数声明结尾。两者均为预期行为，并非错误。

| 文件 | 最后声明 | 分析 |
|---|---|---|
| `config/defaults.go` | 第 318 行 `var DefaultProjectName` | **可接受。** 这个文件只包含默认值——全是常量和变量，没有函数。定义明确。 |
| `server/handler/context.go` | 第 18 行 `type QueryContext struct` | **可接受。** 这个文件专门用于 `QueryContext` 类型定义。没有函数属于这里。 |

没有发现游离的错误（例如，在函数块之后被错误添加的类型/变量/常量声明）。

---

### 按严重程度汇总

| 严重程度 | 计数 | 问题 |
|---|---|---|
| **SEVERE** | 1 | `internal/log/log.go`: 构造函数距类型 274 行之遥 |
| **MODERATE** | 5 | `server/upstream/pool/tcp.go`、`server/upstream/pool/quic.go`（构造函数放置）；`cache/stats.go`、`server/resolver/dnssec/nsec.go`、`zone/zone.go`（方法分散） |
| **LOW** | 15 | 构造函数间距（`internal/pool/pool.go`）和方法分散（`edns/ecs.go`、`edns/edns.go`、`internal/stamp/encode.go`、`internal/log/log.go`、`server/server.go`、`server/resolver/ns_addresses.go`、`server/resolver/forward.go`、`server/resolver/dnssec_chain.go`、`server/resolver/nameserver.go`、`server/upstream/tls/https.go`、`internal/dnscryptcrypto/encrypted.go`、`internal/dnscryptcrypto/proto.go`、`ruleset/ruleset.go`、`server/upstream/pool/quic.go`、`internal/dnscryptcrypto/certificate.go`） |
| **NONE** | 0 | 声明顺序违规 |

### 优先级修复建议

1. **（严重）** 重构 `internal/log/log.go`——将整个 `TimeCache` 区域（类型 + 构造函数 + 方法 + `DefaultTimeCache`）移到一起，靠近文件顶部。
2. **（中等）** 重构 `server/upstream/pool/tcp.go`——将 `NewConnPool` 移到 `ConnPool` 类型之后。
3. **（中等）** 重构 `server/upstream/pool/quic.go`——将 `NewQUIC` 移到 `type QUIC` 之后。
4. **（中等）** 将 `cache/stats.go` 中的独立函数移到文件末尾。
5. **（中等）** 将 `server/resolver/dnssec/nsec.go` 中的独立函数移到文件末尾。
6. **（中等）** 将 `zone/zone.go` 中的独立函数移到文件末尾。
7. **（低）** 修复 `internal/pool/pool.go` 中的 `NewBuffer` 放置。
8. **（低）** 清理其余 15 个分散放置的实例。