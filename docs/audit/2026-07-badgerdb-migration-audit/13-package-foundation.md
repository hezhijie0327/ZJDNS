# 13 · Foundation 包深度审计

> 审计 Agent：Phase 1 · Foundation
> 覆盖：internal/* 全部 12 个子包，22 个非测试文件


以下是针对 `internal/*` 12 个包中所有非测试 Go 文件的全面审计报告，涵盖所有 18 个维度。

---

# 审计报告：`internal/*` 基础包

**项目**: ZJDNS  
**范围**: `internal/log`, `internal/pool`, `internal/ipdetect`, `internal/stamp`, `internal/ttl`, `internal/dnsutil`, `internal/lrumap`, `internal/pending`, `internal/siphash`, `internal/ipttl`, `internal/dns64`, `internal/latency`  
**文件**: 共 22 个文件, ~1300 行非测试代码  
**日期**: 2026-07-29

---

## 总体评估

代码质量整体较高，符合 CLAUDE.md 中的编码规范。架构分层严格遵循 DAG（无循环导入）。`sync.Pool`、`sync.Mutex`、`atomic` 的使用正确。没有发现 CRITICAL 级别的问题。发现了 1 个 HIGH 级别的问题、5 个 MEDIUM 级别的问题和 19 个 LOW 级别的问题。

---

## 详细发现（按严重程度排序）

---

### HIGH

#### H1. 未受控的 TCP 读缓冲分配

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/tcpframe.go:32` |
| **类别** | `memory-safety` |
| **问题** | `ReadTCPMsg` 根据攻击者控制的二进制长度字段（通过 `int(prefix[0])<<8 | int(prefix[1])` 解析）分配 `make([]byte, length)`。虽然长度上限为 `dns.MaxMsgSize` (65535)，但在同一连接上的每次调用都会分配一个新的字节切片。 |
| **风险** | 每秒数千次查询的 DoS 场景下，每次分配 64KB 会对 GC 造成压力。由于 `dns.Msg.Unpack()` 会复用输入的 `msg.Data` 切片，外部调用者必须复制切片才能安全复用（请参阅 `https_dns.go:28` 中通过 `append([]byte{}, msg.Data...)` 复制的模式），导致额外的分配。 |
| **修复建议** | 在 `dnsutil` 中添加一个按连接分级的 `sync.Pool`（键为 `*net.Conn` 或类似标识），用于复用大小最大为 `dns.MaxMsgSize` 的读取缓冲。或者，接受一个可选缓冲参数，让调用者传入一个可复用的缓冲。 |

---

### MEDIUM

#### M1. `DownloadFile` 缺乏上下文（Context）传播

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/download.go:61` |
| **类别** | `context-propagation` |
| **问题** | `DownloadFile` 使用一个包级别的 `downloadClient`（`http.Client{Timeout: 30s}`），未接受 `context.Context`。调用 `client.Get(url)` 使用内部 `context.Background()`，在服务器关闭期间无法取消。 |
| **风险** | 如果服务器在启动期间下载根提示文件（或 zone 文件）时收到关闭信号，`shutdown` 会被阻塞最多 30 秒。 |
| **修复建议** | 将 `DownloadFile(url, path string)` 改为 `DownloadFile(ctx context.Context, url, path string)`。将内部的 `client.Get(url)` 改为 `client.Get(url)`（或者最好是 `client.Do(req.WithContext(ctx))`）。从 `downloadClient` 中移除 `Timeout`，改用上下文的超时。更新 `ResolveDataFile` 以接受 `ctx` 并传播它。 |

#### M2. `LogHandshake` 将所有安全协议硬编码为 "TLS:" 组件前缀

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/dnsutil.go:207` |
| **类别** | `logging-quality` |
| **问题** | `LogHandshake` 按 `info.Role` 将握手详情写入消息体，但日志格式字符串是硬编码的 `"TLS: %s"`。这意味着 TLCP、DTLS 和 DTLCP 握手日志信息会附加 "TLS:" 组件前缀，而不是 `info.Role` 中的内容。根据 CLAUDE.md，"TLCP:" → `TLCP` 组件，"DTLS:" → `TLS`，"DTLCP：" → `TLCP`。这里，TLCP 和 DTLCP 的握手信息归类在 "TLS" 组件下，导致组件过滤不一致。 |
| **风险** | 使用 `log_level: "debug:TLCP"` 过滤将错过 TLCP/DTLCP 握手日志，因为这些日志是在 "TLS" 组件下发出的。操作员/调试者无法独立过滤安全协议的握手信息。 |
| **修复建议** | 将 `info.Role` 传播到日志格式字符串中：`log.Debugf("%s: %s", info.Role, buf.String())`，或者如果格式字符串必须保持静态（为了组件过滤正确性），则在 `log.Debugf` 之前预先添加正确的组件前缀。 |

#### M3. 端口提取逻辑的重复

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/stamp/parse.go:30-52`, `75-92`, `203-219` |
| **类别** | `code-quality` |
| **问题** | 解析器中的 IPv6 感知端口提取模式——`colIndex := strings.LastIndex(s.Address, ":")` + `bracketIndex` 检查 + 空端口验证——在三个解析函数中完全重复：`parsePlainDNS`、`parseDNSCrypt` 和 `parseDNSCryptRelay`。总共约 40 行重复逻辑，差别仅在于默认端口和错误消息。 |
| **风险** | 如果发现端口解析错误，修复必须应用于三个地方。维护开销。 |
| **修复建议** | 提取一个辅助函数 `extractAndValidateIPPort(addr string, defaultPort int) (string, error)`，它返回带有默认端口补齐的 IP:port 字符串，或返回错误。用此辅助函数替换三个重复的块。 |

#### M4. `IsTemporaryError` 中易脆的字符串匹配

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/dnsutil.go:226` |
| **类别** | `error-handling` |
| **问题** | 在 `errors.As` 的 `net.Error` 检查失败后，`IsTemporaryError` 回退到 `strings.Contains(err.Error(), "timeout")`。这会将包含 "timeout" 的错误消息（例如 "got timeout argument: 42"）误分类为临时性错误，并可能遗漏 Go 标准库中已正确调整的错误（例如 `os.SyscallError` 包装的 `syscall.ETIMEDOUT`）。 |
| **风险** | 接受循环使用 `IsTemporaryError` 来决定重试还是中止。误报可能导致无限重试循环；漏报可能导致过早的连接断开。 |
| **修复建议** | 将基于字符串的回退限制为已知会丢失 `net.Error` 接口的特定库错误（例如 quic-go 的 `ApplicationError`）。添加针对特定已知错误包的 `errors.Is` 链，而不是无差别的子串匹配。 |

#### M5. `ProbeIPsLatency` 在 goroutine 启动后缺少上下文取消检查

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/latency/prober.go:84-99` |
| **类别** | `goroutine-lifecycle` |
| **问题** | `ProbeIPsLatency` 中的 goroutine 会在获取信号量之前（第 84-89 行）和之后（第 94-99 行）检查上下文的取消。然而，`measureIPLatency` 会在未被检查的情况下运行更长的代码路径——每个探测步骤可能持续 `stepTimeout` 毫秒（默认为几秒）。如果上下文的截止时间在这些步骤内到期，函数只会在下一个步骤开始之前返回（在 `measureIPLatency` 的第 54 行，`context.WithTimeout` 会在步骤内部取消）。所以并不是泄露，但值得注意。 |
| **风险** | 在高延迟步骤期间，上下文取消的响应延迟最高可达 `stepTimeout`。对于服务器关闭场景不是问题，因为步骤通常很短（<5s）。 |
| **修复建议** | 如果这是一个可观测的问题，可以在 `measureIPLatency` 中的步骤之间添加额外的 `select { case <-ctx.Done(): ... }` 检查。目前风险较低。 |

---

### LOW

#### L1. `TimeCache` goroutine 在没有 `HandlePanic` 的情况下运行

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/log/log.go:324-339` |
| **类别** | `goroutine-lifecycle` |
| **问题** | `TimeCache` goroutine 的延迟恢复部分使用 `fmt.Fprintf(os.Stderr, ...)` 来记录恐慌信息，而不是通过日志框架（日志框架本身可能已经恐慌）。这是正确的做法，但与代码库其余部分使用 `dnsutil.HandlePanic` 的模式不一致。 |
| **风险** | 极低——这是有意为之的正确行为。 |
| **修复建议** | 无需更改（这是正确的）。 |

#### L2. `Message.Get()` 对 `sync.Pool.Get()` 返回 nil 的防御性检查

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/pool/pool.go:86-88` |
| **类别** | `code-quality` |
| **问题** | `Message.Get()` 检查 `v == nil`，但 `sync.Pool` 设置了 `New` 函数，除非 `New` 返回 nil，否则 `Get()` 永远不会返回 nil。第 86 行的检查和第 90 行的类型断言检查是冗余的。 |
| **风险** | 无——只是防御性开销。 |
| **修复建议** | 可选：移除 nil 检查，简化函数为 `return m.pool.Get().(*dns.Msg)`。 |

#### L3. `NewLogger` 在 `Default` 变量之前声明在类型之后

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/log/log.go:77-83` |
| **类别** | `function-ordering` |
| **问题** | CLAUDE.md 规定 "New* constructors immediately follow their type"。但 `Logger` 类型在 `log.go:32` 定义，而 `NewLogger` 在 `log.go:83`，中间插入了 `TimeCache` 类型、所有常量、`Default` 和 `DefaultTimeCache` 变量。这是因为 `Default = NewLogger()` 在第 77 行使用包级别变量初始化，必须出现在函数体之前。 |
| **风险** | 违反了 CLAUDE.md 的排序约定。轻微的风格问题。 |
| **修复建议** | 在文件内部重新组织，使 `Logger` 类型尽早出现，`NewLogger` 在其后，变量在两者之后。 |

#### L4. `Buffer.Put` 在将切片归还到池之前，在本地变量上调用 `clear()`

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/pool/pool.go:149-155` |
| **类别** | `memory-safety` |
| **问题** | `Buffer.Put` 将本地 `buf` 变量设置为 `buf[:b.size]`，然后 `clear(buf)`，然后将 `&buf` 的地址放入池中。但 `clear` 会清除本地切片（而非调用者切片底层的数组）所引用的整个数组范围：由于 `cap(buf) == b.size` 是经过检查的，因此会清除整个数组。这是正确的——调用者在 `Put` 之后不能安全地读取他们的切片。注释说明了这一行为。 |
| **风险** | 无——实现正确。 |
| **修复建议** | 无。这是一个正确的实现。 |

#### L5. `ttl.go` 中多余的 `remaining <= 0` 检查

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/ttl/ttl.go:54-59` |
| **类别** | `code-quality` |
| **问题** | `ShouldPrefetch` 在第 48 行调用 `IsExpired`（如果已过期则返回 `false`），然后重新计算 `remaining := int64(ttlSeconds) - (NowUnix() - timestamp)`，如果 `remaining <= 0` 则返回 `false`。由于 `IsExpired` 已经排除了已过期的情况，第二次检查是多余的，除非 `NowUnix()` 恰好在两次调用之间发生了变化。 |
| **风险** | 一个非常短暂的时间窗口内（约 1ns），`NowUnix()` 可能进位，导致第二个检查捕获到刚好过期的情况。但两个检查都返回 `false`，所以没有行为改变。 |
| **修复建议** | 可选：移除第 58-60 行的检查以简化函数。也可以保留作为防御性编程——两种方式都可接受。 |

#### L6. `extractPrefix` 不处理仅空格的字符串

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/log/log.go:253-258` |
| **类别** | `code-quality` |
| **问题** | `extractPrefix` 检查 `idx <= 0` 后返回 `""`。如果消息是 `": "`（冒号后跟空格），`idx` 为 0，因此返回空字符串。这种情况下，组件过滤降级为允许全部通过。对于格式错误的消息这是正确的行为。 |
| **风险** | 无——设计如此。 |
| **修复建议** | 无。 |

#### L7. `sanitizeLogMessage` 在消息过长时复制

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/log/log.go:287-313` |
| **类别** | `performance` |
| **问题** | 当消息包含控制字符时，`sanitizeLogMessage` 使用 `make([]byte, 0, len(msg))`。这会在慢路径上复制整个消息。控制字符在日志消息中非常罕见，所以这不是问题。 |
| **风险** | 极低——这是正确的防御性清理。 |
| **修复建议** | 无。 |

#### L8. `NowUnix` 可变函数变量

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/ttl/ttl.go:15` |
| **类别** | `data-race` |
| **问题** | `NowUnix` 是一个可变的 `var`（用于测试注入）。如果某个测试在运行时更改它，而生产代码正在读取它（在没有同步的情况下），则存在数据竞争。 |
| **风险** | 仅存在于测试配置不当时。生产代码中，该变量在 `init()` 时设置一次后从未修改。 |
| **修复建议** | 用 `atomic.Int64` 替代，或者通过在测试文件中显式设置包变量来保持 `var` 不变（但附带注释，说明这只适用于测试）。 |

#### L9. `ProbeIPsLatency` 中的结果切片由多个协程写入

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/latency/prober.go:102` |
| **类别** | `data-race` |
| **问题** | 没有竞争：每个 goroutine 通过闭包变量 `idx`（第 78 行的 `i` 副本）写入一个不同的 `results[idx]`。Go 的内存模型保证不同 goroutine 对不同切片元素的操作不会构成数据竞争。代码正确。 |
| **风险** | 无——分析确认正确。 |
| **修复建议** | 无。 |

#### L10. `ICMPBufPool` 类型断言写为检查形式，但类型固定

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/latency/probes.go:192` |
| **类别** | `panic-detection` |
| **问题** | `bufPtr, ok := icmpBufPool.Get().(*[]byte)` 通过 `ok` 检查确保了类型安全，尽管 `New` 始终返回 `*[]byte`。 |
| **风险** | 如果在其他地方向池中放入了错误的类型，会优雅地降级。 |
| **修复建议** | 无——这是正确的模式。 |

#### L11. `probeUDP` 创建连接后立即读取但没有设置读超时

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/latency/probes.go:115-139` |
| **类别** | `goroutine-lifecycle` |
| **问题** | `probeUDP` 基于上下文设置截止时间（第 124-126 行），然后在第 138 行调用 `conn.Read(buffer)`。截止时间正确传播。 |
| **风险** | 无。 |
| **修复建议** | 无。 |

#### L12. `detect()` 没有接受上下文

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/ipdetect/ipdetect.go:42` |
| **类别** | `context-propagation` |
| **问题** | `detect()` 通过 `client.Get(traceURL)` 发出 HTTP GET 请求，该请求使用 `context.Background()`。通过 `client.Timeout` 设置超时，但没有响应关闭信号的方法。注释说：仅在启动时调用。 |
| **风险** | 如果在 IP 检测期间（可能持续最多 3 秒：`ipDetectTimeout`）关闭服务器，关闭会被阻塞。 |
| **修复建议** | 添加 `context.Context` 参数，改为使用 `client.Do(req.WithContext(ctx))`。 |

#### L13. `WriteTCPMsg` 在每次调用时分配长度前缀 + 数据缓冲

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/tcpframe.go:105` |
| **类别** | `performance` |
| **问题** | `WriteTCPMsg(msg.Data)` 中的每个 DNS 消息都会在 `make([]byte, 2+len(msg.Data))` 中分配一个合并的长度前缀 + 消息缓冲。这是正确的（每 RFC 7766 §8），但会产生分配开销。 |
| **风险** | 在基准测试中，每个外发查询的 ~2 次额外分配（一个针对 `msg.Data`，一个针对合并缓冲）会在高 QPS 下累积。 |
| **修复建议** | 对合并缓冲使用 `sync.Pool`，以 `msg.Data` 大小作为键（例如，按 256 字节/1024 字节/4096 字节/65535 字节的级别分组）。 |

#### L14. `msg.ID = 0` 修改 API 调用方的消息

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/https_dns.go:20-21` |
| **类别** | `code-quality` |
| **问题** | `ExecuteDoHRequest` 中调用了 `msg.ID = 0`。这个修改会泄漏到调用方，除非按第 73 行进行恢复。在所有返回路径上（第 25、45、55、62、70 行）都会恢复 ID，但如果函数中间某个位置发生恐慌，则无法恢复。 |
| **风险** | 如果 `ExecuteDoHRequest` 中途发生恐慌，调用方的 `msg` 在恐慌后 ID 会为 0。由于恐慌被视为致命错误且连接会关闭，所以并非实际问题。 |
| **修复建议** | 使用 `defer func() { msg.ID = originalID }()` 确保在恐慌时也能恢复。 |

#### L15. `ServerDOHMsgAccept` 拒绝了 TCP 保活选项

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/dnsutil/https_dns.go:93-96` |
| **类别** | `rfc-consistency` |
| **问题** | 服务器端 DoH 接受函数拒绝了 `TCPKEEPALIVE` 伪选项。这在 RFC 中并没有要求，这是服务器端策略。 |
| **风险** | 发送了 `TCPKEEPALIVE` 选项的合法 DoH 客户端（尽管罕见）会被拒绝。 |
| **修复建议** | 如果这是故意的，请添加注释解释原因。否则，移除该检查（保持兼容性）。 |

#### L16. `DeduptElapsedCyclical` 在每个 RR 上调用 `Clone()`，可能很昂贵

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/ttl/ttl.go:77-96` |
| **类别** | `performance` |
| **问题** | 对于结果集中的每个 RR（可能包含多达 50-100 个记录），`DeduptElapsedCyclical` 调用 `rr.Clone()`，这会在堆上分配新的 RR 结构体。这是为响应合成所必需的，因为不能就地修改缓存的 RR。 |
| **风险** | 在每个更新的响应中，对于包含大量 RR 的响应，会产生中等 GC 压力。 |
| **修复建议** | 如果需要，可以考虑在后续 PR 中为 RR TTL 覆盖使用基于切片的对象池。目前的做法是正确的。 |

#### L17. `Map.Set` 使用了手动锁/解锁，而 `LoadOrStore` 使用了延迟解锁

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/lrumap/lru.go:72-108` |
| **类别** | `code-quality` |
| **问题** | `Set` 和 `Get` 使用 `m.mu.Lock()` + 通过 if-else 路径进行显式 `m.mu.Unlock()`，而 `LoadOrStore` 使用 `defer m.mu.Unlock()`。这种不一致性使得人们更容易在 `Set` 或 `Get` 中引入新的返回语句时忘记调用 `Unlock()`。 |
| **风险** | 如果未来向 `Set` 或 `Get` 添加提早返回路径，可能导致锁泄漏。 |
| **修复建议** | 在 `Set` 和 `Get` 中也改用 `defer m.mu.Unlock()`。手动锁/解锁是相对较快的路径（避免延迟开销约几纳秒），但速度差异可以忽略不计。 |

#### L18. 验证前缀时未检查 `net.ParseIP(ip) == nil` 中 `ip` 为空的情况

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/stamp/encode.go:199` |
| **类别** | `parameter-validation` |
| **问题** | 在 `validateAddrAndHostname` 中，当 `addr` 为空字符串时，`ip`（来自 `splitOptionalPort`）也为空。代码会跳过解析（因为 `addr` 检查从第 189 行的 `addr != ""` 后就进入了早期返回）。所以当 `addr` 为空时，永远不会到达第 199 行的 `net.ParseIP(ip)`。正确。 |
| **风险** | 无——逻辑正确。 |
| **修复建议** | 无。 |

#### L19. `internal/latency/probes.go:125` 中的注释包含了重复文本

| 维度 | 值 |
|-------|-------|
| **文件** | `internal/latency/probes.go:125` |
| **类别** | `documentation-quality` |
| **问题** | `// _ = error: deadline advisory, benign on closed conn // _ = error: deadline advisory, benign on closed conn`——注释文本被复制了两次。 |
| **风险** | 排版错误。对代码没有影响。 |
| **修复建议** | 修复注释为单个副本。 |

---

## 按维度汇总

| 维度 | 发现数量 | 关键发现 |
|-----------|--------|-------------|
| 1. 代码质量 | 3 | M3（重复的端口解析），L2（冗余 nil 检查），L5（多余的检查） |
| 2. 内存安全 | 2 | H1（TCP 读缓冲分配），L4（`Buffer.Put` 清零） |
| 3. 锁正确性 | 1 | L17（`Set` 与 `LoadOrStore` 的锁风格不一致） |
| 4. 耦合度 | 0 | — |
| 5. 架构设计 | 0 | — |
| 6. 性能 | 2 | L13（`WriteTCPMsg` 分配），L16（RR 克隆） |
| 7. 恐慌检测 | 1 | L10（防御性类型断言） |
| 8. 错误处理 | 1 | M4（`IsTemporaryError` 中脆弱的字符串匹配） |
| 9. 上下文传播 | 2 | M1（`DownloadFile` 缺少 ctx），L12（`detect()` 缺少 ctx） |
| 10. 协程生命周期 | 1 | L1（`TimeCache` 恐慌恢复风格） |
| 11. 资源生命周期 | 0 | — |
| 12. 日志质量 | 1 | M2（`LogHandshake` 组件前缀硬编码） |
| 13. 文档质量 | 1 | L19（重复的注释文本） |
| 14. 参数验证 | 1 | L18（空 IP 处理，确认正确） |
| 15. 常量提取 | 0 | — |
| 16. RFC 一致性 | 1 | L15（`ServerDOHMsgAccept` 拒绝 TCPKEEPALIVE） |
| 17. 函数排序 | 1 | L3（`NewLogger` 与类型分离） |
| 18. BadgerDB 存储 | 0 | 这些包中没有使用 BadgerDB |

---

## 未发现问题的维度

- **耦合度 (#4)**: 所有导入均符合 CLAUDE.md 中严格的分层 DAG。`internal/latency` 导入 `config`（允许），`internal/dnsutil` 导入 `internal/log`（允许）。`internal/stamp`、`internal/siphash`、`internal/ipttl` 根本没有任何 zjdns 内部导入。
- **架构设计 (#5)**: 无 god 包。命名一致（PascalCase 导出，camelCase 未导出）。`lrumap.Map` 和 `pending.Group` 中使用泛型是正确的。
- **资源生命周期 (#11)**: 所有 `Close()` 方法都是幂等的（通过 `closeOnce` 或 nil 检查）。`New`/`Close` 在所有检查过的包中都是对称的。
- **常量提取 (#15)**: 所有的魔法数字都是命名的。在 `dnsutil/keepalive.go` 和 `ipdetect/ipdetect.go` 中存在一些与 `config` 的重复，但这些是由于导入层级限制造成的，有注释说明。
- **BadgerDB (#18)**: 这些包都没有直接使用 BadgerDB——这是 `database/` 和 `cache/` 包的职责。

---

## 文件级摘要

| 文件 | 行数 | 发现级别 | 备注 |
|------|------|----------|-------|
| `internal/log/log.go` | 374 | L1,L3,L6,L7 | 正确的日志框架；TimeCache 运行良好；排序风格问题 |
| `internal/pool/pool.go` | 156 | L2,L4 | sync.Pool 使用良好；防御性检查但无害 |
| `internal/ipdetect/ipdetect.go` | 86 | L12 | 启动时使用；缺少上下文 |
| `internal/pending/pending.go` | 76 | — | 干净；正确有界；无问题 |
| `internal/ttl/ttl.go` | 97 | L5,L8,L16 | 零分配 TTL 函数；正确的循环陈化；用于测试的可变 NowUnix |
| `internal/ipttl/ipttl.go` | 62 | — | 干净；平台无关的 TTL 捕获；无问题 |
| `internal/dns64/dns64.go` | 105 | — | 符合 RFC 6147；分配最少；无问题 |
| `internal/stamp/stamp.go` | 238 | — | 在所有协议变体中正确解析；坚实的错误处理 |
| `internal/stamp/parse.go` | 225 | M3 | 端口提取逻辑重复 |
| `internal/stamp/encode.go` | 231 | L18 | VLP 编码正确；空输入安全 |
| `internal/lrumap/lru.go` | 188 | L17 | 正确的 LRU 有界映射；锁风格不一致 |
| `internal/lrumap/dtls_session.go` | 44 | — | DTLS 会话的薄包装；无问题 |
| `internal/siphash/siphash.go` | 195 | — | 标准 SipHash-2-4；内联轮次；无依赖；干净 |
| `internal/dnsutil/dnsutil.go` | 228 | M2,M4 | `LogHandshake` 前缀问题；`IsTemporaryError` 回退 |
| `internal/dnsutil/clientip.go` | 23 | — | 干净的单函数文件；无问题 |
| `internal/dnsutil/download.go` | 77 | M1 | 下载器缺少上下文；安全权限警告 |
| `internal/dnsutil/https_dns.go` | 100 | L14,L15 | DoH 执行正确；ID 修改可防御恐慌；策略拒绝保活 |
| `internal/dnsutil/keepalive.go` | 32 | — | 最小的 TCP 保活监听器包装；无问题 |
| `internal/dnsutil/tcpframe.go` | 112 | H1,L13 | TCP 帧读取器每次读取分配；分割写入正确 |
| `internal/dnsutil/bind.go` | 76 | — | 地址绑定预检正确；TOCTOU 问题已记录 |
| `internal/latency/prober.go` | 161 | M5,L9 | 良好控制的探测并发；无数据竞争 |
| `internal/latency/probes.go` | 275 | L10,L11,L19 | ICMP/TCP/UDP/HTTP 探测符合 RFC；注释重复 |
| `internal/latency/httppool.go` | 88 | — | HTTP 客户端池在关闭后安全；无问题 |

---

## 推荐行动项

1. **立即（HIGH）**: 修复 `tcpframe.go:32` 中的 TCP 读缓冲分配模式——添加一个按连接分级的 `sync.Pool`。
2. **下一版本（MEDIUM）**: 为 `download.go` 添加上下文支持；将端口提取逻辑提取到 `stamp/parse.go` 的辅助函数中；修复 `dnsutil.go:207` 中的组件前缀。
3. **准备就绪（LOW）**: 统一 `lrumap/lru.go` 中的锁风格；修复 `probes.go` 中重复的注释；为 `tcpframe.go:105` 添加写缓冲池；为 `https_dns.go:20` 添加延迟 ID 恢复。