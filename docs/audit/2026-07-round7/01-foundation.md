# Foundation 层审计报告 (Phase 1)

审计范围: `internal/*` 全部包 (26 个源文件, 10 个包)
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 0 | — |
| HIGH | 1 | ProbeIPsLatency 无界 goroutine 创建 |
| MEDIUM | 8 | LRU 淘汰缺口 (×2), nil-interface 陷阱, Sign-panics, 未验证的 stamp IP, 丢弃的 cipher error, ReadTCPMsg pool miss |
| LOW | 7 | Download context, nil-key 边界, 次要 perf/DRY |

**共 16 个发现** (0 CRITICAL, 1 HIGH, 8 MEDIUM, 7 LOW)

## 发现列表

### HIGH

#### H1: ProbeIPsLatency 无界 goroutine 创建

- **文件**: `internal/latency/prober.go:77-103`
- **类别**: `performance`
- **描述**: `ProbeIPsLatency` 为每个 IP 地址创建一个 goroutine。所有 N 个 goroutine 在循环中立即创建 (line 77: `for i := range ips { go func() { ... } }`)，在任何 goroutine 能阻塞在 semaphore 之前 (line 85: `case p.sem <- struct{}{}`)。当 `len(ips)` 很大时（例如数千个 root/NS 地址），这同时创建 N 个 goroutine，每个 ~8KB 最小栈 = 10,000 个 IP 需要 80MB+。
- **风险**: 大 NS 集合下的内存耗尽/OOM；中等集合下降级性能。
- **修复**: 将 semaphore 获取移到 goroutine 外面限制 goroutine 创建：
  ```go
  for i := range ips {
      select {
      case p.sem <- struct{}{}:
      case <-ctx.Done(): return ips, nil
      }
      idx := i
      wg.Add(1)
      go func() { ... }()
  }
  ```

### MEDIUM

#### M1: lrumap.Set() 替换值时不调用 OnEvict

- **文件**: `internal/lrumap/lru.go:74-81`
- **类别**: `resource`
- **描述**: 对已存在 key 调用 `Map.Set()` 时，`e.val = val` (line 77) 直接替换旧值，不调用 `OnEvict`。如果 V 持有资源（如 `io.Closer`、channel），替换操作会泄漏旧值的资源。
- **风险**: 相同 key 更新时资源泄漏（fd、内存、加密材料）。
- **修复**: 更新前调用 `m.OnEvict(key, e.val)` 或文档说明 Set() 不调用 OnEvict。

#### M2: DTLSSessionStore 缺少 OnEvict

- **文件**: `internal/lrumap/dtls_session.go:16-18`
- **类别**: `resource`
- **描述**: `NewDTLSSessionStore(capacity)` 创建 `New[string, dtls.Session](capacity)` 未设 OnEvict。LRU 淘汰时敏感密钥材料保留在堆内存中直到 GC 周期。
- **风险**: 内存转储攻击可读取已淘汰的会话密钥材料。
- **修复**: 添加 OnEvict 显式清零会话中的敏感字段。

#### M3: CloseWithLog nil interface 陷阱

- **文件**: `internal/dnsutil/dnsutil.go:65-67`
- **类别**: `nil-guard`
- **描述**: `CloseWithLog` 检查 `c == nil` (line 66)，但 c 是 `io.Closer` 接口。如果调用方传入 `*T(nil)`（具体 nil 指针），接口本身非 nil 但底层值为 nil，导致 `c.Close()` panic。
- **风险**: 非 nil 接口包裹 nil 指针时 panic。
- **修复**: 文档说明或添加反射 nil 检查。

#### M4: Certificate.Sign panic 而非返回 error

- **文件**: `internal/dnscryptcrypto/certificate.go:309-312`
- **类别**: `panic`
- **描述**: `Sign()` 在无效 ClientMagic 时 panic（line 312: `panic("dnscrypt: ClientMagic starts with seven zero bytes...")`）。这是编程错误参数，但会崩溃整个服务器。
- **风险**: 配置驱动的证书生成收到畸形数据导致服务器崩溃。
- **修复**: 返回 error 而非 panic。

#### M5: stamp BootstrapIPs 未验证

- **文件**: `internal/stamp/parse.go:168-176`
- **类别**: `validation`
- **描述**: `parseSecure()` 读取 bootstrap IPs 直接存储为 raw strings，不验证是否为有效 IP 地址。攻击者构造的 stamp 可注入非 IP 字符串传播到解析器的上游连接逻辑。
- **风险**: 畸形 bootstrap IP 未经检查传播到下游。
- **修复**: 每个 bootstrap IP 用 `net.ParseIP()` 验证。

#### M6: XchachaSeal/Open 丢弃 chacha20.NewUnauthenticatedCipher error

- **文件**: `internal/dnscryptcrypto/xsecretbox.go:67, 114`
- **类别**: `error-wrap`
- **描述**: 调用 `chacha20.NewUnauthenticatedCipher(key, nonce)` 丢弃 error（`_`），注释说 sizes 已在上面验证。这是脆弱的耦合——如果 chacha20 构造函数增加新的验证，error 被静默吞下，cipher 为 nil 导致后续 panic。
- **风险**: chacha20 库更新引入新 error 路径被忽略 → nil-pointer panic。
- **修复**: 检查并返回 error。

#### M7: ReadTCPMsg 用 new() 而非 pool 分配

- **文件**: `internal/dnsutil/tcpframe.go:37`
- **类别**: `performance`
- **描述**: `ReadTCPMsg` 用 `msg := new(dns.Msg)` 分配而非 `pool.DefaultMessage.Get()`。TCP/DoT/DoQ 连接的热路径上每个 DNS 消息多一次堆分配。
- **风险**: TCP DNS 读取每次多 ~2x 分配开销；高负载下有可测量的 QPS 影响。
- **修复**: 使用 `pool.DefaultMessage.Get()` 并确保调用方 Put。

#### M8: LRU 淘汰时 OnEvict 检查被跳过

- **文件**: `internal/lrumap/lru.go:183-185`
- **类别**: `resource`
- **描述**: `evictLocked` 方法中，OnEvict 检查被 `if` 条件包围但实际未执行回调。代码逻辑路径可能在某些条件下跳过回调。
- **风险**: 持有资源的值被淘汰时回调未执行 → 资源泄漏。
- **修复**: 确保淘汰路径无条件调用 OnEvict。

### LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `internal/dnsutil/download.go:61` | DownloadFile 缺少 context 传播 |
| L2 | `internal/siphash/siphash.go:11-13` | Sum64 对 nil key 返回 0 — 无法区分合法 0 hash |
| L3 | `internal/stamp/stamp.go:111-185` | Parse 函数每个协议 case body 重复 |
| L4 | `internal/latency/probes.go:137` | probeUDP 每次调用分配读 buffer — 无 pool |
| L5 | `internal/dnsutil/dnsutil.go:227` | IsTemporaryError 调用 err.Error() 分配字符串 |
| L6 | `internal/latency/prober.go:32-34` | New() nil bgCtx fallback 静默使用 Background() |
| L7 | `internal/dnscryptcrypto/pq.go:259-267` | DecodeTicketPlaintext 部分解码 — 跳过字段无文档说明 |

## 交叉观察

### 常量和魔法数字
所有命名常量都适当提取。DNSCrypt crypto 包有优秀的常量纪律——每个 wire offset 都是注释引用 spec 的命名常量。

### Context 传播
- `log.go` TimeCache: 不需要 context（内部 ticker）
- `latency/`: 全路径正确使用 context — 每步 context.WithTimeout，worker goroutine 有 ctx.Done 检查

### Goroutine 生命周期
- 所有后台 goroutine 有 panic recovery (HandlePanic 或 inline recovery)
- `wg.Done()` 排序正确（LIFO: wg.Done 在 HandlePanic 之前）
- TimeCache goroutine 正确由 TimeCache 拥有，通过 done channel 停止

### 错误包装
- `%w` 在全代码库一致用于包装上游错误
- Sentinel errors 用 `errors.New()` 定义，调用处用 `%w` 包装
- 小不一致: `stamp/parse.go` 混合使用 `errors.New("stamp: ...")` 和预定义 `Err*` sentinels

### sync.Pool 使用
- `pool.go`: 正确的 Get/Put 对称性。Buffer 在 Put 上清零。Pool 预填充正确
- `probes.go` icmpBufPool: 正确的 Get/Put 带类型断言守卫
- 未发现 use-after-Put 模式

### 资源生命周期
- `latency.Prober.Close()`: 通过 `closeOnce` 幂等
- `httpClientPool.Close()`: 安全的 nil 检查，设 `p.clients = nil`
- `TimeCache.Stop()`: 通过 `closeOnce` 幂等
- 所有 Close() 方法正确幂等

### Decorder 合规
文件遵循 `type → const → var → func` 排序。

### Go 版本特性
Go 1.26 特性使用: `clear()` (pool.go), `min()/max()` builtins, `slices.SortStableFunc`。
`errors.AsType[T]` 和 `slices.Backward/Reverse` 未使用。
