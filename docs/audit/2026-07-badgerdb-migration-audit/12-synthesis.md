# 12 · 最终综合报告（18 维度 × 7 包组 × 25 Agent 全项目审计）

**日期**：2026-07-29
**方法论**：Phase 1（7 包级 agent）+ Phase 2a（9 交叉维度 agent）+ Phase 2b（9 交叉维度 agent）= 25 agent 并行审计
**覆盖范围**：207 个 Go 源文件，40 个包，18 个审计维度

---

## 审计执行架构

```
Phase 1: 包级审计（7 agent）           Phase 2a: 交叉分析（9 agent）        Phase 2b: 交叉分析（9 agent）
├── Foundation: internal/*         ├── Locks: 锁正确性              ├── Perf: 性能
├── Domain: config/edns            ├── Memory: 内存安全             ├── Arch: 架构设计
├── Protocol: server/protocol/*    ├── Panic: Panic 检测           ├── Logging: 日志质量
├── Upstream: server/upstream/*    ├── Error: 错误处理              ├── Docs: 文档一致性
├── Resolver: server/resolver/*    ├── Context: Context 传播        ├── Constants: 常量提取
├── Handler: server/handler/*      ├── Goroutine: Goroutine 生命周期 ├── RFC: RFC 一致性
└── Defense: server/defense/*      ├── Resource: 资源生命周期        ├── Comments: 注释准确性
                                   ├── Validation: 参数校验          ├── Ordering: 函数排序
                                   └── DeadCode: 死代码              └── GoVersion: Go 版本特性
```

---

## 总览

| 严重度 | 第一轮 | Phase 1+2 新增 | 合计 |
|--------|--------|---------------|------|
| CRITICAL | 1 | 2 | **3** |
| HIGH | 5 | 15 | **20** |
| MEDIUM | 11 | 26 | **37** |
| LOW | 3 | 53 | **56** |
| **合计** | **20** | **96** | **116** |

---

## CRITICAL（3 项）

### C1（已修复）：`LatencyLastProbe` 总是返回 true
- **文件**：`cache/stats.go:358-368`
- **状态**：✅ 已修复（第一轮）

### C2：`server/resolver/dnssec/nsec.go:172,178,181` — DNSSEC 验证错误未用 `%w` 包装标记错误
- **类别**：error-handling / dnssec
- **问题**：`isDenialOfExistenceValid()` 中三个返回路径使用 `fmt.Errorf(...)` 但未用 `%w` 包装 `dnssec.ErrBogusSignature`。代码库中其他所有 DNSSEC 验证正确使用了 `%w`。
- **风险**：`errors.Is(err, dnssec.ErrBogusSignature)` 将无法检测 NSEC/NSEC3 否定存在性验证失败。`dnssec_chain.go:396` 已使用此模式——第 172/178/181 行的错误本应被捕获但会被漏过。
- **修复**：三行添加 `%w` 包装：`fmt.Errorf("%w: ...", dnssec.ErrBogusSignature, ...)`

### C3：`server/protocol/dnscrypt/server.go:44,117,236-261` — `s.wg` 上的数据竞争
- **类别**：lock / data-race
- **问题**：`s.wg` 在 `Shutdown()` 中持有 `s.mu` 时被写入（交换新 `WaitGroup`），但在 `serveTCP`/`serveUDP` 中读取时未持有 `s.mu`。无锁共享可变指针导致"已使用的 WaitGroup 被后续使用"。
- **修复**：`serveTCP`/`serveUDP` 中读取 `s.wg` 时加 `s.mu.RLock()`，或不交换 WaitGroup 仅依赖 context 取消。

---

## HIGH（20 项）

### 错误处理（1 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-ERR1 | `server/protocol/padding.go:40` | `Pack()` 错误被 `_` 丢弃——OPT 伪记录损坏时静默 | Domain |

### Context 传播（3 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-CTX1 | `server/resolver/probe/probe.go:226` | `context.Background()` 使 Prober 的 ctx.Done() 无效 | Crosscut |
| H-CTX2 | `server/upstream/warmup.go:51` | warmup goroutine 未绑定服务器生命周期 | Crosscut |
| H-CTX3 | `server/handler/middleware/cache_lookup.go:95` | 后台刷新用 `context.Background()` 不传播关闭信号 | Handler |

### Goroutine 生命周期（3 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-GO1 | `server/handler/middleware/cache_lookup.go:71` | `errgroup.Go()` 在刷新容量饱和时同步阻塞查询处理程序 | Handler |
| H-GO2 | `server/handler/middleware/cache_lookup.go:BADCOOKIE` | BADCOOKIE 响应上重复的 `ApplyToMessage` 导致 OPT 选项重复 | Handler |
| H-GO3 | `server/resolver/nameserver.go:270,276` | NS 解析 goroutine 无 ctx 短路保护 | Crosscut |

### 日志质量（3 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-LOG1 | `server/protocol/tls/dtls.go:81` | accept 错误用 Errorf 并终止监听器（应 Warnf+continue） | Crosscut |
| H-LOG2 | `server/protocol/tlcp/dtlcp.go:255` | 与 H-LOG1 相同模式 | Crosscut |
| H-LOG3 | `server/bridge.go:49` | 热路径 Errorf——类型断言失败在每查询路径 | Crosscut |

### Panic 检测（2 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-PAN1 | `server/tasks.go:116` | `key.(string)` 裸类型断言在 sync.Map.Range 中 | Crosscut |
| H-PAN2 | `server/protocol/dnscrypt/server.go` | `key.(ed25519.PublicKey)` 裸类型断言 | Crosscut |

### 性能（3 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-PERF1 | `internal/ttl/ttl.go:15` | `NowUnix` 默认 `time.Now().Unix()` 而非 `log.NowUnix()`（热路径系统调用） | Crosscut |
| H-PERF2 | `server/resolver/nameserver.go:71` | `baseMsg.Copy()` 在递归热循环中堆分配 | Crosscut |
| H-PERF3 | `internal/dnsutil/tcpframe.go:32` | 每次 TCP 帧读取根据攻击者控制的长度字段分配新缓冲区 | Foundation |

### 资源生命周期（2 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-RES1 | `server/upstream/pool/tcp.go:221-227` | 连接关闭后 readLoop 仍尝试读取（竞态窗口） | Upstream |
| H-RES2 | `server/upstream/pool/tcp.go:294-310` | `close()` 设置 `c.inflight = nil` 后 readLoop 可能正在读取 | Upstream |

### 架构与排序（2 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-ARCH1 | `server/resolver/` | God package 趋势（11 type / 3975 lines / 11 files） | Crosscut |
| H-ORD1 | `internal/log/log.go:41→317` | `TimeCache` 类型和 `NewTimeCache` 被 274 行代码分隔 | Crosscut |

### 上游协议（1 项）
| ID | 文件:行 | 问题 | 来源 |
|----|---------|------|------|
| H-UP1 | `server/upstream/dnscrypt/client.go:137-158` | PQ 控制块处理后 `state.mu` 加解锁不一致 | Upstream |

---

## MEDIUM（37 项）

### 错误处理（3 项）
- M-ERR1: `server/resolver/dnssec/nsec.go:172,178,181` — NSEC3 错误丢失验证上下文
- M-ERR2: `edns/padding.go:40` — `Pack()` 错误被丢弃无注释
- M-ERR3: `server/resolver/dnssec/crypto.go` — 部分路径错误包装策略不一致

### Context 传播（4 项）
- M-CTX1: `server/resolver/probe/probe.go:145,182` — 非关键路径用 `Background()`
- M-CTX2: `server/handler/middleware/cache_lookup.go:153` — Prefetch 用 `Background()` 而非 `WithoutCancel`
- M-CTX3: `server/protocol/tls/server.go:308,314` — Shutdown timeout 用 `Background()`
- M-CTX4: `server/upstream/socks5/socks5.go:451` — UDP associate 硬编码 `Background()`

### 日志质量（4 项）
- M-LOG1: `cache/store.go:284` — Warnf 缺少 qname/qtype 上下文
- M-LOG2: `cache/store.go:278` — Warnf 缺少域名上下文
- M-LOG3: `server/protocol/tlcp/http_tlcp.go:50` — 关闭期间缺少 ctx.Err() 检查导致虚假 Errorf
- M-LOG4: `cache/async_writer.go:178` — WriteBatch 刷新错误缺少上下文

### 架构设计（5 项）
- M-ARCH1: `cache/cache.go:57` — `Store` 接口定义在生产者包而非消费者包
- M-ARCH2: `edns/edns.go:23` — `DNSHandler` 接口定义在生产者包
- M-ARCH3: `internal/dnsutil/` — 杂物包（30 导出符号，7 种不同关注点）
- M-ARCH4: `internal/dnscryptcrypto/` — 64 导出符号，考虑拆分
- M-ARCH5: `server/protocol/tls/server.go` — TLS Server 承担过多职责（DoT+DoQ+DoH+DoH3+DTLS）

### 性能（4 项）
- M-PERF1: `zone/zone.go:268,350` — `PrefetchValues=true` 在 zone 前缀扫描中（有 value 但应设为 false）
- M-PERF2: `server/resolver/nameserver.go:422-436` — `resolveNSAddrType` 中不必要的字符串分配
- M-PERF3: `cache/stats.go:78` — ReverseLookup 中 `string(item.Key())` 产生额外分配
- M-PERF4: `server/resolver/recursive.go` — DNSSEC 验证中的临时切片分配

### Goroutine 生命周期（3 项）
- M-GO1: `server/resolver/nameserver.go:270,276` — NS 地址解析 goroutine 无 ctx 短路
- M-GO2: `server/server.go:459-468` — Server 协调 goroutine 未被追踪
- M-GO3: `server/handler/pending.go` — 待处理请求 LRU 驱逐导致 SERVFAIL 静默丢失

### 资源生命周期（4 项）
- M-RES1: `server/upstream/client.go:289` — `Client.Close()` 缺少幂等性守卫
- M-RES2: `server/upstream/tls/client.go:101` — `TLSClient.Close()` 缺少幂等性守卫
- M-RES3: `server/upstream/pool/tcp.go:85` — `Conn.done` channel 已分配但从未被读取
- M-RES4: `server/upstream/socks5/socks5.go:168-172` — `ctrlClosed` 初始 channel 泄漏

### 配置与常量（3 项）
- M-CFG1: `config/validate.go:351` — DTLS 被排除在 TLS 证书验证之外
- M-CFG2: `config/validate.go:437` — DTLCP 证书验证缺位
- M-CFG3: 多处 — `86400` 内联在 cache、stats、dns64 中，未使用命名常量

### RFC 一致性（3 项）
- M-RFC1: `docs/rfc/` — RFC 6895 未归档（被 `validation.go` 引用）
- M-RFC2: `server/protocol/tls/https.go:171` — DoH `Cache-Control: max-age=0` 忽略 DNS TTL
- M-RFC3: `server/resolver/recursive.go` — 空非终端检测可能不完整（RFC 9156 §4.3）

### Defense（3 项）
- M-DEF1: `server/defense/poisonguard.go:43-48,87-91` — `VerdictUncertain` 被注释承认未被消费——死逻辑
- M-DEF2: `server/defense/hopguard.go:146-148` — nil receiver 返回 `true`（语义有歧义）
- M-DEF3: `server/defense/hopguard.go:64-65,96-97` — TTL=0 静默忽略

### Resolver（5 项）
- M-RES1: `server/resolver/nameserver.go` — poisonguard 启用但 detector 为 nil 时潜在的 nil interface panic
- M-RES2: `server/resolver/recursive.go` — `dns.Msg` use-after-Put 切片别名（有意设计但未文档化）
- M-RES3: `server/resolver/dnssec/poison.go` — `probeTLDForPoison` 仅探测第一台 TLD 服务器
- M-RES4: `server/resolver/root_hints.go` — 无界 `rootHints` map 在高基数解析时可能 panic
- M-RES5: `server/handler/middleware/validation.go` — `MaxDomainLength=253` 对完整 FQDN 边界有误

---

## LOW（56 项）

按维度分布：

| 维度 | 数量 | 主要发现 |
|------|------|----------|
| 文档/注释 | 8 | CLAUDE.md benchmark 数量过时、stale package path、FLOWCHARTS.md SQL 引用 |
| Go 版本特性 | 5 | `errors.AsType[T]` 未使用（5 处）、`strings.CutPrefix` 可替代手写模式 |
| RFC 注释 | 4 | RFC 8484 章节引用错误、ECS scope prefix 始终为 0 |
| 函数排序 | 14 | 方法散落、构造函数未紧跟类型 |
| 常量（魔法数字） | 3 | `MaxPortNumber` 未引用、SOCKS5 硬编码 255、1500 |
| 性能微优化 | 5 | 不必要的字符串分配、defer 在热循环中 |
| 日志微调 | 3 | Debug 级别细节、格式微调 |
| 参数校验 | 3 | 空 IP 未检查、边界情况 |
| 其他 | 11 | 测试注释、命名不一致、多余的 nil 守卫、文件拆分建议 |

---

## 修复优先级

### Sprint 1（CRITICAL + 高影响 HIGH）— 8 项
1. **C2**：nsec.go `%w` 包装（3 行）
2. **C3**：DNSCrypt s.wg 数据竞争
3. **H-PAN1**：sync.Map 裸类型断言
4. **H-PAN2**：ed25519 裸类型断言
5. **H-LOG1/H-LOG2**：DTLS/DTLCP accept Errorf→Warnf
6. **H-CTX1**：probe.go Background→派生 ctx
7. **H-GO1**：errgroup.Go() 阻塞查询处理程序
8. **H-PERF1**：ttl.NowUnix→log.NowUnix

### Sprint 2（剩余 HIGH）— 12 项
9-20. 其余 HIGH 项（性能优化、资源竞争、架构重构）

### Sprint 3（MEDIUM + LOW）— 96 项
21-116. 文档更新、错误包装统一、日志上下文补充、Close 幂等性加固、Go 1.26 特性采用、常量提取、RFC 归档

---

## 第一轮修复验证（20/20 ✅）

第一轮 BadgerDB 迁移审计的全部 20 项发现已在本轮审计开始前修复并验证通过：
- `go build ./...` ✅
- `golangci-lint run` ✅（0 issues）
- `go test ./... -short` ✅
