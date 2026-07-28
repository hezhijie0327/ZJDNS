# 综合审计报告 — 2026-07 Round 7

审计日期: 2026-07-28
审计范围: 151 个非测试 Go 文件，18 个审计维度

## 总体概览

| 严重程度 | Phase 1 | Phase 2 | 合计 |
|----------|---------|---------|------|
| **CRITICAL** | 11 | 0 | **11** |
| **HIGH** | 23 | 0 | **23** |
| **MEDIUM** | 52 | 3 | **55** |
| **LOW** | 52 | 7 | **59** |
| **总计** | **138** | **10** | **148** |

> 全部 7 个 Phase 1 审计组已完成 + 18 项 Phase 2 交叉分析。

## CRITICAL 发现（9 个）

| # | 组 | 文件 | 描述 |
|---|-----|------|------|
| C1 | Domain | `cache/store.go:152-157` | sync.Pool 双重归还 — msg 在 Unpack error 路径被 Put 两次 |
| C2 | Domain | `zone/parse.go:84-96` | 裸 "." 或 "*." domain header 导致 slice 越界 panic |
| C3 | Domain | `zone/parse.go:84-96` | 单字符 "." 行触发同 C2 的 panic 路径 |
| C4 | Protocol | `dnscrypt/crypto.go:180-189` | sharedKeyCache data race — decrypt() 无锁读 vs rotateKeys() 有锁写 |
| C5 | Protocol | `dnscrypt/server.go:260` | WaitGroup.Go() 绕过 Shutdown 中的 WaitGroup swap 模式 |
| C6 | Upstream | `upstream/tls/quic.go:31-54` | DoQ+代理: poolKey 被错误用作拨号地址 — 代理 DoQ 100% 失败 |
| C7 | Upstream | `upstream/dnscrypt/state.go:226-231` | deleteState nil 指针竞态 — 并发 Close+Execute 导致 panic |
| C8 | Defense | `defense/poisonguard.go:169` | TLD 检测永久失效 — FQDN label 计数错误导致 isTLD 永远返回 false |
| C9 | Defense | `defense/poisonguard.go:126-129` | 权威级盲点 — classify default 始终返回 VerdictUncertain（设计限制） |
| C10 | Resolver | `resolver/dnssec_chain.go:306` | DNSSEC nil crypto dereference panic — 非 DNSSEC 模式任何递归查询崩溃 |
| C11 | Resolver | `resolver/forward.go:60` | forward.go errgroup goroutines 缺少 HandlePanic — 上游错误崩溃服务器 |

## HIGH 发现（18 个）

### 内存/资源泄漏 (6)
| # | 文件 | 描述 |
|---|------|------|
| H1 | `latency/prober.go:77-103` | ProbeIPsLatency 无界 goroutine 创建 |
| H2 | `cache/async_writer.go:101-112` | Flush/Close 竞态 — unbuffered flushSig 永久阻塞 |
| H3 | `upstream/tls/quic.go:89-95` | 非池化 DoQ: Err0RTTRejected 连接泄漏 |
| H4 | `upstream/tls/https.go:50-64` | DoH/DoH3 传输器不关闭活跃连接 |
| H5 | `upstream/tls/client.go:81-85` | 旧传输器 LRU 逐出未完全清理 |
| H6 | `handler/middleware/cache_lookup.go` | 后台刷新 goroutine 存活超过 server shutdown |

### 并发/锁问题 (4)
| # | 文件 | 描述 |
|---|------|------|
| H7 | `edns/cookie.go:221-231` | rfc9018MAC clientIP nil 时 ipLen 不匹配 |
| H8 | `upstream/dnscrypt/client.go:144-156` | PQ 控制块过早解锁 — 锁边缘情况 |
| H9 | `defense/hopguard.go:95-110` | Feed vs Validate 竞态窗口 |
| H10 | `server/tasks.go:108-116` | sync.Map Range 内 Delete 竞态 |

### 架构/设计 (4)
| # | 文件 | 描述 |
|---|------|------|
| H11 | `handler/middleware/cache_lookup.go` | 后台刷新 goroutine 数量无界 |
| H12 | `handler/middleware/response.go` | restoreDomain 违反复制合约 |
| H13 | `server/bridge.go:46-58` | tcpWriteMu 无界增长（每 IP:port） |
| H14 | `cmd/zjdns/cli/generate.go:15` | CLI 导入 server/protocol/dnscrypt — 层级违规 |

### 协议/性能 (4)
| # | 文件 | 描述 |
|---|------|------|
| H15 | `dnscrypt/crypto.go:158` | DNSCrypt decrypt 绕过 message pool |
| H16 | `tlcp/dtlcp.go:264-266` | DTLCP 同步单客户端瓶颈 |
| H17 | `tlcp/http_tlcp.go:95-97` | TLCP DoH nil 响应静默返回 200 |
| H18 | `dnsutil/tcpframe.go:36` | ReadTCPMsg 用 new(dns.Msg) 而非 pool |

## 按包组分布

| 包组 | CRITICAL | HIGH | MEDIUM | LOW | 总计 |
|------|----------|------|--------|-----|------|
| Foundation | 0 | 1 | 8 | 7 | 16 |
| Domain | 3 | 2 | 14 | 12 | 31 |
| Protocol | 2 | 4 | 6 | 4 | 16 |
| Upstream | 2 | 4 | 3 | 5 | 14 |
| **Resolver** | **2** | **5** | **7** | **8** | **22** |
| Handler | 0 | 3 | 8 | 7 | 18 |
| Defense+Server+CLI | 2 | 4 | 6 | 9 | 21 |
| **Phase 1 合计** | **11** | **23** | **52** | **52** | **138** |

## 系统性根因模式

本次审计识别的重复模式：

### 1. Pool 生命周期错误（2 个 CRITICAL + 3 个 HIGH）
- **双重归还**: cache/store.go — error 路径显式 Put + defer Put
- **绕过 pool**: DNSCrypt decrypt、ReadTCPMsg、TLCP 路径使用 new() 而非 pool.Get()
- **预防**: 审计时逐对验证每个 pool.Get() 的 Put() 路径

### 2. Zone 文件解析 panic（2 个 CRITICAL）
- 边界输入 "`.`" 和 "`*.`" 导致 slice 越界
- **预防**: 所有解析器需要 fuzz 测试覆盖边界输入

### 3. DNSCrypt 并发安全（2 个 CRITICAL + 2 个 HIGH）
- sharedKeyCache data race、WaitGroup swap 竞态、deleteState nil 指针、PQ 过早解锁
- **根因**: DNSCrypt 是最近添加的协议，并发模型比 TLS 更复杂
- **预防**: 以 TLS 实现为模板对齐并发模式

### 4. 防御算法缺陷（2 个 CRITICAL + 1 个 HIGH）
- poisonguard TLD 检测永久失效 — FQDN 处理 bug
- poisonguard 权威级盲点 — 设计限制
- hopguard 竞态窗口
- **根因**: 防御算法缺少端到端集成测试
- **预防**: 每个防御模块需要 fuzz 测试 + 已知攻击向量验证

### 5. Shutdown 安全（4 个 HIGH）
- 后台刷新 goroutine 无 shutdown 同步
- Flush/Close 竞态
- WaitGroup swap 竞态
- sync.Map Range 删除
- **根因**: Shutdown 路径未充分测试
- **预防**: 添加 shutdown 顺序的集成测试

## 交叉分析关键发现

| 发现 | 严重程度 |
|------|----------|
| ARCHITECTURE.md 完全缺失防御机制文档 | MEDIUM |
| CLAUDE.md "max 10 steps" vs 代码 DefaultMaxRecursionDepth=16 | MEDIUM |
| TLCP/DTLCP 国标文档未在 docs/rfc/ 存档 | MEDIUM |
| 86400 魔法数字未提取（3 处） | LOW |
| DNSCrypt 2000 硬编码缓存大小 | LOW |
| SOCKS5 Close 非幂等（mutex 无 Once 守卫） | MEDIUM |
| database.Open() 命名偏离 New* 惯例 | LOW |
| errors.AsType[T] 和 slices.Backward 未采用（Go 1.26） | LOW |
| 顶级 server errgroup 无 SetLimit | LOW |

## 修复路线图

### Sprint 1 — 立即修复（9 个 CRITICAL）
优先级顺序:
1. **Pool 双重归还** (cache/store.go) — 单行修复
2. **Zone panic** (zone/parse.go) — 添加长度守卫
3. **DNSCrypt data race** (crypto.go) — 快照 sharedKeyCache
4. **DoQ 代理地址** (upstream tls/quic.go) — 修正 addr 使用
5. **DNSCrypt nil 竞态** (state.go) — 添加锁守卫
6. **Poisonguard TLD** (poisonguard.go) — 修正 label 计数
7. **WaitGroup swap** (dnscrypt server.go) — 添加读锁序列化
8. **Poisonguard 权威盲点** — 文档化设计限制

### Sprint 2 — 下个发布周期（18 个 HIGH）
- 6 个内存/资源泄漏修复
- 4 个并发/锁修复
- 4 个架构/设计修复
- 4 个协议/性能修复

### Sprint 3 — 后续（99 个 MEDIUM + LOW）
- 文档更新
- 性能微优化
- 常量提取
- 代码清理

## 质量门禁

- [ ] `go build ./...` — 零编译错误
- [ ] `golangci-lint run` — 零警告
- [ ] `go test -short ./...` — 全部通过
- [ ] Benchmark 回归检测（>15% 变慢 = 回归）
- [ ] `go test -race ./...` — 零竞态
