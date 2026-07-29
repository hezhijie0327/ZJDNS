# 00 · 逐项修复计划（116 项）

**审计批次**：2026-07-badgerdb-migration-audit（含 25-Agent 扩展）
**总发现**：3 CRITICAL + 20 HIGH + 37 MEDIUM + 56 LOW = 116 项

---

## 修复概览

| Sprint | 范围 | 数量 | Commit 数 | 状态 |
|--------|------|------|-----------|------|
| Round 1 | CRITICAL+HIGH+MEDIUM+LOW（BadgerDB 迁移） | 20 | 1（已 amend） | ✅ 完成 |
| Sprint 1 | CRITICAL（本轮） | 2 | 1 | ⬜ 待开始 |
| Sprint 2 | HIGH | 18 | 9 | ⬜ 待开始 |
| Sprint 3 | MEDIUM + LOW | 76 | 8 | ⬜ 待开始 |

---

## Commit 策略

严格遵循 CLAUDE.md：
- **每 commit 只含一类修复**，跨维度修复分多次提交
- 主题行格式：`<type>: <具体描述> (<审计引用>)`
- 每次提交前：`go build ./... && golangci-lint fmt && golangci-lint run`（零警告）

---

## Round 1（已完成 ✅）

全部 20 项 BadgerDB 迁移审计发现已修复：C1（LatencyLastProbe）、H1（maxEntries）、H2（SQL 注释）、H3（benchmark 死文件）、H4（testStore）、H5（defer-in-loop）、M1-M11、L1-L3。见 commit `445e91b`。

---

## Sprint 1：CRITICAL（2 项）— 1 commit

### C1：`nsec.go` 错误包装断裂

**文件**：`server/resolver/dnssec/nsec.go:172,178,181`
**根因**：三处 `fmt.Errorf(...)` 未用 `%w` 包装 `dnssec.ErrBogusSignature`
**修复**：添加 `%w` 包装
**验证**：`go test ./server/resolver/dnssec/... -v`

### C2：DNSCrypt `s.wg` 数据竞争

**文件**：`server/protocol/dnscrypt/server.go`
**根因**：`serveTCP`/`serveUDP` 读取 `s.wg` 时未持有 `s.mu`，但 `Shutdown()` 在锁内交换 WaitGroup
**修复**：读取 `s.wg` 时加 `s.mu.RLock()`
**验证**：`go test -race ./server/protocol/dnscrypt/...`

### C3（已修复）：LatencyLastProbe

Round 1 已修复。无需操作。

**Commit 1**：`fix: wrap DNSSEC sentinel errors in nsec.go and fix DNSCrypt wg data race (C1,C2)`

---

## Sprint 2：HIGH（18 项）— 9 commits

### Commit 2：Bare 类型断言（H-PAN1, H-PAN2）

| ID | 文件:行 | 改前 | 改后 |
|----|---------|------|------|
| H-PAN1 | `server/tasks.go:116` | `key.(string)` | `keyStr, ok := key.(string)` |
| H-PAN2 | `server/protocol/dnscrypt/server.go:355` | `s.signingSK.Public().(ed25519.PublicKey)` | comma-ok 守卫 |

**Commit**：`fix: replace bare type assertions with comma-ok pattern (H-PAN1,H-PAN2)`

---

### Commit 3：DTLS/DTLCP accept 错误终止监听器（H-LOG1, H-LOG2）

| ID | 文件:行 | 改前 | 改后 |
|----|---------|------|------|
| H-LOG1 | `server/protocol/tls/dtls.go:81` | `log.Errorf(...); return err` | `log.Warnf(...); continue` |
| H-LOG2 | `server/protocol/tlcp/dtlcp.go:255` | 同上 | 同上 |

**Commit**：`fix: replace Errorf with Warnf+continue in DTLS/DTLCP accept loops (H-LOG1,H-LOG2)`

---

### Commit 4：Context 传播（H-CTX1, H-CTX2）

| ID | 文件:行 | 修复 |
|----|---------|------|
| H-CTX1 | `server/resolver/probe/probe.go:226` | `latency.New(ctx, ...)` — 传入调用方 ctx |
| H-CTX2 | `server/upstream/warmup.go:51` | 用传入的 ctx 替代 `context.Background()` |

**Commit**：`fix: propagate context in probe and warmup paths (H-CTX1,H-CTX2)`

---

### Commit 5：日志降级（H-LOG3）

| ID | 文件:行 | 修复 |
|----|---------|------|
| H-LOG3 | `server/bridge.go:49` | Errorf → Warnf（热路径类型断言失败） |

**Commit**：`fix: downgrade Errorf to Warnf in hot-path type assertion (H-LOG3)`

---

### Commit 6：errgroup 阻塞 + BADCOOKIE 重复（H-GO1, H-GO2）

| ID | 文件:行 | 修复 |
|----|---------|------|
| H-GO1 | `server/handler/middleware/cache_lookup.go:71,95,141,215` | `refreshGroup.Go()` 非阻塞化 |
| H-GO2 | BADCOOKIE 路径 | 删除重复的 `ApplyToMessage` 调用 |

**Commit**：`fix: prevent errgroup blocking in cache refresh and dedup BADCOOKIE ApplyToMessage (H-GO1,H-GO2)`

---

### Commit 7：性能优化（H-PERF1, H-PERF3）

| ID | 文件:行 | 修复 |
|----|---------|------|
| H-PERF1 | `internal/ttl/ttl.go:15` | `NowUnix` 改用 `log.NowUnix()`（需解决循环导入） |
| H-PERF3 | `internal/dnsutil/tcpframe.go:32` | 添加 `sync.Pool` 复用 TCP 读缓冲区 |

**Commit**：`perf: use log.NowUnix in ttl package and pool TCP read buffers (H-PERF1,H-PERF3)`

---

### Commit 8：函数排序（H-ORD1）

| ID | 文件:行 | 修复 |
|----|---------|------|
| H-ORD1 | `internal/log/log.go:41→317` | 将 TimeCache 类型+NewTimeCache+方法移到文件顶部 |

**Commit**：`refactor: move TimeCache type near its constructor in log.go (H-ORD1)`

---

### Commit 9：连接池竞态 + Close 幂等性（H-RES1, H-RES2, H-UP1）

| ID | 文件 | 修复 |
|----|------|------|
| H-RES1 | `server/upstream/pool/tcp.go:221` | readLoop 竞态窗口：添加 conn 关闭状态检查 |
| H-RES2 | `server/upstream/pool/tcp.go:294` | inflight=nil 后 readLoop 读取：添加 nil 守卫 |
| H-UP1 | `server/upstream/dnscrypt/client.go:137` | PQ mutex 加解锁不一致：统一 defer 模式 |

**Commit**：`fix: connection pool races and DNSCrypt PQ mutex consistency (H-RES1,H-RES2,H-UP1)`

---

### Commit 10：TLCP/DTLCP/DNSCrypt 协议修复（C1-TLCP, H-DTLCP, H-DNSUDP）

| ID | 文件 | 修复 |
|----|------|------|
| C1-TLCP | `server/protocol/tlcp/server.go` | 部分启动失败时取消 context 并清理已创建监听器 |
| H-DTLCP | `server/protocol/tlcp/dtlcp.go` | 记录 DTLCP 串行化限制为已知问题，标注 gotlcp 上游修复后改善 |
| H-DNSUDP | `server/protocol/dnscrypt/udp.go` | 添加 defer pool.Put 到 UDP 响应路径 |

**Commit**：`fix: TLCP startup rollback, document DTLCP limitation, add DNSCrypt UDP pool Put (C1-TLCP,H-DTLCP,H-DNSUDP)`

---

## Sprint 3：MEDIUM + LOW（76 项）— 8 commits

### Commit 11：错误处理（~5 项）
- M-ERR1~3：nsec.go 上下文补充、padding.go `_` 注释、crypto.go 策略统一
- L-ERR*：unwrap 路径优化

### Commit 12：日志上下文（~8 项）
- cache/store.go:284,278：Warnf 添加 qname/qtype
- tlcp/http_tlcp.go:50：ctx.Err() 检查
- async_writer.go:178：错误上下文
- bridge.go 类型断言日志

### Commit 13：Close() 幂等性 + 资源泄漏（~6 项）
- upstream/client.go:289：添加 sync.Once
- upstream/tls/client.go:101：添加 sync.Once
- socks5 ctrlClosed channel 泄漏
- pool/tcp Conn.done channel 未读取

### Commit 14：常量提取 + 配置验证（~8 项）
- 添加 `SecondsPerDay = 86400` 到 config/defaults.go
- 替换 cache/async_writer.go、cache/stats.go、dns64.go 中的内联 86400
- SOCKS5 引用 config.MaxPortNumber
- DTLS/DTLCP 加入 TLS 证书验证（config/validate.go）

### Commit 15：Zone/Defense/Resolver（~10 项）
- zone PrefetchValues=false（zone/zone.go:268,350）
- VerdictUncertain 死代码标注
- poisonguard nil receiver 语义文档化
- hopguard TTL=0 警告
- resolver 中的 use-after-Put 文档化
- probeTLDForPoison 单服务器探测限制文档化

### Commit 16：文档更新（~12 项）
- RFC 6895 归档到 docs/rfc/
- CLAUDE.md：benchmark 数量更新、internal 包列表更新
- FLOWCHARTS.md：SQL 引用修正
- ARCHITECTURE.md：过时引用修正
- 注释：stale package path（server/server.go:377、cmd/zjdns/cli/generate.go:107）

### Commit 17：Go 1.26 特性（~10 项）
- errors.AsType[T] 替换（5 处：probe.go、dnsutil.go、cache_lookup.go 等）
- strings.CutPrefix 替换手写 HasPrefix+下标模式
- 删除冗余 nil 守卫
- `go fix ./...` 验证

### Commit 18：函数排序 + 注释清理（~17 项）
- 14 处方法聚合（edns/ecs.go、edns/edns.go、internal/stamp/、server/ 等）
- 构造函数紧跟类型（pool/pool.go Buffer、resolver 各文件）
- 过时 TODO/FIXME 评估和清理

---

## 验证流程

每个 commit 前：
```bash
go build ./...                 # 零编译错误
go fix ./...                   # 自动现代化
golangci-lint fmt              # 格式化
golangci-lint run              # 零警告
```

每个 Sprint 后：
```bash
go test ./... -short           # 全部通过
go test -race ./...            # 无竞态（Sprint 1/2）
```

最终 benchmark 回归检测：
```bash
go test -bench=. -short -benchtime=500ms ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
git diff HEAD~18 -- docs/benchmark/benchmark-baseline.txt  # >15% 变慢 = 回归
```
