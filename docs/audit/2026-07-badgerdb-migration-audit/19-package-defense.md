# 19 · Defense 包深度审计

> 审计 Agent：Phase 1 · Defense
> 覆盖：server/defense/* 全部 2 个非测试文件


Now I have a thorough understanding of both files. Let me compile the full audit report.

---

## server/defense/ 审计报告

审计范围: `/Users/hezhijie/Downloads/ZJDNS/server/defense/hopguard.go` (264 行), `/Users/hezhijie/Downloads/ZJDNS/server/defense/poisonguard.go` (180 行)

---

### 1. 代码质量

**F-01 | MEDIUM | deadcode | poisonguard.go:43-48, 87-91** — `VerdictUncertain` 被代码自身注释明确标注为"no caller checks VerdictUncertain"，且在 `Validate()` 中导致第一次匹配到的 RR 就短路返回。对于 authoritative zone 的响应，`classify()` 必定返回 `VerdictUncertain`，导致 `Validate()` 在首个 RR 后就提前返回，不再检查后续 RR。虽然 authoritative zone 中所有 RR 的 classify 结果均为 VerdictUncertain，不存在漏报，但保留一段明确无人消费的 code path 增加了阅读者的认知负担，也使得未来如果有人在 classifyRoot/classifyTLD 中返回 VerdictUncertain 时，这个短路行为会静默跳过剩余 RR。

风险: 无安全影响，但属于被承认的死代码，应移除或启用。

修复: 将 authoritative zone 的 default 分支改为返回 VerdictClean（而非 VerdictUncertain），或添加一个实参让调用者决定是否消费 Uncertain。同时考虑删除 VerdictUncertain 枚举值（或被 Future 工作引用则保留但确保 type-switch exhaustiveness）。

---

### 2. 内存安全

无发现。`hopguard.go` 使用定长 LRU Map（`hopGuardCacheCapacity = 256`），`serverState.histogram` 受 uint8 TTL 值域限制最多 256 条，`serverState.trusted` 上限与 histogram 一致。不存在无界增长。

---

### 3. 锁正确性

**F-02 | LOW | race | hopguard.go:100-110** — `Feed()` 中 Get → LoadOrStore 两步操作之间，另一个 goroutine 可能为同一 serverIP 并发创建了 state。当前代码使用 `LoadOrStore` 正确解决了这个竞态，返回已有 state。没有竞态问题，但确认该模式正确。无需修复。

**F-03 | INFO | lock | hopguard.go:153-155** — `Confident()` 只读取 `st.armed`，但使用 `st.mu.Lock()` 而非 `st.mu.RLock()`（如果 mutex 改为 RWMutex）。当前是 Mutex，没有错误。如果未来需要更高并发度，可考虑将 `armed` 改为 `atomic.Bool`。

---

### 4. 耦合度

无导入分层违规。两个文件的导入链均只涉及：
- `zjdns/internal/log` (foundation)
- `zjdns/internal/lrumap` (foundation)
- `codeberg.org/miekg/dns` / `dnsutil` (外部 DNS 库)

不依赖任何 domain package 或 `server/` 子包，符合 DAG 约束。

---

### 5. 架构设计

**F-04 | INFO | naming | hopguard.go:42** — 常量的 project 前缀 `hopGuard`（camelCase 首字母小写）与 CLAUDE.md 的 `PascalCase exported, camelCase unexported` 规则一致，但常量不导出所以用 `hopGuard` 前缀合理。无违规。

`Detector` 为空结构体，用作方法 namespace。这在本项目中是可接受的模式（类似 `internal/pool` 的 `Message`/`Buffer` 类型），不构成 God package。

---

### 6. 性能

**F-05 | LOW | alloc | poisonguard.go:84,108** — `dnsutil.Canonical(rr.Header().Name)` 在每个 RR 上调用，`Canonical` 内部使用 `strings.Map` 无论是否需要转换都会重新分配字符串。对于有大量 Answer RR 的响应，这会产生显著的分配压力。同样模式出现在 `Validate()` 和 `IsPoisonedByTLD()` 中风险: 每条查询 + 每个 delegation 响应都可能触发，在递归解析高 QPS 场景下成为分配热点。

修复: 对 `rr.Header().Name` 使用 `strings.EqualFold(name, n)` 替代 `Canonical`，前提是 `n` 已规范化（已在 Validate 开头对 queryName 做了 Canonical）。这样可以完全避免 `Canonical` 在循环内的分配。

**F-06 | INFO | alloc | poisonguard.go:87,90** — `dns.RRToType(rr)` 在同一迭代中被调用两次（一次传入 classify，一次在日志中）。缓存到局部变量可消除第二次调用。仅在 poison 被检测到的罕见路径上触发，性能影响可忽略。

---

### 7. Panic 检测

**F-07 | MEDIUM | nil | hopguard.go:146-148** — `Confident()` 的 nil receiver 检查返回 `true`，语义上意味着"一个 nil HopGuard 是完全 confident 的"。这与 `Validate()`（nil 时返回 true = pass）和 `Feed()`（nil 时 silent return）看似一致但不合理：一个不存在的 guard 不应该被报告为 confident。

风险: 如果调用方通过 `Confident()` 的结果决定是否需要对某个 server IP 执行额外动作（例如跳过学习阶段），nil guard 返回 true 会导致调用方误以为 guard 已武装，行为异常。

修复: 将 `Confident()` 的 nil 分支改为返回 `false`，或删除该防御性检查（使它在 nil receiver 时 panic，暴露调用方 bug）。

**F-08 | LOW | bounds | hopguard.go:206-208** — `passTrusted` 中的 `lo < 1` clamp 是多余的，因为 `Validate` 和 `Feed` 在入口处已拒绝 `observed == 0`。且 trusted TTL 本身也来自已被过滤过的观测值（TTL ≥ 1）。不构成 bug，但增加一句无用分支。

**F-09 | INFO | nil | poisonguard.go:90** — `dns.TypeToString[dns.RRToType(rr)]` 是 map 读取，Go 中对缺失 key 返回零值（空字符串），不会 panic。安全。

---

### 8. 错误处理

两个文件均不返回 error，使用 bool/Verdict 表示结果。没有 sentinel error 或 `%w` 格式串。这种设计对于 defense 机制是合理的——快速判定而非传播错误。

---

### 9. Context 传播

两个文件均不使用 context。这是合理的——HopGuard 和 Detector 执行纯内存同步操作，不涉及任何 I/O 或可取消操作。

---

### 10. Goroutine 生命周期

两个文件均不创建 goroutine。HopGuard 的方法（Validate/Feed/Confident）预期被多个 goroutine 并发调用，mutex 提供了正确保护。无 errgroup、无 channel。

---

### 11. 资源生命周期

**F-10 | INFO | close | hopguard.go:51-55** — `HopGuard` 没有 `Close()` 方法。`lrumap.Map` 的底层实现可能包含后台 goroutine 或定时器（取决于实现），若存在则缺少 Close 会导致泄漏。需要确认 `lrumap` 的实现是否可安全 GC。

---

### 12. 日志质量

**F-11 | INFO | flooding | hopguard.go:129-131** — 学习阶段每 8 个样本记录一行 Debug 日志。对于一个从 0 开始学习的 server，会产生 4 行日志（8, 16, 24, 32 samples）后才武装。仅在 Debug 级别触发，不会影响生产环境，但可考虑降低至每 16 或 32 次。

所有日志均使用 `Debugf` 级别，使用 `UPSTREAM:` / `SECURITY:` 规范前缀，包含 serverIP、TTL 值、trusted 集合等完整上下文。日志质量优秀。

---

### 13. 文档质量

整体文档质量非常高。关键文档涉及：

- HopGuard 的算法描述（line 12-25）：TTL 直方图、自适应阈值、GFW 防御原理完整说明
- Feed 和 Validate 的角色分离：明确指出 Feed 只在 spoofguard 确认后调用
- VerdictUncertain 的局限性：明确说明"no caller checks"
- classifyRoot 和 classifyTLD 的规则：清晰的合法记录类型说明

所有导出类型和方法均有 godoc。

---

### 14. 参数校验

**F-12 | MEDIUM | param | hopguard.go:64-65, 96-97** — `Validate` 和 `Feed` 都检查 `observed == 0` 并返回 pass/noop。TTL=0 的包在网络层已被丢弃，该检查是防御性的。但如果 TTL=0 真的到达，静默忽略而非记录 WARNING 可能掩盖上游问题。

修复: 考虑在 `observed == 0` 时记录一条 Warning 级别日志（但注意不要刷屏，可用 `log.RateLimit` 或采样）。

两个文件均在入口处对 `response == nil` 做了防御检查。

---

### 15. 常量提取

**F-13 | LOW | const | hopguard.go:248** — 衰减因子 `3/4` 是内联魔法数字。该值直接影响路由变化后的收敛速度，应当提取为命名常量如 `hopGuardDecayNumerator = 3` / `hopGuardDecayDenominator = 4` 或组合常量。

风险: 无法在测试或配置中引用该常数，修改时需要搜索全文。

**F-14 | LOW | const | hopguard.go:197** — 阈值公式 `max(maxCount/4, 4)` 中的除数 `4` 和下限 `4` 应提取为命名常量（如 `hopGuardThresholdDivisor` / `hopGuardThresholdFloorMin`），因为它们是算法调优的关键参数。

**F-15 | INFO | const | hopguard.go:129** — 学习日志采样间隔 `8` 应提取为 `hopGuardLearningLogInterval`。可与 `hopGuardMinSamples` 合并为 `minSamples/4` 以表达语义关联。

---

### 16. RFC 一致性

**F-16 | LOW | rfc | poisonguard.go:112** — `IsPoisonedByTLD` 仅检查 A 和 AAAA 记录类型。RFC 的 poisoning 检测应该也考虑 CNAME 链——如果一个 TLD 服务器返回 `www.example.com CNAME other.example.com`，中间盒也可能通过这种方式注入。当前实现不会捕获这种场景。

风险: 可能漏报通过 CNAME 注入的 poisoning 攻击。

修复: 扩展 `IsPoisonedByTLD` 的 switch 检查，添加 `dns.TypeCNAME` 和可能的 `dns.TypeDNAME`。

**F-17 | INFO | rfc | hopguard.go:42** — `hopGuardFluctuation = 2` 的文档明确说明这是经验值，并提示 anycast PoP 可能需要更宽的窗口。文档完善，体现了对 RFC 不确定性的诚实。

---

### 17. 函数排序

两个文件均遵循 `type → const → var → func` 的 decorder 规则。构造函数 `NewHopGuard` 紧跟在 `HopGuard` 类型定义之后。`serverState` 类型没有构造函数（内联创建），符合 Go 实践。

---

### 18. BadgerDB 存储

不适用。`hopguard.go` 使用 `lrumap.Map`（内存 LRU），`poisonguard.go` 无存储依赖。

---

### 发现汇总

| ID | 文件 | 行 | 严重度 | 类别 | 描述 |
|----|------|------|--------|------|------|
| F-01 | poisonguard.go | 43-48, 87-91 | MEDIUM | deadcode | VerdictUncertain 被自身注释承认无人消费；Validate 对其短路返回，跳过后续 RR |
| F-07 | hopguard.go | 146-148 | MEDIUM | nil/semantics | Confident() nil receiver 返回 true，语义不合理 |
| F-12 | hopguard.go | 64-65 | MEDIUM | param | observed==0 时静默 pass，无日志记录 |
| F-05 | poisonguard.go | 84, 108 | LOW | alloc | Canonical 在循环内对每个 RR 产生 string 分配 |
| F-06 | poisonguard.go | 87, 90 | LOW | perf | dns.RRToType(rr) 在 poison 路径上调用两次 |
| F-13 | hopguard.go | 248 | LOW | const | 3/4 衰减因子为内联魔法数字 |
| F-14 | hopguard.go | 197 | LOW | const | 阈值公式中的 4 应提取为命名常量 |
| F-16 | poisonguard.go | 112 | LOW | rfc | IsPoisonedByTLD 未检查 CNAME/DNAME，可能漏报 |
| F-03 | hopguard.go | 153 | INFO | lock | Confident 使用 Lock 而非 RWMutex（可通过 atomic.Bool 优化） |
| F-04 | hopguard.go | 42 | INFO | naming | 常量前缀合规，无问题 |
| F-08 | hopguard.go | 206-208 | INFO | bounds | lo<1 clamp 因 caller 已过滤 observed==0 而冗余 |
| F-09 | poisonguard.go | 90 | INFO | nil | dns.TypeToString 是 map 读取，不会 panic |
| F-10 | hopguard.go | 51-55 | INFO | lifecycle | 无 Close() 方法（依赖 lrumap 可 GC） |
| F-11 | hopguard.go | 129-131 | INFO | log | 学习日志每 8 条记录一次，频率略高 |
| F-15 | hopguard.go | 129 | INFO | const | 学习日志间隔 8 应提取常量 |
| F-17 | hopguard.go | 42 | INFO | rfc | Fluctuation=2 的经验值已文档化，OK |

### 关键改进建议

1. **高优先级**: 统一 nil HopGuard 的行为（F-07）—— `Confident` 应返回 `false` 而非 `true`，避免误导调用方。
2. **死代码治理**: 移除或启用 `VerdictUncertain`（F-01）—— 可以将其从枚举中删除，或将 authoritative zone 的 classify 改为返回 `VerdictClean`。
3. **性能**: 在 `Validate` 和 `IsPoisonedByTLD` 循环中使用 `strings.EqualFold` 替代 `dnsutil.Canonical`（F-05），消除每 RR 一次 string 分配。
4. **可维护性**: 提取 `3/4`（F-13）、`4`（F-14）、`8`（F-15）为命名常量，使算法参数可引用和测试。
5. **RF完整性**: 扩展 `IsPoisonedByTLD` 检查 `dns.TypeCNAME`（F-16）以覆盖通过别名注入的场景。