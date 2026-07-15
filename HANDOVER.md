# ZJDNS 综合审计报告与重构进度

> 2026-07-15 · 4 代理并行审计 · 23,500 行 Go 代码 · 28 项发现

---

## 审计结果汇总

| 优先级 | 数量 | 主要影响 |
|--------|------|----------|
| 🔴 Critical | 3 | 数据竞争可致 panic、全项目 DNS 库传递依赖、架构分层违规 |
| 🟠 High | 9 | 运行时循环耦合、不可测试、内存泄漏、连接泄漏 |
| 🟡 Medium | 7 | 性能浪费、维护性差、未来重构陷阱 |
| 🟢 Low | 9 | 命名不一致、冗余代码、代码异味 |

---

## 🔴 严重问题（Critical）

### C-1. DNSCrypt `s.keys` 数据竞争 — 可致 Panic
**文件**: `server/protocol/dnscrypt/server.go:305-314` + `server_crypto.go:85,140`
**问题**: 加密/解密路径无锁读取 `s.keys` 切片，`rotateKeys()` 在 `s.mu.Lock()` 下修改切片头（append）。Go 内存模型规定并发读写切片为 data race，可导致切片越界 panic、读到垃圾数据。
**读取路径（无锁）**: `current()`, `hasClientMagic()`, `decrypt()`, `decryptPQResumed()`
**写入路径（有锁）**: `rotateKeys()` — `s.keys = append([]keyEntry{entry}, s.keys...)`
**修复**: 所有读取路径加 `s.mu.RLock()`，或用 `atomic.Pointer[[]keyEntry]`。
**状态**: ⏳ 待修复

### C-2. `config` 包引入 DNS 库 + 运行时状态污染配置类型
**文件**: `config/config.go:4-6, 155-169`
**问题 A**: `config` 包（Layer 2 基础层）导入 `codeberg.org/miekg/dns`，仅为了在 `ZoneRule` 上放 `[]dns.RR` 字段。所有导入 `config` 的包（几乎全部）都传递依赖了 DNS 库。
**问题 B**: `ZoneRule` 包含 4 个 `json:"-"` 运行时字段（`CachedAnswer`, `CachedAuthority`, `CachedAdditional`）和一个函数闭包字段（`DynamicContent`）。配置类型变成运行时状态的混合容器。
**修复**: 创建 `zone.LoadedRule` 包装类型承载运行时字段，从 `config.ZoneRule` 移除所有 `json:"-"` 字段和 DNS 库依赖。
**状态**: ⏳ 待修复

### C-3. 领域包相互导入，违反分层架构
**文件**: `cache/store.go:10`, `zone/zone.go:15`
**问题**: CLAUDE.md 声明 "Domain packages never import other domain packages"，但 `cache → database` 和 `zone → database` 违背此规则。
**修复**: 在 `database` 层定义 `Storage` 接口，`cache.New()` 和 `zone.New()` 接受接口而非具体 `*database.DB`。
**状态**: ⏳ 待修复

---

## 🟠 高优先级（High）

### H-1. Handler ↔ Resolver 运行时双向耦合
**文件**: `server/server.go:212-219`, `handler/handler.go:50,108`
**问题**: `handler.Handler` 持有具体 `*resolver.Resolver`，`resolver.Resolver` 持有捕获 handler 方法的 `BuildQueryFunc` 闭包。运行时循环：`handler → resolver → handler`，迫使使用两阶段初始化。
**修复**: 在 `resolver` 包定义 `MessageBuilder` 接口，handler 实现它。
**状态**: ⏳ 待修复

### H-2. Handler 持有具体 `*resolver.Resolver` 而非接口
**文件**: `server/handler/handler.go:50`
**问题**: 违反 "accept interfaces, return structs"。所有 handler 测试都必须是集成测试。
**修复**: 在 handler 包定义 `Resolver` 接口（Query, Recursive, UpstreamEDEOption 方法）。
**状态**: ⏳ 待修复

### H-3. Resolver 持有具体 `*upstream.Client` 而非接口
**文件**: `server/resolver/resolver.go:68`
**问题**: 硬依赖全部 7 种传输实现，无法无集成测试 resolver 的查询调度逻辑。
**修复**: 在 resolver 包定义 `UpstreamClient` 接口。
**状态**: ⏳ 待修复

### H-4. Resolver 直接导入同级子包 `dnssec`, `hijack`, `probe`
**文件**: `server/resolver/resolver.go:14-17`, `recursive.go:17`
**问题**: 违反依赖倒置——接口定义在生产方，消费者被迫依赖具体实现。
**修复**: 在 resolver 包定义接口（消费者侧），子包实现接口。
**状态**: ⏳ 待修复

### H-5. `upstream.Client` 是上帝对象
**文件**: `server/upstream/client.go:46-53`
**问题**: 硬编码导入全部 7 个传输子包 + SOCKS5。`executeSecureQuery` 是大 switch 语句。
**修复**: 策略模式——`TransportExecutor` 接口 + 注册表。
**状态**: ⏳ 待修复

### H-6. Cache 操纵数据库内部锁（抽象泄漏）
**文件**: `cache/store.go:247-248`, `database/db.go:182-185`
**问题**: Cache 直接获取 database 内部的 `writeMu`。
**修复**: 添加 `db.ExecWrite(fn func(*sql.Tx) error)` 方法封装事务。
**状态**: ⏳ 待修复

### H-7. HTTP 客户端池 Close 后 nil map 访问
**文件**: `internal/latency/httppool.go:83`
**问题**: `Close()` 设置 `p.clients = nil`，但 `get()` 无 nil 保护，关闭后可能 panic。
**修复**: `get()` 加 nil map 守卫。
**状态**: ⏳ 待修复

### H-8. TCP/QUIC 连接池 TOCTOU 连接泄漏
**文件**: `server/upstream/pool/tcp.go:327-362`, `pool/quic.go:69-127`
**问题**: `dialAndAdd` 释放锁拨号期间，`Shutdown()` 可清空池，新连接被加入空池永不关闭。
**修复**: 重新获取锁后检查池关闭标志。
**状态**: ⏳ 待修复

### H-9. `upstream.Result` 有 4 个死字段
**文件**: `server/upstream/client.go:31-42`
**问题**: `Answer`, `Authority`, `Additional`, `ECS` 字段全代码库从未赋值，每次查询浪费 ~72 字节。
**修复**: 删除死字段，仅保留 `Validated`（有在使用）。
**状态**: ⏳ 待修复

---

## 🟡 中优先级（Medium）

### M-1. DNSCrypt WaitGroup 交换时间窗口
**文件**: `server/protocol/dnscrypt/server.go:277-278`
**问题**: 先交换 `s.wg` 再 `s.cancel()`，存在 goroutine 未被 join 的极窄窗口。
**修复**: 先 cancel 再交换 wg。
**状态**: ⏳ 待修复

### M-2. DNS64 A 子查询绕过 Pending 去重
**文件**: `server/handler/handler_cache.go:185-195`
**问题**: 两个并发 AAAA miss 各自独立发起 A 子查询，绕过 `PendingRequests` 去重。
**状态**: ⏳ 待修复

### M-3. 动态 SQL IN 子句在缓存热路径上构建
**文件**: `cache/store.go:186-196`
**问题**: 每次 `Get()` 用 `strings.Builder` 构建 `IN (?,?,?)` 字符串。
**状态**: ⏳ 待修复

### M-4. 不完整的 `h.edns` nil 守卫
**文件**: `server/handler/handler.go:300-306`
**问题**: nil 守卫只覆盖 `req.Unpack()`，后面两行无保护。
**状态**: ⏳ 待修复

### M-5. 陈旧的 fallback goroutine 无生命周期管理
**文件**: `server/handler/handler_cache.go:143-158`
**问题**: 超时后的后台 goroutine 不被 errgroup 跟踪。
**状态**: ⏳ 待修复

### M-6. 大文件超 500 行
- `internal/stamp/stamp_codec.go` (645 行) — 拆分为 parse/encode/vlp
- `server/protocol/dnscrypt/server.go` (489 行)
- `server/handler/handler.go` (468 行)
- `zone/zone.go` (463 行)
- `server/server.go` (453 行)
**状态**: ⏳ 待拆分

### M-7. 误导性文件名
| 文件 | 建议重命名 |
|------|-----------|
| `server/resolver/chain.go` | `dnssec.go` |
| `server/resolver/recursive_cache.go` | `ns_addresses.go` |
| `server/handler/message.go` | `response.go` |
| `server/protocol/tls/https_http.go` | `doh.go` |
| `server/protocol/dnscrypt/encryptedresp.go` | `encryptedresponse.go` |
**状态**: ⏳ 待重命名

---

## 🟢 低优先级（Low）

| # | 文件 | 问题 |
|---|------|------|
| L-1 | `resolver/resolver.go:305` | `ShuffleSlice` 返回被原地修改的同一切片 |
| L-2 | `handler/handler_cache.go:235-332` | `Recursive()` 同一函数内调用 5 次 |
| L-3 | `upstream/client.go:126,152,192` | `ToLower`→`ToUpper` 往返 |
| L-4 | `server/server.go:28` | import alias `traditionalserver` → `servertraditional` |
| L-5 | `resolver/nameserver.go:324` | `isEqualFoldTrimDot` 过于冗长 |
| L-6 | `edns/cookie.go:289-344` | SipHash-2-4 提取到 `internal/siphash/` |
| L-7 | `handler/handler.go:29` | 类型别名 `Question = resolver.Question` |
| L-8 | `handler/handler.go:91-93` | 运行时类型断言获取 `ReverseLookup` |
| L-9 | `resolver/resolver.go:79` | handler 和 resolver 各自持有冗余 cache 引用 |

---

## 重构路线图

### 阶段 1：数据安全（当前执行中）
- [ ] C-1: DNSCrypt `s.keys` 加读锁
- [ ] H-7: HTTP pool nil map 守卫
- [ ] H-8: TCP/QUIC pool TOCTOU 连接泄漏
- [ ] H-9: 删除 `upstream.Result` 死字段

### 阶段 2：解耦
- [ ] C-2: config 移除 DNS 库依赖和运行时字段
- [ ] C-3: 领域包接口倒置
- [ ] H-1/H-2: Handler↔Resolver 循环 → 接口
- [ ] H-3: Resolver 接受 UpstreamClient 接口
- [ ] H-6: DB ExecWrite 封装

### 阶段 3：模块化
- [ ] H-4: Resolver 消费者侧接口（dnssec/hijack/probe）
- [ ] H-5: upstream.Client → 策略模式
- [ ] M-6: 拆分大文件
- [ ] M-7: 重命名误导性文件

### 阶段 4：优化
- [ ] M-1: DNSCrypt WaitGroup 顺序
- [ ] M-2: DNS64 去重
- [ ] M-3: SQL 热路径优化
- [ ] L-1 ~ L-9: 低优先级清理

---

## 关键决策

1. 不考虑向后兼容——允许彻底重构
2. 零耦合是所有架构修改的目标
3. 所有修改需通过 `go fix ./... && golangci-lint run && golangci-lint fmt`
4. 每个阶段完成后提交
