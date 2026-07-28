# Synthesis — Round 6 Deep Audit

**日期**: 2026-07-28
**范围**: 172 源文件，213 Go 文件总计，21 Agent（8 Phase 1 + 13 Phase 2）
**维度**: 14 维度 × 每个文件 + 13 跨包交叉分析

---

## 总体统计

| 严重程度 | Phase 1 | Phase 2 | 总计 |
|----------|---------|---------|------|
| **CRITICAL** | 0 | 3 | **3** |
| **HIGH** | 6 | 18 | **24** |
| **MEDIUM** | 18 | ~50 | **~68** |
| **LOW** | 54 | ~73 | **~127** |
| **总计** | **78** | **~144** | **~222** |

---

## 🔴 CRITICAL 发现 (3)

| ID | 来源 | 文件 | 描述 |
|----|------|------|------|
| C1 | CrossCut Locks | `server/protocol/dnscrypt/server.go:236-292` | DNSCrypt `Shutdown()` 中 `s.wg` 数据竞争 — `s.mu.Unlock()` 和重新 `Lock()` 之间的窗口期并发读写 `s.wg` 指针，导致 goroutine 泄漏或 shutdown 挂起 |
| C2 | CrossCut Perf | `server/upstream/plain/udp.go:307,342,382` | Spoofguard 三路 `make([]byte, n)` 每候选分配 — 10k QPS 下产生 50k+ allocs/s，~8-20 MB/s 垃圾 |
| C3 | CrossCut Perf | `server/resolver/dnssec/crypto.go:294` 等 | DNSSEC 验证中重复 `strings.ToLower` — 已验证响应的每个 RR 都分配新字符串，150k+ strings/s |

---

## 🟡 HIGH 发现 Top 10

| ID | 来源 | 文件 | 描述 |
|----|------|------|------|
| H1 | Phase 1 Protocol | `tls/quic.go:197` | Pool 归还纪律缺失 — `Get()` 无 `defer Put()` |
| H2 | Phase 1 Protocol | `tls/https.go:124`, `tlcp/http_tlcp.go:95`, `tlcp/tlcp.go:101` | 非 pool 对象 Put 入 pool |
| H3 | Phase 1 Upstream | `tlcp/dtlcp.go:43`, `http_tlcp.go:18` | ExecuteDTLCP/ExecuteHTTPTLCP 缺少 nil 检查 |
| H4 | Phase 1 Handler | `middleware/dns64.go:66` | `pending.Join` 返回 nil 未检查 → panic |
| H5 | Phase 1 Resolver | `nameserver.go:141-143` | NXDOMAIN pool 泄漏 — CAS 存储的响应永不归还 |
| H6 | CrossCut Memory | `socks5/udp.go:179-198` | SOCKS5 dialer LRU 淘汰 → goroutine 泄漏 |
| H7 | CrossCut Logging | `upstream/plain/udp.go:143` | HopGuard 不支持的平台每查询触发 Warn（日志刷屏） |
| H8 | CrossCut Docs | `ARCHITECTURE.md:124-127` | 三个不存在的 DNSCrypt 函数名 |
| H9 | CrossCut Docs | `CLAUDE.md:154` | SQL 示例引用不存在的列 `e.hit_udp` |
| H10 | CrossCut Docs | `BENCHMARK.md:168` | DTLCP 测试端口错误 (14553 vs 14653) |

---

## 📊 系统性主题

### 1. Pool 生命周期纪律 (最高频)

**影响**: Protocol + Resolver + Upstream
**修复工作量**: ~20 处单行修改

- `tls/quic.go` 缺少 deferred Put
- 3 处非 pool 对象 Put 入 pool
- 系统性 `response.Data` 未 nil 化 (15+ 处)
- NXDOMAIN pool 泄漏

### 2. 跨协议一致性 (持续问题)

**影响**: TLCP 处理器系统性落后于 TLS
**模式**: DTLCP/HTTP-TLCP 缺少 nil 检查、关闭时 I/O 持锁、证书到期阈值不一致、net.ErrClosed 检查不对称

### 3. DNSSEC 热路径性能

**影响**: 所有 DNSSEC 验证的递归查询
**根因**: 重复的 `strings.ToLower`、无容量提示的 map 分配、重复的 `getZoneCutSigner` 调用、三次 DS 验证 RR 切片分配

### 4. 文档腐化

**影响**: ARCHITECTURE.md、CLAUDE.md、BENCHMARK.md、DEBUG.md
**根因**: 代码演进后文档未同步更新 — 函数名、SQL 列名、端口号、日志格式均已过期

### 5. 架构耦合 (Layer 4 子包)

**影响**: 5 个跨子包直接导入绕过 server 布线层
**关键**: `resolver→defense`、`resolver→upstream`、`handler→resolver`、`upstream/plain→defense` — 无实际 DAG 违规，但增加重构风险

---

## ✅ 质量亮点

- **零 DAG 层违规** — 所有导入遵守已记录的规则
- **零裸类型断言** — 80+ 断言点全部 comma-ok
- **零除零** — 唯一的变量除法有守卫
- **零 nil map 写入** — 所有 map 在使用前通过 `make()` 初始化
- **零 use-after-Put** — `msg.Data = nil` 模式正确应用
- **零 TODO/FIXME/HACK** — 生产代码中无技术债务标记
- **零过时注释引用** — 所有注释符号引用均有效
- **完整 RFC 存档** — 所有实现协议在 `docs/rfc/` 中有对应文本
- **Defense 包** — 清洁代码，无中高级别发现

---

## 🔧 Sprint 修复计划

### Sprint 1: CRITICAL (立即)

1. **C1**: DNSCrypt `Shutdown()` — 将 `s.wg` swap 移入同一锁区间
2. **C2**: Spoofguard — 复用池读缓冲区给 `resp.Data`，消除 `make([]byte, n)`
3. **C3**: DNSSEC ToLower — 预规范化 + 传递小写名称通过验证链

### Sprint 2: HIGH (下个发布周期)

4. **H1**: QUIC handler 添加 `defer pool.Put()`
5. **H2**: 移除/修复 3 处非 pool 对象的 `pool.Put()`
6. **H3**: DTLCP/HTTP-TLCP 添加 nil 参数检查
7. **H4**: DNS64 添加 nil 守卫
8. **H5**: NXDOMAIN 返回路径添加 `pool.Put()`
9. **H6**: SOCKS5 dialer LRU 淘汰回调
10. **H7**: HopGuard Warn 添加抑制 (sync.Map 去重)
11. **H8-H10**: 修复 ARCHITECTURE.md、CLAUDE.md、BENCHMARK.md 文档错误

### Sprint 3: MEDIUM + LOW (持续改进)

12. Pool 生命周期: 系统性 `Data=nil` 前 Put (15+ 处)
13. DNSSEC 性能: map 容量提示、zone cut signer 缓存
14. 协议一致性: TLCP 对齐 TLS (net.ErrClosed、证书阈值)
15. 日志降级: Error→Warn (6 处可恢复条件)
16. 构造函数校验: ruleset/cache/zone/handler 添加 nil 检查
17. 函数排序: 重组 `log.go` 和 `dnscrypt/server.go` 方法组
18. Godoc: 补充 `zone.Evaluator`、`ipdetect.Detector`、`dns64` 方法、`dnscryptcrypto` PQ 函数
19. 死代码清理: `ipttl.Capture.conn`、重复 `tcpKeepAliveListener`、重复 `KTLSSettings`
20. 常量: `socks5WriteBufSize`、`SecondsPerDay`、CLI 端口引用

---

## 📋 修复全覆盖清单

- [ ] C1: DNSCrypt Shutdown 数据竞争
- [ ] C2: Spoofguard 三重分配
- [ ] C3: DNSSEC 重复 ToLower
- [ ] H1: QUIC handler deferred Put
- [ ] H2: 非 pool 对象 Put 移除
- [ ] H3: DTLCP/HTTP-TLCP nil 检查
- [ ] H4: DNS64 nil 守卫
- [ ] H5: NXDOMAIN pool 归还
- [ ] H6: SOCKS5 dialer 淘汰回调
- [ ] H7: HopGuard Warn 抑制
- [ ] H8-H10: 文档修复 (3 文件)
- [ ] H11-H12: Locks HIGH (TCP pool close、DTLCP I/O)
- [ ] H13-H14: Panic HIGH (CSPRNG 错误返回)
- [ ] H15-H16: Ordering HIGH (log.go、dnscrypt/server.go)
- [ ] M1-M50: MEDIUM 发现（见各包报告）
- [ ] L1-L127: LOW 发现（见各包报告）
