# Fix Plan — Round 6 Deep Audit

**日期**: 2026-07-28
**审计范围**: 213 Go 文件，14 维度，21 Agent
**发现总计**: 3 CRITICAL + 24 HIGH + ~68 MEDIUM + ~127 LOW ≈ 222

---

## Sprint 1: CRITICAL (立即修复 — 3 项)

### C1: DNSCrypt Shutdown 数据竞争
- **文件**: `server/protocol/dnscrypt/server.go:236-292`
- **问题**: `Shutdown()` 在 `s.mu.Unlock()` 后、重新 `Lock()` 前，并发 `serveUDP`/`serveTCP` 可能读到不一致的 `s.wg` 指针
- **修复**: 将 `s.wg` swap 保持在锁区间内，避免锁-drop 窗口

### C2: Spoofguard 三重分配
- **文件**: `server/upstream/plain/udp.go:307,342,382`
- **问题**: 每个 spoofguard 候选都 `make([]byte, n)` 分配新缓冲区
- **修复**: 复用 `spoofguardBufPool` 缓冲区，避免 per-candidate 分配

### C3: DNSSEC 重复 ToLower
- **文件**: `server/resolver/dnssec/crypto.go:294`, `nsec.go:59,60,123,124,127,162`, `extract.go:36`
- **问题**: 已验证响应的每个 RR 都调用 `strings.ToLower` 分配新字符串
- **修复**: 在 DNSSEC 验证入口预规范化，传递小写名称通过验证链

---

## Sprint 2: HIGH (24 项)

| ID | 文件 | 问题 | 修复 |
|----|------|------|------|
| H1 | `tls/quic.go:197` | Pool Get 无 defer Put | 添加 `defer pool.DefaultMessage.Put(req)` |
| H2a | `tls/https.go:124` | 非 pool 对象 Put 入 pool | 移除 Put 或清理后 Put |
| H2b | `tlcp/http_tlcp.go:95` | 同上 | 同上 |
| H2c | `tlcp/tlcp.go:101` | 同上 | 同上 |
| H3a | `tlcp/dtlcp.go:43` | ExecuteDTLCP 缺少 nil 检查 | 添加 nil msg/server 检查 |
| H3b | `tlcp/http_tlcp.go:18` | ExecuteHTTPTLCP 缺少 nil 检查 | 添加 nil msg/server 检查 |
| H4 | `middleware/dns64.go:66` | pending.Join nil 未检查 | 添加 nil 守卫 |
| H5 | `resolver/nameserver.go:141-143` | NXDOMAIN pool 泄漏 | NOERROR 返回路径添加 Put |
| H6 | `socks5/udp.go:179-198` | SOCKS5 dialer 淘汰 → goroutine 泄漏 | 添加淘汰回调或定时清理 |
| H7 | `upstream/plain/udp.go:143` | HopGuard 每查询 Warn | 添加 sync.Map 抑制 |
| H8 | `docs/ARCHITECTURE.md:124-127` | 不存在的 DNSCrypt 函数名 | 更新为正确函数名 |
| H9 | `CLAUDE.md:154` | 不存在的列 `e.hit_udp` | 更新 SQL 示例 |
| H10 | `docs/benchmark/BENCHMARK.md:168` | DTLCP 端口错误 | 14553→14653 |
| H11 | `pool/tcp.go:426` | Conn.close() 持锁调用 | 移出锁外 |
| H12 | `tlcp/dtls.go:88-105` | I/O 在临界区内 | 收集指针、放锁、再关闭 |
| H13 | `dnscryptcrypto/encryption.go:58` | CSPRNG 失败 panic | 改为返回 error |
| H14 | `dnscryptcrypto/keys.go:28` | CSPRNG 失败 panic | 改为返回 error |
| H15 | `internal/log/log.go` | Logger 方法碎片化 | 重组为单一连续块 |
| H16 | `dnscrypt/server.go` | Server 方法碎片化 | 重组为单一连续块 |
| H17 | `upstream/plain/udp.go:47` | 裸 4096 应引用 pool.RecursiveUDPBufferSize | 使用命名常量 |
| H18 | `resolver/forward.go:31` | 每查询复制完整 server 列表 | 随机起始索引 |
| H19 | `resolver/recursive.go:290` | visitedCNAMEs map 每链分配 | 固定数组 [12]struct{} |
| H20 | `resolver/dnssec/crypto.go:288` | groupRRset 无容量提示 | make(map[...], len/2) |
| H21 | `resolver/dnssec_chain.go:235` | DS 验证 RR 切片分配 | sync.Pool 或接口改写 |
| H22 | `resolver/nameserver.go:67-69` | buildMsg 每 NS goroutine | 缓存模板、浅克隆 |
| H23 | `resolver/recursive_ns.go` | 重复 Fqdn/Canonical | 缓存到局部变量 |
| H24 | `siphash/siphash.go:10` | Sum64 无 nil key 检查 | 添加 nil 守卫 |

---

## Sprint 3: MEDIUM + LOW (~195 项)

按类别分组修复：

### Pool 生命周期 (MEDIUM)
- [ ] 系统性 `response.Data = nil` 前 Put (15+ 处协议处理器)
- [ ] 系统性 `defer Put` 配合 Get (quic, dtls, tlcp)
- [ ] `recursive_helpers.go:42-43` 响应 Put 移到调用方

### 性能 (MEDIUM)
- [ ] DNSSEC map 容量提示 (`nsec.go:236`, `crypto.go:288`)
- [ ] `upstream/client.go:142` ToLower 移到 config 加载
- [ ] `server/handler/prefetch.go:78` sort.Slice → slices.SortFunc
- [ ] `forward.go:103-113` g.Wait goroutine → done channel

### 日志 (MEDIUM)
- [ ] `cache/store.go:347,353,358` Warn 添加 qname + 降级
- [ ] `dnscrypt/server.go:375` Error→Warn (可恢复)
- [ ] `tls/server.go:397` Error→Warn (证书到期)
- [ ] `tlcp/server.go:160` Error→Warn (同上)
- [ ] `dnssec/crypto.go:53,58` Error→Warn (可恢复)
- [ ] `tasks.go:182,190,200,208` Error→Warn (shutdown)

### 文档 (HIGH/MEDIUM)
- [ ] DEBUG.md — 添加 spoofguard-socks5.json 到目录树
- [ ] DEBUG.md — 修复 Hopguard/Spoofguard 日志格式
- [ ] zone.Evaluator / ipdetect.Detector / dns64 方法 / PQ 函数 godoc

### 参数校验 (MEDIUM)
- [ ] `edns/padding.go:40` msg.Pack() 错误注释
- [ ] `cache/stats.go:45,48,187` 丢弃错误注释
- [ ] `qname_minimise.go:56` 添加 Prev 错误注释
- [ ] ruleset/cache/zone/handler 构造函数 nil 校验

### RFC 合规 (MEDIUM)
- [ ] NSEC3 迭代上限 → 0 (RFC 9077)
- [ ] rfc9018MAC 写入保留字节
- [ ] DDR 端口 853 时省略 port=

### 死代码/重复 (LOW)
- [ ] `ipttl.Capture.conn` 移除
- [ ] `siphash.Hash` → hash
- [ ] tlcp tcpKeepAliveListener → zdnsutil
- [ ] TLS KTLSSettings → config
- [ ] cloneRRs 提升到 internal/dnsutil

### 常量 (LOW)
- [ ] socks5/udp.go 1500 → socks5WriteBufSize
- [ ] cache/store.go + database/stmts.go 86400 → SecondsPerDay
- [ ] CLI probe.go/probe.go 端口 → config.Default*
- [ ] hopguard.go 8 → named const
- [ ] certs.go 128 → certSerialBitLen

### 函数排序 (HIGH)
- [ ] `internal/log/log.go` 重组 Logger 方法
- [ ] `server/protocol/dnscrypt/server.go` 重组 Server 方法
- [ ] 其他 MEDIUM/LOW 排序文件

### 架构耦合 (MEDIUM)
- [ ] resolver→defense: 提取共享类型或注入
- [ ] upstream/plain→defense: HopGuard 注入而非直接实例化

---

## 修复执行顺序

1. **单行修复** → C1, H1-H4, H7-H10
2. **模式匹配修复** → Pool 生命周期、nil 检查、错误降级
3. **逻辑重写** → C2-C3, H6, H11-H12
4. **死代码/重复删除** → 移除死字段、统一重复实现
5. **文档更新** → ARCHITECTURE.md, CLAUDE.md, BENCHMARK.md, DEBUG.md, godoc
6. **排序重组** → log.go, dnscrypt/server.go

## 质量门禁

每个 Sprint 后执行:
- `go build ./...` — 零编译错误
- `go fix ./... && golangci-lint run && golangci-lint fmt` — 零警告
- `go test -short ./...` — 全部通过
