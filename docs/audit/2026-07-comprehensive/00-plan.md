# ZJDNS 审计修复计划 — 2026-07 全覆盖清单

## 概述

基于 `12-synthesis.md` 综合报告的 60 个发现，按 AUDIT-METHODOLOGY.md §2 修复流程执行。

| Sprint | 范围 | 数量 | 策略 |
|--------|------|------|------|
| Sprint 1 | CRITICAL | 1 | 立即修复 |
| Sprint 2 | HIGH | 8 | 立即修复 |
| Sprint 3 | MEDIUM + LOW | 51 | 按优先级子排序 |

## 修复优先级（同一 Sprint 内）

1. **单字符/单行修复** — 最快
2. **模式匹配修复** — 可模板化
3. **逻辑重写** — 状态机/并发结构
4. **死代码删除** — 未用符号

---

## Sprint 1 — CRITICAL（1）

### C1. ReadTCPMsg use-after-Put

- **文件**: `internal/dnsutil/tcpframe.go:36-47`
- **类别**: pool-leak, memory, panic
- **修复类型**: 单行修复
- **修复**: L43 后添加 `msg.Data = slices.Clone(msg.Data)`
- **验证**: `go build ./... && go test -short ./internal/dnsutil/...`

---

## Sprint 2 — HIGH（8）

### H1. ExecuteDoHRequest HTTP 响应体泄漏

- **文件**: `internal/dnsutil/https_dns.go:57,65`
- **类别**: resource, memory
- **修复类型**: 逻辑重写
- **修复**: 在替换 Body 前关闭原始响应体；或将 NopCloser 替换为包装了原始 Close 的自定义 ReadCloser
- **验证**: `go build ./... && go test -short ./internal/dnsutil/...`

### H2. DTLCP 单连接 Accept DoS

- **文件**: `server/protocol/tlcp/dtlcp.go:265`
- **类别**: goroutine, performance
- **修复类型**: 逻辑重写
- **修复**: 在 `handleDTLCPConnection` 调用周围添加 select with timeout，防止单连接永久阻塞 accept 循环
- **验证**: `go build ./...`

### H3. HopGuard 永久拒绝所有状态

- **文件**: `server/defense/hopguard.go:117-126`
- **类别**: correctness, state-machine
- **修复类型**: 逻辑重写
- **修复**: `rebuildTrusted` 后检查 `len(st.trusted) == 0` → 重置 `st.armed = false`, `st.samples = 0`
- **验证**: `go test -short ./server/defense/...`

### H4. Pending-refresh 锁泄漏（stale-prefetch）

- **文件**: `server/handler/middleware/cache_lookup.go:88-98`
- **类别**: resource, goroutine
- **修复类型**: 单行修复
- **修复**: `TryGo` 返回 false 时立即调用 `m.finishRefresh(...)`
- **验证**: `go build ./...`

### H5. serveExpiredWithRefresh goroutine + 锁泄漏

- **文件**: `server/handler/middleware/cache_lookup.go:119-145`
- **类别**: resource, goroutine
- **修复类型**: 逻辑重写
- **修复**: `TryGo` 失败时间步关闭 `done` channel 并调用 `finishRefresh`
- **验证**: `go build ./...`

### H6. 递归 NS 路径池消息泄漏

- **文件**: `server/resolver/nameserver.go:71-82`
- **类别**: pool-leak
- **修复类型**: 单行修复
- **修复**: 在 `msg` 获取后添加 `defer pool.DefaultMessage.Put(msg)`，并更新注释
- **验证**: `go build ./... && go test -short ./server/resolver/...`

### H7. ExecuteQuery 消息所有权约定冲突

- **文件**: `server/resolver/forward.go:83-85`, `nameserver.go:71-77`
- **类别**: api-design
- **修复类型**: 模式匹配修复
- **修复**: 在 `ExecuteQuery` 文档中明确"调用方拥有消息所有权，应在调用后 Put"；确保两个调用点一致
- **验证**: `go build ./...`

### H8. DNSCrypt 递归重试

- **文件**: `server/upstream/dnscrypt/client.go:186`
- **类别**: correctness
- **修复类型**: 逻辑重写
- **修复**: 将递归改为带最大迭代次数的 for 循环
- **验证**: `go build ./... && go test -short ./server/upstream/dnscrypt/...`

---

## Sprint 3 — MEDIUM（18）

### M1. padding.go 双重 Pack

- **文件**: `edns/padding.go:40`
- **类别**: performance
- **修复**: 缓存打包结果并复用；或在计算后不重复 Pack

### M2. cache.Set 静默 Pack 失败

- **文件**: `cache/store.go:233-236`
- **类别**: error-handling
- **修复**: `Pack()` 失败时记录 Debug 日志，不存储条目

### M3. padding.go 阻塞式 crypto/rand.Read

- **文件**: `edns/padding.go:46`
- **类别**: performance
- **修复**: 替换为 `math/rand/v2.Rand.Read`

### M4. makeAddrValidator nil 缓存

- **文件**: `server/protocol/tls/addr_validator.go:18`
- **类别**: panic
- **修复**: 添加 nil 检查，nil 时返回 true

### M5. decrypt 无边界检查

- **文件**: `server/protocol/dnscrypt/crypto.go:146,170`
- **类别**: panic
- **修复**: 函数顶部添加 `len(b) < ClientMagicSize` 检查

### M6. plain.Server.Start() 无 nil 检查

- **文件**: `server/protocol/plain/server.go:34`
- **类别**: validation
- **修复**: 添加 g 和 handler 的 nil 检查

### M7. Spoofguard copyBuf 无界增长

- **文件**: `server/upstream/plain/udp.go:307-314`
- **类别**: memory
- **修复**: 定期缩小 copyBuf（如每 N 次调用重置）

### M8. TLCP fmt.Sprintf → strings.Builder

- **文件**: `server/upstream/tlcp/http_tlcp.go:35`
- **类别**: performance
- **修复**: 替换为 `strings.Builder` + `Grow`

### M9. SOCKS5 双重 goroutine

- **文件**: `server/upstream/socks5/udp.go:180-201`
- **类别**: code-quality
- **修复**: 添加重构注释，标记为技术债务

### M10. SOCKS5 UDP deadline

- **文件**: `server/upstream/socks5/udp.go:164`
- **类别**: resource
- **修复**: 清除 UDP socket 的 deadline

### M11. 死 nolint 注释

- **文件**: `server/upstream/dnscrypt/crypto.go:21-23`
- **类别**: comments
- **修复**: 移除无效的 nolint

### M12. HTTP3 warmup cfg 遮蔽

- **文件**: `server/upstream/tls/http3.go:148-149`
- **类别**: code-quality
- **修复**: 添加注释说明有意遮蔽

### M13. cache.Set 错误静默丢弃

- **文件**: `server/handler/middleware/cache_lookup.go:191-192,225`, `cache_store.go:108`
- **类别**: logging
- **修复**: 添加 Debug 级别错误日志

### M14. Validation 穿透逻辑

- **文件**: `server/handler/middleware/validation.go:62-84`
- **类别**: code-quality
- **修复**: 重构为早期返回模式

### M15. handler→resolver 耦合

- **文件**: `server/handler/handler.go:17`
- **类别**: coupling
- **修复**: 文档化（有意为之，不修改代码）

### M16. Req "immutable" 注释

- **文件**: `server/handler/context.go:19-21`
- **类别**: comments
- **修复**: 更新注释为 "Pointer is never reassigned"

### M17. processUpstreamResponse 参数过多

- **文件**: `server/resolver/forward.go:240`
- **类别**: code-quality
- **修复**: 将参数分组到 processUpstreamResponseParams 结构体

### M18. cacheGlueRecords 混合类型

- **文件**: `server/resolver/recursive_ns.go:107-110`
- **类别**: correctness
- **修复**: 在缓存前按 A/AAAA 类型分组

---

## Sprint 3 — LOW（33）

### L1. 死参数 isUDP

- **文件**: `internal/dnscryptcrypto/encrypted.go:109,163`
- **修复**: 移除 isUDP 参数，更新所有调用点

### L2. MarshalBinary 文档

- **文件**: `internal/dnscryptcrypto/certificate.go:170-171`
- **修复**: 更新注释

### L3. Decrypt/DecryptPQInitial 类型不一致

- **文件**: `internal/dnscryptcrypto/encrypted.go:434,488`
- **修复**: 统一参数类型

### L4. IdleConnTimeout + DisableKeepAlives

- **文件**: `internal/latency/httppool.go:56,62`
- **修复**: 移除 IdleConnTimeout

### L5. readVLP 放错文件

- **文件**: `internal/stamp/encode.go:156`
- **修复**: 移动到 parse.go

### L6. splitOptionalPort 括号 IPv6

- **文件**: `internal/stamp/encode.go:223-230`
- **修复**: 修正 host 切片边界

### L7. 重复 ESVersion switch

- **文件**: `internal/dnscryptcrypto/encrypted.go:196-249`
- **修复**: 提取为单个守卫检查

### L8. stats 高延迟桶

- **文件**: `stats/stats.go:120-127`
- **修复**: >10s 值计入最后一个桶

### L9. additional 双重 clone

- **文件**: `cache/store.go:221,226`
- **修复**: 重构为单次 clone

### L10. 空协议错误消息

- **文件**: `config/validate.go:162-183`
- **修复**: 添加显式协议非空检查

### L11. ecsFallbackCandidates 分配

- **文件**: `cache/store.go:329-349`
- **修复**: 使用栈分配数组

### L12. DNSHandler 重复注释

- **文件**: `edns/edns.go:17-23`
- **修复**: 合并注释块

### L13. Content-Type 精确匹配

- **文件**: `server/protocol/tls/https.go:148-149`
- **修复**: 使用 strings.HasPrefix

### L14. 自赋值 no-op

- **文件**: `server/protocol/tlcp/certs.go:89,98`
- **修复**: 移除 self-assignment

### L15. 非池化消息分配

- **文件**: `server/protocol/dnscrypt/crypto.go:158-268`
- **修复**: 添加注释说明原因

### L16. 孤儿监听器

- **文件**: `server/protocol/plain/tcp.go:24-29`
- **修复**: 失败时关闭已打开的监听器

### L17. errgroup.WithContext 返回值

- **文件**: `server/protocol/tls/quic.go:138`
- **修复**: 命名变量

### L18. handleDOQStream nil 检查

- **文件**: `server/protocol/tls/quic.go:171`
- **修复**: 添加 nil guard

### L19. DTLS 缓冲区

- **文件**: `server/protocol/tls/dtls.go:107`
- **修复**: 处理 io.ErrShortBuffer

### L20. 握手大小估算

- **文件**: `server/protocol/dnscrypt/server.go:402-425`
- **修复**: 添加 TODO 注释用于预计算

### L21. 死代码 var _ int64

- **文件**: `server/handler/middleware/cache_store.go:100`
- **修复**: 移除

### L22. 关闭超时孤儿 goroutine

- **文件**: `server/tasks.go:212-232`
- **修复**: 添加注释说明可接受

### L23. HasPaddingOption 两次调用

- **文件**: `server/handler/middleware/response.go:57-59`
- **修复**: 缓存结果

### L24. needsTCPFallback 死代码

- **文件**: `server/upstream/client.go:312-314`
- **修复**: 添加注释标记为防御性代码

### L25. fetchCertOverUDP 缓冲区

- **文件**: `server/upstream/dnscrypt/cert.go:66`
- **修复**: 添加注释说明低频调用

### L26. socks5PacketConn 零值

- **文件**: `server/upstream/socks5/udp.go:310`
- **修复**: 添加 nil guard

### L27. splitHostPort 错误

- **文件**: `server/upstream/socks5/socks5.go:396-401`
- **修复**: 记录原始错误

### L28. DefaultQUICClientIdleTimeout

- **文件**: `server/upstream/tls/client.go:189`
- **修复**: 确认（无问题）

### L29. 死错误处理

- **文件**: `server/resolver/nameserver.go:331-333`
- **修复**: 移除 dead 分支

### L30. discard resolveNSAddrType 返回值

- **文件**: `server/resolver/nameserver.go:280,289`
- **修复**: 添加注释说明

### L31. captureUpstreamEDE

- **文件**: `server/resolver/forward.go:160`
- **修复**: 移至文件顶部

### L32. NSEC3 Opt-Out 常量

- **文件**: `server/resolver/dnssec/nsec.go:216`
- **修复**: 定义为命名常量

### L33. RootKeys() 切片

- **文件**: `server/resolver/dnssec/crypto.go:183`
- **修复**: 返回 slices.Clone

---

## 质量门禁

### 每次提交前

```bash
go build ./...                    # 零编译错误
go fix ./...                      # 自动修复
golangci-lint run                 # 零警告
golangci-lint fmt                 # 格式化
```

### Sprint 1+2 完成后

```bash
go test -short ./...              # 全部测试
go test -short ./internal/dnsutil/...
go test -short ./server/defense/...
go test -short ./server/resolver/...
```

### 全部 Sprint 完成后

```bash
go test -short ./...              # 全量测试
go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
# 对比旧基线检测 >15% 回归
```

---

## 提交计划

每个发现独立提交，主题行格式 `<type>: <具体描述> (<审计引用>)`：

```
Sprint 1:
git commit -m "fix: clone msg.Data after Unpack in ReadTCPMsg to prevent use-after-Put (C1)"

Sprint 2:
git commit -m "fix: close original HTTP body before replacing in ExecuteDoHRequest (H1)"
git commit -m "fix: add connection timeout in DTLCP accept loop to prevent DoS (H2)"
git commit -m "fix: reset HopGuard to learning mode when all trusted TTLs decay (H3)"
git commit -m "fix: release pending-refresh lock on TryGo failure in stale-prefetch (H4)"
git commit -m "fix: close done channel on TryGo failure in serveExpiredWithRefresh (H5)"
git commit -m "fix: return pool message after ExecuteQuery in recursive NS path (H6)"
git commit -m "fix: document ExecuteQuery message ownership — caller owns after return (H7)"
git commit -m "refactor: replace recursive Execute call with loop in DNSCrypt truncation (H8)"

Sprint 3: (分组提交同类修复)
git commit -m "fix: log cache Set failures at debug level (M2, M13)"
git commit -m "perf: use math/rand/v2 for padding bytes to avoid crypto/rand blocking (M3)"
...
```

---

*计划日期: 2026-07-30 | 预计总提交: ~50 | 预计修复时间: Sprint 1 (5min) + Sprint 2 (30min) + Sprint 3 (2hr)*
