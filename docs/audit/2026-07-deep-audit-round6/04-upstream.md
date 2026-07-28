# Upstream Audit — server/upstream/*

**日期**: 2026-07-28
**范围**: server/upstream/plain, tls, tlcp, dnscrypt, pool, socks5, warmup (27 文件)

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| U1 | **HIGH** | validation, panic | `tlcp/dtlcp.go:43` | `ExecuteDTLCP` 缺少 nil msg/server 检查 |
| U2 | **HIGH** | validation, panic | `tlcp/http_tlcp.go:18` | `ExecuteHTTPTLCP` 缺少 nil msg/server 检查 |
| U3 | MEDIUM | code-quality, performance | `dnscrypt/client.go:169-186` | 截断重试使用递归而非循环（最多 56 次递归） |
| U4 | MEDIUM | validation, rfc-compliance | `plain/udp.go:340` | Spoofguard EDNS 门控在查询缺少 OPT 时被绕过 |
| U5 | MEDIUM | memory | `tls/quic.go:173-191` | Pooled buffer 地址在 Unpack 前存在于 response.Data 中 |
| U6 | MEDIUM | performance | `plain/tcp.go:86` | `exchangeViaProxy` 中进行堆分配而非使用 pool |
| U7 | LOW | dead-code | `socks5/udp.go:207-208` | `cleanupLocked` 中未使用的 `ctrlClosed` channel 替换 |
| U8 | LOW | performance | `dnscrypt/state.go:99-101` | 并发证书获取无 singleflight 去重 |
| U9 | LOW | lock, documentation | `pool/tcp.go:352-354` | TOCTOU 注释不完整（未提及 Shutdown） |
| U10 | LOW | ordering | `tlcp/client.go:39-83` | `dtlcpClientConfig` 在 `client.go` 中，而非 `dtlcp.go` |
| U11 | LOW | validation | `dnscrypt/client.go:183` | 递归重试路径中的冗余 nil 检查 |
| U12 | LOW | code-quality | `socks5/udp.go:245-377` | `ReadFrom`/`Read` 和 `WriteTo`/`Write` 之间重复的中继逻辑 |

---

## 关键发现

### U1/U2 — DTLCP/HTTP-TLCP 中缺少 nil 检查 (HIGH)

`ExecuteDTLCP` 和 `ExecuteHTTPTLCP` 均不对 `msg` 或 `server` 执行 nil 检查，而其他所有 `Execute*` 方法均有此检查（`tls/tls.go:19-24`、`plain/udp.go:57-62`）。

**修复**: 在函数顶部添加 nil 检查，与其他 Execute* 方法保持一致。

### U3 — 截断重试递归 (MEDIUM)

DNSCrypt `Execute` 在 TC 位上递归调用自身，可达 56 次递归。每次递归都会增加栈帧、defer 和状态机重新进入。

**修复**: 将 `return c.Execute(ctx, msg, server, useTCP)` 替换为 `for state.minQueryLen < maxQueryLen { ... }` 循环。

### U4 — Spoofguard 故障开放 (MEDIUM)

当 `queryUDPSize == 0`（无 OPT 记录）时，非 EDNS 拒绝代码块被完全跳过。实际的 EDNS 中间件总是会添加 OPT，但若其中间件被禁用，则防御会静默减弱。

**修复**: 将门控条件从 `queryUDPSize > 0` 改为 `true`，或为非 EDNS 查询添加显式的提前返回。

---

## 无问题维度

- 锁正确性：无 ABBA 死锁路径
- goroutine 生命周期：使用 HandlePanic 和信号 channel 进行正确的清理
- 错误包装：所有路径均有一致的上下文
