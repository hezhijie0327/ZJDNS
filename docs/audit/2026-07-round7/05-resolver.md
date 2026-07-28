# Resolver 层审计报告 (Phase 1)

审计范围: `server/resolver/*` + `server/resolver/dnssec/*` + `server/resolver/probe/*` (17 个源文件)
审计日期: 2026-07-28

## 总览

| 严重程度 | 数量 | 关键问题 |
|----------|------|----------|
| CRITICAL | 2 | DNSSEC nil crypto dereference panic、forward.go 缺少 HandlePanic |
| HIGH | 5 | pool-use-after-free (×2)、CDS RRSIG 绕过、nil-crypto (×3)、retry mutation |
| MEDIUM | 7 | 性能/分配、永久失败无重试、context 取消、TTL cap 时机 |
| LOW | 8 | 边界情况、字节长度比较、非确定性 shuffle |

**共 22 个发现** (2 CRITICAL, 5 HIGH, 7 MEDIUM, 8 LOW)

## CRITICAL

### C1: DNSSEC nil crypto dereference panic

- **文件**: `server/resolver/dnssec_chain.go:306-307, 141-148, 218`
- **类别**: `panic`
- **描述**: CryptoValidator 为 nil 时（DNSSEC 未配置），`isDNSSECValid()`、`ensureZoneDNSKEYs()` 和 `verifyDelegationDSRRSIG()` 在无 nil 守卫的情况下解引用 `r.resolver.validator.Crypto`，导致 panic 崩溃服务器。
- **风险**: DNSSEC 未配置时任何递归查询导致服务器崩溃 — 生产环境 DoS。
- **修复**: 添加 `if crypto == nil { return false }` 守卫。

### C2: forward.go errgroup goroutines 缺少 HandlePanic

- **文件**: `server/resolver/forward.go:60, 72`
- **类别**: `goroutine`
- **描述**: errgroup goroutines 缺少 `zdnsutil.HandlePanic()` recovery。任何 panic（buildMsg/ExecuteQuery/processUpstreamResponse 内部）会使整个服务器崩溃。而 nameserver.go errgroup goroutines (line 63) 正确有 HandlePanic。
- **风险**: 单次畸形上游响应导致全服务器崩溃。
- **修复**: 添加 `defer zdnsutil.HandlePanic("UPSTREAM query")`。

## HIGH

### H1: CDS RRSIG 验证绕过 — offline-KSK 回退路径

- **文件**: `server/resolver/dnssec_chain.go:276-303`
- **类别**: `rfc`
- **描述**: `verifyViaCDS()` 逐字节比较 CDS 和父 DS 记录但不验证 RRSIG。中间人攻击者可注入伪造 CDS 记录匹配父 DS，绕过 offline-KSK 认证。RFC 7344 要求 CDS 通过 RRSIG 验证。
- **风险**: Offline-KSK 委托认证绕过 — 攻击者使解析器信任伪造 DNSKEY。
- **修复**: 用已验证的 DNSKEY 验证 CDS RRSIG。

### H2: response sections 在 pool.Put() 后继续使用 — 悬挂指针

- **文件**: `server/resolver/recursive_helpers.go:45-52, 93-100`
- **类别**: `memory`
- **描述**: `checkLameDelegation()` 和 `collectBestNSMatch()` 在 `pool.DefaultMessage.Put(response)` 后存储 `response.Ns/Extra` 切片到 QueryResult。切片头指向已归还的 pooled memory。
- **风险**: DNS 响应段数据损坏 → SERVFAIL、错误答案或下游内存损坏。
- **修复**: Put 前深度复制 response 段。

### H3-H5: nil crypto panic 路径

| ID | 文件 | 描述 |
|----|------|------|
| H3 | `dnssec_chain.go:306-373` | isDNSSECValid 无 nil 守卫 — 非 DNSSEC 模式主要 panic 触发点 |
| H4 | `dnssec_chain.go:147-148` | ensureZoneDNSKEYs 无 nil 守卫 — NODATA 响应触发 |
| H5 | `dnssec_chain.go:428-430` | tryRRSIGRetry 修改调用方 response — 脆弱的同步依赖 |

## MEDIUM (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| M1 | `forward.go:60-99` | errgroup goroutines 缺少 HandlePanic（与 C2 同源） |
| M2 | `nameserver.go:273,278` | resolveNSAddrType 未使用的 addrs 返回值 — 浪费分配 |
| M3 | `nameserver.go:349-357` | domainNamesEqual "." / "" 边界情况 |
| M4 | `root_hints.go:40-58` | loadHints sync.Once 永久失败 — 无重试 |
| M5 | `dnssec/trust_anchor.go:45-106` | 信任锚加载失败无重试 |
| M6 | `probe/probe.go:180-182` | ProbeNSAddrs nil ctx → Background() — 忽略关闭取消 |
| M7 | `dnssec/nsec.go:233-269` | TTL cap 时序 — pooled response 可能丢失 capped 值 |

## LOW (摘要)

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `recursive_helpers.go:29-30` | QNAME minimisation 用字节长度而非 label 计数 |
| L2 | `ns_addresses.go:120-139` | refreshEntry 冷启动死代码 |
| L3 | `dnssec_chain.go:261-270` | key tag 碰撞可能性 |
| L4 | `nameserver.go:361` | CancelFunc vs CancelCauseFunc 不一致 |
| L5 | `dnssec_chain.go:218-256` | verifyDelegationDSRRSIG 缺少 nil 守卫 |
| L6 | `zonecut.go:77-78` | verifyZoneCut 缺少 nil 守卫 |
| L7 | `dnssec/extract.go:151-156` | TTL int 转换 32 位溢出风险 |
| L8 | `resolver.go:253-261` | math/rand/v2 不可种子化 — 非确定性测试 |
