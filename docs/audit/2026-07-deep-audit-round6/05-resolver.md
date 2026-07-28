# Resolver Audit — server/resolver/*

**日期**: 2026-07-28
**范围**: server/resolver (recursive, forward, dnssec, probe, root_hints, zonecut) — 17 文件

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| R1 | **HIGH** | pool-leak | `nameserver.go:141-143` | NXDOMAIN pool 泄漏 — CAS 存储的响应在 NOERROR 胜出时永不归还 |
| R2 | MEDIUM | comment-accuracy | `dnssec_chain.go:426-428` | `tryRRSIGRetry` 无文档说明地修改调用方的 response 原地替换 |
| R3 | MEDIUM | performance | `dnssec_chain.go:394` + `zonecut.go:80` | `getZoneCutSigner` 在同一 zone-cut 解析周期内重复调用 |
| R4 | MEDIUM | rfc-compliance | `forward.go:81-88` | 硬编码的 `isSecure` 协议白名单，缺少新协议自动判定 |
| R5 | MEDIUM | validation | `resolver.go:154-157` | `New(cfg)` 不验证内部字段（`QueryClient`、`EDNS`、`Cache`） |
| R6 | MEDIUM | coupling | `root_hints.go:27-30` | 包级别 `rootHints` 单例 — 测试无法重置缓存状态 |
| R7 | LOW | pool-leak | `nameserver.go:155-157` | 当 `result.Error != nil` 时 `result.Response` 静默丢弃 |
| R8 | LOW | dead-code | `zonecut.go:179-181` | `isZoneCut` 是 `getZoneCutSigner` 的薄包装 |
| R9 | LOW | memory | `recursive_helpers.go:42-43` | 响应 Put 在 helper 函数内部 — 生命周期脆弱 |
| R10 | LOW | performance | `recursive_helpers.go:46` | 响应在 helper 内 Put — 在循环级别统一管理更清晰 |
| R11 | LOW | performance | `forward.go:103-113` | `g.Wait()` goroutine 每次转发查询产生（每个查询一个短生命周期 goroutine） |
| R12 | LOW | panic | `qname_minimise.go:27,41,56` | `dnsutil.Prev()` 错误被丢弃 — 无效 FQDN 可能导致切片越界 |
| R13 | LOW | panic | `recursive.go:87` | `dns.TypeToString` map 查找未知 qtype — 日志中显示空字符串 |
| R14 | LOW | performance | `recursive_ns.go:115` | 每个 glue 记录集的探测 goroutine 爆发 |
| R15 | LOW | comment-accuracy | `dnssec/extract.go:146` | `CacheZoneKeys` godoc 未提及 canonicalization |

---

## 关键发现

### R1 — NXDOMAIN Pool 泄漏 (HIGH)

`queryNameserver` 使用 `atomic.Pointer[dns.Msg]` CAS 延迟 NXDOMAIN 作为备用。当任何 goroutine 发送 NOERROR 响应到 `resultChan` 时，主 select 读取并返回。CAS 成功的指针持有的 NXDOMAIN `*dns.Msg` 永不归还 `pool.DefaultMessage`。

**修复**: 从 `resultChan` 读取 NOERROR 结果后，加载 `nxdomainMsg` 指针，若非 nil 则调用 `pool.DefaultMessage.Put(nx)`。

### R2 — tryRRSIGRetry 副作用 (MEDIUM)

`tryRRSIGRetry` 将 `response.Answer`、`response.Ns` 和 `response.Extra` 替换为重试响应中的切片，从而原地修改调用方的 `*dns.Msg`。这一副作用在函数注释中未说明。

**修复**: 在函数注释中说明此修改是刻意的，或将重试响应单独返回，由调用方决定是否替换。

### R4 — 硬编码协议白名单 (MEDIUM)

`isSecure` 布尔值是安全协议的白名单。新增安全协议（如 DoH/3 的 QUIC）时必须手动更新此列表，否则会被错误地当作非安全协议处理。

**修复**: 在 `config.UpstreamServer` 或 `config.Protocol` 上添加 `IsSecure()` 方法，统一维护判定逻辑。

---

## 无问题维度

- 死锁：递归 singleflight 去重正确使用 defer
- RFC 一致性：QNAME 最小化（RFC 9156）和 DNSSEC 验证（RFC 4034/4035）正确实现
- 函数排序：所有文件均遵循规范
