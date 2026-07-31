# 2026-08 深度审计 — 综合报告

## 审计方法

- **框架**: `AUDIT-METHODOLOGY.md` 18 维度
- **工具**: 交叉 grep 扫描 + 深度代码阅读 + 编译验证
- **范围**: 核心运行时路径（cache, handler, protocol, resolver, upstream, defense, database, config）

## 发现详情

### C1 — CRITICAL: cache.Get 池泄漏

**文件**: `cache/store.go:101-106`

**问题**: `Get()` 方法在 `pool.DefaultMessage.Get()` 后若 `msg.Unpack()` 失败，pool message 未归还。

```go
msg := pool.DefaultMessage.Get()
msg.Data = msgWire
if err := msg.Unpack(); err != nil {
    log.Warnf(...)
    return nil, false, false  // ← BUG: msg 泄漏
}
defer pool.DefaultMessage.Put(msg)
```

**影响**: 每次 Unpack 失败永久丢失一个 `*dns.Msg`，高负载下池耗尽导致频繁 GC。

**修复**: 在 return 前添加 `pool.DefaultMessage.Put(msg)`。

---

### H1 — HIGH: DNSCrypt 客户端 defer-in-loop

**文件**: `server/upstream/dnscrypt/client.go:103`

**问题**: `defer func() { _ = conn.Close() }()` 在 for 循环内，每次迭代累积 defer 直到函数返回。

**影响**: 最多 `maxTCRetries` 个 defer 累积。功能安全但延迟关闭，违反资源生命周期最佳实践。

**修复**: 提取 `executeOnce()` 辅助函数，defer 自然在函数边界执行。

---

### H2 — HIGH: CacheStore ECS mismatch 静默丢弃

**文件**: `server/handler/middleware/cache_store.go:91-93`

**问题**: `buildSuccess()` 中 ECS 不匹配返回 `nil`，调用方 `serve()` 收到 nil 后直接 return，客户端无任何响应。

```go
if !edns.VerifyECSResponse(ecsOpt, responseECS) {
    return nil  // ← 静默丢弃
}
```

**影响**: 检测到 ECS 投毒时客户端永远无响应，表现为 DNS 超时。

**修复**: 返回 SERVFAIL 而非 nil，让客户端能收到响应并重试其他服务器。

---

### H3 — HIGH: DNSCrypt sharedKeyCache 旋转泄漏

**文件**: `server/protocol/dnscrypt/server.go:328`

**问题**: `rotateKeys()` 创建新 `sharedKeyCache` 替换旧的，但旧实例未显式清理。

**影响**: 旧实例依赖 GC 回收。DNSCrypt 密钥每 24h 旋转，泄漏量可控但不符合显式资源管理原则。

**修复**: 替换前调用旧实例的清理方法，或复用同实例清空条目。

---

### M3 — MEDIUM: cache_lookup 死代码

**文件**: `server/handler/middleware/cache_lookup.go:137-139`

**问题**: `refreshCtx` 来自 `errgroup.WithContext()` 永远非 nil，`context.Background()` 回退是死代码。

**修复**: 添加注释说明 refreshCtx 来源保证，移除死代码分支。

---

### M4 — MEDIUM: cache Warn 日志可能刷屏

**文件**: `cache/store.go:104,290,296`

**问题**: `Warnf("unpack wire")` 和 `Warnf("serialize msg")` 在重复损坏条目场景下可能高频触发。

**修复**: 降级为 Debugf，或添加限流。

---

## 合规维度总结

| 维度 | 状态 | 备注 |
|------|------|------|
| 错误包装 | ✅ 100% | 全部使用 `%w` |
| Close 幂等 | ✅ | sync.Once / atomic 守卫 |
| Context 传播 | ✅ | 无断裂 |
| Goroutine 生命周期 | ✅ | HandlePanic + owner |
| 池归还纪律 | ⚠️ | C1 泄漏 |
| 常量提取 | ✅ | 全部命名常量 |
| 文档同步 | ✅ | 无过期 TODO |
| lrumap OnEvict | ✅ | 资源型值均设回调 |
| 热路径日志 | ⚠️ | M4 潜在刷屏 |
| RFC 合规 | ✅ | 9250/7871/9461 等合规 |
