# 2026-08 深度审计 — 修复计划

## 审计范围

按 `AUDIT-METHODOLOGY.md` 18 维度框架，对以下核心包执行深度审计：

- `cache/` — BadgerDB 缓存层
- `server/handler/middleware/` — 中间件管道
- `server/protocol/{tls,dnscrypt}/` — 协议处理器
- `server/upstream/{dnscrypt,tls}/` — 上游客户端
- `server/defense/` — 防御模块
- `server/resolver/` — 递归/转发解析器
- `database/` — 存储引擎
- `config/` — 配置与常量

## 交叉扫描覆盖

| 维度 | 方法 | 结果 |
|------|------|------|
| Goroutine 生命周期 | `grep go func` — 25 处，全部有 HandlePanic + owner | ✅ 无发现 |
| 池归还纪律 | `grep defer.*Put` — 25+ 处正确 defer Put | ⚠️ C1 泄漏 |
| 错误包装 | `grep fmt.Errorf.*%v.*err` — 0 处 | ✅ 100% %w |
| Context 断裂 | `grep context.Background` — 仅测试/main/防御性回退 | ✅ 无发现 |
| Close 幂等 | `grep func.*Close` — sync.Once/atomic 守卫 | ✅ 无发现 |
| 裸类型断言 | `grep .(\*` — 0 处 | ✅ 无发现 |
| 魔法数字 | 长数字字面量扫描 | ✅ 已抽取为命名常量 |
| 手写反向循环 | `grep for i := len.*-1` — 0 处 | ✅ 已现代化 |
| 手动有界 map | `grep map.*sync.Mutex` — 0 处 | ✅ 全部用 lrumap |
| lrumap OnEvict | 11 处 lrumap.New，资源型值均设 OnEvict | ✅ 无发现 |
| 热路径日志 | `grep log.Info/Warn` — 均在启动/状态变更路径 | ✅ 无刷屏 |
| TODO/FIXME | `grep TODO\|FIXME\|HACK` — 0 处 | ✅ 无过期 TODO |
| 冗余函数对 | `grep func.*With[A-Z]` — 无冗余对 | ✅ 无发现 |

## 发现清单

| ID | 严重度 | 文件 | 描述 |
|----|--------|------|------|
| C1 | CRITICAL | cache/store.go:101-106 | Get 的 Unpack 失败路径泄漏 pool message |
| H1 | HIGH | server/upstream/dnscrypt/client.go:103 | defer Close 在 for 循环中累积 |
| H2 | HIGH | server/handler/middleware/cache_store.go:91-93 | ECS 不匹配时静默丢弃查询，客户端无响应 |
| H3 | HIGH | server/protocol/dnscrypt/server.go:328 | rotateKeys 替换 sharedKeyCache 未清理旧实例 |
| M1 | MEDIUM | server/protocol/dnscrypt/server.go:171-204 | serveUDP/serveTCP 用原始 goroutine 而非 errgroup（风格不一致） |
| M3 | MEDIUM | server/handler/middleware/cache_lookup.go:137-139 | context.Background() 防御回退是死代码 |
| M4 | MEDIUM | cache/store.go:104,290,296 | Warn 日志在重复损坏条目场景下可能刷屏 |

## 修复顺序

1. **C1** — 单行修复，池泄漏
2. **H2** — ECS mismatch 返回 SERVFAIL
3. **H1** — 提取辅助函数消除 defer-in-loop
4. **H3** — sharedKeyCache 旋转清理
5. **M3** — 添加注释说明
6. **M4** — 降级为 Debug 或限流
