# 2026-08 全库审计 — 逐项修复计划

> 遵循 AUDIT-METHODOLOGY.md §2 Sprint 策略与 §3 质量门禁。
> 每个修复独立提交，主题行描述**具体修复内容**（附发现编号），禁止笼统描述。
> 提交前: `go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt`（零警告）。
> 每 Sprint 后: `go test -short ./...` + benchmark 基线对比（>15% 变慢即回归）。

## Sprint 1 — HIGH（立即修复）

### 1.1 bridge.go tcpWriteEntry refcount 修复（H1/H6）【CRITICAL 级修复须谨慎】
- **文件**: `server/bridge.go:55-76`、`server/tasks.go:117-144`
- **修复**: 引入 `s.tcpWriteMuLock sync.Mutex`（server.go 字段）；请求路径在锁内完成 `LoadOrStore + refs.Add(1)`（去掉 line 56/65 的 placeholder 语义或保留但立即释放）；sweep 在锁内完成 `refs==0 && stale → Delete`。消除 check-then-delete TOCTOU。
- **验证**: 新增单测——完整请求后 `refs.Load() == 0`；sweep 能删除 stale entry；`go test -race ./server/`。
- **禁止**: 仅补 `refs.Add(-1)` 而不处理 TOCTOU（会重新激活帧交错损坏窗口）。

### 1.2 dns64 RFC 6052 前缀相关嵌入（H2）
- **文件**: `internal/dns64/dns64.go:49-63`
- **修复**: 按 RFC 6052 Figure 1 实现 /32,/40,/48,/56,/64,/96 的 IPv4 嵌入位置（含 u octet 置零与双段拆分），ExtractIPv4 同步反转。
- **验证**: RFC 6052 §2.4 golden 用例（/32: 2001:db8::/32+192.0.2.33 → 2001:db8:c000:221::；/96 well-known 前缀）；全部 prefix 长度 round-trip 测试。

### 1.3 TLS Shutdown 持锁迭代（H3）
- **文件**: `server/protocol/tls/server.go:338-394`
- **修复**: 全部切片迭代与 `s.h3Server` 读取置于 `s.listenerMu.Lock()` 内（对齐 closeListeners 纪律）。
- **验证**: `go test -race` + 启动窗口内信号压测。

### 1.4 TLCP Shutdown 同步（H4）
- **文件**: `server/protocol/tlcp/server.go:196-228`、`tlcp.go:53`、`http_tlcp.go:36`、`dtlcp.go:236`
- **修复**: 引入 `listenerMu`，append 与 Shutdown 迭代统一持锁（仿 TLS 模式）。
- **验证**: `go test -race`。

### 1.5 proxyDialers nil 写竞态（H5）
- **文件**: `server/upstream/client.go:306`
- **修复**: 删除 `c.proxyDialers = nil`（仿 `server/upstream/tls/client.go:106-108` 既有注释模式——map 随 Client 死亡，dialer 已 Close）。若确需释放引用，用互斥保护 proxyDialer 全部读写。
- **验证**: `go test -race ./server/upstream/...` + 关闭窗口代理查询压测。

### 1.6 cache Set() 计数膨胀（H7）
- **文件**: `cache/store.go:336-374`
- **修复**: 仅新行创建时 `AddEntryCount(1)`：`INSERT ... ON CONFLICT DO NOTHING` 或 `RETURNING id, (xmax = 0)` 判断是否替换；同步修正 store.go:386-387 误导性注释（drift 并非 rare）。
- **验证**: 单测——对同一 key 连续 Set N 次后 `EntryCount() == 1`（或与 `SELECT COUNT(*)` 一致）；TTL 循环压力下无提前驱逐。

### 1.7 database.Version 接线（H8）
- **文件**: `database/migration.go:23`、`cmd/zjdns/main.go:42`、`database/open.go`（如存在）
- **修复**: 启动时设置 `database.Version`（从 `config.DefaultVersion` 或显式传入 `Open()`），删除"调用方设置"的间接注释陷阱；补一个真实版本字符串的集成测试（已有 cache.db 场景）。
- **验证**: 用旧版二进制建库 → 新版启动 → 断言迁移执行、version 行 = 实际版本。
- **注意**: 这是升级路径安全修复，优先级最高之一——现有部署升级后可能因 schema 过期拒绝启动。

## Sprint 2 — MEDIUM 高价值（下个发布周期）

| # | 文件 | 修复 |
|---|------|------|
| M1 | middleware/cache_lookup.go:168 | 替换 qctx.Res 前先 `pool.DefaultMessage.Put(旧 msg)` |
| M2 | middleware/cache_lookup.go:138 | errgroup.Go 改 `TryGo` + 失败降级（stale 直接返回），或预分配 slot |
| M3 | middleware/cache_lookup.go:176 | 刷新成功路径清除 `qctx.EDE` |
| M4 | middleware/response.go:67 + edns.go:127 | BADCOOKIE 响应跳过二次 ApplyToMessage（标记 qctx 或在 ApplyToMessage 内去重既有 SUBNET/COOKIE） |
| M5/M24 | middleware/edns.go | 全量 unpack 后检查 `opt.Version()`，非零回 RCODE=BADVERS（RFC 6891 §6.1.3 MUST）+ OPT 携带版本 0 |
| M8 | protocol/tlcp/tlcp.go:119 | 写响应前 `SetWriteDeadline(DefaultDNSQueryTimeout)`（对齐 tls.go:124） |
| M12/M28 | protocol/dnscrypt/server.go:385 + tcp.go:99 + udp.go:108 | wg swap 与读取统一持 s.mu；serveUDP/serveTCP 加入 wg 跟踪 |
| M13 | upstream/pool/tcp.go:158 | 防御分支移出锁区或补 Unlock |
| M14 | cmd/zjdns/cli/parse.go:257 | --sql 失败 `os.Exit(1)` |
| M17 | internal/dns64/dns64.go:57 | ExtractIPv4 私有化或删除（无生产调用者） |
| M29 | ruleset/ruleset.go:126 | 加 `StmtRulesetDomain` 预编译语句（仿 StmtZoneExact）；空表短路 |
| M30 | cache/store.go:308 | 去掉 stripOPT 前的多余深拷贝 |
| M31 | cache/store.go:322 | msgWire == nil 时跳过插入，补 Debug 日志 |

## Sprint 3 — 其余 MEDIUM + LOW（文档/优化）

### 3.1 死代码（M15/M16 + LOW dead-code 项）
- `cache/cache.go:18` RequestRecord 只写字段、不存在的 FK 注释
- `handler/context.go:37` QueryContext 6 死字段

### 3.2 性能（M6/M18/M19 + LOW perf 项）
- M6: getRootServers 内存缓存（13 根名 × 26 SQLite 查询/每递归查询 → TTL 内存副本）
- M18: DNS64 二次 A 查询走缓存
- M19: cache 写路径改用 database 包 prepared stmts

### 3.3 文档（M21-M23, M25 + LOW docs 项）
- ARCHITECTURE.md PQ client-magic / ticket 布局与代码对齐
- CLAUDE.md prepared stmts 8→10
- 6 个未存档 RFC 镜像到 docs/rfc/

### 3.4 日志与注释（M20, M26, M10, M9, M11 + LOW 项）
- TLCP DoH Error→Warn 对齐
- DTLS accept 循环补退避（与注释矛盾）
- TLCP DoT 连接洪水 → accept 前 handshake 超时
- TLS/TLCP Shutdown 缩短读 deadline（或接受 60s 上限并记录）
- 注释准确性逐项（LOW）

### 3.5 函数排序/常量/Go 版本（LOW 项）
- 按 decorder 与聚合规则调整（golangci-lint 已覆盖的跳过）

## 修复顺序铁律

1. 每个修复独立 commit，主题行 `fix: <具体内容> (<发现编号>)`
2. 跨包同根因可合并（如 M12+M28 同 commit）
3. 修复后立即跑目标包测试 + race
4. 全部完成后刷新 benchmark 基线
