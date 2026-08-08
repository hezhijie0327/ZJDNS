# HANDOVER — 2026-08-08 docs/debug 全场景测试中断项

## 未解决 bug：递归模式 MQTYPE 请求确定性卡死

**复现**：`/tmp/zjdns -config docs/debug/loopback/server-dnssec.json`（递归 + dnssec_enforce）
```
dig @127.0.0.1 -p 12733 +ednsopt=20:001c example.com A +time=20 +tries=1   # 永远无响应
```
20s 也无响应（服务器不返回 SERVFAIL）。**旧代码（d8d2c43 worktree 构建）同样复现** —— 既有 bug，非本次审计修复引入。

**行为**：
- 转发模式（server.json → AliDNS）MQTYPE 正常（AliDNS 忽略选项返回普通 A）
- 递归模式：主查询 A 递归**成功**（日志见 com./example.com 查询 success）→ merge → secondary AAAA resolve → `RECURSION: depth=0, querying example.com. (type=AAAA, zone=., ns=[13 roots])` 日志后**再无输出** → 卡死
- MQTYPE 请求后，**同实例的后续普通查询也全部卡死**（单飞/锁状态被污染？）
- 无 MQTYPE 时递归完全正常（普通 A/AAAA 连续查询成功，偶发间歇性失败——13 个 root 中有不可达的如 192.5.5.241，first-win 竞争导致偶发全失败，dig +time=6 短于 walk 的 9s deadline）

**观察到的关键日志**（debug 级别）：
```
RECURSION: depth=0, querying example.com. (type=AAAA, zone=., ns=[13 roots])   ← 最后输出
CACHE: async batch begin failed (28 items): context deadline exceeded          ← 批写器超时
```

**调查进展**（已排除）：
- ✅ 不是 miekg MQQUERY Unpack 问题（v0.6.91 有 `case *MQQUERY` unpack；请求能到 handler（QUERY 日志存在））
- ✅ 不是 root 服务器对 option 20 返回 FORMERR（直测 198.41.0.4/199.7.91.13 对 MQQUERY 返回 NOERROR）
- ✅ 不是 errgroup first-error cancel（所有 goroutine 返回 nil，成功路径显式 cancel()）
- ✅ 不是客户端 MQQUERY 透传进 root 查询（递归路径 mqt=nil，MQTypeFromContext 只在转发路径读）
- ⚠️ 主查询完成 → merge → secondary 的 walk 卡在 `querying` 日志之后、`qname minimisation` 之前 —— 即 `lookupDelegation`（SQLite 读）或 `applyDelegationStart` 处
- ⚠️ `async batch begin failed: context deadline exceeded` 暗示 SQLite 写锁竞争；delegation lookup 用无 ctx 的 StmtDelegationLookup（busy_timeout=10s 应兜底，但 20s 仍无响应）
- ⚠️ 主查询 A 完成后 28 项缓存待写（batch 未 flush 成功）→ 疑似批写器与 delegation 读的锁竞争

**下一步建议**：
1. 在 `lookupDelegation` 前后加日志确认卡点是否在 SQLite 读
2. 检查 `:memory:` 单连接（MaxOpenConns=1）下批写器持有写锁时读查询的行为；`StmtDelegationLookup` 改 QueryRowContext（带 ctx）
3. 检查主查询 walk 是否有未提交事务/未释放连接
4. 修复后回归：`dig +ednsopt=20:001c example.com A` 应返回 A + AAAA + MQTYPE-Response 选项

## 测试环境注意

- **用户自己的实例在跑**：`./zjdns -config config.debug.json`（PID 49264，占 15353）、`./zjdns -config server.json`（PID 19453）—— **不要杀**
- pkill -f 对 zjdns 实例无效（SIGTERM 优雅关停挂起）—— 用 `kill -9 <pid>` 清理自己的测试实例
- 本机网络：root 服务器 192.5.5.241 不可达（探测失败 MaxInt64）；rfc-editor 不可达（RFC 9443 无法下载存档）
- /tmp/named.root、/tmp/root-anchors.xml 已存在（exec 目录）—— root hints 加载正常
