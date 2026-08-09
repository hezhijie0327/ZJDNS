# 07 — server/defense/* 审计（hopguard / poisonguard / spoofguard / splitguard）

## 结论：防御层自身无泄漏；两个发现归属上游调用方

- **hopguard**：TTL 基线学习状态为 `lrumap`（容量 256）+ 原子计数，淘汰正确；`ShouldSampleRejected`/`Feed` 采样路径无状态累积。
- **poisonguard**：纯函数分类器，无 per-domain 状态。
- **splitguard**：无状态（分段参数即时计算）。
- **spoofguard 状态机**（`spoofguardState`）：per-query 局部变量，全部退出路径归还（`pool.DefaultMessage.Put` 三候选 + previous），无跨查询滞留。
- **发现的池归还缺口（M8）位于调用方** `server/upstream/plain/udp.go` 的 collect 循环（短包/hopguard 拒绝路径漏 `pkt.Release()`），详见 04-upstream.md M8 —— 是上游调用方违反 collectPacket 契约，非 defense 包自身问题。
- **detector 实例生命周期**：per-upstream，随配置固定，无重载泄漏路径。
