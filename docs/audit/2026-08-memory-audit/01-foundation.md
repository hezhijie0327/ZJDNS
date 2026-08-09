# 01 — internal/* 基础包审计

## M6 [MEDIUM] CallGroup.Done 把被淘汰 leader 的结果发布到替代 entry 并误删

- **位置**：internal/pending/pending.go:287（`Done` 的 `Get(key)`）、:306（`CompareAndDelete`）
- **类别**：race
- **问题描述**：`CallGroup` 用 `lrumap.Map`（容量 maxPending）+ `OnEvict`（242-247 行，淘汰时以 `ErrEvicted` 唤醒 followers）。`Done` 按 **key** 反查 entry（287 行）—— 若原 entry 已被 LRU 淘汰、同一 key 有并发新 leader 重新 Join（257 行 LoadOrStore 装入新 entry），旧 leader 的 `Done` 会：
  1. 把旧结果发布进**新** entry（错误结果归属）；
  2. `CompareAndDelete(key, 新entry)` **误删还在运行中的新 entry**（306 行）→ 新 leader 的 `Done` 变成 no-op（288-290 行 Get 失败即返回）→ 新 leader 的 followers 永远不被唤醒，烧满 followerTimeout 后 ErrTimeout。
- **风险**：LRU 淘汰窗口（容量压力 + 并发同 key）下：错误结果被当作正确结果分发（数据正确性）+ 后续调用超时（可用性）。窗口窄但后果是数据级错误，且 `-race` 检测不到（语义错误非内存竞态）—— 这正是"corner case"类问题。
- **修复建议**：leader 身份化 —— `Join` 返回 leader 持有的 entry 令牌（或 `Done` 接收 entry 指针）；发布前校验 entry 仍是 map 当前值（CompareAndDelete 已是正确原语，只缺身份验证）。最小改动：`Join` 的 leader 分支返回 entry，`Done` 签名改 `Done(entry *callEntry[V], val, err)`，更新全部调用点（grep `\.Done(` 确认：DNSKEY fetch 等）。

## lrumap / topk / snapfile / pool / stamp / log / ttl / ipdetect

- **无发现**。已确认：
  - lrumap：`OnEvict` 恰好一次（Delete/CompareAndDelete/淘汰路径统一走 remove → evictLocked）、Clear 幂等、Range 持锁语义正确（但其持锁范围被上层滥用 —— 见 02-domain.md H5，问题在调用方）；
  - topk：容量有界 + 最低计数淘汰正确；
  - snapfile：见 02-domain.md 正向确认；
  - internal/pool：Message/Buffer 分配器 Get/Put 对称，无双重归还路径（协议层身份守卫缺口见 03-protocol.md L5）；
  - stamp/log/ttl/ipdetect：无状态累积。
