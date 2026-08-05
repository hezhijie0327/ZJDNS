# foundation 审计

> agent: `a50d07996b0ee49bf`

发现数: 3

## foundation-01 — LOW

- **位置**: `internal/lrumap/lru.go:85`
- **类别**: resource
- **摘要**: lrumap.Set 覆盖已存在 key 时直接替换 e.val 而不调用 OnEvict，资源型值在并发 miss 竞态下泄漏
- **描述**: Set() 的已有-key 分支（lru.go:84-88）执行 `e.val = val` 静默丢弃旧值，OnEvict 仅在 evictLocked/Clear 路径触发（lru.go:224、147）。真实触发点：server/upstream/warmup.go proxyDialer 的 Get→Set 模式（Get miss 后 New 再 Set）——两个 goroutine 首次使用同一 proxy URL 并发 miss 时各建一个 *socks5.Dialer，后执行的 Set 覆盖先者且不调用其 Close，被覆盖的 Dialer 持有的 UDP relay conn（OnEvict 注释明确它是资源清理）永不关闭。server/upstream/tls/client.go:216 的 dohTransports Set 同理（每次竞态泄漏一个未 CloseIdleConnections 的 *http.Client）。风险有界（每个 proxy/上游 key 至多一次，进程生命周期内固定数量），故判 LOW。
- **风险**: 并发首次使用同一 proxy/上游时泄漏 UDP relay socket 与 http.Client 空闲连接；泄漏次数有界但无法回收，长生命周期进程在配置变更场景下累积
- **修复**: Set() 已有-key 分支在覆盖前调用 OnEvict(key, 旧值)（与 evictLocked 一致的语义），或在 Map 文档中明确 Set 覆盖不触发 OnEvict 并要求调用方改用 LoadOrStore 原子模式（quicConfigs 已用 LoadOrStore，见 tls/client.go:201）

## foundation-02 — LOW

- **位置**: `internal/dnscryptcrypto/encrypted.go:303`
- **类别**: comment
- **摘要**: Decrypt 的 PQ control block 剥离注释句子损坏（重复短语），误导读者对剥离条件的理解
- **描述**: encrypted.go:303 注释原文："We only strip when controlLen is zero or the magic validates — otherwise the packet lacks the prefix the packet has no control prefix and the DNS payload starts at offset 0."——中间 "the packet lacks the prefix the packet has no control prefix" 是编辑残留的重复短语，语义断裂。实际代码逻辑（304-321 行）正确：controlLen==0 或 magic 校验通过才剥离 2+controlLen 字节，否则不解包。
- **风险**: 注释误导后续维护者修改剥离条件时引入解包偏移错误（DNS payload 错位导致解析失败或安全绕过窗口）
- **修复**: 重写该句，例如："When the first two bytes do not parse as a valid control length (magic mismatch), the packet has no control block and the DNS payload starts at offset 0."

## foundation-03 — LOW

- **位置**: `internal/dnsutil/dnsutil.go:74`
- **类别**: comment
- **摘要**: HandlePanic 注释声称 8KB 栈缓冲每次调用都分配，实际仅在 panic 分支内分配
- **描述**: dnsutil.go:74-75 注释 "The 8KB stack buffer allocates on every call, but panics are rare events so per-call allocation is acceptable" 与代码不符：make([]byte, defaultPanicStackBufSize) 位于 `if r := recover(); r != nil` 分支内部（77-78 行），正常路径零分配。注释描述的行为比代码差，会误导读者以为 HandlePanic 是热路径分配点而做无谓优化。
- **风险**: 误导性注释；后续维护者可能基于错误认知重构（如引入池化）反而增加复杂度
- **修复**: 修正注释为 "The 8KB stack buffer is allocated only when a panic is actually recovered — panics are rare, so per-panic allocation is acceptable"

