# defense 审计

> agent: `a2337d18f5a37e071`

发现数: 5

## defense-01 — MEDIUM

- **位置**: `server/upstream/plain/udp.go:247`
- **类别**: validation
- **摘要**: ttlConfident 只依赖 hopguard 武装状态，未考虑当前数据包 TTL=0（控制消息缺失）即快速接受
- **描述**: ttlConfident := hg != nil && hg.Confident(server.Address)（udp.go:247）只看整体武装状态。当 ipttl.ReadFrom 返回 ErrNoControlMessage 时该包 ttl=0，hopguard.Validate 对 observed==0 无条件放行（hopguard.go:70-74），随后 processPacket 进入 collectEDNSCandidate——只要该服务器状态已 armed，这个 TTL 完全未知（0）的 EDNS 响应就按 'TTL trusted' 被快速接受（udp.go:494-508），跳过与第二个候选比较的 500ms 收集窗口直接返回。ipttl 包注释明确说明 'reporting TTL 0 would poison the hopguard fingerprint'（TTL 0 不应视为有效信号），此路径却把无 TTL 信号的数据包当作已通过 TTL 校验。
- **风险**: 缺控制消息的单个 EDNS 数据包绕过 spoofguard 的候选比较保护——第一个到达的 EDNS 响应立即获胜；若未来 GFW 伪造带 EDNS 的响应，将无法依靠等待真实响应来对抗。
- **修复**: ttlConfident := hg != nil && hg.Confident(server.Address) && ttl != 0 —— TTL 未知的包不得进入 fast-accept 路径。

## defense-02 — MEDIUM

- **位置**: `server/upstream/plain/udp.go:237`
- **类别**: validation
- **摘要**: hopguard Feed 在 ID 校验与 spoofguard 内容门之前执行，学习期 GFW 注入包 TTL 仍进直方图，违背代码注释与 docstring 契约
- **描述**: hg.Feed(server.Address, ttl)（udp.go:237）位于 ID 校验（udp.go:240）与 processPacket 的 spoofguard 拒绝逻辑（udp.go:248）之前。学习期（未 armed）Validate 对一切 TTL 放行（hopguard.go:87-89），因此 processPacket 随后以 '单答非 EDNS GFW 签名' 拒绝的注入包（udp.go:443-447）其 TTL 已先被 Feed——直接违背 udp.go:227-232 注释 'GFW-injected TTLs never enter the histogram' 与 hopguard.go:100-102 docstring 'Feed ... called only after spoofguard confirms the response is clean'。后果链：被审查域假/真响应计数均衡（各 1 次 Feed，收集路径无第二次采纳 Feed）时，modeTTL 平局取较小 TTL（hopguard.go:186），假 TTL 若更小即成唯一 trusted 基线；armed 后真响应 TTL 校验被拒（hopguard.go:92-97），仅假 TTL 能通过 Validate 持续 Feed，5 分钟重建周期也无法自愈，该域持续 SERVFAIL 直至关闭 hopguard。
- **风险**: 学习期直方图被 GFW 假包 TTL 污染；在假/真计数均衡且假 TTL 更小的条件下（单答 A/AAAA 被审查域正是 GFW 目标画像），armed 后持续拒绝合法响应，产生永久性 SERVFAIL。
- **修复**: 将 Feed 移到 ID 校验之后，且仅对 processPacket 接受的数据包执行（resp != nil 的快速路径已有第 250 行采纳 Feed，需补：收集路径在超时返回 pickBest 时也对采纳候选 Feed）；或把 udp.go:237 的 Feed 移入 processPacket 各接受分支，与注释契约一致。

## defense-03 — LOW

- **位置**: `server/upstream/plain/udp.go:40`
- **类别**: dead-code
- **摘要**: spoofguardState.prevTTL 只写不读的死字段
- **描述**: prevTTL 在声明（udp.go:40）与 collectEDNSCandidate（udp.go:515 s.prevTTL = s.lastTTL）两处赋值，但全库无任何读取——pickBestTTL（udp.go:526-534）只用 lastTTL 与 nonEDNSTTL。疑似早期'按 TTL 选择候选'设计的遗留。
- **风险**: 死字段误导维护者以为存在候选 TTL 历史比较逻辑，无功能影响。
- **修复**: 删除 prevTTL 字段与第 515 行赋值。

## defense-04 — LOW

- **位置**: `server/defense/poisonguard.go:84`
- **类别**: validation
- **摘要**: Detector.Validate 无 nil RR 防护，同文件 IsPoisonedByTLD 有——防御代码健壮性标准不一致
- **描述**: Validate 遍历 response.Answer 时直接调用 rr.Header().Name（poisonguard.go:84），若 Answer 含 nil 元素即 panic；同文件 IsPoisonedByTLD（poisonguard.go:113-116）有显式 if rr == nil { continue } 防护。当前生产路径响应全部来自 wire Unpack（不会产出 nil RR），因此纯防御性缺口，但同一类型的两处遍历采用不同纪律，未来若引入手工构造响应路径（zone 合成/测试辅助）即成 panic 入口。
- **风险**: nil RR 进入 Validate 时 panic（被 HandlePanic 吞掉后该递归查询静默失败）；当前仅理论风险。
- **修复**: Validate 循环内补 if rr == nil { continue }，对齐 IsPoisonedByTLD 的写法。

## defense-05 — LOW

- **位置**: `server/upstream/plain/udp.go:165`
- **类别**: pool-leak
- **摘要**: ctx.Done 提前返回路径未归还 sg.last/sg.prev/sg.nonEDNS 池消息
- **描述**: 多读循环的 ctx.Done 分支直接 return nil, ctx.Err()（udp.go:165-166），此时已收集的候选消息（均为 pool.DefaultMessage.Get() 分配）未 Put；对照非超时错误路径（udp.go:214-223 显式归还三个候选）与超时返回路径（pickBest 内部归还被弃候选）。ctx.Done 在并发 NS 查询中被 errgroup cancel() 触发是常见路径（nameserver.go:137 首个获胜者 cancel 其余 goroutine），每次取消泄漏 1-3 个池对象到 GC。
- **风险**: 取消频繁时池保留容量持续流失，后续查询重新分配 dns.Msg，池命中率下降（内存池周转损耗，非真实泄漏）。
- **修复**: ctx.Done 分支先归还 sg.last/sg.prev/sg.nonEDNS 再 return nil, ctx.Err()。

