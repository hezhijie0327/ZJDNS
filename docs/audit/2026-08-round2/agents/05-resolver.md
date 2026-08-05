# resolver 审计

> agent: `aff6bbd6af2d03623`

发现数: 6

## resolver-01 — MEDIUM

- **位置**: `server/resolver/nameserver.go:136`
- **类别**: pool-leak
- **摘要**: queryNameserversConcurrent 首个成功响应返回后，迟到 worker 的 NOERROR 响应可能驻留 resultChan 永不归还池
- **描述**: worker 的发送 select（L135-142）在 `cancel()`（winner 已调用）之后仍可选中 `case resultChan <- result.Response`（两个 case 同时就绪时随机选择），且没有 `queryCtx.Err()!=nil` 前置检查。调用方首个 select（L205-213）一旦命中 `case resp := <-resultChan` 就直接 return——drain 逻辑（L222-232）只在首个 select 落到 errgroupDone/ctx.Done 时才执行。因此当两个 NS 服务器响应到达时间接近（等延迟服务器、spoofguard 收集窗口内多个响应）时，迟到 worker 的 `result.Response` 被塞入容量为 1 的 resultChan 后无人读取，该池化消息及其全部 RR 对象永远不会被 `pool.DefaultMessage.Put`，每次泄漏一个池对象。FORMERR 重试路径（retryWithoutEDNS L442-443 的发送）也有同样的无 ctx 检查发送。
- **风险**: 递归解析热路径上重复泄漏池化消息：池周转损耗、RR 对象变垃圾增加 GC 压力；多 NS 高并发负载下该竞态窗口会频繁出现，内存分配持续上升。
- **修复**: 发送前增加 `if queryCtx.Err() != nil { pool.DefaultMessage.Put(result.Response); return nil }`（发送 select 之前），或在调用方首个 select 命中 resultChan 分支时也执行一次 drain；retryWithoutEDNS 的发送同样加 ctx 检查。

## resolver-02 — LOW

- **位置**: `server/resolver/recursive.go:220`
- **类别**: inefficiency
- **摘要**: RFC 9824 NXNAME 语义恢复（L220）位于 RFC 9156 最小化 NXDOMAIN 跳转检查（L204）之后，紧凑 NODATA 响应永不触发跳转
- **描述**: L204 的最小化-NXDOMAIN 跳转检查 `response.Rcode == dns.RcodeNameError` 在 L220 的 `validated && dnssec.HasCompactNXNAME(response)` 恢复之前执行。权威以紧凑 NODATA（NOERROR + NSEC/NSEC3 NXNAME 位）应答不存在的最小化名字时，Rcode 还是 NOERROR，跳转不触发；恢复后的 NXDOMAIN 只在 collectBestNSMatch 的 cont 分支（L42-43）里随响应被 Put 丢弃，minimiseSteps 逐标签推进，每个不存在的标签都要多一轮查询（最多 DefaultQnameMinimiseCount=10 次）。L216-219 注释声称恢复同时服务"minimisation logic below"，但真正受益的跳转逻辑在其上方。
- **风险**: 部署 RFC 9824 紧凑应答的权威（如新 TLD）下，不存在名字的最小化递归每层多 1 次额外往返，负缓存路径也慢一拍；注释误导维护者。
- **修复**: 将紧凑 NXNAME 恢复提前到 L204 跳转检查之前（validateNODATAWithNSEC 之后、跳转之前），或在跳转条件中增加 `dnssec.HasCompactNXNAME(response)` 判断；同时修正注释。不影响正确性，纯效率。

## resolver-03 — LOW

- **位置**: `server/resolver/recursive.go:93`
- **类别**: comment
- **摘要**: 注释声称 CNAME 跟进使用完整 QNAME，但 CNAME.resolve 以 depth=0 调用 resolve，QNAME 最小化实际生效
- **描述**: L92-93 注释："Internal infrastructure queries (NS address resolution, CNAME follow-up) use full QNAME"。但 CNAME.resolve（L376）调用 `c.resolver.recursive.resolve(ctx, currentQuestion, ecs, 0, forceTCP)` 时 depth=0，因此 `qnameMinimise := depth == 0 && r.resolver != nil` 为 true，CNAME 目标实际走最小化。NS 地址解析（depth+1，L314/323）确实用完整 QNAME，注释只有 CNAME 部分过时。行为上对 CNAME 目标最小化符合 RFC 9156 隐私目标，无需改代码。
- **风险**: 注释与行为不符，后续维护者可能误改最小化条件或误判 CNAME 路径的隐私/性能语义。
- **修复**: 修正注释为"NS address resolution uses full QNAME; CNAME follow-up (depth 0) is minimised"。

## resolver-04 — LOW

- **位置**: `server/resolver/zonecut.go:184`
- **类别**: validation
- **摘要**: FindDS 不做 owner 名过滤，Answer+Ns 两段 DS 拼成混合 owner RRset，注入一条异名 DS 即可让整组验证失败（fail-closed DoS）
- **描述**: `dsRecords := dnssec.FindDS(dsResp.Answer)` 后追加 `dnssec.FindDS(dsResp.Ns)`（L184-185），FindDS（dnssec/extract.go L62-70）只按类型过滤不按 owner 名过滤。随后 L216-219 把所有 DS 拼成一个 rrset 交给 VerifyRRset，而 dnssec/crypto.go L96 的 `dnsutil.IsRRset`（fork compat.go）要求所有记录 owner 名一致——响应未认证，on-path 攻击者在 Authority/Answer 注入一条异名 DS 记录即可让合法 DS RRset 验证失败，委派被判定 bogus（verifyDelegationDSRRSIG dnssec_chain.go L347-350 同样模式）。fail-closed，无安全绕过。
- **风险**: 对单域名的选择性 DoS：攻击者只需在未认证的 DS 响应里夹带一条异名 DS，即可让目标域 DNSSEC 链验证失败（dnssec_enforce 时 SERVFAIL）。
- **修复**: 在 resolveZoneCut 和 verifyDelegationDSRRSIG 中对 dsRecords 按 `dns.EqualName(fqdn(owner), fqdn(childZone))` 过滤后再拼 RRset（FindDS 增加 name 参数或调用处过滤）。

## resolver-05 — LOW

- **位置**: `server/resolver/forward.go:299`
- **类别**: validation
- **摘要**: 转发路径 NXDOMAIN 恢复仅凭 NXNAME 位，无 len(Answer)==0 守卫，可能把带答案的 NOERROR 响应错误标记为 NXDOMAIN
- **描述**: L298-302：`rcode := dns.RcodeSuccess; if dnssec.HasCompactNXNAME(queryResult.Response) { rcode = dns.RcodeNameError }`。与递归路径（recursive.go L220 要求 `validated`，且整个响应已通过 NSEC 否认证明校验）不同，转发路径不做任何校验即恢复 NXDOMAIN。HasCompactNXNAME（dnssec/nsec.go L73-87）扫描 Authority 段任意 NSEC/NSEC3 的 NXNAME 位，不检查 NSEC owner 与 qname 的关系。若上游响应 NOERROR 且 Answer 非空但 Authority 夹带一条含 NXNAME 位的 NSEC（异常服务器/防火墙），客户端会收到 NXDOMAIN + 答案的矛盾组合，且按 NXDOMAIN 进负缓存。
- **风险**: 罕见但会向客户端返回 rcode 与 Answer 矛盾（NXDOMAIN+答案）的响应，负缓存语义错误；攻击者无法伪造（要求上游服务器行为），但上游服务器行为不可控。
- **修复**: 恢复条件增加 `len(queryResult.Response.Answer) == 0` 守卫（紧凑 NODATA 定义即空 Answer），与 RFC 9824 §5.1 一致。

## resolver-06 — LOW

- **位置**: `server/resolver/forward.go:343`
- **类别**: coupling
- **摘要**: protocol=recursive 上游路径丢弃客户端 MQTYPE-Query：queryUpstream 的透传只覆盖非递归协议，MQTYPE 中间件又因存在上游而跳过本地合并
- **描述**: L129-131 的 MQTYPE 透传只作用于非递归协议分支；handleRecursiveQuery（L339-370，经 L343 `r.cname.resolve`）完全不读取 MQTypeFromContext，也不附加 MQ 选项。同时 mqtype 中间件在 `len(UpstreamServers()) > 0` 时跳过本地合并——于是配置 protocol=recursive 上游的部署中，客户端 MQTYPE-Query 被静默丢弃：无合并结果也无 MQTYPE-Response，而同样的配置换成 DoH/TCP 上游则透传正常。
- **风险**: 功能不一致：recursive 上游模式下 RFC 10029 客户端附加类型全部丢失且无响应回显，客户端只能逐个回退查询；纯递归模式（无上游）下该功能正常，行为割裂。
- **修复**: 二选一：handleRecursiveQuery 检测 MQTypeFromContext 并让 CNAME/递归路径回传 MQRESPONSE（需要在递归 QueryResult 上回传），或让 mqtype 中间件在"仅 recursive 上游"时仍执行本地合并。

