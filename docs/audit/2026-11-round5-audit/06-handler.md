# ZJDNS Round 5 Handler 审计报告

**审计范围**:`server/handler/` 全部(handler 包 8 个非测试文件 + middleware 包 14 个非测试文件),重点审查 `9c6df186..HEAD` 差异(resolve.go EDE 65281 no-cache 门禁 + store_nocache_test.go)。

**本轮 diff 结论**:resolve.go `StoreIfCacheable` 新增 `edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE)` belt-and-suspenders 门禁,实现正确 —— 与生产者侧(`forward_process.go:141`)、`edns/ede.go:36-38` 定义一致,测试覆盖 65280/65281/对照三种情况。**无问题**。

---

## 确认的发现

### F-1 | MEDIUM | Goroutine 死锁 | server/handler/middleware/mqtype.go:103-112 + mqtype_merge.go:93-96

QTx prefetch goroutine 在 panic 时被 `zdnsutil.HandlePanic` recover 后正常退出,**不向 `qtResults` 发送结果**:

```go
go func() {
    defer zdnsutil.HandlePanic("MQTYPE QTx prefetch")   // 只 recover+log(dnsutil.go:74-80)
    qtCtx, qtCancel := context.WithTimeout(...)
    defer qtCancel()
    qtResults <- qtResult{...}   // panic 时不执行
}()
```

而 merge 的接收循环无条件收满 `len(types)` 个:

```go
for range types {
    r := <-qtResults   // 永久阻塞,不受 ctx 控制
    qtMap[r.qt] = r.qr
}
```

触发链真实存在:`Secondary.Lookup` → `PendingRequests.DoJoin`(pending.go:113-118)leader panic 时 `Done` 后 **re-panic**,该 panic 恰好被 QTx goroutine 的 HandlePanic 吞掉。结果:该查询的 handler goroutine 永久挂起(TCP 连接挂死、UDP goroutine 泄漏约 8KB 栈),每个 panic 泄漏一个。TC 分支不受影响(`for range len(qtResults)` 按当前缓冲量收)。修复:goroutine 内将发送移入 defer —— `res := qtResult{qt: qt}; defer func() { qtResults <- res }(); res.qr = m.secondary.Lookup(...)`。

### F-2 | MEDIUM | 防御标记丢失(违反 EDE 65281 设计意图) | server/handler/middleware/mqtype_merge.go:97-155

merge 的 QTx 录用检查只有 RCODE/flags:

```go
if qr.Rcode != primaryRcode || qr.Validated != primaryAD || qr.Authoritative != primaryAA { ... continue }
```

不检查 `edns.IsZJDNSNoCacheEDE(qr.UpstreamEDE)`。带 65280/65281 标记的 QTx 结果:本侧正确不缓存(StoreIfCacheable:154),但其 **RR 被 merge 进客户端响应**,且 65281 EDE 不传播 —— qctx.EDE 只由 CacheStore 从 *primary* 的 `qr.UpstreamEDE` 设置(cache_store.go:154)。AGENTS.md 明确的契约是"Downstream ZJDNS instances refuse to cache marked responses"(依赖 EDE 传播);merge 路径上 defense-uncertain 数据的 blast radius 从"one query"扩展到下游缓存 TTL。修复建议:merge 对携带 no-cache EDE 的 QTx 跳过合并(与 RCODE mismatch 同等对待)。[影响概率需攻击者控制 UDP 未验证上游 + 客户端发 MQTYPE 查询,评估为 MEDIUM]

### F-3 | LOW | RFC 7830 §4.4 违规(双 PADDING) | server/handler/middleware/edns.go:70 + response.go:142-148

BADVERS 分支强制 append 空 PADDING 以诱导 OPT 生成:

```go
msg.Pseudo = append(msg.Pseudo, &dns.PADDING{})
```

随后 Response.finalizeResponse 的 `msgHasEDNSOptions` 只检查 COOKIE/SUBNET,放行 ApplyToMessage;`addPadding`(padding.go:37-67)在 `(IsSecure && ClientWantsPadding)` 下再 append 一个 PADDING。触发条件:EDNS version≠0 的请求 + 安全传输 + 客户端带 PADDING option(此时 `shouldAddEDNS` 因 `IsSecure&&ClientWantsPadding` 恒为 true)。RFC 7830 §4.4:"The PADDING option MUST NOT occur more than once in a message"。修复:`msgHasEDNSOptions` 增加 PADDING 检查,或 BADVERS 分支不预置 PADDING。

### F-4 | LOW | 注释规范(历史叙述) | stats.go:20、cache_store.go:39-40

stats.go: "Rejected-before-classified queries ... **mirroring the FORMERR gates, which predate the refactor and** stayed invisible to stats";cache_store.go: "markers like ZoneMatched **were redundant here**"。均为历史叙述性注释,违反项目注释规范(无历史叙述)。建议改为描述当前行为。

---

## 性能优化机会(无 bug)

- **P-1 | mqtype_merge.go:169-202 mergeRRs**:注释声称"the dup check must not format both RRs ... for every (existing, candidate) pair",但只预计算了 src 侧 keys;dst(existing)侧在嵌套循环中对每对重复调用 `foldRRData(existing)`(内含 `rr.String()` 分配)。O(|dst|×|src|) 次 String 格式化。dst keys 应在函数入口预计算一次。
- **P-2 | mqtype_merge.go:92-96**:`qtMap` map 分配可省 —— `qtResult` 携带 types 下标后用 slice 接收。微小。

---

## 重点核实后排除的怀疑(回归检查通过)

| 怀疑点 | 结论 |
|---|---|
| serve-stale miss 路径 wire/offsets 泄漏(已知根因回归) | cache_lookup.go:93-94、cache_store.go:183-184、serveSynthesized:148-149、Secondary.Lookup:46-47 全路径成对释放;`ReleaseOffsets` 幂等(cache.go:180-186),无 double-put |
| serveExpiredWithRefresh `qr` 数据竞争 | 写→`close(done)`→`<-done` 读,happens-before 成立;`qr != nil` 均有检查;`refreshFinished` CAS 防双 finish;TryGo 饱和路径 close(done) 防 timer-path 死等 |
| DNS64 AD 位(RFC 6147) | `qr.Validated && aqr.Validated` AND 语义符合 §5.1 场景 2(SHOULD set AD);场景 1(DO=0)由 `ClientUnderstandsAD` 阻止。合规(dns64.go:82 注释措辞欠精确,但实现正确) |
| DNS64 合成 AAAA 缓存 TTL | `min(A TTL, SOA TTL, maxSynTTL)`(dns64.go:122,138,161)符合 RFC 6147 §5.4 |
| 错误变量遮蔽 | 未发现;cache_store.go:200 `errors.AsType` 正确使用 |
| 预打包直发被重 Pack | fast path 条件(Response:53)含 `ResHasDNSSEC` + `!log.IsDebug()`;patchQuestionCase 零分配(栈 backup[255]);0-alloc 契约由 BenchmarkResponseServePrePacked pin |
| pending/singleflight 击穿 | CallGroup token 发布、LRU eviction 唤醒、follower timeout、clone 深拷贝(pending.go)语义正确;DoJoin panic containment 发布错误后 re-panic |
| refreshCoordinator gate 配对 | tryStart/startThrottled/spawnPrefetch/serveExpiredWithRefresh 的获取-释放全配对,含 TryGo 饱和路径 |
| Entry 共享 mutation | NegativeAncestor 返回 `e.soa.Clone()`(nxdomain.go:66);zone/mqtype 路径均为 per-query 克隆 |
| `refresh()` qr nil deref(cache_refresh.go:106) | resolver.Query 返回值类型非指针 nil 不可能;接口其他实现触发时有 HandlePanic 兜底,goroutine 不挂。不报 |

## 验证

- `go vet ./server/handler/...` 通过;`go test ./server/handler/... -short -count=1` 两个包全部通过。
- 声明顺序、命名、热路径 Debug-only 日志、魔法数字(均有命名常量或行内注释)检查无新违规(除 F-4)。

## 审过的文件清单

**server/handler/**:handler.go、context.go、middleware.go、pending.go、prefetch.go、resolve.go(重点)、response.go、store_nocache_test.go(新)
**server/handler/middleware/**:chain.go、stats.go、response.go、edns.go、mqtype.go、mqtype_merge.go、cache_store.go、validation.go、acl.go、zone.go、any.go、cache_lookup.go、cache_refresh.go、dns64.go、resolution.go、benchmark_test.go
**支撑核实**:edns/ede.go、edns/edns.go、edns/padding.go、internal/pending/pending.go、internal/dnsutil/dnsutil.go、cache/cache.go、cache/entries.go、cache/nxdomain.go、cache/nsec.go(签名)、internal/dns64/dns64.go、internal/pool/pool.go、server/resolver/resolver.go、server/resolver/forward_fallback.go、docs/rfc/rfc6147.txt