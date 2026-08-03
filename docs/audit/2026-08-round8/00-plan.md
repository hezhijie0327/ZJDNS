# 审计计划与修复清单 — 2026-08 Round 8

审计日期: 2026-08-03 | 范围: 154 非测试文件 + 18 维度 | 结果: 5 CRITICAL / 12 HIGH / 38 MEDIUM / 57 LOW（112 项）

> 全部发现必须修复。严重度决定顺序，不决定是否修复。LOW 不是"可跳过"。

## Sprint 1 — CRITICAL（立即修复）

| # | 文件:行 | 修复 | 验证 |
|---|---------|------|------|
| C1 | `server/protocol/dnscrypt/udp.go:81,88,118` | 删除三处显式 `pool.DefaultBuffer.Put(buf)`，只保留 :65 defer | `go test -race ./server/protocol/dnscrypt/` + 关停测试（补：DNSCrypt 关停无双重归还测试） |
| C2 | `server/resolver/dnssec/trust_anchor.go:132-133` | 补 `if ds == nil { log.Debugf(...); continue }` | 补：非 SHA DigestType 的 trust_anchor 加载测试 |
| C3 | `server/upstream/dnscrypt/state.go:126` + `tlcp/http_tlcp.go:54` | 补 `c.cache == nil` / `c.httpClient == nil` 守卫（或 Close 改 Clear() 不置 nil） | `go test -race` + Close-while-Execute 并发测试 |
| C4 | `server/resolver/dnssec_chain.go:74-91, 415-423` | 两处根域分支 SelfVerifyDNSKEY 成功后补 `ContainsRootKey` 检查（对齐 :300-303） | 补：MITM 伪造根 DNSKEY 集 → 拒绝测试 |
| C5 | `server/handler/middleware/zone.go:85` | 赋值移入 rcode 分支与 hasRecords 分支内 | 补：动态 zone 规则非配置 qtype → 有响应测试 |

## Sprint 2 — HIGH（下个发布周期）

| # | 文件 | 修复 | 验证 |
|---|------|------|------|
| H1 | `cache/ptr.go:47-52,87` | `append(slices.Clone(old), owner)` + `make([]entryKey,0,len(keys))` 复制式过滤 | 补：PTR 并发填充 -race 测试 |
| H2 | `server/handler/pending.go:119-139` | `p.sets.CompareAndDelete(key, call)` 替换 Get+检查+Delete；result 写入与 close 同临界区 | 补：淘汰与 Done 并发测试 |
| H3 | `server/bridge.go:49-64` + `tasks.go:137-159` | 预构造 `refs.Add(1)` 条目再 LoadOrStore；或 sweep 加 `lastAccess != 0` 条件 | -race + 高频重连测试 |
| H4 | `server/upstream/plain/udp.go:230-235` | Feed 移到 ID 校验 + spoofguard 采纳之后；删 :230-232 无条件 Feed；同步 hopguard.go 两处 docstring | 补：GFW TTL 不进入直方图测试 |
| H5 | `server/defense/poisonguard.go:167-172` | classifyTLD 补 `(DS||NS) && IsSubDomain` 委派豁免 | 补：TLD 返回子域 DS → Clean 测试 |
| H6 | `server/protocol/tls/dtls.go:130-140` | 仿 tlcp/dtlcp.go:324-327 加 `errors.As(err,&ne) && ne.Timeout() → return` | 补：DTLS 空闲超时关闭测试 |
| H7 | `server/protocol/tls/server.go:198-280` | 错误路径先关闭已绑定 listener 再返回（defer 清理） | 补：端口冲突启动测试 |
| H8 | `server/handler/middleware/response.go:77-79` | `ecs := *ecsOpt; ecs.ScopePrefix=...; ecsOpt=&ecs` 或删行 | -race 无 ECS 并发测试 |
| H9 | `server/handler/middleware/dns64.go:86-92` + `cache_store.go:123` | 改写前 per-goroutine 拷贝共享结果 | -race DNS64 并发 AAAA 测试 |
| H10 | `server/upstream/`（6 处） | 抽 `setConnDeadline(ctx, conn)`（模板 dnscrypt/cert.go:63-68）推广到 plain/tcp、plain/udp、tls/tls、tlcp/tlcp、tls/dtls、tlcp/dtlcp | 补：stalled peer + 短 ctx 测试 |
| H11 | `server/upstream/tls/http3.go:167-178` | 错误路径 `_ = pconn.Close()`（照抄 quic.go:56-63） | 补：代理不可达测试 |
| H12 | `server/resolver/nameserver.go:43-62` | Put 移入 g.Wait 之后；或每 goroutine 从不可变 question 构造 | -race 根服务器路径测试 |

## Sprint 3 — MEDIUM + LOW（95 项，按根因分批）

### 批次 A：日志降级/去重（M：root_hints Error、warmup Warn、dns64 Warn、CHAOS Error、handler.go Error；L：probe.go 8 处 `_` 注释）
### 批次 B：共享状态拷贝与竞态加固（dtls_session Get 深拷贝、getQUICConfig LoadOrStore、close 置 nil 清理 tls/tlcp client、onEvict 锁内扫描短路）
### 批次 C：存储层（lrumap load decode 失败备份、Clear 预分配对齐、权重更新路径淘汰、CompareAndDelete 文档、codec uint16 防御、persist 解压上限）
### 批次 D：参数校验（stamp encode 长度、resolveStamp/validate nil err、chain 必需字段、dnsstamp relay、parse flag 组合、http scheme、! 前缀统一、wire 3597 长度）
### 批次 E：RFC/一致性（nsec rrset key→rrsetKey、nsec 大小写 EqualName、quic 0-RTT NOTIFY、TLCP DoH GET 长度/415、证书钳制、ID 校验统一、response EDE 丢失）
### 批次 F：死代码删除（zone rewrite 机制决策、ErrDrop、detectRequestProtocol、statsSaver.file、Server.stats/cacheStore、dns64 ExtractIPv4、hopguard Expected、cachable、unescapeChar、streamCtx、serverCtx、done channel、edns detectVia 参）
### 批次 G：文档同步（FLOWCHARTS.md 重写描述、注释矛盾全部修正、godoc 补全、POC 声明修正、Store 接口注释残片）

## 全覆盖清单（112 项逐项确认）

- [ ] C1-C5 全部修复并测试
- [ ] H1-H12 全部修复并测试
- [ ] MEDIUM 38 项修复（见各章节）
- [ ] LOW 57 项修复（见各章节）
- [ ] 每批次后 `go build ./... && go fix ./... && golangci-lint run && golangci-lint fmt` 零警告
- [ ] `go test -short ./...` 全部通过
- [ ] `go test -race ./server/... ./cache/... ./internal/lrumap/...` 零竞态
- [ ] Benchmark 回归检测（>15% 变慢即回归）：
  `go test -bench=. -short -benchtime=500ms ./... | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt`

## 提交规范

每次提交只含一类修复，主题行描述**具体修复内容**（附审计编号）：
- `fix: delete 3 explicit buffer Puts in DNSCrypt UDP serve loop (C1)`
- `fix: guard nil ToDS return in trust anchor loading (C2)`
- `fix: clone PTR index slices before append/compact (H1)`
- 跨维度修复分多次提交，禁止 `fix audit findings` 类笼统描述。
