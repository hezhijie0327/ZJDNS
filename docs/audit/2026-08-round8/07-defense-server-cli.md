# Defense+Server+CLI 组审计 — server/defense + server + cmd/zjdns + docs/poc（16 文件，双份独立审计合并）

## HIGH

### H4: server/defense/hopguard.go:97-99 + server/upstream/plain/udp.go:230-235 — Feed 契约被调用方违反（见综合报告 H4）
- hopguard.go docstring 契约："Feed records a TTL observation from a response that **spoofguard has confirmed clean**. Only trusted DNS content is used for TTL learning, preventing GFW-injected responses from poisoning the histogram."（:60-62, :97-99）
- 实际调用方 udp.go:231 对**每个收到的数据报**无条件 `hg.Feed(server.Address, ttl)`——在 spoofguard 处理之前、DNS ID 校验（:237）之前、长度检查（:237）之前；且 :246-248 对最终采纳候选又 Feed 一次（`sg.pickBestTTL()`，同一响应的 TTL 双重计数）。
- 后果：(a) samples 计数约 2 倍膨胀，武装提前到 ~16 个被接受响应而非设计的 hopGuardMinSamples=32；(b) GFW 注入包/垃圾数据报进入直方图——攻击者固定 TTL 洪水（GFW 威胁模型具备源 IP 欺骗）使该 TTL 成为 mode，rebuildTrusted 晋升进 trusted 集、真实 TTL 因 <mode/2 被逐出 → 此后所有合法响应被 Validate 拒绝 → **hopguard 使能的上游 UDP 永久 DoS**。
- 三处证据（docstring / POC / 调用方）：POC（docs/poc/hopguard/main.go:184-186）只在 `!isGFW` 时 feed，编码的是文档意图；生产代码无条件 Feed。
- 修复：Feed 移到 ID 校验 + spoofguard 采纳之后（保留 :247 单次 Feed，删除 :230-232），同步修正 hopguard.go 两处文档。

### H5: server/defense/poisonguard.go:167-172 — classifyTLD 误杀合法委派记录（见综合报告 H5）
- `classifyTLD(zone, name)` 仅放行 `name == zone`，任何子域名 RR 判 Poisoned。classifyRoot:154 有 `(NS||DS) && isTLD(name)` 委派豁免，classifyTLD **无对应分支**——对称性遗漏。
- 触发：`resolveZoneCut`（zonecut.go:158）与 `verifyNoDSInParent`（dnssec_chain.go:190）向 TLD 服务器发起 `DS example.com.` 查询（currentDomain="com"）；nameserver.go:119-128 对响应 Validate → classifyTLD → VerdictPoisoned → 响应整体丢弃 → 全部并行 goroutine 被拒 → DS 查询失败 → **签名域 DNSSEC 信任链断裂 SERVFAIL**（poisonguard:true 与 DNSSEC 组合下所有签名域；TCP 重试同样被拒）。
- 修复：`(rrtype == dns.TypeDS || rrtype == dns.TypeNS) && dnsutil.IsSubDomain(zone, name)` 返回 Clean（对齐 classifyRoot:154）；补 "TLD 返回子域 DS → clean" 测试。

### H3: server/bridge.go:49-64 + server/tasks.go:137-159 — tcpWriteMu sweep 竞态（见综合报告 H3）
- `LoadOrStore(addr, &tcpWriteEntry{})`（:49）与 `entry.refs.Add(1)`（:64）之间，清扫器（删除条件 `lastAccess < cutoff && refs == 0`，tasks.go:137-155）可删除 refs==0 的新条目（lastAccess=0 恒小于 cutoff）→ 请求在已脱离 map 的条目上持有 writeMu 写入 → 下一请求重建新 writeMu → **两个写入者并发写同一 TCP 流**，长度前缀帧交错损坏。tasks.go:140-144 注释承认设计意图但保护不完整。
- 修复：预构造 `refs.Add(1)` 的条目再 LoadOrStore（loaded 时对返回条目再 Add）；或 sweep 增加 `lastAccess != 0` 条件。

## MEDIUM（4 项）

| # | 位置 | 描述 |
|---|------|------|
| M1 | server/init.go:98-102 | CHAOS 清理端点失败路径 `log.Errorf`——任意客户端可查询 `zjdns.cache.clear` 等名字（无 per-IP 限制，项目明令禁止），`zjdns.dnscrypt.clear` 在 DNSCrypt 未启用时每次查询必然失败——稳定的日志 DoS 通道。修复：降 Warn/Debug。 |
| M2 | server/bridge.go:108-170 + tasks.go:245-260 | fire-and-forget TCP handler goroutine 不被任何 WaitGroup 追踪；shutdown 期间仍在 `handler.ServeDNS` → `prober.Start` → `backgroundGroup.Go`，与 `backgroundGroup.Wait()`（计数器归零后）并发 → "WaitGroup misuse" panic 窗口。修复：Server 级 WaitGroup 追踪 in-flight 或 prober.Start 在 MarkClosed 后 no-op。 |
| M3 | cmd/zjdns/cli/dnsstamp.go:27-45 | relay 类型 stamp（dnscrypt-relay/odoh-relay）解码输出**不可加载的配置**（ProtoToConfig 返回的协议不在 validate 合法表）；doh 输出 "doh" 而 normalizeStamps 会重写为 "https"——decode 输出与配置加载契约不符（odoh-target 被显式拒绝，relay 静默漏出）。修复：镜像 load.go 重写逻辑 + relay 显式报错。 |
| M4 | cmd/zjdns/cli/generate.go:15 | cli 直接导入 `server/protocol/dnscrypt`——违反 "cmd/zjdns 只能导入 config/log/server" 分层规则（有 NOTE(DC-05) 文档化属明知偏离）。修复：生成函数下沉到 internal/dnscryptcrypto。 |

## LOW（14 项）

| 位置 | 描述 |
|------|------|
| server/defense/hopguard.go:179-201 | `Expected(serverIP)` 仅测试使用——生产死代码。 |
| server/defense/poisonguard.go:83-84 | `Validate` 对 rr.Header() 无 nil 防护（IsPoisonedByTLD:113-116 有）——手工构造含 nil Answer 的响应时裸解引用 panic（miekg 不产生 nil，LOW）。 |
| server/bridge.go:210-223 | `detectRequestProtocol` 唯一调用点（:176）位于 TCP 分支 return（:172）之后——TCP 分支不可达，函数恒返回 ProtoUDP。 |
| server/bridge.go:49 | `entryI, _ := s.tcpWriteMu.LoadOrStore(...)` 丢弃 loaded bool 无注释。 |
| server/init.go:36-41,54 | `statsSaver.file` 字段只写不读（Save 委托 SavePersist）。 |
| server/server.go:52-53,107-116 | `Server.stats`/`Server.cacheStore` 字段仅赋值无读取者（shutdown 实际用 handler.CacheStore()）。 |
| server/server.go:298 | 过时注释 "// set below"（ZoneEvaluator 就在字面量中赋值）。 |
| server/server.go:445 | `dnshttp.MsgAcceptFunc = ...` 在 Start() 改写进程级全局量——多 Server 实例/重启场景竞态。修复：New() 一次性设置或 sync.Once。 |
| server/tasks.go（跨包） | plain 监听器内 ctx watcher（plain/tcp.go:42-45）用 Background ctx 调 Shutdown——与 shutdownServer 有界 Shutdown 竞争 shutdownOnce，无界调用可能先赢绕过 15s 截止。 |
| cmd/zjdns/cli/parse.go:59 | `dnscryptAddr` 默认值硬编码 8443（DefaultDNSCryptPort 已存在）。 |
| cmd/zjdns/cli/parse.go:154-222 | 静默忽略非法组合：--dnscrypt/--provider/--addr 无 --generate-config、--decode/--encode 无 --dnsstamp、--decode --encode 同设静默选 decode（注释声明"冲突必须诊断"）。 |
| cmd/zjdns/cli/probe.go:71,83-94,182,193,212,266,292,306 | 8 处 `_ = SetDeadline(...)`/`rand.Read` 丢弃无注释；71 行 host 无端口时 serverName 为空（TLS SNI 空）；182 行 rand 失败生成全零域名。 |
| docs/poc/hopguard/main.go | POC 学习期只 Feed 非 GFW 响应（:184-186）——与生产 udp.go 无条件 Feed 语义不符（H4 的证据之一），需在头部注明差异。 |
| docs/poc/spoofguard/main.go:77 | `len(r.answers) >= 2` 分支不可达（:65 已 fast-return）；:187 "Collect window expired (500ms)" 注释与代码不符（无窗口逻辑）。 |
| docs/poc/splitguard/main.go:253 | 对比表 "Segment size: 1–5 bytes each" 与算法实际（首段 3–6、后续 1–4）不符。 |

## 系统性根因

1. **防御状态学习门控漂移**（H4）：包内注释定义的"干净内容才入直方图"契约在调用方被无门控 Feed + 双重 Feed 破坏——修复后需补喂入语义测试（现有测试全部在包内自证）。
2. **fire-and-forget goroutine 无 owner**（M2 + tasks.go）：bridge TCP handler、plain watcher 均无追踪，shutdown 排序依赖超时/取消而非等待。
3. **CLI 输出按理想契约而非实际校验器**（M3 + poc）：dnsstamp decode 声称镜像 normalizeStamps 却漏掉重写；POC 三处"算法镜像"声明与实际不符。
4. **`_` 丢弃无注释**：probe.go 8 处、bridge.go 1 处——方法论规则 11 的系统性违反。

## 已排除疑点（有代码证据安全）

- cmd/zjdns/main.go/banner.go/version.go：errLogged 模式正确；banner 用 ReplaceAll 有注释；DefaultProjectName 默认值非空保证 usage 正常。
- cli/generate.go：示例密钥为生成时新鲜密钥对；错误均 %w 包装。
- docs/poc/splitguard：segmentMessage 守卫（segSize<=0 || >=len-2）、parseLabels 边界检查到位。
- docs/poc/spoofguard：纯顺序模拟无并发无 panic 路径。
- 无导入分层违规（server/ 各子包互不反向依赖；cli→dnscrypt 为已文档化 MEDIUM 偏离）。
- 所有 goroutine 均有 HandlePanic；热路径日志均为 Debug/启动期 Info。
