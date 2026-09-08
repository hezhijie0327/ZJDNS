# 2026-09 Round 3 全项目审计 — 综合报告

第三轮全项目审计(前两轮见历史记录表)。审计面:上轮审计(52e029f)以来的
95 个 perf 提交(~2.7 万行插入)为重点风险面,同时覆盖全部 367 个 Go 文件,
并按业主要求新增**注释风格**专项维度。

## 执行结构

| 阶段 | 内容 | 发现 |
|------|------|------|
| Phase 1 | 7 个包级并行审计(foundation/domain/protocol/upstream/resolver/handler/defense+server+cmd)+ 1 个全库注释风格专项 | 1 CRITICAL、8 HIGH、~28 MEDIUM、~155 处注释噪音、~24 处冗长注释块、~18 处变更叙述 |
| Sprint 1-3 | 发现即修复,按包分 11 个提交 | 全部修复,每个修复附回归测试或 E2E 场景 |
| Round B | 修复复查(逐 commit)+ 交叉维度扫描(goroutine/Close/context/锁/无界增长/channel、错误包装/参数校验/日志/文档一致性) | 1 MEDIUM(修复自身引入)、4 LOW、若干注释纪律项 |
| 质量门禁 | go fix + golangci-lint(0 警告)+ 全量测试 + benchmark 对比 + 基线刷新 | 无 actionable 回归 |
| E2E | 14 协议客户端矩阵(冷+热)、7 共享端口、MQTYPE 双场景、连接池复用、RFC 8020 负缓存、DNSSEC 递归、优雅停机 | 全部通过 |

## 关键发现(按严重程度)

### CRITICAL

- **spoofguard pickBest 所有权缺陷**(RA3-C1):`pickBest` 在 `last==nil` 分支返回
  `s.nonEDNS` 但不清槽位;ambiguous 确认路径的 `previous` 随即别名了下一轮
  `processPacket` 会归还的池对象 → `sameUDPAnswer` 读已回收内存、后续每次
  `Put(previous)` 双重归还同一 `*dns.Msg`(两个并发查询可拿到同一消息指针)。
  GFW 注入场景(每查询 2 个裸假应答)必然触发。修复:pickBest 返回
  `(best, ttl)` 并清空获胜槽位(顺带修复 hopguard 学到未选中候选 TTL 的
  优先序不一致)。

### HIGH

1. **ambiguous 回退绕过防御**(RA3-H1):errAmbiguous 落入 executeUDPPooled
   单读路径 —— 注入者的下一个 ID 匹配数据报被直接服务。改为止步并让
   resolver 走 TCP 重试。
2. **MQTYPE QTx 读回收后的 qctx**(RA3-H2):预取 goroutine 在闭包内读
   qctx 字段,主响应 TC/unpack 失败早退后 `qctxPool.Put` 与之竞争。改为
   先捕获值再启动。
3. **预打包缓存命中在 TCP 族变成 12 字节帧**(RA3-H3):plain-TCP/DoT 帧
   构建无条件 `response.Data = frame[...]` + 重 Pack(nil RR sections → 仅
   头部);DoQ/DoH/DoH3/HTTP-over-TLCP 直接 `Pack()` 同病。裸 EDNS 或无
   EDNS 客户端的 TCP 缓存命中必坏(此前 E2E 未抓到是因为测试域名带
   DNSSEC 走了解包路径)。新增 `dnsutil.PackStreamFrame` 统一五个写入方。
4. **DNSSEC 验证按指针记忆化**(RA3-H4):verifyMemo 以池化 `*dns.Msg`
   指针为键,minimisation 重试的 Put-and-continue 使回收指针携带旧判定。
   memo 现按单响应作用域清零。
5. **CNAME 跳数 TTL 写错对象**(RA3-H5):克隆后改原 RR 的 TTL,返回记录
   保留完整原始 TTL(向客户端与缓存高报新鲜度)。
6. **refresh 门泄漏**(RA3-H7):fresh-hit 预取路径取门后 `&&` 链中断不还门,
   pending.Group 条目被 LRU-promote 永久钉住,热键刷新黑屏。`startThrottled`
   封装取门+冷却+拒时还门,并扩展到 stale 路径(刷新风暴修复)。
7. **损坏 BLOB 自愈死循环**(RA3-H6):self-heal 的 `Delete` 触发 OnEvict
   重新 spill 同一损坏记录(每查询一次磁盘追加,无界增长)。lrumap 新增
   `DeleteNoEvict`。
8. **spillfile 扫描持锁做 IO**(RA3-H8):Entries/EntryCount 在 mu 内逐块
   pread(正是 fe76f19 为 Get/Compact 移除的停顿);Flush 在 mu 内 fsync。
   改为锁内快照、锁外读。

### MEDIUM(摘要)

防御/协议:collect 路径缺问题回显校验、共享端口 DNSCrypt TCP accept
静默退出/无退避、DoQ+DoH3 同端口不可分(启动拒绝)、EOF 半关丢弃在途响应
(三个 writer 的 connCancel/wg.Wait 顺序)、Start() 运行时错误跳过 shutdown。
upstream:DTLS→TLS 回退 `context.Background()` 脱钩、QUIC Put 锁外读
p.total、qdcount=0 响应仅凭 ID 匹配即交付、capsguard disabledUntil 无锁读
(3 词 time.Time 撕裂)、ExecuteTCP 回退绕过饱和门与 splitguard 分段、
0x20 随机化问题在错误路径未还原、新建 DoH client 首请求不重试。
handler:DNS64 对 NXDOMAIN 合成且不清 rcode(RFC 6147 §5.1.2)、Secondary
offsets 泄漏、UnpackPrePackedForModify 遗弃 wire 池缓冲、<12 字节 wire 到
达 serve 路径。resolver/domain:delegation 查找未规范化大小写、根区
wildcard `"*.."` 畸形(验证器与 RFC 8198 合成两处)、无 RRSIG 证明入库、
validateNODATAWithNSEC 以 childDS 为门导致根区否认不验证、RFC 9520 失败
退避成功不重置、FlushDB 截断前不排空 async writer(复活窗口)、延迟排序
fast-path 双重物化泄漏、dnscert 静默重生成密钥破坏 PQ 种子不变量。

### 注释风格专项(业主关注点)

~170 处来源噪音清除:日期引用(`(2026-09 D2)`)、审计编号(`(H1)`/`(M-low)`/
`(R3-M2)`)、pprof/生产事故战史、`previously X` 变更叙述;24 处多行故事块
压缩为不变量(pion 版本 saga、ns_flight 放大故事、evictOne godoc 等)。
残留扫描为零。已固化为方法论维度(见下)。

## Round B 复查产出

- **自查回归 1 项(MEDIUM)**:plain-TCP 饱和门错误遮蔽可返回 `(nil, nil)`
  (Acquire 错误被 Exchange 错误遮蔽);拆分变量修复。
- **测试捕获回归 1 项**:DNSCrypt Start 的 started 标志在重构中丢失置位,
  serve 循环不工作(dnscrypt E2E 测试超时暴露)。
- 交叉扫描:goroutine 生命周期、Close 幂等、context 脱钩、锁内 IO、无界
  增长、channel 单一关闭 —— 除 2 个 LOW(spillfile Close 幂等、delegation
  spill 未关闭)外全部清洁;错误包装/参数校验/日志热路径全部清洁。

## 修复提交清单

| 提交 | 内容 |
|------|------|
| dcbcf0c | spoofguard 所有权 + ambiguous 止步 + 问题回显 |
| 6c232a2 | MQTYPE 值捕获 + startThrottled 门纪律 |
| 84d3b03 | PackStreamFrame 五写入方预打包直发 |
| df22c26 | verifyMemo 作用域 + CNAME TTL + 取消 join |
| cbdf678 | DeleteNoEvict 自愈 + spillfile 锁外扫描 |
| faa6d25 | readClean teardown + dispatch 标签 + accept 退避 + QUIC/H3 冲突 + Start shutdown |
| f1452ff | upstream 批(回退 ctx、池竞态、问题回显、caps 竞态、分段回退、DoH 重试) |
| d4209cb | handler 批(DNS64 rcode、池释放、损坏 wire 降级 miss) |
| 757c9aaa | resolver/domain 批(规范化、NSEC 根、退避重置、FlushDB 排空) |
| beb26eb | 注释清理(~120 文件 ~170 标记) |
| 5035c3a + 594f977 | LOW 加固批 + Round B 修复批 |

## 验证证据

- `go test ./... -short`:全绿(含新增回归测试:PickBest 所有权、问题不匹配
  丢弃、startThrottled 还门、DeleteNoEvict、PackStreamFrame 三路径)。
- `golangci-lint run`:0 警告。
- benchmark:128 项对比,零分配契约路径 allocs 不变;可疑项经 -count=3 复测
  判定为布局噪声(lrumap 仅新增方法,Get/Set 字节级未变);direct-wire +1.5ns
  为 RFC 6840 §5.8 AD 位修复的已知代价。基线已刷新。
- E2E(loopback 配置):14 协议冷+热、7 共享端口、MQTYPE forward/recursive
  合并 + FORMERR、连接池 1 dial/0 fallback、RFC 8020 NXDOMAIN、DNSSEC 递归
  (cloudflare/isc.org)、`+noedns +tcp` 缓存命中(H3 修复场景)、SIGTERM
  优雅停机 —— 全部通过。

## 经验沉淀(已并入方法论)

1. **帧写入方必须守护预打包 Data** —— `len(Data)==0` 才 Pack,否则从 nil
   RR sections 重序列化出 12 字节帧;E2E 需覆盖无 EDNS 客户端(带 DNSSEC
   的测试域名会掩盖该路径)。
2. **池对象所有权转移必须清槽** —— 返回状态槽内消息的 getter 要么清槽
   要么文档化别名契约。
3. **grep 管道里的 `head` 会吞 FAIL 行** —— 全量测试必须查退出码。
4. **注释引用日期/审计编号即腐烂** —— 修复理由写约束,不写出处。
