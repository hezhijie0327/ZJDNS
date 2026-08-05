# goroutine 审计

> agent: `a30d94568bbedf1d9`

发现数: 3

## goroutine-01 — HIGH

- **位置**: `server/bridge.go:110`
- **类别**: memory
- **摘要**: tcpWriteEntry.refs 每请求 +2 但每路径只 -1，净漂移 +1/请求，sweep 永无法淘汰 entry（回归 H1 未修净）
- **描述**: handleDNSRequest TCP 路径对 entry.refs 执行两次 Add(1)：line 98（shard 锁内）与 line 110（capacityOnce.Do 之后），但每条退出路径只有一个 Add(-1)：goroutine（line 155）与 SERVFAIL 路径（line 115）。每个 TCP 请求净增 +1，refs 永不归零。tasks.go:137 的 sweepTCPWriteMu 以 `refs.Load() != 0` 跳过 entry，因此所有服务过请求的 entry 永远无法被删除——每次新的 TCP 连接（源端口不同即新 key）永久占用一条 entry（含 capacity chan×16 + writeMu chan），进程生命周期内无界增长。上一轮 H1（12-synthesis.md H1，修复提交 9f6001c 声称 "refs now reach 0"）只删除了 LoadOrStore 前的 placeholder +1，却保留了 line 110 这个重复的 in-flight +1，漂移依旧；其单测（server/tasks_test.go:27-46）手工模拟 +1/-1，从未走真实 handleDNSRequest 路径，因此断言通过。f7e7f13 分片重构（shard 化）后注释块重复了两份（line 94-97 与 106-109），bug 原样保留。
- **风险**: 每服务过一个 TCP 请求的 (ip:port) 都永久滞留 entries map（16 shard × 无界条目），长期运行的内存无限增长直至 OOM；sweep 成为死代码（与 H1 描述的后果完全相同）。
- **修复**: 删除 line 110 的重复 `entry.refs.Add(1)`（保留锁内 line 98 的一次），使每请求净增 1 次、每条退出路径释放 1 次，refs 归零后 sweep 恢复驱逐；并补一条真实路径测试（走 handleDNSRequest + 完成请求后断言 refs.Load()==0），避免再次依赖手工模拟。

## goroutine-02 — HIGH

- **位置**: `server/handler/middleware/cache_lookup.go:247`
- **类别**: goroutine
- **摘要**: serveExpiredWithRefresh 前台 TryGo 失败时 done 永不关闭，定时器路径的第二个 TryGo 闭包在 select 上阻塞到进程退出，占用 refreshGroup 槽位
- **描述**: serveExpiredWithRefresh 中 done channel（line 150）仅由前台刷新闭包（line 160-178）的 defer close(done)（line 162）关闭。若前台 TryGo 因 refreshGroup 饱和失败（line 179-181），done 永远不关闭；但 600ms 客户端超时（DefaultServeExpiredClientTimeout=600ms）后代码仍发起第二个 TryGo（line 247），其闭包执行 `select { case <-done: ... case <-rc.Done(): }`（line 260-267）。rc 是 m.refreshCtx（server.go:78 的 cacheRefreshCtx），只在服务关闭时取消。于是该闭包连同它占用的 refreshGroup 槽位（DefaultCacheRefreshConcurrency=64）一直驻留到 shutdown。场景：过期查询 + 刷新池恰好饱和（前台 TryGo 失败）+ 600ms 后有空位（后台 TryGo 成功）——上游延迟尖峰时高概率发生；驻留的闭包占满 64 个槽位后，所有后续 TryGo（line 77/104/160/247 的 prefetch、stale refresh、背景写回）全部失败，缓存刷新系统在服务器剩余生命周期内停摆。
- **风险**: goroutine + errgroup 槽位泄漏（上限 64 个），一旦驻满，全部后台缓存刷新/prefetch/背景写回失效，缓存只能靠过期条目与前端请求维持，直到进程重启；自增强式资源耗尽。
- **修复**: 记录前台刷新是否真正启动（如 `foregroundStarted bool`）：仅当其为 true 时才在定时器路径发起第二个 TryGo；或在 line 179-181 的前台 TryGo 失败分支中一并 close(done)（此时闭包 2 的 <-done 立即返回，不会阻塞），二选一即可。

## goroutine-03 — MEDIUM

- **位置**: `cache/async_writer.go:119`
- **类别**: goroutine
- **摘要**: AsyncStatsWriter.run() 后台 goroutine 无 defer HandlePanic，flush() 中 SQLite panic 将直接崩溃整个进程
- **描述**: NewAsyncStatsWriter 启动的 run() goroutine（line 41 go w.run()）只有 `defer close(w.done)`（line 120），没有 `defer zdnsutil.HandlePanic(...)`，是全库唯一缺失 HandlePanic/recover 的生产 goroutine（其余 23 处均有）。run() 调用的 flush()（line 159-185）对 db.StmtQueryStats.Exec / StmtQueryLog.Exec 不做 recover，错误虽被丢弃但 panic 无法拦截——goroutine 内未捕获的 panic 会使整个进程崩溃。同文件 Record()（line 52-56）已有 recover 兜底，说明作者认可 DB 调用存在 panic 风险（如 IsClosed() 检查与 Exec 之间的关闭竞态、modernc SQLite 内部断言），run() 却未加同等防护。
- **风险**: 查询统计写入路径上的任何 panic（DB 关闭竞态、驱动内部异常）都会使整个 DNS 服务器进程崩溃，属于可避免的稳定性缺口；同时 panic 后 w.done 虽由 defer 关闭，但统计写入静默终止。
- **修复**: 在 run() 顶部加 `defer zdnsutil.HandlePanic("Async stats writer")`（排在 defer close(w.done) 之前，或两者并用——HandlePanic 先注册、后注册 close(done) 亦可），与全库其余 goroutine 的防护标准对齐。

