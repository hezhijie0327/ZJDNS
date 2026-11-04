# ZJDNS Round 5 Foundation 审计报告(只读,仓库未修改)

先跑了 `git diff 9c6df186..HEAD -- internal/ cmd/`(16 个文件,+622/−33),核心变更为 demux MSG_PEEK 嗅探、全新 ktls 包、ipttl 注释整理、pion/dtls v3→v4。所有平台(linux/freebsd/windows/darwin)交叉编译通过,darwin 下 demux/ktls/ipttl/lrumap 测试全绿。

## 发现

### F-1 | HIGH | 性能/远程 DoS | internal/demux/sniff_peek.go:59-82(peekHeader + waitReadable)

**问题**:部分头部(1–4 字节已到达)时嗅探循环全核自旋。`recvfrom(MSG_PEEK)` 不消费字节,而 `poll(2)` 是水平触发——只要接收缓冲区里还有未读字节,POLLIN 永远立即可读:

```go
n, _, err := unix.Recvfrom(fd, buf, unix.MSG_PEEK|unix.MSG_DONTWAIT)
switch {
case err == nil:
    switch {
    case n == 0:       return io.EOF
    case n >= len(buf): return nil
    }   // 0 < n < 5 → 落到 waitReadable
...
if err := waitReadable(fd, deadline); err != nil { return err }  // 立即返回(POLLIN 电平触发)→ 死循环
```

**实证**(独立模块在 /tmp 复现该循环,未触碰仓库):对端发 2 字节后停发,300ms 内迭代 **423,967 次**(recvfrom+poll 约 1.4M syscalls/秒,满占一核);外推到 10s 的 `sniffTimeout` 每连接约 1400 万次系统调用。任何远端 peer 对共享端口 TCP 连接发送 1–4 字节后停发(或 FIN 不 RST——RST 会走 ECONNRESET→fallback 正常退出,FIN+部分数据则继续自旋)即触发;`SniffConcurrency = config.DefaultServerGoroutineLimit = 256`,256 个并发停滞连接即可打满所有核,且每个嗅探槽被占用至多 10s,挤占正常连接。这是 23bcf781(旧实现 `io.ReadFull`+`SetReadDeadline` 阻塞在 netpoller,零 CPU)引入的回归。`sniff_peek_test.go` 的 trickle 测试(2+2+1 字节、100ms 间隔)只验证正确性,测试本身在每个间隔内就在自旋——掩盖了问题。附带缺陷:部分数据+EOF 场景旧路径立即返回 `ErrUnexpectedEOF`,新路径自旋满 10s 后误报 `os.ErrDeadlineExceeded`。

**修复方向**:(任选或组合)
- 进度检测:`poll` 唤醒后 `n` 与上轮相同且 `revents` 含 `POLLHUP/POLLRDHUP` → 返回 `io.ErrUnexpectedEOF`(Linux 需在 `Events` 中订阅 `POLLRDHUP` 才能探测半关闭);
- 零进展退避:连续两次唤醒 `n` 无增长则 sleep(如 1ms 起、上限 25–50ms),把自旋降为低频轮询;
- 或改用 runtime 的 `SetReadDeadline`+单字节探测读等待新数据(注意 waitReadable 注释里弃用 runtime deadline 的理由,需重新评估)。

### F-2 | LOW | 注释准确性 | internal/demux/sniff_peek.go:37-38

`// Control runs with exclusive fd access — the conn is fresh off Accept, nobody else reads it yet.` 前半句不成立:`syscall.RawConn.Control` 在 internal/poll 中只持有共享 incref(`FD.RawControl` → incref/decref),并不排斥 runtime 侧并发读写。真正成立的安全论据是后半句(Accept 后新连接、单读者)。注释夸大了保证,若未来有人在已使用的连接上复用 `sniffHeader` 会依赖错误前提。建议改为只陈述"fresh off Accept、无其他读者"论据。

### F-3 | LOW | 风格(声明顺序) | internal/ktls/limit.go:59

项目规范要求 `New*` 构造器紧跟类型,但 `NewLimitListener` 与 `limitListener` 之间隔了 `limitConn` 类型及其 3 个方法,且 `limitListener.Accept` 位于构造器之后(decorder 不检查此项,lint 通过)。纯风格问题,可不修。

## 深审通过(无发现)的要点

- **ktls 包整体**:`limitListener` 阻塞式信号量 Accept 与 x/net/netutil 及 dnsutil.LimitListener 语义一致(Close 后随连接释放最终解阻塞);`limitConn.Close` 用 `sync.Once` 防双释放;`ConnectionState/HandshakeContext` 转发与 eTLS `compatibleConn`(`Compatible()`)+ `Conn.HandshakeContext(context.Context) error` 签名逐一核实匹配;`options_kernel/stub` 的平台拆分与 eTLS `KernelOptions{TX,RX}`(仅 linux/freebsd 有字段)精确对应;`warnOffloadBlocked` 用 `sync.Once` 全局一次,合理。
- **demux 接线**:peek 平台 TLS 路由透传裸 `*net.TCPConn`,满足 eTLS KTLS 直连要求;`sniffHeaderRead` 回退时无已消费字节(MSG_PEEK 不消费),重放无重复;`queue.go` push/Close 竞态由二次 ctx 检查闭合(通道滞留连接不会泄漏);sniff goroutine 有 sem 释放 + `HandlePanic`。
- **ipttl.go**:纯字段注释/对齐调整,`//nolint:unused` 为 Windows lint 所需(capture_unix.go 仅 unix 构建),无行为变化。
- **pool.go**:`Message.Put` 释放 Data 的容量级路由(2048)排除跨池污染;抽查全部 `ReleaseWire` 调用点(response.go、resolve.go、cache_lookup/store、ns_addresses)均遵守"先读后释放、释放后清 Data/不再读"纪律,未发现双重归还。
- **pending.go / lrumap/lru.go / spillfile/async.go / latency/prober.go / log / ipdetect**:WaitGroup Add/Wait 互斥、eviction 唤醒、Once 发布、Close 幂等、nil-ctx 防御均正确;仅 lru.go 的 `Len()` 用写锁、`Range` 用写锁(可用 RLock)属既有 LOW 性能小疵,本轮未变更,不计入。
- **cmd/zjdns**(main.go/version.go/banner.go + cli/:probe/dnsstamp/generate/parse):无 context.TODO/Background(除测试);probe.go 的 seen 位图短路防越界正确;`errors.AsType` 已用 Go 1.27 特性。version 4.8.24 与发布序列一致。

## 审阅文件清单

逐行深审(本轮 diff):`internal/demux/{detect,sniff_peek,sniff_read,tcp,queue}.go`、`internal/ktls/{ktls,limit,options_kernel,options_stub}.go`、`internal/ipttl/ipttl.go`、`cmd/zjdns/version.go`。
完整审阅:`internal/pool/pool.go`、`internal/pending/pending.go`、`internal/lrumap/lru.go`、`internal/spillfile/async.go`、`internal/latency/prober.go`、`internal/dnsutil/keepalive.go`、`internal/log/log.go`(节选)、`internal/ipdetect/ipdetect.go`(节选)、`cmd/zjdns/{main,banner}.go`、`cmd/zjdns/cli/probe.go`,并交叉核实 `server/protocol/{tls/https.go,shared/tcp.go}` 的 ktls 接线与 `.etls-patched` 的 `Compatible/NetConn/HandshakeContext/KernelOptions` 语义。
扫描式覆盖(grep 维度排查,未变更):stats/journal.go(节选)、其余 internal 包无触发。

结论:本轮 1 个 HIGH(peek 嗅探自旋,F-1,已实证)需要尽快修复;2 个 LOW 可选。