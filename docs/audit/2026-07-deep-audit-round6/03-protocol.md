# Protocol Audit — server/protocol/{plain,tls,tlcp,dnscrypt}

**日期**: 2026-07-28
**范围**: server/protocol/plain, tls, tlcp, dnscrypt (23 文件)

---

## 发现汇总

| # | 严重程度 | 分类 | 文件:行 | 描述 |
|---|----------|------|---------|------|
| P1 | **HIGH** | pool-leak | `tls/quic.go:197` | `pool.Get()` 无 `defer Put()` — panic 时泄漏 |
| P2 | **HIGH** | pool-leak | `tls/https.go:124`, `tlcp/http_tlcp.go:95`, `tlcp/tlcp.go:101` | 非 pool 对象被 `Put()` 入 pool（来自 miekg/dns 的 `new(dns.Msg)`） |
| P3 | MEDIUM | memory | 系统性（15+ 处） | `response.Data` 在 `pool.Put()` 前未 nil 化 |
| P4 | MEDIUM | pool-leak | 系统性 | 无 `defer Put` 配合 `pool.Get()`（仅 `tls/tls.go` goroutine 和 `dnscrypt/server.go` 合规） |
| P5 | LOW | constants | `tls/server.go:396` vs `tlcp/server.go:159` | TLS (`< 0`) 和 TLCP (`<= 0`) 证书到期阈值不一致 |
| P6 | LOW | performance | `tlcp/dtls.go:254-259` | DTLCP 同步连接处理（已文档化，gotlcp 限制） |
| P7 | LOW | performance | `tls/dtls.go:106`, `tlcp/dtls.go:275` | 内联 `make([]byte, ...)` 而非 pool buffer（已文档化权衡） |
| P8 | LOW | rfc-compliance | `tlcp/tlcp.go:74` vs `tls/tls.go:64` | TLCP 检查 `net.ErrClosed` 但 TLS 不检查 — 关闭时产生虚假日志 |

---

## 关键发现

### P1 — QUIC handler 缺少 deferred Put (HIGH)

`tls/quic.go:197` 中 `pool.DefaultMessage.Get()` 在 panic 恢复路径上缺少 `defer Put`。对比：`tls/tls.go` 的 goroutine（第 221 行）使用了 `defer pool.DefaultMessage.Put(query)`。

**修复**: 在第 197 行 `Get()` 之后添加 `defer pool.DefaultMessage.Put(req)`。

### P2 — 非 pool 对象被 Put 入 pool (HIGH)

三处对非 pool 来源的 `*dns.Msg` 调用 `pool.DefaultMessage.Put()`：
- `https.go:124` — 来自 `dnshttp.Request(r)`（内部 `new(dns.Msg)`）
- `http_tlcp.go:95` — 同上
- `tlcp.go:101` — 来自 `zdnsutil.ReadTCPMsg(conn)`（`new(dns.Msg)`，非 pool）

**修复**: 移除这些 `Put()` 调用（让 GC 处理），或在 Put 前清理对象（`msg.Data = nil; msg.Answer = nil; msg.Ns = nil; msg.Extra = nil`）。

### P3 — response.Data 在 Put 前未 nil 化 (MEDIUM, 系统性)

协议处理器中 `pool.DefaultMessage.Put()` 的 15+ 处调用均未先设置 `response.Data = nil`。Pool 持有带有指向已打包 DNS 线格式缓冲区的陈旧 `.Data` 引用的 `*dns.Msg`。

**修复**: 在每次 `pool.DefaultMessage.Put(msg)` 前添加 `msg.Data = nil`。

---

## 无问题维度

- 锁正确性：无死锁或数据竞争
- 耦合：协议处理器之间无循环依赖
- 函数排序：声明顺序正确
- 参数校验：所有处理器均检查 nil msg/clientIP
