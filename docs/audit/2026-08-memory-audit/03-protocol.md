# 03 — server/protocol/* 审计（plain / tls / tlcp / dnscrypt）

## M5 [MEDIUM] DoT 10s 握手 deadline 每次读取重新武装，60s 空闲超时从未生效

- **位置**：server/protocol/tls/tls.go:187（循环顶部 SetReadDeadline 10s）、:200（成功后 SetReadDeadline 60s）
- **类别**：timer
- **问题描述**：读取循环每次迭代先 arm 10s 握手 deadline（187 行），再阻塞 `io.ReadFull`（189 行）；读取成功后 arm 60s（200 行）—— 但下一次迭代的 187 行**立即覆盖**它。支配阻塞读取的是最后一次 SetReadDeadline，因此 60s 空闲超时对任何一次读取都不生效，所有读取都被 10s 截断。注释（182-186 行、198-199 行）明确意图：10s 只用于首读（懒握手），之后 60s。
- **风险**：每 15-55s 轮询一次的合法客户端（按 60s 设计）在两次查询间被断开 → 6 倍握手频率，每连接 churn（goroutine + 4KB bufio + TLS 握手 + errgroup 槽位）；与关停设计中"60s 空闲保持"的注释矛盾。
- **修复建议**：`firstRead := true` 守卫 —— 首读前 arm 10s，此后永久 60s（删除循环顶部的 SetReadDeadline，只保留 200 行处）。

## L5 [LOW] 协议处理器缺"ServeDNS 返回请求本体"守卫（防御性 double-Put）

- **位置**：server/protocol/tls/dtls.go:185-186（query 在 ServeDNS 后立即 Put + sendDTLSResponse defer Put response）、tls.go:259/270（DoT worker 双 defer）、tlcp、dnscrypt 同构
- **类别**：pool-leak（防御性）
- **问题描述**：所有协议处理器约定 `response := handler.ServeDNS(query, ...)` 后独立归还 query 和 response。若中间件链某天把 `qctx.Res` 设为请求本体（当前**不可达** —— 全链 grep 确认所有 `qctx.Res =` 都赋新构建的消息，无 `Res = req` 路径），两个 defer/Put 会对同一 `*dns.Msg` 双重归还 → 同一缓冲被两个并发查询复用 → 数据损坏。当前是无守卫的隐式契约。
- **风险**：现在为零（不可达）；未来中间件改动静默破坏契约时，pool 双重归还引发难以定位的并发数据损坏。防御成本一行。
- **修复建议**：ServeDNS 调用后统一加 `if response == query { response = nil }`（nil 路径已有 `resp == nil` 守卫，天然安全）。五个处理器（plain/tls/dtls/tlcp/dnscrypt）同批加。

## 其余（plain / tlcp / dnscrypt / QUIC 服务端）

- **无发现**。已确认：
  - UDP/TCP 读缓冲池归还在所有错误路径正确（含 hopguard/spoofguard 交互路径 —— 见 04-upstream.md 中唯一例外 M8）；
  - DTLS 会话存储（lrumap）OnEvict 正确；
  - dnscrypt 密钥轮换：旧 key 正确释放，ticket map 有界；
  - 各 accept/handler goroutine 均有 HandlePanic + errgroup 追踪；
  - QUIC 服务端（DoQ/DoH3 服务侧）连接关闭路径完整 —— 泄漏只在客户端代理路径（04-upstream.md H3）。
