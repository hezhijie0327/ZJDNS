# 完整修复方案 — 2026-07 Deep Audit

> 审计报告: `12-synthesis.md` | 总计 **51 项发现** | 15 CRITICAL · 17 HIGH · 3 MEDIUM · 16 LOW

---

## Sprint 1 — CRITICAL（15 项，立即修复）

### Pattern A: Pool use-after-free — Unpack 错误路径缺 `Data=nil`（C2-C5）

**根因**: 4 个协议处理器在 success 路径正确设置 `response.Data = nil`，但 Unpack 失败
路径遗漏。`response.Data` 指向已归还到 `pool.DefaultBuffer` 的内存 → dangling pointer。

**模板修复**: 在每个 `pool.DefaultMessage.Put(response)` 前添加 `response.Data = nil`。

---

#### C2 — `server/upstream/pool/tcp.go:248`

**Before (line 241-249)**:
```go
resp := zpool.DefaultMessage.Get()
resp.Data = body
if err := resp.Unpack(); err != nil {
    if pooled {
        zpool.DefaultBuffer.Put(bodyBuf)
    }
    log.Debugf("TCPPOOL: unpack error from %s: %v", c.addr, err)
    zpool.DefaultMessage.Put(resp)
    continue
}
```

**After**:
```go
resp := zpool.DefaultMessage.Get()
resp.Data = body
if err := resp.Unpack(); err != nil {
    if pooled {
        zpool.DefaultBuffer.Put(bodyBuf)
    }
    log.Debugf("TCPPOOL: unpack error from %s: %v", c.addr, err)
    resp.Data = nil
    zpool.DefaultMessage.Put(resp)
    continue
}
```

**验证**: `go test -race -short ./server/upstream/pool/...`

---

#### C3 — `server/upstream/tls/quic.go:189`

**Before (line 185-191)**:
```go
response := pool.DefaultMessage.Get()
response.Data = body
if err := response.Unpack(); err != nil {
    msg.ID = originalID
    pool.DefaultMessage.Put(response)
    return nil, fmt.Errorf("unpack: %w", err)
}
```

**After**:
```go
response := pool.DefaultMessage.Get()
response.Data = body
if err := response.Unpack(); err != nil {
    msg.ID = originalID
    response.Data = nil
    pool.DefaultMessage.Put(response)
    return nil, fmt.Errorf("unpack: %w", err)
}
```

**验证**: `go test -race -short ./server/upstream/tls/... -run TestQUIC`

---

#### C4 — `server/upstream/tls/dtls.go:96`

**Before (line 93-98)**:
```go
response := pool.DefaultMessage.Get()
response.Data = msgBuf
if err := response.Unpack(); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, fmt.Errorf("dtls: unpack response: %w", err)
}
```

**After**:
```go
response := pool.DefaultMessage.Get()
response.Data = msgBuf
if err := response.Unpack(); err != nil {
    response.Data = nil
    pool.DefaultMessage.Put(response)
    return nil, fmt.Errorf("dtls: unpack response: %w", err)
}
```

**验证**: `go test -race -short ./server/upstream/tls/... -run TestDTLS`

---

#### C5 — `server/upstream/tlcp/dtlcp.go:96`

**Before (line 93-98)**:
```go
response := pool.DefaultMessage.Get()
response.Data = msgBuf
if err := response.Unpack(); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, fmt.Errorf("dtlcp: unpack response: %w", err)
}
```

**After**:
```go
response := pool.DefaultMessage.Get()
response.Data = msgBuf
if err := response.Unpack(); err != nil {
    response.Data = nil
    pool.DefaultMessage.Put(response)
    return nil, fmt.Errorf("dtlcp: unpack response: %w", err)
}
```

**验证**: `go test -race -short ./server/upstream/tlcp/... -run TestDTLCP`

---

### Pattern B: Pool leak — fallback 路径覆盖前未归还（C6, H1）

---

#### C6 — `server/upstream/client.go:205`

**Before (line 205-206)**:
```go
if tcpResp, tcpErr := c.plainClient.ExecuteTCP(tcpCtx, msg, &tcpServer); tcpErr == nil {
    result.Response = tcpResp
    result.Error = nil
```

**After**:
```go
if tcpResp, tcpErr := c.plainClient.ExecuteTCP(tcpCtx, msg, &tcpServer); tcpErr == nil {
    if result.Response != nil {
        pool.DefaultMessage.Put(result.Response)
    }
    result.Response = tcpResp
    result.Error = nil
```

**验证**: `go test -race -short ./server/upstream/... -run TestFallback`

---

#### H1 — `server/upstream/client.go:163`

**Before (line 163)**:
```go
result.Response, result.Error = c.dnscryptClient.Execute(tcpCtx, msg, server, true)
```

**After**:
```go
if result.Response != nil {
    pool.DefaultMessage.Put(result.Response)
    result.Response = nil
}
result.Response, result.Error = c.dnscryptClient.Execute(tcpCtx, msg, server, true)
```

**验证**: 同 C6

---

### Pattern C: Nil deref — 可选依赖无 nil 守卫（C7-C15）

---

#### C7 — `server/upstream/client.go:114`

**Before**:
```go
c.proxyDialers.OnEvict = func(_ string, d *socks5.Dialer) { _ = d.Close() }
```

**After**:
```go
c.proxyDialers.OnEvict = func(_ string, d *socks5.Dialer) {
    if d != nil {
        _ = d.Close()
    }
}
```

**验证**: `go test -race -short ./server/upstream/...`

---

#### C8 — `server/handler/middleware/resolution.go:65-71`

**Before**:
```go
qr := m.resolver.Query(ctx, question, ecsOpt)

qctx.ResolutionResult = qr
qctx.Resolved = true
if qr.Err != nil {
    qctx.ResolutionError = true
}
```

**After**:
```go
qr := m.resolver.Query(ctx, question, ecsOpt)
if qr == nil {
    qctx.ResolutionError = true
    return nil
}

qctx.ResolutionResult = qr
qctx.Resolved = true
if qr.Err != nil {
    qctx.ResolutionError = true
}
```

**验证**: `go test -race -short ./server/handler/middleware/... -run TestResolution`

---

#### C9 — `server/handler/middleware/dns64.go:61`

**Before**:
```go
if aqr.Err == nil && len(aqr.Answer) > 0 {
```

**After**:
```go
if aqr != nil && aqr.Err == nil && len(aqr.Answer) > 0 {
```

**验证**: `go test -race -short ./server/handler/middleware/... -run TestDNS64`

---

#### C10 — `server/handler/middleware/cache_lookup.go:70,92,133,190`

**Before** (4 处调用均无 nil 检查):
```go
m.refreshGroup.Go(func() error { ... })
```

**After** (每处包裹 nil 守卫):
```go
if m.refreshGroup != nil {
    m.refreshGroup.Go(func() error { ... })
}
```

具体位置:
- Line 70: `m.refreshGroup.Go(func() error {` → `if m.refreshGroup != nil { m.refreshGroup.Go(`
- Line 92: 同上
- Line 133: 同上
- Line 190: 同上

**验证**: `go test -race -short ./server/handler/middleware/... -run TestCacheLookup`

---

#### C11 — `server/handler/middleware/cache_lookup.go:67,89,109`

**Before** (3 处):
```go
if !m.closed() && ...
```

**After**:
```go
if m.closed != nil && !m.closed() && ...
```

**验证**: 同 C10

---

#### C12 — `server/handler/middleware/cache_lookup.go:143`

**Before**:
```go
refreshCtx, cancel := context.WithTimeout(m.refreshCtx, config.DefaultBackgroundTimeout)
```

**After**:
```go
rc := m.refreshCtx
if rc == nil {
    rc = context.Background()
}
refreshCtx, cancel := context.WithTimeout(rc, config.DefaultBackgroundTimeout)
```

**验证**: 同 C10

---

#### C13 — `server/resolver/resolver.go:159-160` + call sites

**Before** (`New()` at line 159-160):
```go
if cfg.EDNS == nil {
    log.Warnf("RESOLVER: EDNS handler is nil — resolver will panic on first query")
}
```

**After**:
```go
if cfg.EDNS == nil {
    return nil, errors.New("resolver: EDNS handler is required")
}
```

同步修改 `New()` 签名返回 `(*Resolver, error)`:
```go
func New(cfg *Config) (*Resolver, error) {
    if cfg == nil {
        return nil, errors.New("resolver: nil config")
    }
    if cfg.EDNS == nil {
        return nil, errors.New("resolver: EDNS handler is required")
    }
    // ...
    return r, nil
}
```

调用方更新（`server/server.go` 中的 `initDNSResolver`）:
```go
dnsResolver, err := resolver.New(&resolver.Config{...})
if err != nil {
    return nil, fmt.Errorf("resolver init: %w", err)  // 传播到 New()
}
```

**验证**: `go build ./... && go test -short ./server/resolver/...`

---

#### C14 — `server/resolver/resolver.go:162-163`

同 C13 模式，`New()` 中:
```go
if cfg.BuildMsg == nil {
    return nil, errors.New("resolver: BuildMsg function is required")
}
```

---

#### C15 — `server/resolver/resolver.go:165-166`

同 C13 模式，`New()` 中:
```go
if cfg.QueryClient == nil {
    return nil, errors.New("resolver: QueryClient is required")
}
```

**注意**: C13/C14/C15 三项在同一个 commit 中完成，因为共享同一处签名变更。

---

### Pattern D: Shared-key cache ordering（C1）

#### C1 — `server/protocol/dnscrypt/crypto.go:176-187`

**Before**:
```go
// RFC §8: cache shared keys to avoid X25519 per query.
cpk := query.ClientPk
if cached, ok := s.sharedKeyCache.Get(cpk); ok {
    query.SharedKey = cached
}
decrypted, decErr := query.Decrypt(b, k.pair.Classical.ResolverSk)
if decErr == nil && query.SharedKey == [dnscryptcrypto.SharedKeySize]byte{} {
    // Cache miss — compute the key and store it.
    sk, skErr := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &k.pair.Classical.ResolverSk, &cpk)
    if skErr == nil {
        s.sharedKeyCache.Set(cpk, sk)
    }
}
```

**After**:
```go
decrypted, decErr := query.Decrypt(b, k.pair.Classical.ResolverSk)
if decErr == nil {
    // RFC §8: cache shared keys to avoid X25519 per query.
    // ClientPk is populated by Decrypt — read it after Decrypt returns.
    cpk := query.ClientPk
    if query.SharedKey == [dnscryptcrypto.SharedKeySize]byte{} {
        if cached, ok := s.sharedKeyCache.Get(cpk); ok {
            query.SharedKey = cached
        } else {
            sk, skErr := dnscryptcrypto.ComputeSharedKey(dnscryptcrypto.XChacha20Poly1305, &k.pair.Classical.ResolverSk, &cpk)
            if skErr == nil {
                s.sharedKeyCache.Set(cpk, sk)
                query.SharedKey = sk
            }
        }
    }
```

**验证**: `go test -short ./server/protocol/dnscrypt/...`（需确认已有测试覆盖 classical query decrypt 路径）

---

## Sprint 2 — HIGH（17 项）

### Pattern E: Non-deferred pool.Put（H10）— 5 handlers

**参考模板**: `server/protocol/tls/tls.go:234` — `defer pool.DefaultMessage.Put(resp)`

---

#### H10a — `server/protocol/tls/https.go:128-130`

**Before**:
```go
response := s.handler.ServeDNS(req, clientIP, true, protocol)
if err := s.respondDOH(w, response); err != nil {
    log.Debugf("TLS: DoH response failed for %s: %v", r.URL.String(), err)
}
if response != nil {
    pool.DefaultMessage.Put(response)
}
```

**After**:
```go
response := s.handler.ServeDNS(req, clientIP, true, protocol)
if response != nil {
    defer pool.DefaultMessage.Put(response)
}
if err := s.respondDOH(w, response); err != nil {
    log.Debugf("TLS: DoH response failed for %s: %v", r.URL.String(), err)
}
```

---

#### H10b — `server/protocol/tls/dtls.go:154,161,169,178,181`

将所有 `pool.DefaultMessage.Put(response)` / `pool.DefaultMessage.Put(query)` 替换为
`defer pool.DefaultMessage.Put(...)` 模式。

修改策略: 在 `query` / `response` 赋值后立即添加 `defer pool.DefaultMessage.Put(x)`，
然后删除所有显式 Put 调用。

---

#### H10c — `server/protocol/tls/quic.go:223,229`

**Before**:
```go
pool.DefaultMessage.Put(req)
// ...
if response != nil {
    pool.DefaultMessage.Put(response)
}
```

**After**:
```go
defer pool.DefaultMessage.Put(req)
// ...
if response != nil {
    defer pool.DefaultMessage.Put(response)
}
```

---

#### H10d — `server/protocol/tlcp/tlcp.go:107,110`

**Before**:
```go
if err := zdnsutil.WriteTCPMsg(conn, resp); err != nil {
    log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
    pool.DefaultMessage.Put(resp)
    return
}
pool.DefaultMessage.Put(resp)
```

**After**:
```go
defer pool.DefaultMessage.Put(resp)
if err := zdnsutil.WriteTCPMsg(conn, resp); err != nil {
    log.Debugf("TLCP: DoT write error to %s: %v", clientIP, err)
    return
}
```

---

#### H10e — `server/protocol/tlcp/dtlcp.go:316,323,331,340,343`

同 H10b 模式 — 全部替换为 `defer pool.DefaultMessage.Put(...)`。

---

### Pattern F: Missing read deadline / context check（H4, H9, H12）

---

#### H4 — `server/upstream/client.go:277-297`

`Close()` 缺少 `tcpPool` 关闭。

**After** (在 `Close()` 末尾添加):
```go
func (c *Client) Close() {
    if c == nil {
        return
    }

    c.warmWg.Wait()

    c.tlsClient.Close()

    if c.proxyDialers != nil {
        c.proxyDialers.Range(func(key string, d *socks5.Dialer) bool {
            if d != nil {
                _ = d.Close()
            }
            return true
        })
        c.proxyDialers = nil
    }

    c.dnscryptClient.Close()
    c.plainClient.Close()  // ADD: 关闭 plainClient 内部的 tcpPool
}
```

同步修改 `server/upstream/plain/client.go` 添加 `Close()` 方法关闭 tcpPool。

---

#### H9 — `server/protocol/tlcp/tlcp.go:85-112`

**Before**:
```go
func (s *Server) handleDOTConn(conn net.Conn) {
    defer zdnsutil.HandlePanic("TLCP DoT handler")
    defer func() { _ = conn.Close() }()

    clientIP := zdnsutil.ClientIPFromAddr(conn.RemoteAddr())

    for {
        msg, err := zdnsutil.ReadTCPMsg(conn)
        // ...
```

**After**:
```go
func (s *Server) handleDOTConn(conn net.Conn) {
    defer zdnsutil.HandlePanic("TLCP DoT handler")
    defer func() { _ = conn.Close() }()

    clientIP := zdnsutil.ClientIPFromAddr(conn.RemoteAddr())

    for {
        _ = conn.SetReadDeadline(time.Now().Add(config.DefaultTCPPoolIdleTimeout))

        msg, err := zdnsutil.ReadTCPMsg(conn)
        // ...
```

**验证**: `go test -short ./server/protocol/tlcp/...`

---

#### H12 — `server/protocol/tls/quic.go:171-231`

在 `handleDOQStream` 的每次 `io.ReadFull` 前添加 context 检查:

**After** (在 line 176 前添加):
```go
select {
case <-s.ctx.Done():
    return
default:
}
if _, err := io.ReadFull(stream, respBuf[:zdnsutil.DNSFramePrefixLen]); err != nil {
```

同样在 line 198 的 `io.ReadFull` 前添加相同的 context 检查。

**验证**: `go test -short ./server/protocol/tls/... -run TestQUIC`

---

### Pattern G: Data not cleared before pool.Put（H2, H3, H5）

---

#### H2 — `server/upstream/tls/tls.go:87-96`

**Before**:
```go
response := pool.DefaultMessage.Get()
if _, err := response.ReadFrom(tlsConn); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
if err := response.Unpack(); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
return response, nil
```

**After**:
```go
response := pool.DefaultMessage.Get()
if _, err := response.ReadFrom(tlsConn); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
if err := response.Unpack(); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
response.Data = nil
return response, nil
```

---

#### H3 — `server/upstream/plain/tcp.go:93-103`

**Before**:
```go
response := pool.DefaultMessage.Get()
if _, err := response.ReadFrom(conn); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
if err := response.Unpack(); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
response.ID = msg.ID
return response, nil
```

**After**:
```go
response := pool.DefaultMessage.Get()
if _, err := response.ReadFrom(conn); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
if err := response.Unpack(); err != nil {
    pool.DefaultMessage.Put(response)
    return nil, err
}
response.Data = nil
response.ID = msg.ID
return response, nil
```

---

#### H5 — `server/upstream/pool/tcp.go:270`

**Before**:
```go
} else {
    zpool.DefaultMessage.Put(resp)
}
```

**After**:
```go
} else {
    resp.Data = nil
    zpool.DefaultMessage.Put(resp)
}
```

---

### Pattern H: 其他 HIGH 修复

---

#### H6 — `server/upstream/socks5/udp.go:151`

**Before**:
```go
d := net.Dialer{}
conn, err := d.DialContext(context.Background(), "udp", relayAddr)
```

**After**:
```go
d := net.Dialer{}
conn, err := d.DialContext(ctx, "udp", relayAddr)
```

---

#### H7 — `server/handler/middleware/chain.go:67`

在 `AssembleChain` 入口添加 nil deps 检查。需先确定当前返回值签名 —
如果返回 `handler.QueryHandler` 需改为 `(handler.QueryHandler, error)` 或直接 panic
（等同 C13-C15 策略）。

**选项 A**（与 C13-C15 保持一致 — 调用方传播 error）:
```go
func AssembleChain(deps *Dependencies) (handler.QueryHandler, error) {
    if deps == nil {
        return nil, errors.New("middleware: nil Dependencies")
    }
    // ...
}
```

**选项 B**（防御性 panic — 编程错误不应静默）:
```go
func AssembleChain(deps *Dependencies) handler.QueryHandler {
    if deps == nil {
        panic("middleware: nil Dependencies — programming error")
    }
    // ...
}
```

**推荐选项 A**。同步更新 `server/server.go` 中调用 `AssembleChain` 的位置。

---

#### H8 — `server/handler/response.go:15-28`

**After** (在 `BuildResponseMsg` 末尾补齐):
```go
func BuildResponseMsg(req *dns.Msg) *dns.Msg {
    msg := pool.DefaultMessage.Get()
    if req != nil && len(req.Question) > 0 {
        dnsutil.SetReply(msg, req)
    } else {
        if req != nil {
            msg.SetReply(req)
        }
        msg.Response = true  // ADD: 确保 nil req 也设置 QR=1
    }
    return msg
}
```

---

#### H11 — `server/protocol/tlcp/tlcp.go:101-102`

**Before**:
```go
if resp == nil {
    return
}
```

**After**:
```go
if resp == nil {
    continue
}
```

---

#### H13 — `server/resolver/forward.go:30`

`lastUpstreamEDE` 从 `*Resolver` 级别移到 per-query 级别。

**Before**: `lastUpstreamEDE` 是 `*Resolver` 的字段。
**After**: 在 `queryUpstream` 函数内创建局部 `*dns.EDE` 变量，传递给 `captureUpstreamEDE`:

```go
func (r *Resolver) queryUpstream(...) QueryResult {
    // ...
    var lastEDE atomic.Pointer[dns.EDE]  // per-query, not per-resolver

    g, queryCtx := errgroup.WithContext(ctx)
    for _, server := range servers {
        g.Go(func() error {
            // ...
            if ede := extractEDE(result.Response); ede != nil {
                lastEDE.Store(ede)  // per-query safe
            }
            // ...
        })
    }
    // ...
    if opt := lastEDE.Load(); opt != nil {
        return QueryResult{Err: dnssecEDEError(uint64(opt.InfoCode))}
    }
}
```

同步删除 `Resolver.lastUpstreamEDE` 字段，将 `captureUpstreamEDE` 改为接收参数而非 `r.lastUpstreamEDE`。

**验证**: `go test -race -short ./server/resolver/...`

---

#### H14 — `server/resolver/nameserver.go:360`

在 `retryWithoutEDNS` 的 resultChan 发送成功后调用 `cancel()`:

**After** (在发送成功结果到 resultChan 的路径后):
```go
select {
case resultChan <- retryResp:
    cancel()  // ADD: 取消其余 errgroup goroutines
    return nil
case <-ctx.Done():
    pool.DefaultMessage.Put(retryResp)
    return ctx.Err()
}
```

---

#### H15 — `server/resolver/recursive_helpers.go:169-178,196-205`

**修复**: 在 `processAnswerWithDNSSEC`、`checkLameDelegation`、`collectBestNSMatch`
函数中添加注释说明 pool zeroing 依赖:

```go
// pool.DefaultMessage.Put zeroes *dns.Msg; auth/extra slices remain valid
// because their backing arrays are not zeroed.  See internal/pool/pool.go:99.
pool.DefaultMessage.Put(response)
return &QueryResult{..., Authority: auth, Additional: extra}
```

---

#### H16 — `server/resolver/nameserver.go:43-45,71-72`

**修复**: 将 `baseMsg.Copy()` 替换为新建 `dns.Msg` + 显式拷贝字段（避免
non-pool allocation 注入 pool）:

```go
// Before:
msg := baseMsg.Copy()
defer pool.DefaultMessage.Put(msg)

// After: 不将 Copy 结果注入 pool
msg := baseMsg.Copy()
// 不使用 defer pool.Put — msg 不是从 pool 分配的
```

或者更干净的方案：在 goroutine 内直接构建 question-specific message，不 Copy:

```go
msg := r.resolver.buildMsg(question, ecs, false, false)
defer pool.DefaultMessage.Put(msg)
// ... use msg directly, don't copy
```

---

#### H17 — `server/resolver/qname_minimise.go:27,41,56`

**Before**:
```go
offset, _ := dnsutil.Prev(fqOrig, offset)
```

**After**:
```go
offset, err := dnsutil.Prev(fqOrig, offset)
if err != nil {
    log.Debugf("RECURSION: QNAME minimisation Prev error for %s: %v", fqOrig, err)
    return queryQuestion, 0
}
```

---

## Sprint 3 — MEDIUM + LOW（19 项）

### MEDIUM

| ID | 文件 | 修复 |
|----|------|------|
| M1 | `internal/dnsutil/dnsutil.go:54` | `IsSecureProtocol` 添加 `"dnscrypt"` case；删除 `warmup.go:45` 和 `validate.go:189` 中的显式 DNSCrypt 检查 |
| M2 | `internal/dnscryptcrypto/certificate.go:197-201` | 修复长度检查顺序：先检查 `len(b) < PQCertByteLength`，再检查 `len(b) < CertByteLength` |
| M3 | `internal/dnscryptcrypto/dns.go:70,95` | `ReadPrefixed`/`WritePrefixed` 添加 `if conn == nil { return ErrXxx }` 守卫 |

### LOW（前 8 项 — 注释准确性）

| ID | 文件 | 修复 |
|----|------|------|
| L1 | `internal/dnscryptcrypto/dns.go:40` | godoc: `dnsSize` → `DNSSize` |
| L2 | `internal/dnsutil/bind.go:65,72` | 注释: "during shutdown" → "best-effort preflight" |
| L3 | `internal/dnsutil/keepalive.go:27-28` | 添加 `// _ = error: ...` 内联注释 |
| L4 | `internal/dnscryptcrypto/xsecretbox.go:67,92,114,122` | 添加 `// _ = error: ...` 内联注释 |
| L6 | `internal/ipttl/ipttl.go:1` | Package doc: "ttlcap" → "ipttl" |
| L9 | `internal/latency/httppool.go:82` | 添加 `// _ = error: ...` 内联注释 |
| L16 | `server/upstream/dnscrypt/crypto.go:81` | 添加 `// _ = error: ...` 内联注释 |

### LOW（后 8 项 — 代码质量）

| ID | 文件 | 修复 |
|----|------|------|
| L5 | `internal/ipdetect/ipdetect.go:64-66` | 删除 `resp == nil` 检查（http.Client 保证 resp 非 nil 时 err==nil 不成立） |
| L7 | `internal/dnscryptcrypto/keys.go:38-43` | `GenerateEd25519Keypair` 添加 `%w` 包装 |
| L8 | `internal/latency/prober.go:45-49` | `Close()` 添加 `sync.Once` 守卫 |
| L10 | `internal/dnscryptcrypto/encrypted.go:590-602` | 考虑删除 `EncryptQuery`/`DecryptResponse` wrapper（可选） |
| L11 | `config/config.go:202-203` | `ProviderName()` 添加 domain 非空校验 |
| L12 | `database/stmts.go:68-73` | 添加跨包常量一致性注释 |
| L13 | `server/protocol/dnscrypt/crypto.go:183` | 由 C1 修复自动解决 |
| L14 | `cache/store.go:352,358,363` | `%v` → 保持一致（logging 非 error wrapping — 不强制改） |
| L15 | `config/load.go:152` | `ProtoHTTP` → `ProtoHTTPS`（或添加注释说明为什么用 http） |
| L17 | `internal/log/log.go:170` | 可选优化: TimeCache 缓存预格式化时间戳 |

---

## 提交计划

按 root cause pattern 分批提交，每批一个 commit。

```
Commit 1: fix: add Data=nil before pool.Put on Unpack error paths (C2-C5)
Commit 2: fix: return pooled response before UDP-to-TCP fallback (C6, H1)
Commit 3: fix: add nil guards for optional middleware dependencies (C8-C12)
Commit 4: fix: reject nil required deps in resolver.New() (C13-C15)
Commit 5: fix: guard nil socks5.Dialer in OnEvict callback (C7)
Commit 6: fix: move DNSCrypt shared-key cache population after Decrypt (C1)
Commit 7: fix: use defer pool.Put in 5 protocol handlers (H10)
Commit 8: fix: add read deadline/ctx checks in TLCP DoT and QUIC handlers (H9, H12, H4)
Commit 9: fix: clear response.Data after Unpack in TLS and plain TCP (H2, H3, H5)
Commit 10: fix: per-query EDE storage instead of per-resolver (H13)
Commit 11: fix: cancel errgroup on FORMERR retry success (H14)
Commit 12: fix: check dnsutil.Prev errors in QNAME minimisation (H17)
Commit 13: fix: document pool zeroing dependency, fix Copy→Put (H15, H16)
Commit 14: fix: nil deps guard + QR=1 in response builder (H7, H8)
Commit 15: fix: use caller ctx for SOCKS5 UDP dial, continue on nil resp (H6, H11)
Commit 16: fix: MEDIUM findings — IsSecureProtocol, dead code, nil checks (M1-M3)
Commit 17: fix: LOW findings — documentation, comments, minor cleanup (L1-L17)
```

## 质量门禁

每次提交后:

```bash
go build ./...                    # 零编译错误
go fix ./...                      # 自动修复
golangci-lint run                 # 零警告
golangci-lint fmt                 # 格式化
```

每个 Sprint 后:

```bash
go test -short ./...              # 全部测试
go test -race -short ./...        # 竞态检测（CI 必需）

# Benchmark 回归检测（>15% 变慢即回归）
go test -bench=. -short -benchtime=500ms ./... \
  | grep '^Benchmark' | sort > docs/benchmark/benchmark-baseline.txt
git diff HEAD~1 -- docs/benchmark/benchmark-baseline.txt
```
