# 04-upstream.md — server/upstream/*

Phase 1 package audit of the outbound query stack (module `zjdns`, Go 1.26.4).
Method: docs/AUDIT-METHODOLOGY.md §1.1 (18 dimensions), §1.3, §4.1, §6.1/§6.2.
Every in-scope file read in full; all findings re-verified against exact code.

## Inventory (21 files, ~5,000 lines)

| File | Lines | Role |
|------|------:|------|
| server/upstream/client.go | 333 | Client: ExecuteQuery dispatch, TCP fallback, KTLS, Close |
| server/upstream/warmup.go | 105 | proxyDialer LRU + pre-warm fan-out |
| server/upstream/plain/client.go | 57 | plain UDP/TCP client + hopguard wiring |
| server/upstream/plain/tcp.go | 120 | ExecuteTCP (pooled pipelining + proxy fallback) |
| server/upstream/plain/udp.go | 818 | ExecuteUDP: spoofguard multi-read/collect state machine |
| server/upstream/pool/quic.go | 221 | QUIC conn pool (DoQ/DoH3) |
| server/upstream/pool/tcp.go | 564 | Conn/ConnPool: RFC 7766 pipelined TCP/DoT |
| server/upstream/pool/udp.go | 519 | UDPConn/UDPPool: demux by match key, collect mode, TTL capture |
| server/upstream/socks5/socks5.go | 498 | RFC 1928/1929 dialer, datagram framing, pools |
| server/upstream/socks5/tcp.go | 90 | DialContext (CONNECT) |
| server/upstream/socks5/udp.go | 407 | UDP ASSOCIATE relay (ListenPacket/DialUDP) |
| server/upstream/tls/client.go | 317 | TLS client: pools, LRU transports, QUIC configs, warm-up |
| server/upstream/tls/tls.go | 113 | ExecuteTLS + exchangeOverTLS |
| server/upstream/tls/quic.go | 254 | ExecuteQUIC + doQUICQuery (RFC 9250) |
| server/upstream/tls/dtls.go | 210 | ExecuteDTLS (RFC 8094) + dialDTLSConn |
| server/upstream/tls/https.go | 196 | ExecuteHTTPS (RFC 8484, transport retry/eviction) |
| server/upstream/tls/http3.go | 251 | ExecuteHTTP3 + http3Transport |
| server/upstream/tlcp/client.go | 144 | TLCP client: pools, session caches, configs |
| server/upstream/tlcp/tlcp.go | 142 | ExecuteTLCP + ALPN enforcement (RFC 7858 §4.1) |
| server/upstream/tlcp/dtlcp.go | 164 | ExecuteDTLCP (GM/T 0128-2023) |
| server/upstream/tlcp/http_tlcp.go | 100 | DoH-over-TLCP with redirect/plaintext guards |
| server/upstream/dnscrypt/cert.go | 126 | Certificate TXT fetch (UDP→TCP fallback) |
| server/upstream/dnscrypt/client.go | 397 | Execute: TC escalation, pooled UDP, PQ tickets |
| server/upstream/dnscrypt/crypto.go | 88 | Query encryption (classical/ephemeral/PQ) |
| server/upstream/dnscrypt/state.go | 316 | State cache + singleflight cert fetch |

## Findings

### CRITICAL

- [CRITICAL/pool-use-after-put] server/upstream/plain/udp.go:604-606, 734-736, 274-276 — spoofguardState double-returns `s.prev` to `pool.DefaultMessage`: `processPacket` fast-return (`AN>=2/NS>0/AD=1`, lines 604-606) and `collectEDNSCandidate` TTL-confident path (lines 734-736) `Put(s.prev)` without nil-ing the pointer; `executeUDPCollect`'s adoption block then `Put`s the same stale `s.prev` again (lines 274-276) | risk: the same `*dns.Msg` enters the pool twice → two concurrent queries `Get()` one message → concurrent mutation → corrupted answers/panics. Trigger is remotely reachable under the exact GFW threat model this code defends against: ≥2 injected ambiguous EDNS candidates (prev non-nil) followed by the real AN≥2 response or a TTL-confident EDNS packet | fix: `s.prev = nil` (and `s.last = nil`) after every `Put` inside `processPacket`/`collectEDNSCandidate`, and make the adoption block in `executeUDPCollect` Put only candidates it provably still owns (or delete the redundant Puts — the fresh-return paths already Put all candidates except the returned one).

- [CRITICAL/panic] server/upstream/dnscrypt/state.go:103-105, 118-120 — `state()` dereferences `c.cache` (`*lrumap.Map`) without a nil check; `Client.Close` (client.go:390-392) sets `c.cache = nil`, and `lrumap.Map.Get` has no nil-receiver guard (internal/lrumap/lru.go:67) → nil-pointer dereference panic on any DNSCrypt query racing or in flight during shutdown (server/tasks.go:291-293 closes the client while in-flight request goroutines may still execute) | risk: process crash during shutdown with DNSCrypt upstreams | fix: nil-check `c.cache` in `state()` (return "dnscrypt client closed"), mirroring the guards already present in `deleteState`/`buildState`.

### HIGH

- [HIGH/panic] server/upstream/plain/udp.go:260 — collect-path datagram gate checks only `len(pkt.Data) < 2` before `processPacket` reads raw header bytes `raw[6]..raw[9]` (lines 591-593) → index-out-of-range panic on a 2–9-byte datagram whose first two bytes match the tracking ID (sniffed, or 1/65536 brute force). The multi-read path gates `n < 12` (line 479) — the collect path is missing the same guard | risk: remotely-triggered per-query panic on spoofguard-enabled plain UDP upstreams (recovered by HandlePanic in server/resolver/forward.go:86, but every such packet kills the query and floods logs — DoS on the defense path) | fix: gate `len(pkt.Data) < 12` (shared `dnsHeaderSize` constant) before calling `processPacket` in `executeUDPCollect`.

### MEDIUM

- [MEDIUM/goroutine] server/upstream/dnscrypt/client.go:328, 350 — `readUDPWithCancel` / `readPrefixedWithCancel` spawn goroutines without `defer zdnsutil.HandlePanic` — the only goroutines in server/upstream without it (all pool readLoops, warm-up, and SOCKS5 relay have it) | risk: panic in `conn.Read` path escapes recovery | fix: add `defer zdnsutil.HandlePanic("DNSCrypt read")` in both goroutines.

- [MEDIUM/pool] server/upstream/pool/udp.go:283 — readLoop allocates `packet := make([]byte, n)` per response on the pooled-UDP hot path (every plain-UDP and DNSCrypt response) | risk: one heap allocation + copy per query | fix: size-tiered `sync.Pool` of byte slices (like `spoofguardBufPool`), with the TTL-bearing collect mode kept separate.

- [MEDIUM/pool] server/upstream/tls/quic.go:89-97 — 0-RTT retry path: when the re-dialed `fresh` conn's `doQUICQuery` fails again (incl. a second `Err0RTTRejected`), the conn is neither removed nor closed, contradicting the code's own policy "the rejected conn must never re-enter the pool" (comment lines 113-115); the non-retry error path does `Remove(pc)` for ANY error (line 96), but the retry path is inconsistent | risk: an invalidated conn handed out to future queries → repeated failures | fix: after the second failed attempt, `Remove(fresh)` / close the conn.

- [MEDIUM/perf] server/upstream/tls/quic.go:96 — pooled DoQ path removes the QUIC conn on ANY query error, including caller-side `context.Canceled` (resolver first-wins fan-out) — a healthy conn is evicted and must re-handshake on the next query. The DoH path explicitly distinguishes caller-side cancellation (`isCallerSideTimeout`, https.go:89-98) — DoQ lacks the equivalent | risk: pool churn under concurrency → constant redial latency | fix: only `Remove` on connection-level errors, not on ctx cancellation.

- [MEDIUM/lock] server/upstream/pool/udp.go:288-295, 306-320 — collect-mode waiters are never woken when the conn dies: `close()` signals only `resultCh` entries (nil `resultCh` on collect entries is a no-op), `collectCh` is never closed, and the `!ok` branch in `executeUDPCollect` (plain/udp.go:243-249) is unreachable dead code → a collector whose socket is closed (Remove/Shutdown/write error) blocks until `maxDeadline` burns the full query budget | risk: slow failure path, misleading "no UDP response received" error, dead code | fix: have `close()` close each `collectCh` (or send a sentinel) under the write lock.

- [MEDIUM/perf] server/upstream/tls/client.go:30, server/upstream/tlcp/tlcp.go:29 + client.go:84-87 — per-query transport config construction even when the pool serves the query from an existing connection: `ExecuteTLS` builds `eTLSClientConfig(server).Clone()` (new VerifyConnection closure) every call; `ExecuteTLCP` additionally calls `smx509.SystemCertPool()` which returns a Clone of the entire system CA pool per query (gmsm v0.42.0 cert_pool.go:113-119 — cached load, but full Clone per call) | risk: per-query heap allocations + CA-store clone on the DoT/TLCP hot path | fix: construct the config only inside the dial closure (pool hit paths don't need it), or cache per `transportKey`/`tlcpPoolKey`.

- [MEDIUM/perf] server/upstream/plain/udp.go:285 — `time.After(config.DefaultSpoofguardPollInterval)` allocates a fresh timer every collect-loop iteration (the multi-read path uses `SetReadDeadline` — no timer) | risk: per-iteration allocation during every spoofguard collect window | fix: reuse one timer per collect call.

### LOW

- [LOW/legacy-api] server/upstream/tls/https.go:131 — deprecated `net.OpError.Temporary()` (deprecated since Go 1.18) in `shouldRetryHTTP` | fix: check `Timeout()` + `errors.Is(err, syscall.ECONNRESET/ECONNREFUSED)` instead.

- [LOW/validation] server/upstream/socks5/socks5.go:173 — `d.password, _ = u.User.Password()`: uncommented `_` discard (methodology 6.1.11); also `socks5://user@host` (no password) still advertises password auth with an empty password, failing against no-auth proxies | fix: comment the discard; offer password auth only when the password is present, else treat as no-auth.

- [LOW/comment] server/upstream/client.go:312-316 — comment says dialers are "closed by the Range above", but the `Range` is below the comment (lines 317-324).

- [LOW/lock] server/upstream/pool/quic.go:206-220 — `Remove` calls `pc.close()` (`CloseWithError`) while holding `p.mu`, unlike the TCP pool's deliberate close-outside-lock discipline (tcp.go:532-543, 547-563) | risk: low (quic-go CloseWithError is non-blocking), but inconsistent with the pool's own ABBA-avoidance pattern | fix: collect and close after unlock.

- [LOW/error] server/upstream/client.go:234-236 — when both UDP and TCP fallback fail, the original UDP error is dropped (only the TCP error is wrapped) — diagnostic loss on double failure.

- [LOW/context] server/upstream/client.go:148, 212 — TCP fallback re-derives `context.WithTimeout(ctx, c.timeout)` from the caller's ctx, giving the query up to 2×DefaultDNSQueryTimeout (18s) beyond the caller's budget; also `needsTCPFallback` fires on caller-side `ctx.Canceled` (first-wins), wasting a fallback attempt that immediately fails | risk: budget overshoot and noisy Debug logs | fix: skip fallback on `errors.Is(err, context.Canceled)`; cap the combined budget.

- [LOW/validation] server/upstream/tlcp/dtlcp.go:93-95 — no >65535 query-size guard before the `uint16(queryLen)` length prefix (dtls.go:87-89 has the guard; dtlcp's is only a nolint'd G115) — unreachable today (DNS msgs bounded), but inconsistent | fix: add the same guard.

- [LOW/correctness] server/upstream/plain/tcp.go:50 — `SetSegmentation(segSize)` on a shared pooled conn: concurrent queries with different `Splitguard` settings cross-apply segmentation to each other's writes (guarded by writeMu, so no data race — defense degradation only).

- [LOW/ordering] server/upstream/tls/client.go:283, 301 — `WarmUpHTTPS`/`WarmUpHTTP3` use `_ context.Context` for an unused param (interface-consistency across WarmUp* — acceptable, note only).

- [LOW/dead-code] server/upstream/plain/udp.go:243-249 — `collectCh` `!ok` branch is unreachable (see MEDIUM pool/udp.go close-wake finding).

## Package observations

**plain** — The spoofguard state machine is the highest-risk code in the audit: candidate ownership (prev/last/nonEDNS) is split across three functions (`processPacket`, `collectEDNSCandidate`, `executeUDPCollect`'s adoption block, `pickBest`) with only implicit invariants ("fast-return means the loop exits immediately") — this split produced the double-Put (C1). Ownership should be centralized: one function computes the winner + return list, callers never touch the candidate fields. The `n < 12` header gate exists in the multi-read path but not the collect path (H1) — the two loops diverged. HopGuard integration (Validate-before-Feed, TTL confidence fast-accept) is well-reasoned and documented.

**pool** — TCP Conn/ConnPool discipline is strong: capacity semaphore + inFlight, collision-safe tracking IDs, verify-then-deliver under RLock, close-outside-lock in Shutdown/Remove, dead-conn filtering with TOCTOU documented as benign. Weak spots: UDP per-response allocation (M3), collect-mode close signalling (M5), QUIC Remove-holding-lock (L4). `time.After`-free read loops use deadlines correctly.

**socks5** — Correct RFC 1928/1929 framing (RSV/FRAG checks, ATYP bounds, rep codes); per-call fresh relay is an intentional, documented tradeoff (per-query TCP handshake + UDP ASSOCIATE on the proxy path). Pool zeroing (`clear(buf[:nr])`) is applied consistently.

**tls** — DoH/DoH3 transport eviction distinguishes caller-side timeouts from transport failures (good); DoQ does not (M4). 0-RTT rejection handling (token-store reset + conn eviction) is thorough except the retry-path inconsistency (M2). DTLS bufio wrapper correctly papers over pion's small-read rejection; dtlcp needs no wrapper (gotlcp has stream semantics — verified in module source).

**tlcp** — ALPN enforcement at dial time (RFC 7858 §4.1) is a nice touch; HTTP-TLCP guards plaintext/redirect leakage. SystemCertPool-per-query is the main cost (M7). No retry loop on HTTP-TLCP failures (unlike DoH/DoH3) — acceptable divergence, undocumented.

**dnscrypt** — Singleflight cert fetch, TC escalation with minQueryLen doubling, PQ ticket lifetime capping, and per-query sharedKey capture under the lock are all correct. The Close-nil cache panic (C2) and missing HandlePanic in the two read goroutines (M1) are the gaps. `deleteState` on any decrypt/ID failure is a documented thrash risk (valid cert + one bad datagram → refetch).

**upstream (root)** — `Result`/`ExecuteQuery` handles pool-buffer lifetimes correctly (`resp.Data = nil` before Put on every fallback path); proxy dialer LRU has OnEvict Close (methodology 6.2.20 compliant); warm-up goroutines have HandlePanic + WaitGroup owner. Hot-path logging is uniformly Debug with per-query dedup gates (sync.Map) for Warns — compliant with §6.1.6/6.1.8.

**Systemic patterns** — (1) Candidate/connection ownership across function boundaries is the recurring root cause (C1, M2, M5) — explicit ownership comments or a small state struct would harden all three. (2) Per-query config construction (M7) recurs in tls+tlcp — hoist to dial time. (3) The ctx-budget overshoot on fallback paths (L6) recurs in plain TCP fallback and DNSCrypt TCP fallback — deliberate but should be capped. (4) All sentinel-free pool errors are string-formatted `fmt.Errorf("client: ...")` — callers only test `err != nil`, so `errors.Is` never breaks; consistent by design.
