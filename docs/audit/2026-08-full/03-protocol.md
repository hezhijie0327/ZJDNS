# 03-protocol.md — server/protocol/*

Phase 1 package audit of the four protocol listener packages. Method: every
non-test file read in full; every `pool.Get()`/`Put()` pair traced on all code
paths against the TLS DoT template (AUDIT-METHODOLOGY §2.3); library behavior
verified in the Go module cache (pion/dtls v3.1.3, gotlcp, circl ed25519 v1.6.5,
quic-go) before classifying severity.

## Inventory

| Package | Files | Lines | Listener(s) |
|---------|-------|-------|-------------|
| `server/protocol/plain` | server.go, tcp.go, udp.go | 165 | Plain DNS UDP/TCP (miekg `dns.Server`) |
| `server/protocol/tls` | addr_validator.go, certs.go, dtls.go, http3.go, https.go, quic.go, server.go, tls.go | 1831 | DoT, DoQ, DoH, DoH3, DTLS |
| `server/protocol/tlcp` | certs.go, dtlcp.go, http_tlcp.go, server.go, tlcp.go | 1028 | TLCP DoT/DoH, DTLCP |
| `server/protocol/dnscrypt` | crypto.go, generate.go, persist.go, server.go, tcp.go, udp.go | 1952 | DNSCrypt v2 UDP/TCP |

## Findings

### CRITICAL

None.

### HIGH

- [HIGH/memory] tls/dtls.go:138-140 — `io.ErrShortBuffer` is handled with `continue`, but pion does NOT consume the oversized record (verified: pion/dtls v3.1.3 `internal/net/buffer.go` returns `io.ErrShortBuffer` before advancing the read pointer), and each iteration re-arms the 30s read deadline, so one >8192-byte DTLS record from a handshaked client spins `conn.Read` at 100% CPU on one core forever — only peer close or server shutdown exits | risk: CPU-exhaustion DoS — every authenticated DTLS client can pin a core indefinitely with a single jumbo record; the DTLS/DTLCP fixed-buffer pattern the methodology warns about | fix: on `io.ErrShortBuffer`, return (close the connection) or drain/consume the record; never `continue`.
- [HIGH/lock] tlcp/dtlcp.go:211-229 — `s.serverGroup.Go(...)` is called while holding `l.mu`: when the errgroup limit (1024) is saturated, Go blocks indefinitely, freezing datagram dispatch for ALL DTLCP clients and blocking `dtlcpListener.Close()` (Shutdown) on `l.mu` until a slot frees; recovery relies on the 30s read/handshake deadlines, so shutdown can stall ~30s and the listener can stop serving entirely under load | risk: listener freeze + shutdown stall under >1024 concurrent DTLCP connections | fix: release `l.mu` before `serverGroup.Go` (spawn-duplicate guard via a flag set under the lock), or bound admission like the QUIC semaphore.
- [HIGH/validation] dnscrypt/server.go:90-103 — the configured Ed25519 identity key length is never validated: circl `ed25519.Sign` panics on `len(key) != PrivateKeySize` (verified circl v1.6.5 ed25519.go:290), and `Public()` silently returns a truncated/zero public key for short inputs (ed25519.go:111-114) — so a valid-hex but wrong-length `certificate.dnscrypt.private_key` either panics the whole process in `New()` → `NewCertPair()` → `Sign()` (startup crash) or mints certs under a wrong identity (all clients fail) | risk: crash on misconfiguration; silent identity corruption | fix: validate `len(skBytes) == ed25519.PrivateKeySize` in `New` and return a descriptive error.

### MEDIUM

- [MEDIUM/resource] tls/tls.go:165-189 + tlcp/tlcp.go:99-109 — established DoT/TLCP connections are never woken on Shutdown: the read loop blocks in `io.ReadFull` with a 60s idle deadline refreshed only on success, so `serverGroup.Wait()` in Shutdown blocks up to 60s per active connection (DNSCrypt explicitly wakes conns with `SetReadDeadline(time.Unix(1,0))` in server.go:391-393; DoQ closes conns; DTLS/pion and DTLCP close their sockets/queues — DoT alone relies on the deadline) | risk: graceful shutdown latency up to the 60s idle timeout under load | fix: close active conns in Shutdown, or bound the wait with a context-derived deadline.
- [MEDIUM/rfc] tlcp/certs.go:61-72 — leaf `NotAfter = time.Now().Add(DefaultServerCertValidity)` is evaluated after the CA's `time.Now()`, so the leaf expires microseconds AFTER its CA; `tls/certs.go` fixed exactly this with the `leafNotAfter` clamp (tls/certs.go:73,109-115) — TLCP did not | risk: strict RFC 5280 validators reject a chain whose leaf outlives its signer; cross-package inconsistency | fix: port the clamp.
- [MEDIUM/protocol] tlcp/dtlcp.go:178 — the shared-socket dispatcher reads with a fixed 1232-byte buffer (`pool.UDPBufferSize`): any inbound DTLCP record > 1232 bytes is truncated at the socket read (the datagram is destroyed), silently capping DTLCP queries at 1232 while DTLS reads with 8192 and RFC 8094 framing allows 65535 | risk: large legitimate DTLCP queries (>1232B, e.g. EDNS-heavy or padded) are silently mangled | fix: use `pool.SecureBufferSize` (or read length-aware) in the dispatcher.
- [MEDIUM/memory] tlcp/dtlcp.go:65-95 — `demuxPacketConn.ReadFrom` does `return copy(p, pkt.data), pkt.addr, nil` with no `len(p) < len(pkt.data)` check: an oversized record is silently truncated instead of surfacing `io.ErrShortBuffer` like pion — the DTLCP parser then sees corrupt data and closes the connection, making >8192-byte records indistinguishable from network corruption | risk: silent data corruption of large records; connection churn | fix: return `io.ErrShortBuffer` when `len(p) < len(pkt.data)`.
- [MEDIUM/rfc] tlcp/http_tlcp.go:92-96 — POST with a wrong Content-Type returns 400; RFC 8484 §4.2.1 requires 415 for a non-`application/dns-message` POST, which the TLS DoH handler implements (tls/https.go:162-167) | risk: spec deviation, client confusion; cross-protocol inconsistency | fix: mirror the 415 branch.
- [MEDIUM/lock] dnscrypt/server.go:207-231 vs 458-492 — `ResetKeys()` (CHAOS handler) and `updateKeys()` (renewal ticker) can run concurrently: both snapshot `s.keys[0]` as `previous` and both mint windows for the same `tsStart`, appending duplicate key windows (same serial/timestamps); decrypt tries each so the damage is benign, but the behavior is nondeterministic and duplicates grow `s.keys` | risk: duplicate windows, unpredictable rotation state | fix: serialize window minting (single `keyMu` covering snapshot→derive→append).

### LOW

- [LOW/pool] tls/quic.go:282-290 — the identity-response guard (`response == req`) never returns the message to the pool in that branch; currently unreachable (the handler always returns a fresh pooled message via `BuildResponseMsg`), but any future handler returning the request pointer leaks one pooled message per query | risk: latent pool leak | fix: single unconditional `Put` with a `!=` check, i.e. `if response != req { Put(response) }; Put(req)`.
- [LOW/log] tlcp/dtlcp.go:262-263 — handshake log starts with `TLS:` for a DTLCP event; CLAUDE.md maps `DTLCP:` → `TLCP:` | risk: prefix discipline violation, log filtering misses the component | fix: use `TLCP:`.
- [LOW/design] tls/quic.go:114-127 + tls/http3.go:95-112 — DoQ/DoH3 conn admission (quicConnSem) and their handler goroutines share the single serverGroup limit (1024) with the DoT/DTLS/DoH accept loops (which are themselves group members): a QUIC connection flood (30s keep-alive) can starve the other TLS-family listeners of slots | risk: cross-protocol starvation under QUIC load | fix: per-listener goroutine budgets.
- [LOW/style] tls/server.go:169 — `serverGroup, _ := errgroup.WithContext(ctx)` discards the derived context without a reason comment (methodology §6.1.11); behaviour is correct because `s.ctx` is used everywhere, but the derived-context error-cancellation semantics are silently unused | fix: comment the discard or use `serverCtx`.

## Package observations

**plain** — Clean. Framing, pooling and deadlines are all delegated to miekg's `dns.Server` (RFC 7766 §6.2.3 `ReadTimeout=120s`, RFC 6891 `UDPSize=1232`). Accept loops check `ctx.Done()` and `Shutdown` closes servers under the caller's ctx. No findings.

**tls** — Pool discipline is exemplary (the §2.3 template): every `Get()` has a `Put()` on every path including panics (`tls.go` worker defers + `writeCh` drain; `quic.go` req/response split; `dtls.go` sequential loop Puts; `https.go` deferred response Put). The only pool deviation is the unreachable identity guard (LOW). Real defects: the DTLS `ErrShortBuffer` busy-spin (HIGH, confirmed against pion source) and the DoT shutdown-wake gap (MEDIUM). `dtls.go` conn goroutines are bounded only by the group limit (no admission sem like DoQ) — see the shared-limit starvation note. Shutdown snapshots slices under `listenerMu` and closes outside the lock — correct per §6.1.2.

**tlcp** — Pool discipline matches the TLS template (`tlcp.go` `sendDOTResponse` defer-Put; `dtlcp.go` sequential loop Puts + deferred response Put). The DTLCP demux layer (`dtlcpListener`/`demuxPacketConn`) is the weak spot: blocking `serverGroup.Go` under `l.mu` (HIGH), silent `copy` truncation (MEDIUM), 1232-byte dispatcher buffer (MEDIUM), and no `leafNotAfter` clamp in `certs.go` (MEDIUM). On shutdown DTLCP conns unblock promptly (queues closed by `Close()`), but DoT conns do not (MEDIUM, shared with tls). `http_tlcp.go` drops the RFC 8484 415 distinction (MEDIUM).

**dnscrypt** — Pool discipline is sound and careful: the UDP buffer-ownership transfer (`udp.go:102-103`) with worker-side `Put`, the `handleHandshake` nil-guarded message defer, and the `res` copy-before-Put (server.go:671-677) are all correct; the per-`wg` swap under `s.mu` (Add under the same lock as Shutdown's swap) is a textbook fix for Add-during-Wait. `encrypt`/`Normalize`/`Encrypt` interplay is consistent (budget enforced in both layers; `PadResponseWithin` keeps UDP within the §10.3 budget). Main gaps: identity-key length validation → startup panic (HIGH) and the benign `updateKeys`/`ResetKeys` duplicate-window race (MEDIUM). Decrypt key/cache snapshots under RLock match `rotateKeys`'s write-lock discipline.

**Cross-protocol systemic patterns** (methodology §6.1: one protocol bug → grep all handlers):

1. **Fixed-buffer read paths diverge exactly as warned**: DTLS reads 8192 and *spins* on `ErrShortBuffer` (pion keeps the record); DTLCP reads 8192 at the conn but *silently truncates* in `ReadFrom`; DTLCP dispatcher reads only 1232 (truncating any larger datagram); DoT (`tls.go`) and DoQ (`quic.go`) handle >8192 correctly via heap fallback. Fixing one of these without the other two leaves the class open.
2. **Shutdown unblocking is inconsistent**: DNSCrypt wakes TCP conns explicitly; DoQ closes conns; DTLCP/DTLS close sockets/queues; DoT (tls + tlcp) rely on read deadlines → up to 60s Shutdown latency.
3. **Pool discipline is uniform and correct** — no leak, no double-Put, no use-after-Put found on any traced path (identity guard in `quic.go` is the single deviation, currently unreachable).
4. **Cross-package clamps differ**: `tls/certs.go` clamps leaf NotAfter to the CA; `tlcp/certs.go` does not.
5. **Error wrap policy is consistent** (`%w` everywhere; discarded errors are annotated or innocuous), context propagation is correct (no `WithoutCancel` misuse; per-conn cancellation derived from `s.ctx`), Close idempotency is guarded (`dtlcpListener.closed` atomic, DNSCrypt `started` under mutex, demux `closed` CAS), and handshake/accept loops all carry `HandlePanic`.
