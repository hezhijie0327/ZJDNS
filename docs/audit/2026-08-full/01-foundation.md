# 01-foundation.md — internal/* 基础包审计

Audit date: 2026-08-08 · Phase 1 package audit · Method: docs/AUDIT-METHODOLOGY.md §1.1 (18 dimensions)

## Package inventory

| Package | Files (non-test) | Lines |
|---------|-----------------|-------|
| internal/dns64 | dns64.go | 122 |
| internal/dnscryptcrypto | certificate.go, dns.go, encrypted.go, encryption.go, keys.go, pq.go, proto.go, string.go, xsecretbox.go | 2,093 |
| internal/dnsutil | bind.go, clientip.go, dnsutil.go, download.go, https_dns.go, keepalive.go, tcpframe.go, wire.go | 849 |
| internal/doq | doq.go | 32 |
| internal/ipdetect | ipdetect.go | 186 |
| internal/ipttl | ipttl.go | 84 |
| internal/latency | httppool.go, prober.go, probes.go | 582 |
| internal/log | log.go | 384 |
| internal/lrumap | dtls_session.go, lru.go | 276 |
| internal/pending | pending.go | 285 |
| internal/pool | pool.go | 131 |
| internal/siphash | siphash.go | 194 |
| internal/stamp | encode.go, parse.go, stamp.go | 808 |
| internal/ttl | ttl.go | 96 |
| **Total** | 28 files | **6,122** |

## Findings

### HIGH

- [HIGH/lock] internal/pending/pending.go:246 — `CallGroup.Join` timeout branch reads `existing.Err` without synchronization while the leader (`Done`, line 269, write inside `entry.Once.Do`) or the LRU eviction callback (line 217) concurrently writes it — there is no happens-before edge between the `once.Do` write and this read | risk: data race (torn/indeterminate error value reported to followers); `go test -race` on a follower-timeout + leader-finish interleaving fails; follower may surface a leader error that was never completed or a nil | fix: in the timeout branch, don't read `existing.Err` (return `ErrTimeout` alone), or synchronize via `existing.Once.Do(func(){})` before reading (Once establishes happens-before), or store Err in a separate atomic value.

### MEDIUM

- [MEDIUM/log] internal/dnsutil/dnsutil.go:215 — `LogHandshake` hardcodes `log.Debugf("TLS: %s", buf.String())` while `buf` already starts with `info.Role + ": "` — output is duplicated ("TLS: TLS: QUIC handshake ...") for TLS, and TLCP/DTLCP/UPSTREAM handshakes are misattributed to the TLS component | risk: violates the 27-canonical-prefix convention (CLAUDE.md: DTLCP: → TLCP:); `debug:TLCP` component filtering silently drops TLCP/DTLCP handshake logs; log noise | fix: `log.Debugf("%s", buf.String())` — the Role prefix is already in the buffer and is a canonical prefix.
- [MEDIUM/dead-code] internal/dns64/dns64.go:85 — `Synthesize` is a standalone exported method (not an interface impl; called directly at server/handler/middleware/dns64.go:85) with 3 of 7 parameters discarded (`_` origAnswer, `_` origAdditional, `_ bool`) | risk: dead API surface; callers cannot tell which arguments are consumed; per methodology §6.1 #12, `_` params on standalone functions are dead code that must be removed | fix: trim signature to `(origAuthority, aAnswer, aAuthority, aAdditional []dns.RR)` and update the single call site (the discarded bool is correctly dropped — synthesized AAAA must not carry the AD flag, RFC 6147).
- [MEDIUM/memory] internal/lrumap/lru.go:136,166 — `Delete`/`CompareAndDelete` never invoke `OnEvict`, while `Set`-overwrite (lru.go:88) and capacity eviction (lru.go:229) do — resource-holding values (the documented use case: "dialers, clients, sessions") explicitly deleted bypass the release callback | risk: resource leak (fd/QUIC conn/channel) for any future caller that Deletes a resource-holding key; contract inconsistency today (verified: current callers — DTLSSessionStore.Del is data-only, pending's CompareAndDelete runs after the leader closed the channel itself — are safe) | fix: invoke `OnEvict` in `Delete` and `CompareAndDelete` on the removed entry, and document that explicit removal also routes through the callback.

### LOW

- [LOW/panic] internal/ipttl/ipttl.go:76 — `Capture.ReadFrom` with a zero-value `Capture` (both `pc4` and `pc6` nil) takes the else branch and calls `c.pc6.ReadFrom` on a nil `*ipv6.PacketConn` → panic | risk: nil-deref crash if a caller ever uses a non-`New`-constructed Capture; `New` can't produce this today | fix: `if c.pc6 != nil { ... } else { return 0, 0, errors.New("ipttl: no packet connection") }`.
- [LOW/comment] internal/dnscryptcrypto/xsecretbox.go:114 — comment says key/nonce sizes are "validated by panic checks above" but the checks return errors, they do not panic | risk: misleading comment | fix: "validated by the error checks above".
- [LOW/comment] internal/dnscryptcrypto/encrypted.go:310 — comment garbled: "otherwise the packet lacks the prefix the packet has no control prefix and the DNS payload starts at offset 0" (duplicated clause) | risk: unreadable rationale for the no-strip branch | fix: rewrite sentence.
- [LOW/comment] internal/log/log.go:208 — comment claims "all 23 canonical prefixes" but CLAUDE.md documents 27 | risk: stale count; new prefixes added since the comment was written are not reflected | fix: "all 27 canonical prefixes" or drop the number.
- [LOW/constants] internal/ttl/ttl.go:32 — `return 30` inline magic number for the RFC 8767 §4 stale TTL fallback | risk: un-named constant; diverges from config if the default ever changes | fix: named const (e.g. `defaultStaleTTL = 30`) with RFC reference.
- [LOW/validation] internal/siphash/siphash.go:11 — `Sum64` silently returns 0 (a valid-looking MAC) on nil key | risk: masked caller bug; a nil key produces a quiet wrong hash instead of a panic/error | fix: document the contract or let it panic on nil (caller edns/cookie.go:242 always passes non-nil).
- [LOW/constants] internal/stamp/stamp.go:117,129,138,146,156,164,176,184 — per-protocol minimum-length literals (11/44/15/13/12/2) in `Parse` are partially commented but not named constants | risk: a future format tweak can silently desync the guards from the parsers | fix: named consts with the field arithmetic in the name (or compute from the existing size consts).
- [LOW/memory] internal/ipdetect/ipdetect.go:147 — `io.ReadAll` unbounded on the HTTP trace body; `TraceURL` is user-configurable | risk: a misconfigured/hostile endpoint returns gigabytes and the startup detect path buffers it all | fix: `io.LimitReader(resp.Body, 4<<10)` — trace payloads are <1KB.
- [LOW/ordering] internal/lrumap/lru.go:41 — `SetOnEvict` method sits between `type Map` and `func New`, so `New` is not the first func after the type (methodology §6.1 #16) | risk: ordering convention violation only | fix: move `SetOnEvict` below `New`.
- [LOW/dead-code] internal/pool/pool.go:59-66 — `Message.Get`'s `v == nil` and type-assertion fallbacks are unreachable (`New` always returns `*dns.Msg{}`) | risk: dead defensive branches that hide a real invariant | fix: keep only the assertion or drop the fallback.
- [LOW/redundant-pair] internal/dnsutil/wire.go:38,47 — `Decompress`/`DecompressTo` are a classic Foo/FooWithX pair differing only in the dst-reuse parameter (methodology §4.2 #19) | risk: API surface split for one optional behavior | fix: single `Decompress(data, dst []byte)` with nil-dst semantics.
- [LOW/redundant-pair] internal/dnscryptcrypto/encryption.go:62,78 — `PadResponse`/`PadResponseWithin` share ~90% logic, the only difference is clamping to maxLen (and With returns an error) | risk: two functions drift apart; the non-With variant is only used on TCP paths | fix: single `PadResponse(packet, key, nonce, maxLen int)` returning `([]byte, error)`; TCP callers pass `0` = unbounded (needs care: the clamp expression must be conditional).
- [LOW/error-handling] internal/dnscryptcrypto/certificate.go:291 — `Validate()` returns `ErrESVersion` for a wrong-length PQ public key while `marshalPQ` (certificate.go:188) returns a descriptive `fmt.Errorf` for the same condition — inconsistent sentinel policy within one package | risk: callers distinguishing "unsupported es-version" from "broken PQ key" get a misleading sentinel | fix: return a dedicated error (e.g. `ErrPQKeyLength`) in both places.
- [LOW/validation] internal/stamp/encode.go:19-30 — `String()` returns `"sdns://error:field-exceeds-255-bytes"` sentinel strings instead of an error (fmt.Stringer constraint) | risk: a caller that encodes then re-parses gets `ErrNotAStamp`; failure is silent at the call site | fix: keep as-is (documented) or expose a `MarshalStamp() (string, error)` for the CLI path.
- [LOW/performance] internal/dnscryptcrypto/encrypted.go:117-118 — `Encrypt` (response path) appends `ResolverMagic[:]` + `Nonce[:]` with zero preallocation | risk: 1-2 reallocations per encrypted response on the hot DNSCrypt path | fix: `response := make([]byte, 0, ResolverMagicSize+NonceSize)` before appends.

## Package observations

### Strengths

- **dnscryptcrypto** is uniformly excellent on wire-format safety: every slice index is guarded by a minimum-length check or exact-size validation before use (UnmarshalBinary, ParsePQResumedHeader, PQParseControlBlock, ReadPrefixed); no panic path found on adversarial input. Nonce-reuse protections (client nonce half verification on Decrypt, forced re-derivation of the classical shared key at encrypted.go:485-493) and the X-Wing length pre-guards (pq.go:145,156) show deliberate security engineering. Constant offsets (certificate.go const block) are derived arithmetically with verified values.
- **Go 1.26 feature adoption is exemplary**: `errors.AsType` (dnsutil.go:225), `slices.Backward` (encryption.go:133), `slices.Clone` (tcpframe.go:48), `for range workers` (prober.go:118), `min`/`max` builtins throughout — no hand-written replacements found; `go fix` modernizers appear already applied.
- **Pool discipline**: tcpframe.go ReadTCPMsg clones `msg.Data` out of the pooled buffer before deferred Put (tcpframe.go:48 — the documented pool buffer use-after-free pattern handled correctly); dnscrypt protocol handlers pair Get/Put via a single deferred Put (verified at server/protocol/dnscrypt/udp.go:67-70); pool.Buffer discards grown slices to preserve the size invariant.
- **lrumap consumers are correctly wired**: all resource-holding values (socks5.Dialer, *http.Client for DoH/DoH3/TLCP) set OnEvict/CloseIdleConnections; pending's resultCall/callEntry eviction closes the done channel via sync.Once (no double-close); quicConfigs/serverState/addrCache are pure data. No un-released lrumap resource found.
- **Logging hot-path discipline holds**: no info/warn on per-query paths in scope; log.go's level check precedes Sprintf and a fast static-prefix filter rejects filtered-out calls before formatting; handlePanic-style 8KB stack buffer allocated only on panic (dnsutil.go:76-81).
- **Context propagation**: no `context.TODO()` anywhere in production code in scope; the three `context.Background()` sites are legitimate (nil-guard fallbacks and startup-only ipdetect).
- **Error wrapping**: no `%v`-style error truncation found; `%w` chains intact; `_ = error` discards all carry inline reason comments (per §6.1 #11).
- **RFC consistency**: every referenced RFC (1035, 2181, 6052, 6147, 6891, 7766, 7873, 8484, 8767, 9000, 9250) is archived in docs/rfc/; DNS64 prefix layouts verified against RFC 6052 Figure 1 (all six lengths correct); 1232-byte UDP buffer and RFC 8767 30s stale-TTL values are RFC-conformant.

### Systemic patterns

- **Stale constant/count in comments** (log.go "23 prefixes" vs 27) — grep doc comments for numbers when the canonical lists change.
- **Delete-vs-evict callback asymmetry in lrumap** (F4) is the one contract gap in an otherwise tight resource-lifecycle story.
- **stamp min-length literals and String() error-sentinel strings** are pragmatic given the fmt.Stringer constraint but should be documented on the type.
- **Accepted deviations worth noting**: stamp's Default* ports duplicate config/defaults.go values (documented layering exception — internal/ cannot import config/); log.TimeCache uses an inline recover instead of dnsutil.HandlePanic (correct — dnsutil imports log, the cycle is impossible); latency's InsecureSkipVerify probe clients are deliberate (documented nolint).

### Cross-package notes (Phase 2 leads)

- The F1 race (pending.CallGroup) is exercised from server/handler/pending.go's `Join` — the DNS pending-request path; the CrossCut Locks audit should add a `-race` test for follower-timeout-vs-leader-done interleaving.
- `LogHandshake` prefix bug (F2) affects server/protocol/{tls,tlcp} and server/upstream/{tls,tlcp} callers — grep for "TLS: %s" patterns in other shared log helpers during the CrossCut Logging pass.
- pool.DefaultMessage/DefaultBuffer pairing in server/protocol/* is the Protocol audit's scope; spot checks here passed.
- DNS64 `Synthesize` signature trim (F3) requires a one-line update at server/handler/middleware/dns64.go:85 — coordinate with the Handler audit.
