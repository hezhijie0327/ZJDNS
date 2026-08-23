# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## Storage

ZJDNS is in-memory with an optional disk spill tier — there is no database.
The cache, stats, zone rules, ruleset, latency and delegation data live in
memory (lrumap for LRU maps for cache/latency/delegations, atomic.Pointer
snapshots for zone/ruleset rules, atomic counters for stats). The disk
tier is opt-in via `state_file`: when set, each store (cache entries,
latency, delegation) gets a second-tier **spill store** (`internal/spillfile`
— an append-only log of evicted-but-fresh records with an in-memory index).
Evictions land on disk, memory misses promote disk records back, shutdown
flushes the in-memory tiers, and a 5-min ticker compacts the file (dropping
expired and over-cap records, temp+rename atomic rewrite). The disk cap is
`limit.disk` (in entries; ≤0 = unbounded); `limit.mem` bounds the hot tier
(≤0 applies the store default). On startup the hottest `limit.mem` records
are loaded into memory, the rest stay on disk. The DNSCrypt state file
(`dnscryptstate`) is a separate ~300-byte blob holding the provider identity

- cert windows so restarts resume the same certificates. All `state_file`
  keys are empty by default — persistence disabled, no file created, cold
  start per restart. Stats are never persisted (reset on restart).

### In-memory data

| Data                            | Structure                                                                                                                                                                                                                                                                  | Lifetime                                                                                                                             |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| DNS cache entries               | `lrumap.Map[string, *cacheEntry]` — key = (qname, qtype, qclass, ecs) flattened, value = pre-packed wire (format 0x02) + ts/ttl. The key never splits on the client's DO bit — outbound queries always carry DO=1 (RFC 6840 §5.9) and DO=0 filtering happens at serve time | LRU-bounded (limit.mem), TTL-expired lazily on read; spill tier when `state_file` set (evict → disk, miss → promote, shutdown flush) |
| Query stats + per-RCODE journal | `statsjournal` (atomic counters + `topk.Map`)                                                                                                                                                                                                                              | Resets on restart                                                                                                                    |
| Zone rules                      | `zoneTable` atomic.Pointer snapshot (exact/wildcard maps, compressed RR blobs)                                                                                                                                                                                             | Rebuilt from config at startup                                                                                                       |
| Ruleset rules                   | `ruleTable` atomic.Pointer snapshot (IP trie + domain suffix map)                                                                                                                                                                                                          | Rebuilt from config at startup                                                                                                       |
| IP latency                      | `lrumap.Map[string, latEntry]`                                                                                                                                                                                                                                             | LRU-bounded, lazy expiry + periodic cleanup                                                                                          |
| Delegations                     | `lrumap.Map[string, *delegationEntry]`                                                                                                                                                                                                                                     | LRU-bounded, lazy TTL expiry + periodic cleanup                                                                                      |
| DNSCrypt state                  | `dnscryptstate.FileStore` — ~300B blob: identity (96B) + cert windows                                                                                                                                                                                                      | Persisted across restarts                                                                                                            |

The cache entry value is the pre-packed response (format 0x02: [0x02][2:num TTL offsets][2 each:offset][wire], zstd-compressed above the threshold). The
wire carries the full response header — including the RCODE (e.g. NXDOMAIN) —
so cache hits serve the exact rcode.

### Key Patterns

- **Cache hit path**: pre-packed wire (format 0x02: TTL-offset table + packed
  response). `Get()` serves the wire directly — the Response middleware
  patches the message ID/RD bits and bridge.go writes it without any
  Unpack/Pack round-trip (~14.4ns at the middleware layer, 0 allocs). TTL
  deduction happens in-place via the offset table; DNSSEC filtering for
  DO=0 clients uses a wire scan (WireHasDNSSEC) — entries store whatever the
  DO=1 upstream returned, so one entry serves both DO variants. Entries
  below the compression threshold are stored uncompressed (no decompress
  either).
- **RecordRequest**: All results → in-memory atomic counters (`cache/statsjournal.go`); non-hit events also enter a per-RCODE top-N domain journal (`topk.Map`, bounded). No SQL, no disk — pure memory, reset on restart.
- **Stats aggregation**: `Stats()` reads the in-memory snapshot — O(1) counters + per-RCODE top-N sort. Output keeps the previous TXT layout plus `top-rcode<N>` lines.
- **Pruning**: `PruneQueryJournal` is a no-op — the journal is bounded in memory, nothing to prune.
- **Eviction**: Pure LRU — on `Set()` when count > maxEntries the least-recently-used entry is evicted (`lrumap`). With a spill tier the evicted entry (still fresh) is appended to the spill log; a memory miss reads the record back and promotes it. Latency and delegation entries expire lazily on read (past the stale window / TTL); periodic cleanup and spill compaction run only when their `state_file` is configured (5-min state-maintenance ticker).
- **NS latency cache**: NS/Root addresses as TypeA/TypeAAAA entries. Latency probed via `ProbeNSAddrs`, reordered by `sortAnswerByLatency` at `Get()` time.
- **Delegation cache**: Zone-cut delegations (zone to NS names + verified DS) in memory (LRU-bounded, lazy TTL expiry + periodic cleanup). Populated at every delegation crossing during recursive walks; only secure (verified DS) or insecure (authenticated no-DS) delegations are stored. On subsequent queries, a suffix-walk from the deepest ancestor finds the first fresh delegation and starts the walk from that zone instead of the root, skipping already-walked delegation levels. DNSKEYs are fetched fresh by `ensureZoneDNSKEYs` (verified against the cached DS); NS addresses are resolved from the existing TypeA/TypeAAAA cache with the stored address snapshot as a fallback.
- **Fan-out address family**: `server.features.address_family` (`"dual"` default / `"ipv4"` / `"ipv6"`) restricts the recursive fan-out batches (root hints, NS resolutions, TLD probe) to the configured family — explicit operator choice, no runtime reachability probing. Dynamically discovered addresses only; explicitly configured forwarding upstreams are untouched.
- **On-demand DNSSEC chain**: the chain build (parent DNSKEY fetch + DS/no-DS verification) runs only from the DS signal — a delegation WITH DS (a signed zone) builds the full chain as before; without DS the delegation is marked insecure outright when `dnssec_enforce` is off, skipping the DS + DNSKEY queries per unsigned level (most CN domains are unsigned). Enforcement keeps the full no-DS verification for bogus classification.
- **IP latency**: Per-IP keyed, in memory (LRU-bounded `lrumap.Map[string, latEntry]`). Background probes write latency + probe time; cache hits read it to reorder A/AAAA answers fastest-first. All domains sharing a CDN IP reuse the same entry. Entries expire lazily past the stale window.
- **Dynamic queries**: `Store.Stats()` returns TXT records (overview, hits, errors, rcodes, poisoned, plain, encrypted, DNSCrypt, TLCP, DNSSEC). Write: `zjdns.cache.clear` / `zjdns.stats.clear` / `zjdns.latency.clear` / `zjdns.querylog.clear` / `zjdns.dnscrypt.clear` (loopback-only).

## Connection Pools

All outbound protocols multiplex over pooled connections
(`server/upstream/pool/`), with a unified three-tier bound per pool instance.

| Pool       | Transport                              | Routing key                                       | Used by                           |
| ---------- | -------------------------------------- | ------------------------------------------------- | --------------------------------- |
| `UDPPool`  | UDP datagrams                          | plain: 2-byte message ID; DNSCrypt: nonce prefix  | plain UDP, DNSCrypt UDP           |
| `ConnPool` | TCP/DoT/DTLS/TLCP/DTLCP streams        | DNS message ID (rewritten + question re-check)    | plain TCP, DoT, DTLS, TLCP, DTLCP |
| `RawPool`  | length-prefixed frames, no DNS parsing | DNSCrypt nonce prefix / plain ID (dual extractor) | DNSCrypt TCP + cert fetch         |
| `QUIC`     | QUIC connections                       | none (streams multiplex internally)               | DoQ                               |

**Unified bounds** (per pool instance):

- per-key `maxConns=4`, per-conn `maxPipe=16`, **global `maxTotal=32`**
  (`DefaultMaxPoolTotalConns`)
- Global-cap enforcement: `dialAndAdd` evicts via `evictOne` — dead conns
  first, then idle-LRU, then any-LRU (`lastUsed` timestamp, zero-alloc
  `log.NowUnix()`); closes run outside the lock (ABBA convention)
- Idle recycling: UDP 30s, TCP-family 60s; dead conns pruned lazily on
  Acquire, plus periodic `ReapDead` for UDP
- Server-side concurrency caps derive from `DefaultServerGoroutineLimit`
  (256): TLS/TLCP serverGroup, plain-TCP/DoH LimitListener, DNSCrypt
  workerCap; QUIC connection admission at half (128)

**SOCKS5 proxy support**: all 12 client protocols pool proxied connections —
the pool key is `addr|proxy`, the dialFunc establishes the SOCKS5
ASSOCIATE/TCP relay, so the handshake is paid once per socket. Certificate
fetches pool through the proxy too. Raw per-query dials remain only as
pool-unavailable fallbacks. DoH/DoH3/HTTP-TLCP proxy via per-key transport
caches.

**Defense over SOCKS5**: spoofguard/splitguard/poisonguard are fully
transport-agnostic; hopguard degrades (SOCKS5 relays carry no IP TTL
metadata — `Capture()` is nil, a warning is logged, and spoofguard takes
over content filtering when enabled). Recursive mode routes the whole
authority chain through a proxy when `protocol: recursive` upstream sets
`proxy` (`recursiveProxyURL`, `server/resolver/resolver.go`).

**Known bugs fixed in this area** (`server/upstream/socks5/`):

- `socks5PacketConn.ReadFrom` returned a `srcAddr.IP` aliasing the pooled
  read buffer (zeroed by the deferred clear) — the source came back as
  0.0.0.0 and broke source-address validation in gotlcp DTLCP handshakes.
  The IP is copied before return.
- Read timeouts were wrapped in `fmt.Errorf`, breaking the `net.Error`
  identity that gotlcp type-asserts to decide retransmission. `net.Error`
  values now pass through unwrapped.

## Defense Mechanisms

ZJDNS implements five per-upstream defense mechanisms to detect and reject
DNS pollution attacks. Each is enabled via `UpstreamServer` flags and works
for both forwarding and recursive modes (the recursive resolver propagates
the flags of its `protocol: "recursive"` upstream).

| Mechanism       | Layer                  | Algorithm                                                                                                                                                                                                                                                                   |
| --------------- | ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Hopguard**    | UDP upstream           | IP TTL fingerprint: auto-learn baseline, reject responses with TTL outside ±2 range                                                                                                                                                                                         |
| **Spoofguard**  | UDP upstream           | Multi-read loop (adaptive window: 150ms single packet, 500ms multi-packet; identical repeats confirm immediately): fast-accept `AN>=2`/`NS>0`/`AD=1`; EDNS responses are candidates (richness tie-break); bare single-answer A/AAAA → collect, re-query-confirm (≤3 rounds) |
| **Poisonguard** | Recursive              | Zone-authority cross-validation on resolved answers                                                                                                                                                                                                                         |
| **Splitguard**  | TCP upstream           | Random [1,4]-byte payload segmentation (no time jitter)                                                                                                                                                                                                                     |
| **CapsGuard**   | All upstream protocols | Randomize the case bit of every ASCII letter in the outbound question (one bit of transaction entropy per letter, DNS 0x20); discard responses that do not echo the randomized case and retry once unrandomized                                                             |

**Implementation locations:**

- `server/defense/hopguard.go` — HopGuard TTL learning + validation
- `server/defense/poisonguard.go` — PoisonGuard zone classification
- `server/defense/capsguard.go` — `RandomizeCase` (0x20 question randomization)
- `server/upstream/plain/udp.go` — SpoofGuard multi-read loop
- `server/upstream/plain/tcp.go` — SplitGuard segmentation parameter
- `server/upstream/pool/tcp.go` — SplitGuard via `WriteTCPMsgSegmented`
- `server/upstream/client.go` — `ExecuteQuery` CapsGuard randomization, echo verification, unrandomized retry

### CapsGuard

When enabled per-upstream (`capsguard: true`), every outbound query is sent
with the case bit of each ASCII letter in the question name flipped randomly
(draft-vixie-dnsext-dns0x20-00 §5.1): the response must echo the question
byte-for-byte (RFC 4343 §3), so the random case pattern extends the 16-bit
transaction ID by one bit per letter. A response whose question does not
match the randomized case — a spoofing signature or a case-rewriting
middlebox — is discarded and the query retried once with the original case
(§6.4 fallback; the retry's security equals the pre-CapsGuard baseline).
Mismatches are Warn-logged on a sampled basis (every
`config.DefaultCapsGuardWarnEvery`-th) because the path is attacker-
triggerable.

The randomized bytes never outlive the outbound message: cached responses are
rebuilt from the canonical qname, and the server side patches cached-response
wires back to the client's original case at serve time (`server/handler/
response.go` `patchQuestionCase`) — so no random case can leak into the cache
or subsequent responses (§5.4).

### HopGuard

Learns per-upstream TTL baseline from verified responses. After 32 samples,
enforces ±2 TTL tolerance. State stored in bounded LRU map (capacity 256).

**Over SOCKS5**: degrades by design — a SOCKS5 UDP relay terminates the IP
link, so the TTL the client socket observes is the relay-to-client hop, not
the server-to-relay hop (and the relay protocol carries no TTL metadata).
`Capture()` is nil on proxied sockets; a `hopguard TTL/HopLimit capture not
available` warning is logged once, and TTL checks never arm. When
spoofguard is also enabled it takes over content filtering — the combined
config keeps full protection over a proxy.

### Poisonguard

Classifies responses by delegation level:

- **Root-level**: Only NS/DS for TLDs or glue for root-servers.net are legitimate
- **TLD-level**: Only NS/DS sub-delegations or self-referencing A/AAAA are legitimate
- **Authoritative-level**: Always `VerdictUncertain` — design limitation; authoritative
  servers can legitimately return any record type

The delegation cache does not bypass Poisonguard: every query (including
the authoritative query after a cache hit) still passes through
`queryNameserversConcurrent` with the full Poisonguard detector. The TLD
poison probe (`probeTLDForPoison`) is skipped when the cached zone is
not a TLD (no `tldServers` to probe), but spoofguard + poisonguard +
hopguard still protect the authoritative query. The probe queries the
first `DefaultPoisonProbeServers` (3) TLD servers concurrently within a 1s
budget — any peer's A/AAAA answer is injection evidence and forces TCP;
the fan-out covers single-server drops that previously stretched the probe
to its full timeout.

### Spoofguard

Implements a multi-read UDP loop. After sending a query, it reads responses
within an adaptive collect window (100ms poll): a single datagram (nothing
to compare — authorities answer a query once) waits the short
`DefaultSpoofguardSingleWindow` (150ms); a second datagram (a possible
injected peer) keeps the full `DefaultSpoofguardCollectWindow` (500ms) for
comparison. Injected domains are gated upstream by the TLD poison probe
and the poisonguard verdict, so the short single-candidate wait keeps that
defense intact. Candidates are classified:

- Fast-accept (checked on the bare header, before the EDNS gate): `AN≥2` or
  `NS>0` or `AD=1`
- EDNS response: a legitimate candidate (never rejected) — fast-accepted
  when HopGuard is TTL-confident, otherwise collected; two identical
  candidates confirm the deterministic real answer immediately (GFW fakes
  vary per packet) instead of waiting out the window
- Non-EDNS bare single-answer A/AAAA: ambiguous — a lone response is served
  directly; ≥2 responses (injection signal) trigger a re-query confirmation
  (`DefaultSpoofguardConfirmRounds = 3`), a matching repeat confirms the
  deterministic real answer
- Selection: EDNS candidates preferred, most answer records wins, random
  tie-break (answer count only — authority is not compared)

### Splitguard

For TCP upstream queries, segments the DNS message into random [1,4]-byte
chunks (each segment independently sized, first segment carries the 2-byte
length prefix) with `TCP_NODELAY` so segments are sent immediately. Prevents
GFW from fingerprinting DNS-over-TCP traffic by breaking the predictable
2-byte length prefix pattern. There is no time-based jitter — segment-size
randomness alone defeats DPI pattern matching.

## DNSCrypt v2

Full implementation with PQC support. Two crypto constructions: XWingPQ (default, X-Wing PQ/T hybrid KEM + XChacha20-Poly1305 AEAD) and XChacha20Poly1305 (X25519 + XChacha20-Poly1305). XSalsa20 removed.

### Server (`server/protocol/dnscrypt/`)

- UDP+TCP listeners on independent port (default 8443); TCP connections are
  persistent (RFC 7766 §4 — the draft only specifies framing in §5.4.4; the
  old single-transaction-per-connection behaviour was a misreading) — one
  connection serves the handshake plus every subsequent query
- Ed25519 identity key required in config (`certificate.dnscrypt.public_key`/`private_key`, like TLS); resolver encryption keys (X25519/X-Wing) always auto-generated
- `keys []keyEntry` holds current + previous certs for rotation overlap
- `updateKeys()` mints fresh resolver keys every 8h (cert TTL is 24h — the 8h interval creates the current+previous overlap window), signed with fixed Ed25519 identity; ticket keys are derived once from the signing key and **never rotate** (rotating would invalidate client-cached tickets)
- `decrypt()` tries keys newest-first; `decryptPQResumed()` validates tickets against all active certs
- Persistence: identity + cert windows stored in the `dnscrypt_state` state file (`server/protocol/dnscrypt/persist_file.go`) — a restart resumes the exact same windows (client-cached certs stay valid); config key change drops the persisted state and mints fresh windows
- CHAOS `zjdns.dnscrypt.clear` (loopback-only) regenerates all windows immediately (ResetKeys)
- Config generator: `GenerateDNSCryptConfig()` in `generate.go` → called from `cmd/zjdns/cli/generate.go`

### Client (`server/upstream/dnscrypt/`)

- Supports `dnscrypt` (UDP) and `dnscrypt-tcp` (TCP) protocols
- `state()`: fetches cert via plain DNS TXT, verifies Ed25519 signature, auto-detects PQ certs
- `prepareQuery()`: tries resumed query → cached X-Wing encapsulation → fresh X-Wing encapsulation
- UDP→TCP fallback: TC bit, timeouts, padding failures all trigger TCP retry
- Adaptive sizing (draft §5.4.2): per-response EWMA (decay 2/31) of encrypted wire sizes; TC doubles the padded budget (≤4096) and resets the EWMA; an average below half the budget halves it (floor 512) — mirrors dnscrypt-proxy's `QuestionSizeEstimator`. Estimator state is atomic (lock-free on the response path); the same budget drives the classical UDP padding floor and the PQ resumed floor
- State caching: `State` with `pqPublicKey`, `pqCertContext`, `pqTicket`, `pqResumeSecret`, `pqTicketExpiry`
- UDP and TCP queries multiplex over pooled sockets/conns (`UDPPool` +
  `RawPool`), routed by the client-nonce prefix echoed in the response
  header (a dual magic/ID extractor lets plain-DNS cert fetches share the
  same pools, routed by their random message ID); certificate fetches
  (UDP + TCP) pool through the proxy when configured — previously they
  always dialed direct, which broke proxy-only servers

### Wire Formats

- **Classical query**: `<client-magic>(8) <client-pk>(32) <nonce/2>(12) <encrypted>`
- **PQ initial**: `<client-magic>(8) <xwing-ct>(1120) <nonce/2>(12) <encrypted>`
- **PQ resumed**: `<PQResumeMagic>(8) <ticket-len>(2) <ticket>(N) <nonce/2>(12) <encrypted>`
- **Response**: `<resolver-magic>(8) <nonce>(24) <encrypted>`
- PQ responses carry 2-byte control-length prefix after decryption

### Certificate Layout

- **Classical (124B)**: `CertMagic(4) + ESVersion(2) + Minor(2) + Sig(64) + ResolverPk(32) + ClientMagic(8) + Serial(4) + TS-start(4) + TS-end(4)`
- **PQ (1320B)**: Same header + `PqPublicKey(1216) + ClientMagic(8) + Serial(4) + TS-start(4) + TS-end(4) + Extensions(12)`
- ClientMagic for PQ = first 8 bytes of SHA-256(pq_public_key) (flipped first byte when it would collide with QUIC first-byte ranges or PQResumeMagic)
- PqCertContext = HKDF("DNSCrypt-PQ-v1" + es-version + minor + pq-public-key + client-magic + serial + ts-start + ts-end + extensions)

### Ticket Resumption

Server issues tickets sealed with XChacha20-Poly1305 under `ticketKey` (SHA-256 of Ed25519 signing key). Ticket plaintext (86B, `TicketPlaintext*` offsets in `internal/dnscryptcrypto/pq.go`): `ResumeSecret(off 0, 32) + ESVersion(off 32, 2) + ClientMagic(off 34, 8) + Serial(off 42, 4) + TS-end(off 46, 4) + Expiry(off 50, 4) + ProfileExtHash=SHA-256(profile-ext)(off 54, 32)`. Client derives per-query keys via `PQResumedSharedKey(resumeSecret, clientMagic, clientNonce/2, ticket)`.

## DTLCP (GM/T 0128-2023)

Reuses SM2 certificate pair from TLCP. Wire format = DTLS (RFC 8094): 2-byte big-endian length prefix + DNS payload.

### Library Bugs (gotlcp)

- `dtlcp.Listen("udp", ...)` → `net.Listen("udp", ...)` — Go does not support. All official examples fail.
- `dtlcp.Dial("udp", ...)` → `net.Dial` returns connected `*net.UDPConn`; library calls `WriteTo` which Go forbids on connected sockets.

### Workarounds

- **Server** (`server/protocol/tlcp/dtlcp.go`): `net.ListenUDP` + `acceptDTLCP()` feeds pre-read ClientHello through `dtlcp.Server`. Will be replaced with `dtlcp.Listen` when upstream fixes the connected-socket issue.
- **Client** (`server/upstream/tlcp/dtlcp.go`): `net.ListenPacket` + `dtlcp.Client()` + `HandshakeContext()`. Will be replaced with `dtlcp.Dial` when upstream fixes.
- **Synchronous handling**: gotlcp shares one `*net.UDPConn` across all connections. Only one connection at a time until upstream provides per-connection isolation.
- **SOCKS5 proxy compatibility**: the client validates every datagram's
  source address against the server address, and type-asserts read
  timeouts as `net.Error` to drive retransmission — both were broken by
  the SOCKS5 wrapper (zeroed source IP from the pooled read buffer; wrapped
  timeout errors). Fixed in `server/upstream/socks5/`; DTLCP-over-SOCKS5
  is verified working (cookie exchange + full handshake).
- Windows: IPv4 localhost DTLCP handshake unreliable — use `[::1]`.
- **Deadlock fix**: `dtlcpListener.Close()` collects connections under the lock, unlocks, THEN closes — `dtlcpConnWrapper.Close()` also acquires the same mutex.
- **Goroutine tracking**: TLCP server now has `serverGroup` (errgroup) tracking lifecycle goroutines (DoT accept, DTLCP accept, DoH serve). Shutdown waits for all via `serverGroup.Wait()`.

## Shared Port Multiplexing

Multiple protocols share a single TCP or UDP port via record-layer demultiplexing (`internal/demux/`).

### TCP (TLS+TLCP on same port)

Protocol detection reads the 5-byte TLS record header: major version `0x03` → TLS, `0x01` → TLCP. A `bufferedConn` replays the consumed header to the selected protocol server. Per-connection overhead: 1 syscall + 1 `bufferedConn` allocation + 1 channel hop. After the handshake, all subsequent queries flow directly on the TLS/TLCP connection — zero extra overhead.

### UDP (QUIC+DTLS+DTLCP on same port)

Protocol detection inspects the first datagram from each client address: first byte ≥ 0xC0 → QUIC (long header), version ≥ 0x1000 → DTLS, otherwise → DTLCP. The detection result is cached per client address (`peerProto` map).

**Zero per-packet allocation dispatch** (`server/protocol/tlcp/sharedudp.go`):

| Mechanism                     | Purpose                                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| `addrKey{[16]byte, uint16}`   | Allocation-free map key (fixed-size arrays are comparable, unlike `net.UDPAddr.IP` slice)                 |
| `packetBufPool` (`sync.Pool`) | Pooled datagram buffers passed through dispatch channels; consumers copy out and return                   |
| Single-copy pipeline          | Dispatch loop → pool buffer → channel → consumer `ReadFrom` copies to caller buffer → `packetBufPool.Put` |

All per-client maps (`dtlsPacketListener.clients`, `quicPacketConn`, `sharedDTLSClient.conns`, `peerProto`) use `addrKey` instead of `src.String()`, eliminating heap-allocated string keys.

pprof-verified: 300 queries (QUIC+DTLS+DTLCP) across the shared UDP dispatch produce zero new allocations after startup warmup.

## Zone Rules (`zone/`)

- **Zone evaluator**: in-memory maps (exact/wildcard) behind an atomic.Pointer snapshot; rules come from config at startup.
- **Wildcard matching**: suffix-walk over the in-memory wildcard map, deepest match first.
- **Synthetic zone rules**: config load injects zone rules for local answers —
  CHAOS introspection (`config/chaos.go`: id.server/hostname.bind/version._,
  ZJDNS._ stats & clear endpoints, zjdns.whoami — client source IP),
  DDR SVCB records (`config/ddr.go`, RFC 9462), and RESINFO
  (`config/resinfo.go`, RFC 9606, auto-enabled with DDR via
  `shouldEnableDDR` in `config/load.go`).

## EDNS Extensions & RFC Support

The middleware chain (see CLAUDE.md for the full 10-layer pipeline) hosts the
recent RFC features:

- **RFC 10029 MQTYPE**: per-upstream `mqtype` config (numeric QTYPE list).
  Client side: outbound queries attach MQQUERY{config − primary}; merged
  records warm the cache and are stripped from the client-facing answer;
  unsupported authorities fall back to standalone queries (§3.5).
  Server side: `middleware/mqtype.go` (between EDNS and CacheStore) merges
  per §3.4 — RCODE/AA/AD must match the primary, RRs deduplicated, size
  budget never self-triggers TC, empty-list MQTYPE-Response still returned
  as the support signal; §3.3's eight FORMERR conditions enforced. The
  merge is local in every mode (forwarding included) — the option is never
  passed through, so the response supports MQTYPE regardless of upstream
  support.
- **RFC 9824 Compact Denial**: upstream queries set the CO bit
  (`edns/edns.go`); `dnssec.HasCompactNXNAME` detects the NXNAME(128) signal
  and the resolver restores NXDOMAIN (§5.1) — recursive path only after the
  NSEC proof validates. NXNAME queries are REFUSED at Validation.
- **RFC 8482 minimal ANY**: `middleware/any.go` (inside Zone) answers
  QTYPE=ANY with `HINFO "RFC8482"`.
- **RFC 6975**: DAU/DHU/N3U algorithm lists are deliberately NOT advertised — pure optimisation hints that some authorities (e.g. Tencent NS) drop queries over when combined with unknown options such as MQTYPE-Query.
- **RFC 9715**: UDP responses capped at 1400 bytes; oversized wires are
  truncated in place by `truncateWire` (server/bridge.go) — TC=1, no
  Unpack/Pack round-trip.
