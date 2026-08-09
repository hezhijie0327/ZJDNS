# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## Storage

ZJDNS is fully in-memory — there is no database.  The cache, stats, zone
rules, ruleset, latency and delegation data all live in memory (lrumap for
LRU maps for cache/latency/delegations, atomic.Pointer snapshots for
zone/ruleset rules, atomic counters for stats).  The only persistence is the
DNSCrypt state file (`dnscryptstate`), a ~300-byte blob holding the provider
identity + cert windows so restarts resume the same certificates.

### In-memory data

| Data | Structure | Lifetime |
|------|-----------|----------|
| DNS cache entries | `lrumap.Map[string, *cacheEntry]` — key = (qname, qtype, qclass, ecs, dnssec) flattened, value = pre-packed wire (format 0x02) + ts/ttl | LRU-bounded, TTL-expired lazily on read; `state_file` empty (default) = no persistence, restart starts cold |
| Query stats + per-RCODE journal | `statsjournal` (atomic counters + `topk.Map`) | Resets on restart |
| Zone rules | `zoneTable` atomic.Pointer snapshot (exact/wildcard maps, compressed RR blobs) | Rebuilt from config at startup |
| Ruleset rules | `ruleTable` atomic.Pointer snapshot (IP trie + domain suffix map) | Rebuilt from config at startup |
| IP latency | `lrumap.Map[string, latEntry]` | LRU-bounded, lazy expiry + periodic cleanup |
| Delegations | `lrumap.Map[string, *delegationEntry]` | LRU-bounded, lazy TTL expiry + periodic cleanup |
| DNSCrypt state | `dnscryptstate.FileStore` — ~300B blob: identity (96B) + cert windows | Persisted across restarts |

The cache entry value is the pre-packed response (format 0x02: [0x02][2:num
TTL offsets][2 each:offset][wire], zstd-compressed above the threshold).  The
wire carries the full response header — including the RCODE (e.g. NXDOMAIN) —
so cache hits serve the exact rcode.

### Key Patterns

- **Cache hit path**: pre-packed wire (format 0x02: TTL-offset table + packed
  response). `Get()` serves the wire directly — the Response middleware
  patches the message ID/RD bits and bridge.go writes it without any
  Unpack/Pack round-trip (~20ns at the middleware layer, 0 allocs). TTL
  deduction happens in-place via the offset table; DNSSEC filtering for
  DO=0 clients uses a wire scan (WireHasDNSSEC). Entries below the
  compression threshold are stored uncompressed (no decompress either).
- **RecordRequest**: All results → in-memory atomic counters (`cache/statsjournal.go`); non-hit events also enter a per-RCODE top-N domain journal (`topk.Map`, bounded). No SQL, no disk — pure memory, reset on restart.
- **Stats aggregation**: `Stats()` reads the in-memory snapshot — O(1) counters + per-RCODE top-N sort. Output keeps the previous TXT layout plus `top-rcode<N>` lines.
- **Pruning**: `PruneQueryJournal` is a no-op — the journal is bounded in memory, nothing to prune.
- **Eviction**: On `Set()` when count > maxEntries. Prefers past serve-stale, then oldest. Latency and delegation entries expire lazily on read (past the stale window / TTL).
- **NS latency cache**: NS/Root addresses as TypeA/TypeAAAA entries. Latency probed via `ProbeNSAddrs`, reordered by `sortAnswerByLatency` at `Get()` time.
- **Delegation cache**: Zone-cut delegations (zone to NS names + verified DS) in memory (LRU-bounded, lazy TTL expiry + periodic cleanup). Populated at every delegation crossing during recursive walks; only secure (verified DS) or insecure (authenticated no-DS) delegations are stored. On subsequent queries, a suffix-walk from the deepest ancestor finds the first fresh delegation and starts the walk from that zone instead of the root, skipping already-walked delegation levels. DNSKEYs are fetched fresh by `ensureZoneDNSKEYs` (verified against the cached DS); NS addresses are resolved from the existing TypeA/TypeAAAA cache with the stored address snapshot as a fallback.
- **IP latency**: Per-IP keyed, in memory (LRU-bounded `lrumap.Map[string, latEntry]`). Background probes write latency + probe time; cache hits read it to reorder A/AAAA answers fastest-first. All domains sharing a CDN IP reuse the same entry. Entries expire lazily past the stale window.
- **Dynamic queries**: `Store.Stats()` returns TXT records (overview, hits, errors, rcodes, poisoned, plain, encrypted, DNSCrypt, TLCP, DNSSEC). Write: `zjdns.cache.clear` / `zjdns.stats.clear` / `zjdns.latency.clear` / `zjdns.querylog.clear` / `zjdns.dnscrypt.clear` (loopback-only).


## Defense Mechanisms

ZJDNS implements four per-upstream defense mechanisms to detect and reject
DNS pollution attacks. Each is enabled via `UpstreamServer` flags.

| Mechanism | Layer | Algorithm |
|-----------|-------|-----------|
| **Hopguard** | UDP upstream | IP TTL fingerprint: auto-learn baseline, reject responses with TTL outside ±2 range |
| **Spoofguard** | UDP upstream | Multi-read loop: reject `AR=0+NOERROR` without EDNS (bare A/AAAA, GFW signature); accept `AN>=2`/`NS>0`/`AD=1`; collect ambiguous (≤500ms) → pick richest |
| **Poisonguard** | Recursive | Zone-authority cross-validation on resolved answers |
| **Splitguard** | TCP upstream | Random [1,N] payload segmentation with jitter |

**Implementation locations:**
- `server/defense/hopguard.go` — HopGuard TTL learning + validation
- `server/defense/poisonguard.go` — PoisonGuard zone classification
- `server/upstream/plain/udp.go` — SpoofGuard multi-read loop
- `server/upstream/plain/tcp.go` — SplitGuard segmentation parameter
- `server/upstream/pool/tcp.go` — SplitGuard via `WriteTCPMsgSegmented`

### HopGuard

Learns per-upstream TTL baseline from verified responses. After 32 samples,
enforces ±2 TTL tolerance. State stored in bounded LRU map (capacity 256).

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
hopguard still protect the authoritative query.

### Spoofguard

Implements a multi-read UDP loop. After sending a query, it reads up to N
responses within a configurable collect window. Candidates are classified:
- Immediate-reject: `AR=0+NOERROR+EDNS` (GFW signature)
- Immediate-accept: `AN≥2` or `NS>0` or `AD=1`
- Ambiguous: collect all, pick richest (most answer records + authority)

### Splitguard

For TCP upstream queries, segments the DNS message into random [1,4] byte
chunks with inter-segment jitter. Prevents GFW from fingerprinting DNS-over-TCP
traffic by breaking the predictable 2-byte length prefix pattern.


## DNSCrypt v2

Full implementation with PQC support. Two crypto constructions: XWingPQ (default, X-Wing PQ/T hybrid KEM + XChacha20-Poly1305 AEAD) and XChacha20Poly1305 (X25519 + XChacha20-Poly1305). XSalsa20 removed.

### Server (`server/protocol/dnscrypt/`)

- UDP+TCP listeners on independent port (default 8443)
- Ed25519 identity key required in config (`certificate.dnscrypt.public_key`/`private_key`, like TLS); resolver encryption keys (X25519/X-Wing) always auto-generated
- `keys []keyEntry` holds current + previous certs for rotation overlap
- `rotateKeys()` generates fresh resolver keys every 24h, signed with fixed Ed25519 identity; ticket keys rotate alongside (RFC §11.7)
- `decrypt()` tries keys newest-first; `decryptPQResumed()` validates tickets against all active certs
- Persistence: identity + cert windows stored in the `dnscrypt_state` state file (`server/protocol/dnscrypt/persist_file.go`) — a restart resumes the exact same windows (client-cached certs stay valid); config key change drops the persisted state and mints fresh windows
- CHAOS `zjdns.dnscrypt.clear` (loopback-only) regenerates all windows immediately (ResetKeys)
- Config generator: `GenerateDNSCryptConfig()` in `generate.go` → called from `cmd/zjdns/cli/generate.go`

### Client (`server/upstream/dnscrypt/`)

- Supports `dnscrypt` (UDP) and `dnscrypt-tcp` (TCP) protocols
- `state()`: fetches cert via plain DNS TXT, verifies Ed25519 signature, auto-detects PQ certs
- `prepareQuery()`: tries resumed query → cached X-Wing encapsulation → fresh X-Wing encapsulation
- UDP→TCP fallback: TC bit, timeouts, padding failures all trigger TCP retry
- State caching: `State` with `pqPublicKey`, `pqCertContext`, `pqTicket`, `pqResumeSecret`, `pqTicketExpiry`

### Wire Formats

- **Classical query**: `<client-magic>(8) <client-pk>(32) <nonce/2>(12) <encrypted>`
- **PQ initial**: `<client-magic>(8) <xwing-ct>(1120) <nonce/2>(12) <encrypted>`
- **PQ resumed**: `<PQResumeMagic>(8) <ticket-len>(2) <ticket>(N) <nonce/2>(12) <encrypted>`
- **Response**: `<resolver-magic>(8) <nonce>(24) <encrypted>`
- PQ responses carry 2-byte control-length prefix after decryption

### Certificate Layout

- **Classical (124B)**: `CertMagic(4) + ESVersion(2) + Minor(2) + Sig(64) + ResolverPk(32) + ClientMagic(8) + Serial(4) + TS-start(4) + TS-end(4)`
- **PQ (1320B)**: Same header + `PqPublicKey(1216) + ClientMagic(8) + Serial(4) + TS-start(4) + TS-end(4) + Extensions(12)`
- ClientMagic for PQ = bytes 72–79 of the X-Wing public key (official encrypted-dns-server derivation, `generate.go NewPQCert`)
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
- Windows: IPv4 localhost DTLCP handshake unreliable — use `[::1]`.
- **Deadlock fix**: `dtlcpListener.Close()` collects connections under the lock, unlocks, THEN closes — `dtlcpConnWrapper.Close()` also acquires the same mutex.
- **Goroutine tracking**: TLCP server now has `serverGroup` (errgroup) tracking lifecycle goroutines (DoT accept, DTLCP accept, DoH serve). Shutdown waits for all via `serverGroup.Wait()`.

## Zone Rules (`zone/`)

- **Zone evaluator**: in-memory maps (exact/wildcard) behind an atomic.Pointer snapshot; rules come from config at startup.
- **Wildcard matching**: suffix-walk over the in-memory wildcard map, deepest match first.
- **Synthetic zone rules**: config load injects zone rules for local answers —
  CHAOS introspection (`config/chaos.go`: id.server/hostname.bind/version.*,
  ZJDNS.* stats & clear endpoints, zjdns.whoami — client source IP),
  DDR SVCB records (`config/ddr.go`, RFC 9462), and RESINFO
  (`config/resinfo.go`, RFC 9606, auto-enabled with DDR via
  `shouldEnableDDR` in `config/load.go`).

## EDNS Extensions & RFC Support

The middleware chain (see CLAUDE.md for the full 11-layer pipeline) hosts the
recent RFC features:

- **RFC 9824 Compact Denial**: upstream queries set the CO bit
  (`edns/edns.go`); `dnssec.HasCompactNXNAME` detects the NXNAME(128) signal
  and the resolver restores NXDOMAIN (§5.1) — recursive path only after the
  NSEC proof validates. NXNAME queries are REFUSED at Validation.
- **RFC 8482 minimal ANY**: `middleware/any.go` (inside Zone) answers
  QTYPE=ANY with `HINFO "RFC8482"`.
- **RFC 6975**: upstream requests advertise DAU/DHU/N3U algorithm lists.
- **RFC 9715**: UDP responses capped at 1400 bytes; oversized wires are
  truncated in place by `truncateWire` (server/bridge.go) — TC=1, no
  Unpack/Pack round-trip.
