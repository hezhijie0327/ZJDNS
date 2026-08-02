# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).
For the storage-layer redesign rationale, see [DESIGN-STORAGE](design.md).

## Persistence Schema

The cache is **in-memory first**: an O(1) map + embedded LRU list (eviction by
total value bytes, `cache.max_size_mb`). Each subsystem persists its own
small file — zstd-compressed typed binary, written atomically (temp + rename)
via the shared `internal/persist` substrate. A subsystem's file is loaded at
startup and dumped at shutdown / rotation; a corrupt file only invalidates
that subsystem (cache entries are disposable, the DNSCrypt identity is not).

| Data | Persisted? | File | Why |
|------|-----------|------|-----|
| Cache entries {qname, ecs, dnssec, qtype, qclass, wire, expiresAt, validated} | ✅ | `cache.db_file` | Warm restart |
| DNSCrypt {identity, windows} | ✅ | `dnscrypt.zst` (sibling of db_file) | sdns:// stamps break if identity lost |
| PTR reverse index | ❌ | — | Derived — rebuilt from entries on load |
| IP latency | ❌ | — | Transient; bounded LRU, re-probed |
| Entry IDs | ❌ | — | No longer needed (no shared KV store) |

### `cache/persist.go` — typed binary format (entries)

`PersistFile{Version, Entries}` with `Load(path)` / `Save(path)` — pure
serialization, no KV operations. The cache owns its in-memory data.

```
[5B magic "ZJDNS"][2B version=1][8B entry_count]
per Entry: [2B qname_len][qname][1B has_ecs]
           (if has_ecs) [2B ecs_addr_len][ecs_addr][2B ecs_prefix]
           [1B dnssec][2B qtype][2B qclass][4B value_len][value][8B expires_at][1B validated]
```

### DNSCrypt state file — typed binary format

`server/protocol/dnscrypt/state.go` owns its format: `loadStateFile` /
`saveStateFile` via `internal/persist`, written at startup and key rotation.

```
[5B magic "ZJDNS"][2B version=1]
[4B identity_len][identity (96B: sk 64 + pk 32)]
[2B window_count]
per Window: [4B serial][4B not_before][4B not_after][32B resolver_sk][32B resolver_pk]
```

Cache-key fields are typed (no byte-packed `e:` prefixes — the BadgerDB-era
key encoding is gone). Numeric fields use binary BigEndian. `internal/persist`
provides the shared `Save`/`Load` (zstd + atomic write); each subsystem
defines its own format on top.

### Key Patterns

- **Cache hit path**: `Get()` does an O(1) `map[entryKey]` lookup per ECS
  fallback candidate, unpacks the wire. Answers are pre-sorted by latency —
  the probe writes the reordered answer back into the entry, so the hot path
  does no sorting.
- **Cache write path**: `Set()` packs wire format, `insert()` (LRU + size
  budget), then updates the PTR index. Wire stored uncompressed in memory;
  zstd happens once, at file write time.
- **TTL**: each entry carries `ts` + `expiresAt = ts + entryTTL + staleMaxAge`.
  Expired entries are returned for stale-serving/prefetch; physical removal
  happens on LRU eviction, Save/Load filtering, or Clear.
- **LRU eviction**: `insert()` evicts least-recently-used entries until the
  new value fits `maxSizeBytes`. Eviction cleans the evicted entry's PTR
  records (ownerKey linkage).
- **Latency**: bounded `lrumap` (ip → {ms, expiresAt}), transient. Serves the
  probe gate (`LatencyLastProbe`) and the resolver's cross-name NS ordering
  (`LookupIPLatencies`). The probe itself re-sorts the answer and re-Sets it.
- **Reverse lookup (PTR)**: in-memory `map[ip][]ptrRecord` derived from A/AAAA
  records; rebuilt from entries on load. Expired records skipped on scan.
- **Stats aggregation**: `stats.Collector` — plain `map[string]*entry` + `sync.Mutex`. `Record()` upserts directly with lock. `Stats()` iterates the map. All-time counters, reset via `Reset()`. No channel, no goroutine, no persistence.
- **Zone queries**: `Evaluator.Evaluate()` does in-memory exact-match lookup on `exact` map (O(1)), then wildcard suffix search on `wildcards` map (max 16 iterations). Pure WORM maps.
- **Ruleset matching**: `Engine.Match()` does CIDR via binary radix trie (O(128)) and domain suffix via map lookup (O(1)). All in-memory, loaded from config at startup.
- **DNSCrypt**: identity + windows live in memory; the server reads its own
  state file at startup (`loadStateFile`) and writes it at startup + key
  rotation (`saveStateFile`) — independent of the cache, so a corrupt cache
  file never invalidates the identity.
- **CHAOS endpoints**: `ZJDNS.stats` (read-only), `ZJDNS.cache.clear` (clears
  the in-memory cache + PTR index), `ZJDNS.stats.clear` (reset stats).
  Zone/ruleset clearing is not exposed.

### Cache Configuration

Config JSON:

```json
{
  "cache": {
    "prefer_stale": true,
    "max_size_mb": 64,
    "db_file": "/var/lib/zjdns/state.zst"
  }
}
```

- `max_size_mb`: in-memory value budget (LRU eviction), default 64.
- `db_file`: optional persist file; empty = no persistence (in-memory only).
- Missing/corrupt file at startup = cold start (logged, not fatal).

## Defense Mechanisms

ZJDNS implements four per-upstream defense mechanisms to detect and reject
DNS pollution attacks. Each is enabled via `UpstreamServer` flags.

| Mechanism | Layer | Algorithm |
|-----------|-------|-----------|
| **Hopguard** | UDP upstream | IP TTL fingerprint: auto-learn baseline, reject responses with TTL outside ±2 range |
| **Spoofguard** | UDP upstream | Multi-read loop: non-EDNS (no parsed OPT RR) + NOERROR is the GFW signature; accept `AN>=2`/`NS>0`/`AD=1`; collect ambiguous (≤500ms) → pick richest |
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

### Spoofguard

Implements a multi-read UDP loop. After sending a query, it reads up to N
responses within a configurable collect window. Candidates are classified:
- Immediate-accept: `AN≥2` or `NS>0` or `AD=1`
- EDNS-gate: parsed OPT RR determines EDNS presence (not raw ARCOUNT). Non-EDNS
  single-answer responses are rejected as the GFW signature; non-EDNS CNAME/multi-answer
  are collected as fallback. EDNS-bearing responses flow into the ambiguous collection
  block.
- Ambiguous: collect all, pick richest (most answer records + authority); TTL-confident
  EDNS responses are fast-accepted without waiting for a second candidate.

### Splitguard

For TCP upstream queries, segments the DNS message into random [1,4] byte
chunks with inter-segment jitter. Prevents GFW from fingerprinting DNS-over-TCP
traffic by breaking the predictable 2-byte length prefix pattern.


## DNSCrypt v2

Full implementation with PQC support. Two crypto constructions: XWingPQ (default, X-Wing PQ/T hybrid KEM + XChacha20-Poly1305 AEAD) and XChacha20Poly1305 (X25519 + XChacha20-Poly1305). XSalsa20 removed.

### Server (`server/protocol/dnscrypt/`)

- UDP+TCP listeners on independent port (default 8443)
- Ed25519 identity key (auto-generated or from config); resolver encryption keys (X25519/X-Wing) always auto-generated
- `keys []keyEntry` holds current + previous certs for rotation overlap
- `rotateKeys()` generates fresh resolver keys every 24h, signed with fixed Ed25519 identity
- `decrypt()` tries keys newest-first; `decryptPQResumed()` validates tickets against all active certs
- Restart-safe: new keys on startup, old tickets naturally invalidated
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
- ClientMagic for PQ = SHA-256(PqPublicKey)[:8]
- PqCertContext = HKDF("DNSCrypt-PQ-v1" + es-version + minor + pq-public-key + client-magic + serial + ts-start + ts-end + extensions)

### Ticket Resumption

Server issues tickets sealed with XChacha20-Poly1305 under `ticketKey` (SHA-256 of Ed25519 signing key). Ticket plaintext: `PQESVersion(2) + ClientMagic(8) + ResumeSecret(32) + Expiry(8)`. Client derives per-query keys via `pqResumedSharedKey(resumeSecret, clientMagic, clientNonce/2, ticket)`.

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

- **Storage**: Pure in-memory WORM (write-once-read-many) maps. `Evaluator` holds `exact` and `wildcards` (static rules), plus `dynamics` and `wildcardDynamics` (dynamic content generators), populated by `LoadRules` at startup. No persistence dependency — evaluate is a lock-free map lookup.
- **Lookup**: `Evaluate()` first checks `bypass` rules, then exact dynamic rules + `exact` map (O(1), best-scored), then wildcard dynamic rules + `wildcards` suffix search (max 16 iterations). Exact and wildcard dynamic rules live in separate maps — the same name may carry both without overwriting. All fields use `sync/atomic` for lock-free reads.
