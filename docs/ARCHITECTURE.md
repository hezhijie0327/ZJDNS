# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## Persistence Schema

The cache is **in-memory first**: an `lrumap.Map[entryKey, cacheEntry]` with
weighted eviction (total value bytes, `cache.max_size_mb`). Persistence is an
optional capability of the same map — `EnablePersist(path, codec, keep)`
snapshots the LRU to a zstd-compressed file (least-recently-used first, so a
restart restores the same relative recency) and loads it eagerly at startup.
Each subsystem persists its own small file, written atomically (temp + rename)
via the shared `internal/persist` substrate. A corrupt file only invalidates
that subsystem (cache entries are disposable, the DNSCrypt identity is not).
`internal/persist.Manager` owns all persist timing: registered subsystems
(cache, stats, DNSCrypt) are written on `persist.interval_seconds` and once
more at shutdown.

| Data | Persisted? | File (under persist.dir) | Why |
|------|-----------|--------------------------|-----|
| Cache entries {qname, ecs, dnssec, qtype, qclass, wire, expiresAt, validated} | ✅ | `cache.zst` | Warm restart |
| PTR reverse index | ✅ | `ptr.zst` | PTR queries served immediately after restart; missing/corrupt file falls back to deriving from cache entries |
| IP latency | ✅ | `latency.zst` | NS ordering right after restart, no re-probe wait |
| DNSCrypt {identity, windows} | ✅ | `dnscrypt.zst` | sdns:// stamps break if identity lost |
| Query stats (all counters) | ✅ | `stats.zst` | Long-term totals across restarts |

### `cache/codec.go` — per-subsystem codec

KV caches share one persistence mechanism: `lrumap.Map` + a `lrumap.Codec`
that owns the per-field binary encoding. The map owns the file management —
version header, framed key/value pairs, zstd, atomic write:

```
[2B codec_version][8B entry_count]
per Entry: [4B key_len][key][4B val_len][val]
```

The cache codec encodes `entryKey` (typed fields: qname, ecs, dnssec, qtype,
qclass) and `cacheEntry` (wire value + expiresAt + validated). The PTR index
(`ptr.zst`, ip → derived records incl. owner entryKey) and latency map
(`latency.zst`, ip → {ms, expiresAt}) each have their own small codec. A
`Keep` filter skips expired entries at Save; `DecodeValue` skips entries that
expired while on disk. The PTR index is derived data: when `ptr.zst` is
missing/corrupt/empty it is rebuilt from the loaded cache entries. Every
persistent subsystem is a lrumap entry — including the two single-value
stores below (stats snapshot, DNSCrypt state), which use a fixed key and a
capacity of 1. All five files share one mechanism: version-gated framing,
zstd + atomic write, backup of old-format/corrupt files to `path.bak` before
rebuilding, and unified startup logs (`<PREFIX>: loaded N <unit> from <path>`).

### DNSCrypt state — single-entry lrumap

`server/protocol/dnscrypt/state.go` implements `dnscryptCodec` for the
single `dnscryptState` entry (identity + cert windows), written at startup
and key rotation. The old standalone layout is detected as a version
mismatch, backed up, and rebuilt — clients must re-fetch the certificate.

### Stats snapshot — single-entry lrumap

`stats/persist.go` implements `statsCodec` for the single `counters` entry:
one BigEndian int64 per counter field, in Collector field order, restored
with an additive merge.

### Key Patterns

- **Cache hit path**: `Get()` does an O(1) `map[entryKey]` lookup per ECS
  fallback candidate, unpacks the wire. A/AAAA answers are reordered
  fastest-first by cached probe latency (stable sort, unprobed records keep
  their order) — the client-facing counterpart of the resolver's NS address
  ordering. ~0.5µs per hit on a 4-record answer.
- **Cache write path**: `Set()` packs wire format, `store.Set()` (lrumap
  weight-evicted), then updates the PTR index. Wire stored uncompressed in
  memory; zstd happens once, at file write time.
- **TTL**: each entry carries `ts` + `expiresAt = ts + entryTTL + staleMaxAge`.
  Expired entries are returned for stale-serving/prefetch; physical removal
  happens on LRU eviction, Save/Load filtering, or Clear.
- **LRU eviction**: `store.Set()` (lrumap weight eviction) evicts
  least-recently-used entries until the new value fits the byte budget.
  Eviction cleans the evicted entry's PTR records via the OnEvict callback
  (ownerKey linkage).
- **Latency**: bounded `lrumap` (ip → {ms, expiresAt}), transient. Serves the
  probe gate (`LatencyLastProbe`) and the resolver's cross-name NS ordering
  (`LookupIPLatencies`). The probe itself re-sorts the answer and re-Sets it.
- **Reverse lookup (PTR)**: `lrumap` `map[ip][]ptrRecord` derived from A/AAAA
  records (update on Set, cleanup on eviction via OnEvict); byte-budgeted via
  `SetWeight` (16MB default — one IP can map to hundreds of names, so a count
  cap would not bound memory); persisted to `ptr.zst`, derived from entries
  when the file is missing. Expired records skipped on scan. Best-effort:
  `ptr.zst` and `cache.zst` are written in the same persist round, so drift
  is bounded to one interval and costs hit-rate, never correctness.
- **Stats aggregation**: `stats.Collector` — flat atomic counters (no maps, lock-free `Record()`), latency histogram buckets, `Reset()` via `ZJDNS.stats.clear`. `stats.zst` persistence via the single-entry lrumap (`SetPersist` / no-arg `SavePersist`; periodic + shutdown snapshot, startup additive restore).
- **Zone queries**: `Evaluator.Evaluate()` does in-memory exact-match lookup on `exact` map (O(1)), then wildcard suffix search on `wildcards` map (max 16 iterations). Pure WORM maps.
- **Ruleset matching**: `Engine.Match()` does CIDR via binary radix trie (O(128)) and domain suffix via map lookup (O(1)). All in-memory, loaded from config at startup.
- **DNSCrypt**: identity + windows live in memory; the single-entry lrumap
  (`dnscrypt.zst`) is written at startup, rotation, and reset — independent
  of the cache, so a corrupt cache file never invalidates the identity.
- **CHAOS endpoints**: `ZJDNS.stats` (read-only) and five destructive
  loopback-only clear endpoints — `ZJDNS.cache.clear` (cache + PTR + latency),
  `ZJDNS.ptr.clear`, `ZJDNS.latency.clear`, `ZJDNS.stats.clear`,
  `ZJDNS.dnscrypt.clear` (fresh seed, new cert windows). Every clear persists
  the cleared state immediately. Zone/ruleset clearing is not exposed.

### Persist Configuration

Config JSON:

```json
{
  "persist": { "dir": "/var/lib/zjdns", "interval_seconds": 300 },
  "cache": { "prefer_stale": true, "max_size_mb": 64 }
}
```

- `persist.dir`: unified persist directory; each subsystem keeps its own file
  under it (`cache.zst`, `ptr.zst`, `latency.zst`, `stats.zst`,
  `dnscrypt.zst`). Empty = pure in-memory.
- `persist.interval_seconds`: periodic persist interval — all five files are
  dumped every N seconds (bounded crash loss) in addition to the shutdown
  dump. 0 (default) = shutdown-only.
- `cache.max_size_mb`: in-memory value budget (LRU eviction), default 64.
- Missing/corrupt file at startup = cold start for that subsystem (logged,
  not fatal) — one subsystem's corruption never affects the others. An
  old-format or corrupt file is backed up to `path.bak` before rebuilding,
  never silently destroyed.

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
