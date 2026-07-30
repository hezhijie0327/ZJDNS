# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## DB Schema

BadgerDB (`database/`) stores only DNS response cache entries and latency probes.
Zone rules (`zone/`), rulesets (`ruleset/`), and query stats (`stats/`) are all
in-memory data structures — loaded from config at startup, O(1) lookups, no persistence.
All numeric fields use binary BigEndian encoding (not hex), consistent with value encoding.

| Prefix | Purpose | Key Pattern | Value |
|--------|---------|-------------|-------|
| `e:` | DNS response cache | `e:{qname}\x00{ecs_addr}\x00{ecsPrefix:2B}\x00{dnssec:1B}\x00{qtype:2B}\x00{qclass:2B}` | `[0:8]id [8:16]ts [16:20]ttl [20:]raw_wire` |
| `e:ip:` | IP reverse index + latency | `e:ip:{ip}\x00{entryID:8B}\x00{name}` / `e:ip:{ip}\x00_lat` | reverse: `[0:4]ttl` / latency: `[0:2]latency_ms` |

`\x00` is the field separator for string fields. Binary fields use known offsets for parsing (NUL bytes inside binary integers would break separator-based parsing).

### Key Patterns

- **Cache hit path**: `Get()` does a direct BadgerDB key lookup (`txn.Get()`) in a read-only View transaction. Raw DNS wire format is unpacked directly (no app-level decompression).
- **Cache write path**: `Set()` packs wire format, writes entry + reverse index entries in a single Update transaction. Wire stored raw — BadgerDB block-level zstd handles compression.
- **TTL**: BadgerDB native TTL via `Entry.WithTTL()` — entries auto-expire after `entryTTL + DefaultStaleMaxAge` seconds. Reverse index entries share the same TTL via `WithTTL`. No custom eviction code.
- **Latency**: Stored under `e:ip:{ip}\x00_lat` with no TTL — overwritten on each probe, cleaned when `DropPrefix("e:")` runs. `LatencyLastProbe` checks key existence.
- **Stats aggregation**: `stats.Collector` — plain `map[string]*entry` + `sync.Mutex`. `Record()` upserts directly with lock. `Stats()` iterates the map. All-time counters, reset via `Reset()`. No channel, no goroutine, no persistence.
- **Auto-increment IDs**: BadgerDB `Sequence` (bandwidth=1000) for entry IDs. Leases up to 1000 IDs in memory before a disk write.
- **Zone queries**: `Evaluator.Evaluate()` does in-memory exact-match lookup on `exact` map (O(1)), then wildcard suffix search on `wildcards` map (max 16 iterations). No BadgerDB — pure WORM maps.
- **Ruleset matching**: `Engine.Match()` does CIDR via binary radix trie (O(128)) and domain suffix via map lookup (O(1)). All in-memory, loaded from config at startup.
- **Reverse lookup**: Prefix scan on `e:ip:{ip}\x00` returns all cached domains for an IP. Expired entries filtered by `IsDeletedOrExpired()`.
- **CHAOS endpoints**: `ZJDNS.stats` (read-only), `ZJDNS.cache.clear` (clear `e:` + `e:ip:`), `ZJDNS.stats.clear` (reset `s:`). Zone/ruleset clearing is not exposed.

### DB Configuration

The `database.Options` struct exposes 3 memory budget knobs. All other BadgerDB
settings are hardcoded as correct for DNS cache workloads. Pass `nil` to
`database.Open()` for full defaults.

| Field | Default | BadgerDB Setting | Purpose |
|---|---|---|---|
| `MemTableSizeMB` | 4 | `WithMemTableSize` | Single memtable write buffer (MB) |
| `BlockCacheSizeMB` | 4 | `WithBlockCacheSize` | SSTable block read cache (MB) |
| `IndexCacheSizeMB` | 8 | `WithIndexCacheSize` | Bloom filter + table index cache (MB) |

Hardcoded constants:
`ValueThreshold=64KB`, `ValueLogFileSize=64MB`, `MaxLevels=7`,
`BaseLevelSizeMB=4`, `NumMemtables=2`, `NumCompactors=2`,
`NumLevelZeroTables=2`, `NumGoroutines=2`, `ZSTDCompressionLevel=3`,
`NumVersionsToKeep=1`, `DetectConflicts=false`, `SyncWrites=false`,
`Compression=ZSTD`, `CompactL0OnClose=true`, `BaseTableSize=1MB`,
`ValueLogMaxEntries=100K`.

Config JSON:

```json
{
  "database": {
    "db_path": "/var/lib/zjdns/cache.db",
    "memtable_size_mb": 4,
    "block_cache_size_mb": 4,
    "index_cache_size_mb": 8
  }
}
```

## Defense Mechanisms

ZJDNS implements four per-upstream defense mechanisms to detect and reject
DNS pollution attacks. Each is enabled via `UpstreamServer` flags.

| Mechanism | Layer | Algorithm |
|-----------|-------|-----------|
| **Hopguard** | UDP upstream | IP TTL fingerprint: auto-learn baseline, reject responses with TTL outside ±2 range |
| **Spoofguard** | UDP upstream | Multi-read loop: reject `AR=0+NOERROR+EDNS`; accept `AN>=2`/`NS>0`/`AD=1`; collect ambiguous (≤500ms) → pick richest |
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

- **Storage**: Pure in-memory WORM (write-once-read-many) maps. `Evaluator` holds `exact` (map[string][]zoneRule) and `wildcards` (map[string][]zoneRule) populated by `LoadRules` at startup. No BadgerDB dependency — evaluate is a lock-free map lookup.
- **Lookup**: `Evaluate()` first checks `bypass` rules, then `exact` map (O(1)), then `wildcards` suffix search (max 16 iterations). All fields use `sync/atomic` for lock-free reads.
