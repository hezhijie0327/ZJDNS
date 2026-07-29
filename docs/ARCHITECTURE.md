# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## DB Schema

The unified database (`database/`) uses BadgerDB v4 (LSM-tree key-value store) with 7 key prefixes:

| Prefix | Purpose | Key Pattern | Value (big-endian binary) |
|--------|---------|-------------|---------------------------|
| `e:` | DNS response cache | `e:{qname}\x00{ecs_addr}\x00{ecs_prefix:04x}\x00{dnssec_ok}\x00{qtype:04x}\x00{qclass:04x}` | `[0:8]id [8:16]ts [16:20]ttl [20:]zstd_wire` |
| `p:` | PTR reverse lookup | `p:{rdata_ip}\x00{entry_id:016x}\x00{name}` | `[0:4]ttl [4:12]expires_at` |
| `l:` | Per-IP latency | `l:{rdata_ip}` | `[0:2]qtype [2:6]latency_ms [6:14]last_probe` |
| `s:` | Per-day query stats | `s:{stat_day:08x}\x00{result}\x00{protocol}\x00{rcode:04x}\x00{dnssec}\x00{poisoned}` | `[0:8]query_count [8:16]total_ms` |
| `q:` | Query audit log | `q:{timestamp:016x}\x00{seq:016x}` | variable (length-prefixed strings) |
| `z:` | Zone rule entries | `z:{is_wildcard}\x00{qname}\x00{qtype:04x}\x00{qclass:04x}\x00{match_tags}` | `[0:2]rcode` + 3×zstd blobs |
| `r:` | Ruleset entries | `r:{type}\x00{value}\x00{tag}` | empty (key existence check) |

`\x00` is the field separator. Integers are hex-encoded (zero-padded) for correct lexicographic sort order during prefix scans.

### Key Patterns

- **Cache hit path**: `Get()` does a direct BadgerDB key lookup (`txn.Get()`) in a read-only View transaction (~0.1ms).
- **Cache write path**: `Set()` packs wire format, zstd-compresses, writes entry + ptr_map entries + latency in a single Update transaction.
- **TTL**: BadgerDB native TTL via `Entry.WithTTL()` — entries auto-expire after `entryTTL + DefaultStaleMaxAge` seconds. No manual stale-entry scanning needed.
- **Eviction**: When `entryCount >= maxEntries * 9/10`, prefix scan on `e:` finds oldest entries, deletes them in a single Update transaction.
- **Stats aggregation**: `Stats()` does a prefix scan over `s:` prefix (~500 rows) and aggregates in Go code. O(500) — sub-millisecond.
- **Auto-increment IDs**: BadgerDB `Sequence` (bandwidth=1000) for entry IDs and query log IDs. Leases up to 1000 IDs in memory before a disk write.
- **Zone queries**: `queryExact()` uses BadgerDB prefix scan on `z:0:{qname}\x00{qtype:04x}\x00{qclass:04x}\x00`. `queryWildcardBatch()` iterates up to 16 suffix candidates with individual prefix scans.
- **NS latency cache**: NS/Root addresses as TypeA/TypeAAAA entries. Latency probed via `ProbeNSAddrs`, reordered by `sortAnswerByLatency` at `Get()` time.
- **IP latency**: Per-IP keyed. Writes latency_ms + last_probe_time to `l:` prefix. All domains sharing a CDN IP reuse the same key.
- **Dynamic queries**: `Store.Stats()` returns TXT records (overview, hits, errors, rcodes, poisoned, plain, encrypted, DNSCrypt, TLCP, DNSSEC). Write: `zjdns.db.clear` / `zjdns.db.clear.{cache,stats,querylog,latency,zone,ruleset}`.


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

- **ZoneStorage interface**: `Evaluator` depends on `ZoneStorage` (not concrete `*database.DB`), following the same pattern as `ruleset.RuleSetStorage`. The interface provides `Exec`, `Begin`, `QueryZoneExact`, `QueryZoneWildcard`, and `Close`.
- **Wildcard matching**: Batch IN query with fixed 16 placeholders via `StmtZoneWildcard` prepared statement — single query replaces the old per-label N-query loop.
