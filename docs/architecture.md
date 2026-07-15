# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## DB Schema

The unified database (`database/`) contains ten SQLite tables (`github.com/ncruces/go-sqlite3`, WAL mode, mmap, zstd compression):

```sql
-- DNS response cache. Uniqueness: (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok).
CREATE TABLE entries (
    qname      TEXT NOT NULL,
    qtype      INTEGER NOT NULL,
    qclass     INTEGER NOT NULL DEFAULT 1,
    ecs_addr   TEXT NOT NULL DEFAULT '',
    ecs_prefix INTEGER NOT NULL DEFAULT 0,
    dnssec_ok  INTEGER NOT NULL DEFAULT 0 CHECK (dnssec_ok IN (0, 1)),
    timestamp  INTEGER NOT NULL,
    ttl        INTEGER NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0,
    validated  INTEGER NOT NULL DEFAULT 0 CHECK (validated IN (0, 1)),
    msg_wire   BLOB,
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
);
CREATE INDEX idx_entries_expires_ts ON entries(expires_at, timestamp);
CREATE INDEX idx_entries_timestamp ON entries(timestamp);

-- Request journal: one row per miss/stale/zone/error.
CREATE TABLE request_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       INTEGER NOT NULL,
    qname           TEXT NOT NULL DEFAULT '',
    qtype           INTEGER NOT NULL DEFAULT 0,
    qclass          INTEGER NOT NULL DEFAULT 1,
    entry_id        INTEGER,              -- NULL for zone/error paths
    protocol        TEXT NOT NULL,
    result          TEXT NOT NULL,
    response_time_ms INTEGER NOT NULL DEFAULT 0,
    rcode           INTEGER NOT NULL DEFAULT 0,
    server          TEXT NOT NULL DEFAULT '',
    hijack          INTEGER NOT NULL DEFAULT 0,
    fallback        INTEGER NOT NULL DEFAULT 0,
    dnssec_status   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_request_log_ts ON request_log(timestamp);

-- Hit counters: aggregated per-entry+protocol+rcode.
CREATE TABLE entry_hit_counters (
    entry_id  INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    protocol  TEXT NOT NULL,
    rcode     INTEGER NOT NULL DEFAULT 0,
    hit_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (entry_id, protocol, rcode)
) WITHOUT ROWID;

-- Stats metadata: tracks last cleared request_log.id.
CREATE TABLE stats_meta (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    cleared_before INTEGER NOT NULL DEFAULT 0
);

-- PTR reverse-lookup (IP → domain).
CREATE TABLE ptr_map (
    rdata_ip TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    ttl      INTEGER NOT NULL,
    PRIMARY KEY (rdata_ip, entry_id, name)
) WITHOUT ROWID;

-- Per-IP latency measurements. Keyed by rdata_ip only.
CREATE TABLE ip_latency (
    rdata_ip        TEXT NOT NULL,
    qtype           INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL,
    last_probe_time INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rdata_ip)
) WITHOUT ROWID;
CREATE INDEX idx_ip_latency_probe ON ip_latency(last_probe_time);

-- Zone entries (same DB file, shared zstd compression).
CREATE TABLE zone_entries (
    is_wildcard INTEGER NOT NULL DEFAULT 0,
    qname      TEXT NOT NULL,
    qtype      INTEGER NOT NULL DEFAULT 0,
    qclass     INTEGER NOT NULL DEFAULT 0,
    rcode      INTEGER NOT NULL DEFAULT 0,
    answer     BLOB,               -- zstd-compressed answer RRs
    authority  BLOB,               -- zstd-compressed authority RRs
    additional BLOB,               -- zstd-compressed additional RRs
    match_tags TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (is_wildcard, qname, qtype, qclass, match_tags)
) WITHOUT ROWID;
```

### Key Patterns

- **Cache hit path**: `Get()` decompresses zstd + `Msg.Unpack()` (~0.5ms). Returns entry `ID` so `RecordRequest` can skip `EnsureEntry`.
- **RecordRequest split**: Hits → `entry_hit_counters` (upsert, no row bloat). Miss/stale/zone/error → `request_log` (denormalized qname/qtype, no JOIN needed). `entry_id` is nullable.
- **Stats aggregation**: `Stats()` UNION ALLs `entry_hit_counters` + `request_log`. `FlushDB("stats")` only resets stats_meta threshold — request_log rows survive.
- **Eviction**: On `Set()` when count > maxEntries. Prefers past serve-stale, then oldest. `ON DELETE CASCADE` for ptr_map + hit_counters. Also prunes stale ip_latency + request_log rows (30-day cutoff).
- **NS latency cache**: NS/Root addresses as TypeA/TypeAAAA entries. Latency probed via `ProbeNSAddrs`, reordered by `sortAnswerByLatency` at `Get()` time.
- **IP latency**: Per-IP keyed. `INSERT OR REPLACE` writes latency_ms + last_probe_time. All domains sharing a CDN IP reuse the same row.
- **Dynamic queries**: `Store.Stats()` returns 8 TXT records (overview, success, errors, rcodes, anomalies, plain, encrypted, DNSSEC). Write: `zjdns.db.clear` / `zjdns.db.clear.{cache,stats,latency,zone,ruleset}`.

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
- `getDNSCryptState()`: fetches cert via plain DNS TXT, verifies Ed25519 signature, auto-detects PQ certs
- `prepareAndEncryptQuery()`: tries resumed query → cached X-Wing encapsulation → fresh X-Wing encapsulation
- UDP→TCP fallback: TC bit, timeouts, padding failures all trigger TCP retry
- State caching: `dnscryptState` with `pqPublicKey`, `pqCertContext`, `pqTicket`, `pqResumeSecret`, `pqTicketExpiry`

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
- PqCertContext = HKDF("DNSCrypt-PQ-v1" + es-version + minor + resolver-pk + client-magic + serial + ts-start + ts-end + extensions)

### Ticket Resumption

Server issues tickets sealed with XChacha20-Poly1305 under `ticketKey` (SHA-256 of Ed25519 signing key). Ticket plaintext: `PQESVersion(2) + ClientMagic(8) + ResumeSecret(32) + Expiry(8)`. Client derives per-query keys via `pqResumedSharedKey(resumeSecret, clientMagic, clientNonce/2, ticket)`.

## DTLCP (GM/T 0128-2023)

Reuses SM2 certificate pair from TLCP. Wire format = DTLS (RFC 8094): 2-byte big-endian length prefix + DNS payload.

### Library Bugs (gotlcp)

- `dtlcp.Listen("udp", ...)` → `net.Listen("udp", ...)` — Go does not support. All official examples fail.
- `dtlcp.Dial("udp", ...)` → `net.Dial` returns connected `*net.UDPConn`; library calls `WriteTo` which Go forbids on connected sockets.

### Workarounds

- **Server** (`server/protocol/tlcp/dtlcp.go`): `net.ListenUDP` + `acceptDTLCP()` feeds pre-read ClientHello through `dtlcp.Server`. TODO: replace with `dtlcp.Listen` when upstream fixes.
- **Client** (`server/upstream/tlcp/dtlcp.go`): `net.ListenPacket` + `dtlcp.Client()` + `HandshakeContext()`. TODO: replace with `dtlcp.Dial`.
- **Synchronous handling**: gotlcp shares one `*net.UDPConn` across all connections. Only one connection at a time until upstream provides per-connection isolation.
- Windows: IPv4 localhost DTLCP handshake unreliable — use `[::1]`.
