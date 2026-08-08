# Architecture Reference

Detailed technical reference for ZJDNS. For working guidelines, see [CLAUDE.md](../CLAUDE.md).

## DB Schema

The unified database (`database/`) contains ten SQLite tables (`modernc.org/sqlite`, WAL mode, mmap, zstd compression):

```sql
-- Project version (singleton row). Set at build time via database.Version.
CREATE TABLE version (version TEXT NOT NULL);

-- DNS response cache. Uniqueness: (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok).
-- msg_wire holds the pre-packed response (format 0x02): [0x02][2:num TTL
-- offsets][2 each:offset][wire], where wire may be zstd-compressed above the
-- compression threshold.  The wire carries the full response header —
-- including the RCODE (e.g. NXDOMAIN) — so cache hits serve the exact rcode.
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

-- Query statistics: per-day aggregated counters for all results.  Auto-pruned
-- by config.DefaultQueryJournalRetention.  Stats() reads this single table.
CREATE TABLE query_stats (
    stat_day    INTEGER NOT NULL,   -- unixepoch() / 86400
    result      TEXT NOT NULL,      -- 'hit','miss','stale','zone','error','blocked','badcookie'
    protocol    TEXT NOT NULL,
    rcode       INTEGER NOT NULL DEFAULT 0,
    dnssec      TEXT NOT NULL DEFAULT '',  -- 'secure','insecure','bogus','' for hits
    poisoned      INTEGER NOT NULL DEFAULT 0,
    query_count INTEGER NOT NULL DEFAULT 0,
    total_ms    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (stat_day, result, protocol, rcode, dnssec, poisoned)
) WITHOUT ROWID;

-- Query log: per-event audit trail for non-hit queries.  qname/qtype/qclass
-- stored directly (denormalized) — no JOIN needed for debugging.
CREATE TABLE query_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   INTEGER NOT NULL,
    qname       TEXT NOT NULL DEFAULT '',
    qtype       INTEGER NOT NULL DEFAULT 0,
    qclass      INTEGER NOT NULL DEFAULT 1,
    protocol    TEXT NOT NULL,
    result      TEXT NOT NULL,
    rcode       INTEGER NOT NULL DEFAULT 0,
    response_ms INTEGER NOT NULL DEFAULT 0,
    server      TEXT NOT NULL DEFAULT '',
    poisoned    INTEGER NOT NULL DEFAULT 0,
    dnssec      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_query_log_ts ON query_log(timestamp);

-- PTR reverse-lookup (IP → domain).
CREATE TABLE ptr_map (
    rdata_ip TEXT NOT NULL,
    entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,
    ttl      INTEGER NOT NULL,
    PRIMARY KEY (rdata_ip, entry_id, name)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ptr_map_entry_id ON ptr_map(entry_id);

-- Per-IP latency measurements. Keyed by rdata_ip only.
CREATE TABLE ip_latency (
    rdata_ip        TEXT NOT NULL,
    qtype           INTEGER NOT NULL DEFAULT 0,
    latency_ms      INTEGER NOT NULL,
    last_probe_time INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rdata_ip)
) WITHOUT ROWID;
CREATE INDEX idx_ip_latency_probe ON ip_latency(last_probe_time);

-- Resolver-internal zone-cut delegation cache. Stores NS target names,
-- a small address snapshot, and verified DS records (NULL = insecure)
-- per zone. Lookup is suffix-based: for "www.baidu.com.", ancestor zones
-- "baidu.com." and "com." are probed; deepest fresh match wins.
-- Survives restarts; complements NS-address cache (TypeA/TypeAAAA entries)
-- and DNSKEY cache (TypeDNSKEY entries).
CREATE TABLE delegations (
    zone       TEXT NOT NULL PRIMARY KEY,
    parent     TEXT NOT NULL DEFAULT '',
    ns_names   TEXT NOT NULL,
    addrs      TEXT NOT NULL DEFAULT '',
    ds_wire    BLOB,               -- wire-format DS; NULL = insecure delegation
    timestamp  INTEGER NOT NULL,
    ttl        INTEGER NOT NULL,
    expires_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_delegations_expires ON delegations(expires_at);

-- Ruleset entries loaded from config. PK (type, tag, value) enables a prefix
-- seek for WHERE type='domain' AND tag=?. IP entries are CIDR strings.
CREATE TABLE ruleset_entries (
    tag   TEXT NOT NULL,
    type  TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (type, tag, value)
) WITHOUT ROWID;

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

-- DNSCrypt state (singleton): Ed25519 identity (96B) + serialized cert
-- windows. Persisted so a restart resumes the same windows (v3.7.17).
CREATE TABLE dnscrypt_state (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    identity BLOB NOT NULL,
    windows  BLOB NOT NULL
);
```

### Key Patterns

- **Cache hit path**: pre-packed wire (format 0x02: TTL-offset table + packed
  response). `Get()` serves the wire directly — the Response middleware
  patches the message ID/RD bits and bridge.go writes it without any
  Unpack/Pack round-trip (~20ns at the middleware layer, 0 allocs). TTL
  deduction happens in-place via the offset table; DNSSEC filtering for
  DO=0 clients uses a wire scan (WireHasDNSSEC). Entries below the
  compression threshold are stored uncompressed (no decompress either).
- **RecordRequest**: All results → `query_stats` (per-day upsert, ~500 row sliding window). Non-hit events also → `query_log` (audit trail with denormalized qname/qtype/qclass, no JOIN needed).
- **Stats aggregation**: `Stats()` uses a single scan of `query_stats` with CASE expressions (result + protocol + rcode + dnssec + poisoned distributions computed inline). ~500 rows regardless of query volume.
- **Pruning**: `PruneQueryJournal` runs at `config.DefaultPruneInterval`, deleting `query_stats` rows past `config.DefaultQueryJournalRetention` (PK prefix seek) and `query_log` rows via batched delete (`config.DefaultPruneBatchSize` rows per iteration, using `idx_query_log_ts`). Fallback cleanup via `config.DefaultStaleMaxAge` in `evictOldest`.
- **Eviction**: On `Set()` when count > maxEntries. Prefers past serve-stale, then oldest. `ON DELETE CASCADE` for ptr_map. Stale ip_latency + query_log rows pruned during eviction.
- **NS latency cache**: NS/Root addresses as TypeA/TypeAAAA entries. Latency probed via `ProbeNSAddrs`, reordered by `sortAnswerByLatency` at `Get()` time.
- **Delegation cache**: Zone-cut delegations (zone to NS names + verified DS) in `delegations` table. Populated at every delegation crossing during recursive walks; only secure (verified DS) or insecure (authenticated no-DS) delegations are stored. On subsequent queries, suffix-lookup finds the deepest fresh delegation for the qname and starts the walk from that zone instead of the root, skipping already-walked delegation levels. DNSKEYs are fetched fresh by `ensureZoneDNSKEYs` (verified against the cached DS); NS addresses are resolved from the existing TypeA/TypeAAAA cache with the stored address snapshot as a fallback.
- **IP latency**: Per-IP keyed. `INSERT OR REPLACE` writes latency_ms + last_probe_time. All domains sharing a CDN IP reuse the same row.
- **Dynamic queries**: `Store.Stats()` returns TXT records (overview, hits, errors, rcodes, poisoned, plain, encrypted, DNSCrypt, TLCP, DNSSEC). Write: `zjdns.cache.clear` / `zjdns.stats.clear` / `zjdns.ptr.clear` / `zjdns.latency.clear` / `zjdns.dnscrypt.clear` (loopback-only).


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
- Persistence: identity + cert windows stored in the `dnscrypt_state` SQLite table — a restart resumes the exact same windows (client-cached certs stay valid); config key change drops the persisted state and mints fresh windows
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

- **ZoneStorage interface**: `Evaluator` depends on `ZoneStorage` (not concrete `*database.DB`), following the same pattern as `ruleset.RuleSetStorage`. The interface provides `Exec`, `Begin`, `QueryZoneExact`, `QueryZoneWildcard`, and `Close`.
- **Wildcard matching**: Batch IN query with fixed 16 placeholders via `StmtZoneWildcard` prepared statement — single query replaces the old per-label N-query loop.
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
- **RFC 10029 MQTYPE**: `middleware/mqtype.go` (after CacheStore) validates
  and merges additional QTYPE responses in recursive mode; forwarding mode
  passes the option through via context (`resolver/mqtype_ctx.go`) and echoes
  the upstream's MQTYPE-Response.
- **RFC 8482 minimal ANY**: `middleware/any.go` (inside Zone) answers
  QTYPE=ANY with `HINFO "RFC8482"`.
- **RFC 6975**: upstream requests advertise DAU/DHU/N3U algorithm lists.
- **RFC 9715**: UDP responses capped at 1400 bytes; oversized wires are
  truncated in place by `truncateWire` (server/bridge.go) — TC=1, no
  Unpack/Pack round-trip.
