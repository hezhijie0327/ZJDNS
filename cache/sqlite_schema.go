package cache

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"zjdns/config"
	"zjdns/internal/log"
)

const (
	pageSize               = 4096 // SQLite page size in bytes (matches OS page)
	walAutoCheckpointPages = 4096 // trigger checkpoint at 16MB WAL (pageSize * walAutoCheckpointPages)
	schemaVersion          = 6    // increment to drop and recreate all tables on schema change
)

func (s *SQLiteCache) migrate() error {
	// PRAGMAs ordered by category: storage → memory → WAL.
	mmapSize := s.mmapSizeMB * 1024 * 1024
	cacheSize := -s.cacheSizeMB * 1024
	pragmaSQL := fmt.Sprintf(
		"PRAGMA page_size = %d;"+
			" PRAGMA cache_size = %d;"+
			" PRAGMA mmap_size = %d;"+
			" PRAGMA temp_store = MEMORY;"+
			" PRAGMA wal_autocheckpoint = %d;"+
			" PRAGMA journal_size_limit = %d;",
		pageSize, cacheSize, mmapSize, walAutoCheckpointPages, mmapSize,
	)
	if _, err := s.db.Exec(pragmaSQL); err != nil {
		log.Warnf("CACHE: pragma failed (non-fatal): %v", err)
	}

	// Schema versioning: bump schemaVersion to drop and recreate all tables.
	// The migration unconditionally drops old tables when versions differ,
	// then recreates from scratch — no in-place migration logic needed.
	var version int
	_ = s.db.QueryRow("SELECT version FROM schema_version").Scan(&version)
	if version != schemaVersion {
		log.Infof("CACHE: schema v%d → v%d, rebuilding all tables", version, schemaVersion)
		if s.dbPath != "" {
			// Disk-backed: close, delete the file, reopen. O(1).
			_ = s.db.Close()
			_ = os.Remove(s.dbPath)
			db, err := openDB(s.dbPath)
			if err != nil {
				return fmt.Errorf("sqlite reopen: %w", err)
			}
			s.db = db
			// Reapply pragmas on the fresh database.
			if _, err := s.db.Exec(pragmaSQL); err != nil {
				log.Warnf("CACHE: pragma failed on reopen (non-fatal): %v", err)
			}
		}
		// In-memory: nothing to drop — the DB is fresh on every process start.
	}

	//nolint:gosec // G202: DDL migration with constant schema version
	_, err := s.db.Exec(`
		-- ── Schema versioning ───────────────────────────────────────────────
		-- Single-row table that tracks the current schema version. When the
		-- version changes, old tables are dropped and recreated cleanly.

		CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
		INSERT OR REPLACE INTO schema_version (rowid, version) VALUES (1, ` + strconv.Itoa(schemaVersion) + `);

		-- ── Core DNS response cache ─────────────────────────────────────────
		-- Every row is a cacheable DNS response. The unique lookup key is
		-- (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok). Wire
		-- format is zstd-compressed and stored in msg_wire; Get() decompresses
		-- and unpacks in a single step.

		CREATE TABLE IF NOT EXISTS entries (
			-- Lookup key (UNIQUE constraint below)
			qname      TEXT NOT NULL,       -- normalized FQDN (zdnsutil.NormalizeDomain)
			qtype      INTEGER NOT NULL,    -- dns.TypeA=1, AAAA=28, DNSKEY=48, ...
			qclass     INTEGER NOT NULL DEFAULT 1,
			ecs_addr   TEXT NOT NULL DEFAULT '',
			ecs_prefix INTEGER NOT NULL DEFAULT 0,
			dnssec_ok  INTEGER NOT NULL DEFAULT 0 CHECK (dnssec_ok IN (0, 1)),
			-- Lifecycle
			timestamp  INTEGER NOT NULL,    -- insertion time (unix seconds)
			ttl        INTEGER NOT NULL,    -- entry TTL (min of all RR TTLs, floor 10s)
			expires_at INTEGER NOT NULL DEFAULT 0,
			-- Flags
			validated  INTEGER NOT NULL DEFAULT 0 CHECK (validated IN (0, 1)),
			-- zstd-compressed wire format (Answer + Authority + Additional)
			msg_wire   BLOB,
			-- PK + constraint
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		-- Eviction index: sorted by expires_at for efficient range scans when
		-- selecting candidates to evict (oldest expire-first, then by
		-- insertion timestamp).

		CREATE INDEX IF NOT EXISTS idx_entries_expires ON entries(expires_at);

		-- ── PTR reverse lookup (depends on entries) ────────────────────────
		-- Lightweight IP→domain mapping. WITHOUT ROWID uses the clustered PK
		-- directly — no separate index B-tree. ON DELETE CASCADE from entries
		-- keeps ptr_map automatically clean when cache entries are evicted.

		CREATE TABLE IF NOT EXISTS ptr_map (
			rdata_ip TEXT NOT NULL,
			entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			name     TEXT NOT NULL,
			ttl      INTEGER NOT NULL,
			PRIMARY KEY (rdata_ip, entry_id, name)
		) WITHOUT ROWID;

		-- ── Request journal (depends on entries via FK) ──────────────────
		-- Append-only log of every served query. One row per request.
		-- Stats() aggregates from this table; per-request debugging queries
		-- against qname/qtype/rcode/protocol. Survives FlushDB("stats").
		-- entry_id links to the cache entry that owns this request.
		-- ensureEntry guarantees every row has a valid FK. ON DELETE
		-- CASCADE keeps log size bounded by the cache — when an entry is
		-- evicted, its associated log rows go with it.

		CREATE TABLE IF NOT EXISTS request_log (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp       INTEGER NOT NULL,
			entry_id        INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			protocol        TEXT NOT NULL,
			result          TEXT NOT NULL,
			response_time_ms INTEGER NOT NULL DEFAULT 0,
			rcode           INTEGER NOT NULL DEFAULT 0,
			server          TEXT NOT NULL DEFAULT '',
			hijack          INTEGER NOT NULL DEFAULT 0,
			fallback        INTEGER NOT NULL DEFAULT 0,
			dnssec_status   TEXT NOT NULL DEFAULT ''
		);

		-- Time-range scans: Stats() filtering and time-windowed debugging
		-- queries (e.g. "last hour").

		CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_request_log_entry ON request_log(entry_id);

		-- ── Hit counters (depends on entries via FK) ─────────────────────
		-- Aggregated hit counts per entry+protocol. Each cache hit upserts
		-- here instead of inserting into request_log. ON DELETE CASCADE
		-- keeps counters bounded by cache eviction.

		CREATE TABLE IF NOT EXISTS entry_hit_counters (
			entry_id          INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			protocol          TEXT NOT NULL,
			rcode             INTEGER NOT NULL DEFAULT 0,
			hit_count         INTEGER NOT NULL DEFAULT 0,
			total_response_ms INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (entry_id, protocol, rcode)
		) WITHOUT ROWID;

		-- ── Stats metadata (depends on request_log semantically) ───────────
		-- Single row tracking the last request_log.id that was "cleared" by
		-- FlushDB("stats"). Stats() only considers request_log rows with
		-- id > cleared_before. Resetting stats is O(1): just UPDATE this row.

		CREATE TABLE IF NOT EXISTS stats_meta (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			cleared_before INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO stats_meta (id, cleared_before) VALUES (1, 0);

		-- ── Per-IP latency (independent, no FK) ────────────────────────────
		-- Keyed by rdata_ip only — latency is a property of the IP address,
		-- not the domain name. All domains sharing the same CDN IP reuse the
		-- same row. qtype is inferred from IP format (A=1, AAAA=28) for
		-- address-family analytics. Rows with last_probe_time older than
		-- defaultStaleMaxAge (30 days) are cleaned up during eviction.

		CREATE TABLE IF NOT EXISTS ip_latency (
			rdata_ip        TEXT NOT NULL,
			qtype           INTEGER NOT NULL DEFAULT 0,
			latency_ms      INTEGER NOT NULL,
			last_probe_time INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (rdata_ip)
		) WITHOUT ROWID;
	`)
	if err != nil {
		return err
	}

	// Populate query planner statistics so SQLite can make informed
	// index selection decisions (sqlite_stat1 table).
	if _, err := s.db.Exec("ANALYZE"); err != nil {
		log.Warnf("CACHE: ANALYZE failed (non-fatal): %v", err)
	}
	return nil
}

// ensureEntry returns the entry ID for the given cache key, creating a
// lightweight stub if one doesn't exist. The stub has DefaultStaleTTL
// lifetime and empty msg_wire; it will be replaced if Set() later fills
// this key with real data (INSERT OR REPLACE).
func (s *SQLiteCache) ensureEntry(qname string, qtype, qclass int, ecsAddr string, ecsPrefix, dnssecInt int) int64 {
	// Fast path: entry already exists.
	var id int64
	err := s.stmtEnsureEntry.QueryRow(
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&id)
	if err == nil {
		return id
	}

	// Slow path: create stub. Serialized via writeMu to avoid racing with
	// concurrent Set() on the same key.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Double-check after acquiring the lock.
	err = s.stmtEnsureEntry.QueryRow(
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&id)
	if err == nil {
		return id
	}

	now := log.NowUnix()
	err = s.db.QueryRow(
		`INSERT OR IGNORE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, msg_wire)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 RETURNING id`,
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
		now, config.DefaultStaleTTL, now+int64(config.DefaultStaleTTL), 0,
	).Scan(&id)
	if err != nil {
		// INSERT OR IGNORE silently skipped — a concurrent Set() won.
		_ = s.stmtEnsureEntry.QueryRow(
			qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
		).Scan(&id)
	}
	return id
}

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?"+dsnParams)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(config.DefaultCacheMaxOpenConns)
	db.SetMaxIdleConns(config.DefaultCacheMaxIdleConns)
	return db, nil
}
