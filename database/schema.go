package database

import (
	"fmt"
	"zjdns/internal/log"
)

const (
	pageSize               = 4096
	walAutoCheckpointPages = 4096
)

func (db *DB) migrate() error {
	mmapSize := db.mmapSizeMB * 1024 * 1024
	cacheSize := -db.cacheSizeMB * 1024
	pragmaSQL := fmt.Sprintf(
		"PRAGMA page_size = %d;"+
			" PRAGMA cache_size = %d;"+
			" PRAGMA mmap_size = %d;"+
			" PRAGMA temp_store = MEMORY;"+
			" PRAGMA foreign_keys = ON;"+
			" PRAGMA wal_autocheckpoint = %d;"+
			" PRAGMA journal_size_limit = %d;",
		pageSize, cacheSize, mmapSize, walAutoCheckpointPages, mmapSize,
	)
	if _, err := db.SQ.Exec(pragmaSQL); err != nil {
		log.Warnf("DB: pragma failed (non-fatal): %v", err)
	}

	//nolint:gosec // G202: DDL migration with constant schema version
	_, err := db.SQ.Exec(`
		-- ── Project version ───────────────────────────────────────────────────
		-- Tracks the current project version. Base DDL starts at 0.0.0.
		-- Pending migrations run in order via migration.go/runMigrations().

		CREATE TABLE IF NOT EXISTS version (version TEXT NOT NULL);
		INSERT OR IGNORE INTO version (rowid, version) VALUES (1, '` + Version + `');

		-- ── Stats metadata ─────────────────────────────────────────────────────
		-- Single row tracking the last request_log.id that was cleared by
		-- FlushDB("stats"). Resetting stats is O(1): just UPDATE this row.

		CREATE TABLE IF NOT EXISTS stats_meta (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			cleared_before INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO stats_meta (id, cleared_before) VALUES (1, 0);

		-- ── DNS response cache ───────────────────────────────────────────────
		-- Every row is a cacheable DNS response keyed by (qname, qtype, qclass,
		-- ecs_addr, ecs_prefix, dnssec_ok). The wire format is zstd-compressed
		-- in msg_wire; Get() decompresses and unpacks in one step.

		CREATE TABLE IF NOT EXISTS entries (
			qname      TEXT NOT NULL,       -- normalized FQDN
			qtype      INTEGER NOT NULL,    -- dns.TypeA=1, AAAA=28, ...
			qclass     INTEGER NOT NULL DEFAULT 1,
			ecs_addr   TEXT NOT NULL DEFAULT '',
			ecs_prefix INTEGER NOT NULL DEFAULT 0,
			dnssec_ok  INTEGER NOT NULL DEFAULT 0 CHECK (dnssec_ok IN (0, 1)),
			timestamp  INTEGER NOT NULL,    -- insertion time (unix seconds)
			ttl        INTEGER NOT NULL,    -- min of all RR TTLs, floor 10s
			expires_at INTEGER NOT NULL DEFAULT 0,
			validated  INTEGER NOT NULL DEFAULT 0 CHECK (validated IN (0, 1)),
			msg_wire   BLOB,               -- zstd-compressed dns.Msg wire format
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		CREATE INDEX IF NOT EXISTS idx_entries_expires_ts ON entries(expires_at, timestamp);
		CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);

		-- ── PTR reverse lookup ───────────────────────────────────────────────
		-- Lightweight IP→domain mapping populated from A/AAAA rdata. WITHOUT
		-- ROWID uses the clustered PK directly. ON DELETE CASCADE cleans up
		-- automatically when cache entries are evicted.

		CREATE TABLE IF NOT EXISTS ptr_map (
			rdata_ip TEXT NOT NULL,
			entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			name     TEXT NOT NULL,
			ttl      INTEGER NOT NULL,
			PRIMARY KEY (rdata_ip, entry_id, name)
		) WITHOUT ROWID;
		CREATE INDEX IF NOT EXISTS idx_ptr_map_entry_id ON ptr_map(entry_id);

		-- ── Hit counters ─────────────────────────────────────────────────────
		-- Aggregated per-entry+protocol+rcode hit counts. Cache hits upsert
		-- here instead of inserting into request_log to avoid row bloat.
		-- ON DELETE CASCADE keeps counters bounded by cache eviction.

		CREATE TABLE IF NOT EXISTS entry_hit_counters (
			entry_id          INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			protocol          TEXT NOT NULL,
			rcode             INTEGER NOT NULL DEFAULT 0,
			hit_count         INTEGER NOT NULL DEFAULT 0,
			total_response_ms INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (entry_id, protocol, rcode)
		) WITHOUT ROWID;

		-- ── Request journal ──────────────────────────────────────────────────
		-- Append-only log of every non-hit query. qname/qtype/qclass stored
		-- directly (denormalized) — no JOIN needed for debugging. Survives
		-- FlushDB("stats"). entry_id is NULL for zone/error/badcookie paths.

		CREATE TABLE IF NOT EXISTS request_log (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp       INTEGER NOT NULL,
			qname           TEXT NOT NULL DEFAULT '',
			qtype           INTEGER NOT NULL DEFAULT 0,
			qclass          INTEGER NOT NULL DEFAULT 1,
			entry_id        INTEGER,
			protocol        TEXT NOT NULL,
			result          TEXT NOT NULL,
			response_time_ms INTEGER NOT NULL DEFAULT 0,
			rcode           INTEGER NOT NULL DEFAULT 0,
			server          TEXT NOT NULL DEFAULT '',
			hijack          INTEGER NOT NULL DEFAULT 0,
			fallback        INTEGER NOT NULL DEFAULT 0,
			dnssec_status   TEXT NOT NULL DEFAULT ''
		);

		CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(timestamp);

		-- ── Per-IP latency ───────────────────────────────────────────────────
		-- Keyed by rdata_ip only — latency is a property of the IP, not the
		-- domain. All domains sharing the same CDN IP reuse the same row.
		-- Rows with stale last_probe_time are cleaned up during eviction.

		CREATE TABLE IF NOT EXISTS ip_latency (
			rdata_ip        TEXT NOT NULL,
			qtype           INTEGER NOT NULL DEFAULT 0,
			latency_ms      INTEGER NOT NULL,
			last_probe_time INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (rdata_ip)
		) WITHOUT ROWID;
		CREATE INDEX IF NOT EXISTS idx_ip_latency_probe ON ip_latency(last_probe_time);

		-- ── Ruleset entries ───────────────────────────────────────────────
		-- Stores rule set entries loaded from config. IP entries are CIDR
		-- strings; domain entries are TLD+1 keys.  PK is ordered (type, tag,
		-- value) so WHERE type='ip' / WHERE type='domain' AND tag=? use a PK
		-- prefix seek instead of a full scan.

		CREATE TABLE IF NOT EXISTS ruleset_entries (
			tag   TEXT NOT NULL,
			type  TEXT NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (type, tag, value)
		) WITHOUT ROWID;

		-- ── Zone rules ───────────────────────────────────────────────────────
		-- Zone-file-style rule table queried via WITHOUT ROWID B-tree clustered
		-- on (is_wildcard, qname, qtype, qclass, match_tags). Exact lookups use
		-- is_wildcard=0 prefix; wildcard batch IN uses is_wildcard=1 prefix.
		-- answer/authority/additional store zstd-compressed wire-format RR sets.

		CREATE TABLE IF NOT EXISTS zone_entries (
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
	`)
	if err != nil {
		return err
	}

	// Apply incremental migrations.
	if err := db.runMigrations(); err != nil {
		return err
	}

	if db.dbPath != "" {
		if _, err := db.SQ.Exec("ANALYZE"); err != nil {
			log.Warnf("DB: ANALYZE failed (non-fatal): %v", err)
		}
	}
	return nil
}
