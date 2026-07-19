package database

import (
	"fmt"
	"zjdns/internal/log"
)

// migration describes an incremental schema change.
type migration struct {
	version string // app version that introduced this migration
	name    string
	fn      func(db *DB) error
}

const minSupportedVersion = "3.0.0" // refuse to upgrade from anything older

// Version is the current schema version, set by the caller before Open().
// It should match the application version (e.g. "3.1.0"). Migrations tagged
// with a version ≤ this will be skipped; migrations > this will be applied.
var Version = "0.0.0"

// migrations is the ordered list of schema migrations. Each entry must be
// idempotent so it is safe to re-run on already-migrated databases.
// Add new entries at the end in version order; runMigrations iterates
// in slice order.
var migrations = []migration{
	{"3.1.0", "drop legacy schema_version table", migrateV3_1_0},
	{"3.2.0", "rebuild zone_entries with match_tags in PK", migrateV3_2_0},
	{"3.2.1", "add performance indexes and drop redundant idx_zone_qname", migrateV3_2_1},
	{"3.2.13", "rebuild zone_entries PK with is_wildcard", migrateV3_2_13},
	{"3.2.17", "drop nsec_chain table", migrateV3_2_17},
	{"3.2.19", "drop redundant idx_entries_expires", migrateV3_2_19},
	{"3.2.20", "rebuild zone_entries WITHOUT ROWID with is_wildcard-first PK", migrateV3_2_20},
	{"3.2.21", "denormalize qname/qtype/qclass into request_log", migrateV3_2_21},
	{"3.2.22", "drop infra_cache table", migrateV3_2_22},
	{"3.3.5", "normalize protocol identifiers in request_log and entry_hit_counters", migrateV3_3_5},
	{"3.4.6", "reorder ruleset_entries PK to (type, tag, value) for index-seek queries", migrateV3_4_6},
	{"3.4.18", "add last_hit_time to entry_hit_counters for time-based cleanup", migrateV3_4_18},
	{"3.4.19", "query-stats-sliding-window", migrateV3_4_19},
	{"3.4.24", "fqdn-canonical-form", migrateV3_4_24},
}

func migrateV3_2_17(db *DB) error {
	_, err := db.SQ.Exec("DROP TABLE IF EXISTS nsec_chain")
	return err
}

func migrateV3_2_19(db *DB) error {
	// idx_entries_expires_ts(expires_at, timestamp) covers all queries that
	// idx_entries_expires(expires_at) could serve, since expires_at is the
	// leading column. Drop the redundant index to reduce write overhead.
	_, err := db.SQ.Exec("DROP INDEX IF EXISTS idx_entries_expires")
	return err
}

func migrateV3_2_20(db *DB) error {
	_, err := db.SQ.Exec(`
		CREATE TABLE IF NOT EXISTS zone_entries_new (
			is_wildcard INTEGER NOT NULL DEFAULT 0,
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL DEFAULT 0,
			qclass     INTEGER NOT NULL DEFAULT 0,
			rcode      INTEGER NOT NULL DEFAULT 0,
			answer     BLOB,
			authority  BLOB,
			additional BLOB,
			match_tags TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (is_wildcard, qname, qtype, qclass, match_tags)
		) WITHOUT ROWID;
		INSERT INTO zone_entries_new SELECT is_wildcard, qname, qtype, qclass, rcode, answer, authority, additional, match_tags FROM zone_entries;
		DROP TABLE zone_entries;
		ALTER TABLE zone_entries_new RENAME TO zone_entries;
	`)
	if err != nil {
		return err
	}
	return nil
}

func migrateV3_2_21(db *DB) error {
	_, err := db.SQ.Exec(`
		CREATE TABLE IF NOT EXISTS request_log_new (
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
		INSERT OR IGNORE INTO request_log_new
			SELECT rl.id, rl.timestamp,
				COALESCE(e.qname, ''), COALESCE(e.qtype, 0), COALESCE(e.qclass, 1),
				rl.entry_id,
				rl.protocol, rl.result, rl.response_time_ms, rl.rcode,
				rl.server, rl.hijack, rl.fallback, rl.dnssec_status
			FROM request_log rl
			LEFT JOIN entries e ON rl.entry_id = e.id;
		DROP TABLE request_log;
		ALTER TABLE request_log_new RENAME TO request_log;
		CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(timestamp);
		DROP INDEX IF EXISTS idx_request_log_entry;
	`)
	if err != nil {
		return err
	}
	return nil
}

func migrateV3_2_22(db *DB) error {
	_, err := db.SQ.Exec("DROP TABLE IF EXISTS infra_cache")
	return err
}

func migrateV3_2_13(db *DB) error {
	_, err := db.SQ.Exec(`
		CREATE TABLE IF NOT EXISTS zone_entries_new (
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL DEFAULT 0,
			qclass     INTEGER NOT NULL DEFAULT 0,
			rcode      INTEGER NOT NULL DEFAULT 0,
			answer     BLOB,
			authority  BLOB,
			additional BLOB,
			match_tags TEXT NOT NULL DEFAULT '',
			is_wildcard INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (qname, qtype, qclass, is_wildcard, match_tags)
		);
		INSERT OR IGNORE INTO zone_entries_new SELECT * FROM zone_entries;
		DROP TABLE zone_entries;
		ALTER TABLE zone_entries_new RENAME TO zone_entries;
	`)
	if err != nil {
		return fmt.Errorf("v3.2.13: %w", err)
	}
	return nil
}

func migrateV3_2_1(db *DB) error {
	for _, sql := range []string{
		`CREATE INDEX IF NOT EXISTS idx_entries_expires_ts ON entries(expires_at, timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_ip_latency_probe ON ip_latency(last_probe_time)`,
		`DROP INDEX IF EXISTS idx_zone_qname`,
	} {
		if _, err := db.SQ.Exec(sql); err != nil {
			return fmt.Errorf("v3.2.1: %w", err)
		}
	}
	return nil
}

func migrateV3_2_0(db *DB) error {
	// Rebuild zone_entries with match_tags in the primary key so multiple
	// rules for the same (qname, qtype, qclass) with different match tags
	// can coexist.
	_, err := db.SQ.Exec(`
		CREATE TABLE IF NOT EXISTS zone_entries_new (
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL DEFAULT 0,
			qclass     INTEGER NOT NULL DEFAULT 0,
			rcode      INTEGER NOT NULL DEFAULT 0,
			answer     BLOB,
			authority  BLOB,
			additional BLOB,
			match_tags TEXT NOT NULL DEFAULT '',
			is_wildcard INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (qname, qtype, qclass, match_tags)
		);
		INSERT OR REPLACE INTO zone_entries_new SELECT * FROM zone_entries;
		DROP TABLE zone_entries;
		ALTER TABLE zone_entries_new RENAME TO zone_entries;
	`)
	return err
}

func migrateV3_1_0(db *DB) error {
	var count int
	_ = db.SQ.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
	).Scan(&count)
	if count > 0 {
		if _, err := db.SQ.Exec(`DROP TABLE schema_version`); err != nil {
			return err
		}
	}
	return nil
}

// runMigrations applies any pending incremental migrations.
func (db *DB) runMigrations() error {
	var applied string
	_ = db.SQ.QueryRow("SELECT version FROM version").Scan(&applied)

	// "0.0.0" is the sentinel set by base DDL for fresh databases — treat as
	// current and let runMigrations apply any pending migrations on top.
	if applied != "" && applied != "0.0.0" && applied < minSupportedVersion {
		return fmt.Errorf(
			"database too old: version %s is below minimum supported %s; upgrade through an intermediate version first",
			applied, minSupportedVersion,
		)
	}

	if applied == "" {
		applied = "0.0.0"
	}

	if applied < Version {
		log.Infof("DB: running migrations %s → %s", applied, Version)
		for _, m := range migrations {
			if m.version <= applied {
				continue
			}
			log.Infof("DB: migration %s: %s", m.version, m.name)
			if err := m.fn(db); err != nil {
				return fmt.Errorf("migration %s (%s): %w", m.version, m.name, err)
			}
		}
	}

	// Always sync version to current app version.
	if applied != Version {
		if _, err := db.SQ.Exec(
			`INSERT OR REPLACE INTO version (rowid, version) VALUES (1, ?)`,
			Version,
		); err != nil {
			return fmt.Errorf("update version to %s: %w", Version, err)
		}
	}
	return nil
}

// migrateV3_4_19 drops the old stats tables (entry_hit_counters, request_log,
// stats_meta). The new tables (query_stats, query_log) are created by the base
// DDL which runs before migrations on every startup.
func migrateV3_4_19(db *DB) error {
	for _, sql := range []string{
		`DROP TABLE IF EXISTS entry_hit_counters`,
		`DROP TABLE IF EXISTS request_log`,
		`DROP TABLE IF EXISTS stats_meta`,
	} {
		if _, err := db.SQ.Exec(sql); err != nil {
			return err
		}
	}
	return nil
}

// migrateV3_3_5 normalizes protocol identifiers stored in request_log and
// entry_hit_counters to match canonical config field names (dot->tls, doq->quic,
// doh->https, doh3->http3, dod->dtls, doh-tlcp->http-tlcp). Each UPDATE is
// idempotent — already-migrated rows are unaffected.
func migrateV3_4_18(db *DB) error {
	// Add last_hit_time to entry_hit_counters for time-based aging.
	// Idempotent: ALTER TABLE ADD COLUMN is a no-op if column already exists
	// (SQLite ignores duplicate column names in ALTER TABLE, but for safety
	// we check via PRAGMA first).
	var hasColumn bool
	_ = db.SQ.QueryRow(
		"SELECT COUNT(*) FROM pragma_table_info('entry_hit_counters') WHERE name='last_hit_time'",
	).Scan(&hasColumn)
	if !hasColumn {
		if _, err := db.SQ.Exec(
			`ALTER TABLE entry_hit_counters ADD COLUMN last_hit_time INTEGER NOT NULL DEFAULT 0`,
		); err != nil {
			return fmt.Errorf("add last_hit_time: %w", err)
		}
	}
	return nil
}

func migrateV3_4_6(db *DB) error {
	// Rebuild ruleset_entries with PK (type, tag, value) so WHERE type=? uses
	// a PK prefix seek instead of a full table scan. Add index for type+value
	// domain lookups.
	_, err := db.SQ.Exec(`
		CREATE TABLE IF NOT EXISTS ruleset_entries_new (
			tag   TEXT NOT NULL,
			type  TEXT NOT NULL,
			value TEXT NOT NULL,
			PRIMARY KEY (type, tag, value)
		) WITHOUT ROWID;
		INSERT OR REPLACE INTO ruleset_entries_new SELECT tag, type, value FROM ruleset_entries;
		DROP TABLE ruleset_entries;
		ALTER TABLE ruleset_entries_new RENAME TO ruleset_entries;
		CREATE INDEX IF NOT EXISTS idx_ruleset_type_value ON ruleset_entries(type, value);
	`)
	return err
}

func migrateV3_3_5(db *DB) error {
	renames := [][2]string{
		{"dot", "tls"},
		{"doq", "quic"},
		{"doh", "https"},
		{"doh3", "http3"},
		{"dod", "dtls"},
		{"doh-tlcp", "http-tlcp"},
	}
	for _, r := range renames {
		if _, err := db.SQ.Exec("UPDATE request_log SET protocol = ? WHERE protocol = ?", r[1], r[0]); err != nil {
			return fmt.Errorf("update request_log protocol %s->%s: %w", r[0], r[1], err)
		}
		if _, err := db.SQ.Exec("UPDATE entry_hit_counters SET protocol = ? WHERE protocol = ?", r[1], r[0]); err != nil {
			return fmt.Errorf("update entry_hit_counters protocol %s->%s: %w", r[0], r[1], err)
		}
	}
	return nil
}

func migrateV3_4_24(db *DB) error {
	// Canonical form switched from no-trailing-dot (NormalizeDomain) to
	// FQDN with trailing dot (dnsutil.Canonical). Update all stored domain
	// names that don't already end with '.'.
	tables := []struct {
		table string
		col   string
	}{
		{"entries", "qname"},
		{"query_log", "qname"},
		{"ptr_map", "name"},
		{"zone_entries", "qname"},
	}
	for _, t := range tables {
		query := fmt.Sprintf( //nolint:gosec // G201: table and column names are hardcoded in the loop above
			"UPDATE %s SET %s = %s || '.' WHERE %s != '' AND %s != '.' AND %s NOT LIKE '%%.'",
			t.table, t.col, t.col, t.col, t.col, t.col,
		)
		if _, err := db.SQ.Exec(query); err != nil {
			return fmt.Errorf("fqdn migration %s.%s: %w", t.table, t.col, err)
		}
	}
	return nil
}
