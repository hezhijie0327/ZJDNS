package database

import (
	"fmt"
	"sort"
	"zjdns/internal/log"
)

// Version is the current schema version, set by the caller before Open().
// It should match the application version (e.g. "3.1.0"). Migrations tagged
// with a version ≤ this will be skipped; migrations > this will be applied.
var Version = "0.0.0"

const minSupportedVersion = "3.0.0" // refuse to upgrade from anything older

// migration describes an incremental schema change.
type migration struct {
	version string // app version that introduced this migration
	name    string
	fn      func(db *DB) error
}

// migrations is the ordered list of schema migrations. Each entry must be
// idempotent so it is safe to re-run on already-migrated databases.
// Add new entries here and bump Version.
var migrations = []migration{
	{"3.1.0", "drop legacy schema_version table", migrateV3_1_0},
	{"3.2.0", "rebuild zone_entries with match_tags in PK", migrateV3_2_0},
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

// sort migrations by version on init. Uses simple string compare; for
// semver this works as long as major.minor.patch components are zero-padded
// equivalently (e.g. "3.1.0" < "3.10.0").
func init() {
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
}

// runMigrations applies any pending incremental migrations.
func (db *DB) runMigrations() error {
	var applied string
	_ = db.SQ.QueryRow("SELECT version FROM version").Scan(&applied)

	if applied != "" && applied < minSupportedVersion {
		return fmt.Errorf(
			"database too old: version %s is below minimum supported %s; upgrade through an intermediate version first",
			applied, minSupportedVersion,
		)
	}

	if applied == "" {
		applied = "0.0.0"
	}

	if applied < Version {
		log.Infof("CACHE: running migrations %s → %s", applied, Version)
		for _, m := range migrations {
			if m.version <= applied {
				continue
			}
			log.Infof("CACHE: migration %s: %s", m.version, m.name)
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
