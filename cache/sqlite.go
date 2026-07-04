package cache

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"zjdns/internal/log"
)

// sqliteStore provides SQLite-backed persistent storage for cache entries.
type sqliteStore struct {
	db *sql.DB
}

// openSQLite opens (or creates) the SQLite database at path, enables WAL mode,
// and creates the schema if needed.
func openSQLite(path string) (*sqliteStore, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}

	store := &sqliteStore{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}
	return store, nil
}

func (s *sqliteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			key       TEXT PRIMARY KEY,
			data      BLOB NOT NULL,
			timestamp INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS ptr_index (
			ip   TEXT NOT NULL,
			name TEXT NOT NULL,
			ttl  INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (ip, name)
		);

		CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);
	`)
	return err
}

func (s *sqliteStore) Close() error {
	return s.db.Close()
}

// SaveEntry writes a cache entry and its PTR records to SQLite in a single
// transaction.
func (s *sqliteStore) SaveEntry(key string, entry *Entry, ptrs []ptrRecord) error {
	if entry == nil {
		return nil
	}
	cloned := cloneEntryForPersist(entry)

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cloned); err != nil {
		return fmt.Errorf("gob encode entry: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO entries (key, data, timestamp) VALUES (?, ?, ?)`,
		key, buf.Bytes(), cloned.Timestamp,
	); err != nil {
		return fmt.Errorf("insert entry: %w", err)
	}

	ipMap := make(map[string]struct{}, len(ptrs))
	for _, pr := range ptrs {
		ipMap[pr.IP] = struct{}{}
	}
	for ip := range ipMap {
		if _, err := tx.Exec(`DELETE FROM ptr_index WHERE ip = ? AND name = ?`, ip, entryKey(key, ptrs)); err != nil {
			return fmt.Errorf("delete ptrs: %w", err)
		}
	}
	for _, pr := range ptrs {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO ptr_index (ip, name, ttl) VALUES (?, ?, ?)`,
			pr.IP, pr.Name, pr.TTL,
		); err != nil {
			return fmt.Errorf("insert ptr: %w", err)
		}
	}

	return tx.Commit()
}

// entryKey returns the primary cache key for PTR cleanup — the first entry name
// if ptrs are present, otherwise falls back to the cache key.
func entryKey(key string, ptrs []ptrRecord) string {
	if len(ptrs) > 0 {
		return ptrs[0].Name
	}
	return key
}

// LoadAll returns all cache entries stored in SQLite.
func (s *sqliteStore) LoadAll() ([]persistedCacheItem, error) {
	rows, err := s.db.Query(`SELECT key, data, timestamp FROM entries`)
	if err != nil {
		return nil, fmt.Errorf("query entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var items []persistedCacheItem
	for rows.Next() {
		var key string
		var data []byte
		var ts int64
		if err := rows.Scan(&key, &data, &ts); err != nil {
			log.Warnf("CACHE: sqlite row scan failed: %v", err)
			continue
		}
		var entry Entry
		if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
			log.Warnf("CACHE: sqlite gob decode failed for key %s: %v", key, err)
			continue
		}
		items = append(items, persistedCacheItem{Key: key, Entry: &entry})
	}
	return items, rows.Err()
}

// LookupPTR returns all domain names associated with an IP address.
func (s *sqliteStore) LookupPTR(ip string) ([]LookupResult, error) {
	rows, err := s.db.Query(`SELECT name, ttl FROM ptr_index WHERE ip = ? ORDER BY name`, ip)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var results []LookupResult
	for rows.Next() {
		var r LookupResult
		if err := rows.Scan(&r.Name, &r.TTL); err != nil {
			continue
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

// DeleteStale removes entries older than maxAge seconds.
func (s *sqliteStore) DeleteStale(maxAge int64) (int64, error) {
	cutoff := time.Now().Unix() - maxAge
	res, err := s.db.Exec(`DELETE FROM entries WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Count returns the total number of cached entries.
func (s *sqliteStore) Count() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&n)
	return n, err
}

// persistedCacheItem is a key-entry pair used during snapshot migration and
// for loading entries from SQLite into memory.
type persistedCacheItem struct {
	Key   string
	Entry *Entry
	PTRs  []ptrRecord
}

// cloneEntryForPersist deep-copies an Entry and clears cached RR fields
// so gob can encode without type registration.
func cloneEntryForPersist(entry *Entry) *Entry {
	cloned := cloneEntry(entry)
	if cloned == nil {
		return nil
	}
	clearRRFields(cloned.Answer)
	clearRRFields(cloned.Authority)
	clearRRFields(cloned.Additional)
	return cloned
}

// clearRRFields nils the cached RR field in CompactRecords so gob can encode.
func clearRRFields(records []*CompactRecord) {
	for _, r := range records {
		if r != nil {
			r.RR = nil
		}
	}
}
