// Package database provides a unified SQLite database backing all ZJDNS subsystems
// (cache, zone). It manages connection lifecycle, schema migration, prepared
// statements, and shared utilities for wire-format compression.
package database

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"

	_ "github.com/ncruces/go-sqlite3/driver"
)

// Options configures SQLite PRAGMA tunables.
type Options struct {
	MMapSizeMB  int
	CacheSizeMB int
}

// DB is a unified SQLite database backing all ZJDNS subsystems (cache, zone).
// Uses *sql.DB (goroutine-safe connection pool) for both file and in-memory
// databases. :memory: is used for in-memory so all connections share the
// same database (pinned to a single connection).
type DB struct {
	SQ     *sql.DB
	dbPath string

	mmapSizeMB  int
	cacheSizeMB int
	closed      int32

	// Cache subsystem
	maxEntries int
	entryCount atomic.Int64
	writeMu    sync.Mutex

	// Cache prepared statements
	StmtEntry         *sql.Stmt
	StmtQueryLog      *sql.Stmt
	StmtQueryStats    *sql.Stmt
	StmtInsertLatency *sql.Stmt
	StmtLastProbe     *sql.Stmt

	// Zone prepared statements
	StmtZoneExact    *sql.Stmt
	StmtZoneWildcard *sql.Stmt

	// Latency prepared statements
	StmtIPLatency *sql.Stmt
}

const dsnParams = "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&_foreign_keys=ON&_txlock=immediate"

// Open opens or creates the SQLite database at path. An empty path uses
// :memory: (shared in-memory). maxEntries controls the cache eviction
// threshold.
func Open(path string, maxEntries int, opts Options) (*DB, error) {
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxCacheEntries
	}
	if opts.MMapSizeMB <= 0 {
		opts.MMapSizeMB = config.DefaultCacheMMapSizeMB
	}
	if opts.CacheSizeMB <= 0 {
		opts.CacheSizeMB = config.DefaultCacheCacheSizeMB
	}

	var dsn string
	if path == "" {
		dsn = ":memory:"
	} else {
		dsn = "file:" + path + "?" + dsnParams
	}

	sqldb, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	if path == "" {
		// :memory: — each connection gets its own DB, so pin to one.
		sqldb.SetMaxOpenConns(1)
		sqldb.SetMaxIdleConns(1)
	} else {
		sqldb.SetMaxOpenConns(config.DefaultCacheMaxOpenConns)
		sqldb.SetMaxIdleConns(config.DefaultCacheMaxIdleConns)
	}

	if err := sqldb.Ping(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}

	db := &DB{
		SQ:          sqldb,
		dbPath:      path,
		maxEntries:  maxEntries,
		mmapSizeMB:  opts.MMapSizeMB,
		cacheSizeMB: opts.CacheSizeMB,
	}

	if err := db.migrate(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}

	// Initialize entryCount from existing rows.
	var count int64
	if err := db.SQ.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err == nil {
		db.entryCount.Store(count)
	}

	if err := db.prepareStatements(); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("sqlite prepare: %w", err)
	}

	label := path
	if label == "" {
		label = "memory"
	}
	log.Infof("DB: SQLite database opened (db=%s, max_entries=%d, mmap_size=%dMB, cache_size=%dMB)",
		label, maxEntries, opts.MMapSizeMB, opts.CacheSizeMB)
	return db, nil
}

// Close closes the database, running PRAGMA optimize for disk-backed DBs before shutdown.
func (db *DB) Close() error {
	if !atomic.CompareAndSwapInt32(&db.closed, 0, 1) {
		return nil
	}
	for _, stmt := range []*sql.Stmt{
		db.StmtEntry, db.StmtQueryLog, db.StmtQueryStats,
		db.StmtInsertLatency, db.StmtLastProbe,
	} {
		if stmt != nil {
			_ = stmt.Close()
		}
	}
	if db.dbPath != "" {
		_, _ = db.SQ.Exec("PRAGMA optimize")
	}
	if err := db.SQ.Close(); err != nil {
		log.Errorf("DB: sqlite close failed: %v", err)
		return fmt.Errorf("sqlite close: %w", err)
	}
	log.Infof("DB: SQLite database shut down")
	return nil
}

// SQLExec delegates to db.SQ.Exec, exposing a method that satisfies the
// sqlExecutor interface defined by consumer packages (ruleset, zone).
func (db *DB) SQLExec(query string, args ...any) (sql.Result, error) {
	return db.SQ.Exec(query, args...)
}

// SQLQueryRow delegates to db.SQ.QueryRow.
func (db *DB) SQLQueryRow(query string, args ...any) *sql.Row {
	return db.SQ.QueryRow(query, args...)
}

// SQLQuery executes a query and returns the *sql.Rows for iteration.
func (db *DB) SQLQuery(query string, args ...any) (*sql.Rows, error) {
	return db.SQ.Query(query, args...)
}

// Cache methods

// AddEntryCount atomically adds delta to the entry counter.
func (db *DB) AddEntryCount(delta int64) { db.entryCount.Add(delta) }

// EntryCount returns the current entry count.
func (db *DB) EntryCount() int64 { return db.entryCount.Load() }

// SetEntryCount atomically sets the entry counter to n.
func (db *DB) SetEntryCount(n int64) { db.entryCount.Store(n) }

// BeginTx starts a new SQL transaction.
func (db *DB) BeginTx() (*sql.Tx, error) { return db.SQ.Begin() }

// ExecWrite executes fn while holding the cache write serialization mutex,
// ensuring that cache writes and evictions are serialized.
func (db *DB) ExecWrite(fn func() error) error {
	db.writeMu.Lock()
	defer db.writeMu.Unlock()
	return fn()
}

// MaxEntries returns the maximum cache entries before eviction.
func (db *DB) MaxEntries() int { return db.maxEntries }

// QueryZoneExact runs the exact-match zone query via StmtZoneExact.
// Satisfies zone.ZoneStorage.
func (db *DB) QueryZoneExact(qname string, qtype, qclass int) (*sql.Rows, error) {
	return db.StmtZoneExact.Query(qname, qtype, qclass)
}

// QueryZoneWildcard runs the wildcard-batch zone query via StmtZoneWildcard.
// Satisfies zone.ZoneStorage.
func (db *DB) QueryZoneWildcard(args []any) (*sql.Rows, error) {
	return db.StmtZoneWildcard.Query(args...)
}

// Begin starts a new SQL transaction. Satisfies zone.ZoneStorage.
func (db *DB) Begin() (*sql.Tx, error) { return db.SQ.Begin() }

// Exec executes a SQL statement. Satisfies zone.ZoneStorage.
func (db *DB) Exec(query string, args ...any) (sql.Result, error) { return db.SQ.Exec(query, args...) }

// IsClosed reports whether the database has been closed.
func (db *DB) IsClosed() bool { return atomic.LoadInt32(&db.closed) != 0 }
