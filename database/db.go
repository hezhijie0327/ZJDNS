package database

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"

	_ "github.com/ncruces/go-sqlite3/driver"
)

const dsnParams = "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&_foreign_keys=ON&_txlock=immediate"

// Options configures SQLite PRAGMA tunables.
type Options struct {
	MMapSizeMB  int
	CacheSizeMB int
}

// DB is a unified SQLite database backing all ZJDNS subsystems (cache, zone).
// It uses a single pinned connection to guarantee all operations share the
// same in-memory database when path is empty.
type DB struct {
	conn   *sql.Conn
	dbPath string

	mmapSizeMB  int
	cacheSizeMB int
	closed      int32

	// Cache subsystem
	maxEntries int
	entryCount atomic.Int64
	writeMu    sync.Mutex

	// Cache prepared statements
	StmtGetEntry      *sql.Stmt
	StmtInsertLog     *sql.Stmt
	StmtHitCounter    *sql.Stmt
	StmtInsertLatency *sql.Stmt
	StmtGetLastProbe  *sql.Stmt
	StmtEnsureEntry   *sql.Stmt

	// Zone prepared statements
	StmtZoneExact  *sql.Stmt
	StmtZoneWild   *sql.Stmt
	StmtZoneInsert *sql.Stmt
}

// Open opens or creates the SQLite database at path. An empty path uses
// in-memory storage. maxEntries controls cache eviction threshold.
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
	if path != "" {
		sqldb.SetMaxOpenConns(config.DefaultCacheMaxOpenConns)
		sqldb.SetMaxIdleConns(config.DefaultCacheMaxIdleConns)
	}

	// Pin a single connection. For :memory:, this is required because
	// each connection gets its own independent database. For disk-backed,
	// it simplifies connection management by avoiding pool contention.
	conn, err := sqldb.Conn(context.Background())
	if err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("sqlite acquire conn: %w", err)
	}
	_ = sqldb.Close() // conn owns the connection now

	db := &DB{
		conn:        conn,
		dbPath:      path,
		maxEntries:  maxEntries,
		mmapSizeMB:  opts.MMapSizeMB,
		cacheSizeMB: opts.CacheSizeMB,
	}

	if err := db.migrate(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}

	// Initialize entryCount from existing rows.
	var count int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err == nil {
		db.entryCount.Store(count)
	}

	if err := db.prepareStatements(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sqlite prepare: %w", err)
	}

	label := path
	if label == "" {
		label = "memory"
	}
	log.Infof("CACHE: SQLite database opened (db=%s, max_entries=%d, mmap_size=%dMB, cache_size=%dMB)",
		label, maxEntries, opts.MMapSizeMB, opts.CacheSizeMB)
	return db, nil
}

// Exec executes a query on the pinned connection.
func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.conn.ExecContext(context.Background(), query, args...)
}

// Query executes a query that returns rows.
func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.conn.QueryContext(context.Background(), query, args...)
}

// QueryRow executes a query that returns at most one row.
func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.conn.QueryRowContext(context.Background(), query, args...)
}

// Begin starts a transaction on the pinned connection.
func (db *DB) Begin() (*sql.Tx, error) {
	return db.conn.BeginTx(context.Background(), nil)
}

// Close closes the database, running PRAGMA optimize before shutdown.
func (db *DB) Close() error {
	if !atomic.CompareAndSwapInt32(&db.closed, 0, 1) {
		return nil
	}
	for _, stmt := range []*sql.Stmt{
		db.StmtGetEntry, db.StmtInsertLog, db.StmtHitCounter,
		db.StmtInsertLatency, db.StmtGetLastProbe, db.StmtEnsureEntry,
		db.StmtZoneExact, db.StmtZoneWild, db.StmtZoneInsert,
	} {
		if stmt != nil {
			_ = stmt.Close()
		}
	}
	if db.dbPath != "" {
		_, _ = db.Exec("PRAGMA optimize")
	}
	if err := db.conn.Close(); err != nil {
		log.Errorf("CACHE: sqlite close failed: %v", err)
		return fmt.Errorf("sqlite close: %w", err)
	}
	log.Infof("CACHE: SQLite database shut down")
	return nil
}

// Cache methods

// EntryCount returns the approximate cache entry count.
func (db *DB) EntryCount() int64 { return db.entryCount.Load() }

// AddEntryCount atomically adds delta to the entry counter.
func (db *DB) AddEntryCount(delta int64) { db.entryCount.Add(delta) }

// SetEntryCount atomically sets the entry counter to n.
func (db *DB) SetEntryCount(n int64) { db.entryCount.Store(n) }

// WriteLock acquires the cache write serialization mutex.
func (db *DB) WriteLock() { db.writeMu.Lock() }

// WriteUnlock releases the cache write serialization mutex.
func (db *DB) WriteUnlock() { db.writeMu.Unlock() }

// MaxEntries returns the maximum cache entries before eviction.
func (db *DB) MaxEntries() int { return db.maxEntries }

// IsClosed reports whether the database has been closed.
func (db *DB) IsClosed() bool { return atomic.LoadInt32(&db.closed) != 0 }

// EnsureEntry returns the entry ID for the given cache key, creating a
// lightweight stub if one doesn't exist.
func (db *DB) EnsureEntry(qname string, qtype, qclass int, ecsAddr string, ecsPrefix, dnssecInt int) int64 {
	var id int64
	err := db.StmtEnsureEntry.QueryRow(
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&id)
	if err == nil {
		return id
	}

	db.writeMu.Lock()
	defer db.writeMu.Unlock()

	err = db.StmtEnsureEntry.QueryRow(
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&id)
	if err == nil {
		return id
	}

	now := log.NowUnix()
	err = db.QueryRow(
		`INSERT OR IGNORE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, msg_wire)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 RETURNING id`,
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
		now, config.DefaultStaleTTL, now+int64(config.DefaultStaleTTL), 0,
	).Scan(&id)
	if err != nil {
		_ = db.StmtEnsureEntry.QueryRow(
			qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
		).Scan(&id)
	}
	return id
}
