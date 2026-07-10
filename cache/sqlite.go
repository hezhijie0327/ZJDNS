package cache

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"

	_ "github.com/ncruces/go-sqlite3/driver"
)

const (
	dsnParams = "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&_foreign_keys=ON&_txlock=immediate"
)

// SQLiteCache is a DNS response cache backed entirely by SQLite.
type SQLiteCache struct {
	db          *sql.DB
	dbPath      string // database file path; empty = in-memory
	maxEntries  int
	mmapSizeMB  int
	cacheSizeMB int
	closed      int32
	entryCount  atomic.Int64

	// writeMu serializes Set() calls to prevent SQLite write-lock contention
	// under concurrent cache-miss resolution. WAL mode allows only one writer
	// at a time; without this mutex, multiple BEGIN IMMEDIATE transactions
	// queue up in the busy handler and can exceed busy_timeout, producing
	// SQLITE_IOERR. RecordRequest is append-only (no conflict) and does not
	// need this mutex.
	writeMu sync.Mutex

	// Hot-path prepared statements — compiled once, reused forever.
	stmtGetEntry      *sql.Stmt
	stmtInsertLog     *sql.Stmt
	stmtHitCounter    *sql.Stmt
	stmtInsertLatency *sql.Stmt
	stmtGetLastProbe  *sql.Stmt
	stmtEnsureEntry   *sql.Stmt
}

// NewSQLiteCache opens or creates a SQLite database and returns a ready-to-use
// cache. path is the database file path; an empty string uses an in-memory
// database. mmapSizeMB and cacheSizeMB are SQLite PRAGMA tunables; zero means
// use defaults. maxRequestLog is the ring-buffer size for request_log.
func NewSQLiteCache(path string, maxEntries, mmapSizeMB, cacheSizeMB int) (*SQLiteCache, error) {
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxCacheEntries
	}
	if mmapSizeMB <= 0 {
		mmapSizeMB = config.DefaultCacheMMapSizeMB
	}
	if cacheSizeMB <= 0 {
		cacheSizeMB = config.DefaultCacheCacheSizeMB
	}

	var dsn string
	if path == "" {
		dsn = "file::memory:?" + dsnParams
	} else {
		dsn = "file:" + path + "?" + dsnParams
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(config.DefaultCacheMaxOpenConns)
	db.SetMaxIdleConns(config.DefaultCacheMaxIdleConns)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}

	s := &SQLiteCache{
		db:          db,
		dbPath:      path,
		maxEntries:  maxEntries,
		mmapSizeMB:  mmapSizeMB,
		cacheSizeMB: cacheSizeMB,
	}

	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}

	// Initialize entryCount from existing rows before cleanup.
	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err == nil {
		s.entryCount.Store(count)
	}

	if err := s.prepareStatements(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite prepare: %w", err)
	}

	persistLabel := path
	if persistLabel == "" {
		persistLabel = "memory"
	}
	log.Infof("CACHE: SQLite cache enabled (db=%s, max_entries=%d, mmap_size=%dMB, cache_size=%dMB)",
		persistLabel, maxEntries, mmapSizeMB, cacheSizeMB)
	return s, nil
}

// Close closes the database.
func (s *SQLiteCache) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	// Close prepared statements before the database.
	for _, stmt := range []*sql.Stmt{s.stmtGetEntry, s.stmtInsertLog, s.stmtHitCounter, s.stmtInsertLatency, s.stmtGetLastProbe, s.stmtEnsureEntry} {
		if stmt != nil {
			_ = stmt.Close()
		}
	}
	// Run optimize at shutdown — SQLite uses accumulated query patterns
	// to decide whether ANALYZE would be beneficial.
	_, _ = s.db.Exec("PRAGMA optimize")
	if err := s.db.Close(); err != nil {
		log.Errorf("CACHE: sqlite close failed: %v", err)
		return fmt.Errorf("sqlite close: %w", err)
	}
	log.Infof("CACHE: SQLite cache shut down")
	return nil
}
