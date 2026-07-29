// Package database provides a unified BadgerDB key-value store backing all
// ZJDNS subsystems (cache, zone, ruleset). It manages connection lifecycle and
// provides shared key construction, encoding/decoding, and sequence-based ID
// generation utilities.
package database

import (
	"errors"
	"fmt"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
)

// DB is a unified BadgerDB key-value store backing all ZJDNS subsystems
// (cache, zone, ruleset). It wraps *badger.DB with entry counting, ID
// sequences, and lifecycle management.
type DB struct {
	Badger *badger.DB
	dbPath string
	closed int32

	entrySeq *badger.Sequence
}

// ErrDBClosed is returned when an operation is attempted on a closed database.
var ErrDBClosed = errors.New("database: closed")

// Open opens or creates the BadgerDB database at path. An empty path uses an
// in-memory database. All size/count parameters use their config defaults when
// zero/negative.
func Open(path string, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB, valueThresholdBytes, valueLogFileSizeMB, numCompactors, numLevelZeroTables, zstdLevel int) (*DB, error) {
	if memTableSizeMB <= 0 {
		memTableSizeMB = config.DefaultBadgerMemTableSizeMB
	}
	if blockCacheSizeMB <= 0 {
		blockCacheSizeMB = config.DefaultBadgerBlockCacheSizeMB
	}
	if indexCacheSizeMB <= 0 {
		indexCacheSizeMB = config.DefaultBadgerIndexCacheSizeMB
	}
	if numCompactors <= 0 {
		numCompactors = config.DefaultBadgerNumCompactors
	}
	if numLevelZeroTables <= 0 {
		numLevelZeroTables = config.DefaultBadgerNumLevelZeroTables
	}
	if valueThresholdBytes <= 0 {
		valueThresholdBytes = config.DefaultBadgerValueThreshold
	}
	if valueLogFileSizeMB <= 0 {
		valueLogFileSizeMB = config.DefaultBadgerValueLogFileSizeMB
	}
	if zstdLevel <= 0 || zstdLevel > 3 {
		zstdLevel = config.DefaultBadgerZSTDCompressionLevel
	}

	var opts badger.Options
	if path == "" {
		opts = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	} else {
		opts = defaultDiskOptions(path, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB, valueThresholdBytes, valueLogFileSizeMB, numCompactors, numLevelZeroTables, zstdLevel)
	}

	bdb, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("badger open: %w", err)
	}

	// Initialize ID sequences. Bandwidth=1000 means up to 1000 IDs are
	// leased in memory before a disk write is needed.
	entrySeq, err := bdb.GetSequence([]byte(seqEntry), 1000)
	if err != nil {
		_ = bdb.Close()
		return nil, fmt.Errorf("badger entry sequence: %w", err)
	}

	db := &DB{
		Badger:   bdb,
		dbPath:   path,
		entrySeq: entrySeq,
	}

	label := path
	if label == "" {
		label = "memory"
	}
	log.Infof("DB: BadgerDB opened (db=%s)", label)
	return db, nil
}

// defaultDiskOptions returns BadgerDB options tuned for DNS cache workloads.
// DNS values are small (~100-500B) and fit under ValueThreshold(64KB), so they
// are stored inline in SSTables.  The vlog still receives WAL entries for every
// write and must be periodically GC'd via RunValueLogGC.
func defaultDiskOptions(path string, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB, valueThresholdBytes, valueLogFileSizeMB, numCompactors, numLevelZeroTables, zstdLevel int) badger.Options {
	return badger.DefaultOptions(path).
		WithNumVersionsToKeep(1).                              // No MVCC overhead
		WithDetectConflicts(false).                            // No concurrent-key conflicts (upsert pattern)
		WithSyncWrites(false).                                 // Cache is ephemeral; stats are best-effort
		WithCompression(options.ZSTD).                         // Built-in zstd at SSTable level
		WithZSTDCompressionLevel(zstdLevel).                   // Configurable 1-3 (fast→balanced)
		WithValueThreshold(int64(valueThresholdBytes)).        // Value inline threshold; DNS values are small
		WithValueLogFileSize(int64(valueLogFileSizeMB) << 20). // 0 = default 1GB; only matters if values exceed threshold
		WithMemTableSize(int64(memTableSizeMB) << 20).         // Memtable write buffer
		WithBlockCacheSize(int64(blockCacheSizeMB) << 20).     // Block cache for reads
		WithIndexCacheSize(int64(indexCacheSizeMB) << 20).     // Bloom filters + table indices off-heap
		WithNumCompactors(numCompactors).                      // Compaction parallelism
		WithNumLevelZeroTables(numLevelZeroTables).            // L0 tables before compaction triggers
		WithNumLevelZeroTablesStall(numLevelZeroTables * 2).   // Stall at 2× L0 tables
		WithCompactL0OnClose(true).                            // Compact L0 on graceful shutdown
		WithLogger(nil)                                        // Suppress BadgerDB's default logger
}

// NextEntryID returns the next monotonic entry ID from the sequence.
func (db *DB) NextEntryID() (uint64, error) {
	return db.entrySeq.Next()
}

// View executes a read-only transaction. It returns ErrDBClosed if the
// database has been shut down.
func (db *DB) View(fn func(txn *badger.Txn) error) error {
	if db.IsClosed() {
		return ErrDBClosed
	}
	return db.Badger.View(fn)
}

// Update executes a read-write transaction. It returns ErrDBClosed if the
// database has been shut down.
func (db *DB) Update(fn func(txn *badger.Txn) error) error {
	if db.IsClosed() {
		return ErrDBClosed
	}
	return db.Badger.Update(fn)
}

// DropPrefix deletes all keys with the given prefix. It blocks all writes
// until complete and returns ErrDBClosed if the database has been shut down.
func (db *DB) DropPrefix(prefix []byte) error {
	if db.IsClosed() {
		return ErrDBClosed
	}
	return db.Badger.DropPrefix(prefix)
}

// NewWriteBatch creates a new write batch for async writes. Returns nil if
// the database has been closed.
func (db *DB) NewWriteBatch() *badger.WriteBatch {
	if db.IsClosed() {
		return nil
	}
	return db.Badger.NewWriteBatch()
}

// Close releases the sequences, garbage-collects the value log, and closes the
// database. Idempotent.
func (db *DB) Close() error {
	if db.Badger == nil {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&db.closed, 0, 1) {
		return nil
	}
	_ = db.entrySeq.Release()
	// Best-effort vlog GC on shutdown — rewrites live WAL entries to SSTables
	// and reclaims disk space for the next start.
	_ = db.Badger.RunValueLogGC(0.5)
	if err := db.Badger.Close(); err != nil {
		log.Errorf("DB: BadgerDB close failed: %v", err)
		return fmt.Errorf("badger close: %w", err)
	}
	log.Infof("DB: BadgerDB shut down")
	return nil
}

// IsClosed reports whether the database has been closed.
func (db *DB) IsClosed() bool { return atomic.LoadInt32(&db.closed) != 0 }
