// Package database provides a unified BadgerDB key-value store backing all
// ZJDNS subsystems (cache, zone, ruleset). It manages connection lifecycle and
// provides shared key construction, encoding/decoding, and sequence-based ID
// generation utilities.
package database

import (
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

// Open opens or creates the BadgerDB database at path. An empty path uses an
// in-memory database. maxEntries controls the cache eviction threshold.
// memTableSizeMB, blockCacheSizeMB, and indexCacheSizeMB control BadgerDB memory
// usage; 0 uses defaults.
func Open(path string, maxEntries, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB int) (*DB, error) {
	if memTableSizeMB <= 0 {
		memTableSizeMB = config.DefaultBadgerMemTableSizeMB
	}
	if blockCacheSizeMB <= 0 {
		blockCacheSizeMB = config.DefaultBadgerBlockCacheSizeMB
	}
	if indexCacheSizeMB <= 0 {
		indexCacheSizeMB = config.DefaultBadgerIndexCacheSizeMB
	}

	var opts badger.Options
	if path == "" {
		opts = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	} else {
		opts = defaultDiskOptions(path, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB)
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
func defaultDiskOptions(path string, memTableSizeMB, blockCacheSizeMB, indexCacheSizeMB int) badger.Options {
	return badger.DefaultOptions(path).
		WithNumVersionsToKeep(1).                            // No MVCC overhead
		WithDetectConflicts(false).                          // No concurrent-key conflicts (upsert pattern)
		WithSyncWrites(false).                               // Cache is ephemeral; stats are best-effort
		WithCompression(options.ZSTD).                       // Built-in zstd at SSTable level
		WithZSTDCompressionLevel(3).                         // Balance speed vs ratio
		WithValueThreshold(64 << 10).                        // 64KB: all DNS values inline in LSM, no vlog
		WithValueLogFileSize(int64(memTableSizeMB*2) << 20). // 64MB vlog files
		WithMemTableSize(int64(memTableSizeMB) << 20).       // 32MB memtable
		WithBlockCacheSize(int64(blockCacheSizeMB) << 20).   // 32MB block cache
		WithIndexCacheSize(int64(indexCacheSizeMB) << 20).   // Bloom filters + table indices off-heap
		WithNumCompactors(2).                                // Reduce compaction CPU
		WithNumLevelZeroTables(2).                           // Fewer L0 files
		WithNumLevelZeroTablesStall(4).                      // Stall threshold
		WithCompactL0OnClose(true).                          // Compact L0 on graceful shutdown
		WithLogger(nil)                                      // Suppress BadgerDB's default logger
}

// Close releases the sequences and closes the database. Idempotent.
func (db *DB) Close() error {
	if db.Badger == nil {
		return nil
	}
	if !atomic.CompareAndSwapInt32(&db.closed, 0, 1) {
		return nil
	}
	_ = db.entrySeq.Release()
	if err := db.Badger.Close(); err != nil {
		log.Errorf("DB: BadgerDB close failed: %v", err)
		return fmt.Errorf("badger close: %w", err)
	}
	log.Infof("DB: BadgerDB shut down")
	return nil
}

// IsClosed reports whether the database has been closed.
func (db *DB) IsClosed() bool { return atomic.LoadInt32(&db.closed) != 0 }

// NextEntryID returns the next monotonic entry ID from the sequence.
func (db *DB) NextEntryID() (uint64, error) {
	return db.entrySeq.Next()
}
