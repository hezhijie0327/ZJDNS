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
	Badger     *badger.DB
	dbPath     string
	maxEntries int
	entryCount atomic.Int64
	closed     int32

	entrySeq *badger.Sequence
	qlogSeq  *badger.Sequence
}

// Open opens or creates the BadgerDB database at path. An empty path uses an
// in-memory database. maxEntries controls the cache eviction threshold.
// memTableSizeMB and blockCacheSizeMB control BadgerDB memory usage; 0 uses defaults.
func Open(path string, maxEntries, memTableSizeMB, blockCacheSizeMB int) (*DB, error) {
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxCacheEntries
	}
	if memTableSizeMB <= 0 {
		memTableSizeMB = config.DefaultBadgerMemTableSizeMB
	}
	if blockCacheSizeMB <= 0 {
		blockCacheSizeMB = config.DefaultBadgerBlockCacheSizeMB
	}

	var opts badger.Options
	if path == "" {
		opts = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	} else {
		opts = defaultDiskOptions(path, memTableSizeMB, blockCacheSizeMB)
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
	qlogSeq, err := bdb.GetSequence([]byte(seqQLog), 1000)
	if err != nil {
		_ = entrySeq.Release()
		_ = bdb.Close()
		return nil, fmt.Errorf("badger qlog sequence: %w", err)
	}

	// Count existing entries for the atomic counter.
	var count int64
	_ = bdb.View(func(txn *badger.Txn) error { // error always nil — entry counting is best-effort
		opts := badger.DefaultIteratorOptions
		opts.Prefix = EntryKeyPrefix()
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})

	db := &DB{
		Badger:     bdb,
		dbPath:     path,
		maxEntries: maxEntries,
		entrySeq:   entrySeq,
		qlogSeq:    qlogSeq,
	}
	db.entryCount.Store(count)

	label := path
	if label == "" {
		label = "memory"
	}
	log.Infof("DB: BadgerDB opened (db=%s, max_entries=%d, entries=%d)",
		label, maxEntries, count)
	return db, nil
}

// defaultDiskOptions returns BadgerDB options tuned for DNS cache workloads.
func defaultDiskOptions(path string, memTableSizeMB, blockCacheSizeMB int) badger.Options {
	return badger.DefaultOptions(path).
		WithNumVersionsToKeep(1).                            // No MVCC overhead
		WithDetectConflicts(false).                          // No concurrent-key conflicts (upsert pattern)
		WithSyncWrites(false).                               // Cache is ephemeral; stats are best-effort
		WithCompression(options.ZSTD).                       // Built-in zstd at SSTable level
		WithZSTDCompressionLevel(3).                         // Balance speed vs ratio
		WithValueThreshold(256).                             // Values ≤256B stored inline in LSM tree
		WithValueLogFileSize(int64(memTableSizeMB*2) << 20). // 64MB vlog files
		WithMemTableSize(int64(memTableSizeMB) << 20).       // 32MB memtable
		WithBlockCacheSize(int64(blockCacheSizeMB) << 20).   // 32MB block cache
		WithIndexCacheSize(0).                               // All in block cache
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
	_ = db.qlogSeq.Release()
	if err := db.Badger.Close(); err != nil {
		log.Errorf("DB: BadgerDB close failed: %v", err)
		return fmt.Errorf("badger close: %w", err)
	}
	log.Infof("DB: BadgerDB shut down")
	return nil
}

// IsClosed reports whether the database has been closed.
func (db *DB) IsClosed() bool { return atomic.LoadInt32(&db.closed) != 0 }

// AddEntryCount atomically adds delta to the entry counter.
func (db *DB) AddEntryCount(delta int64) { db.entryCount.Add(delta) }

// EntryCount returns the current entry count.
func (db *DB) EntryCount() int64 { return db.entryCount.Load() }

// SetEntryCount atomically sets the entry counter to n.
func (db *DB) SetEntryCount(n int64) { db.entryCount.Store(n) }

// MaxEntries returns the maximum cache entries before eviction.
func (db *DB) MaxEntries() int { return db.maxEntries }

// NextEntryID returns the next monotonic entry ID from the sequence.
func (db *DB) NextEntryID() (uint64, error) {
	return db.entrySeq.Next()
}

// NextQLogID returns the next monotonic query log ID from the sequence.
func (db *DB) NextQLogID() (uint64, error) {
	return db.qlogSeq.Next()
}
