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

// Options configures BadgerDB memory usage. Zero fields use the small-device
// defaults. Pass nil to Open for full defaults.
//
// Only memory budget knobs are exposed — everything else is hardcoded
// in defaultDiskOptions() as correct for all DNS cache workloads.
type Options struct {
	MemTableSizeMB   int // memtable write buffer (MB), 0 = 4
	BlockCacheSizeMB int // block cache for reads (MB), 0 = 4
	IndexCacheSizeMB int // bloom filters + table indices (MB), 0 = 8
}

// Hardcoded BadgerDB tunings — correct for all DNS cache workloads.
const (
	valueThreshold     = 64 << 10 // 64KB: all DNS values fit inline in LSM tree
	valueLogFileSizeMB = 64       // vlog file size (WAL-only since values are inline)
	maxLevels          = 7        // max LSM levels (BadgerDB default); levels created lazily — small datasets stay small
	baseLevelSizeMB    = 4        // LSM base level target (MB)
	numMemtables       = 2        // concurrent memtables
	numCompactors      = 2        // compaction goroutines
	numLevelZeroTables = 2        // L0 tables before compaction triggers
	numGoroutines      = 2        // Stream goroutines (rarely used in DNS)
	zstdLevel          = 3        // zstd compression 1-3 (3=balanced)
	baseTableSize      = 1 << 20  // 1MB SSTable (down from Badger default 2MB)
	valueLogMaxEntries = 100000   // 100K per vlog (down from Badger default 1M)
)

// ErrDBClosed is returned when an operation is attempted on a closed database.
var ErrDBClosed = errors.New("database: closed")

// Open opens or creates the BadgerDB database at path. An empty path uses an
// in-memory database. A nil Options uses small-device defaults.
func Open(path string, opt *Options) (*DB, error) {
	if opt == nil {
		opt = &Options{}
	}
	opt.resolveDefaults()

	var bopts badger.Options
	if path == "" {
		bopts = badger.DefaultOptions("").WithInMemory(true).WithLogger(nil)
	} else {
		bopts = defaultDiskOptions(path, opt)
	}

	bdb, err := badger.Open(bopts)
	if err != nil {
		return nil, fmt.Errorf("badger open: %w", err)
	}

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

// resolveDefaults fills zero-valued fields with config defaults.
func (opt *Options) resolveDefaults() {
	// Memory
	if opt.MemTableSizeMB <= 0 {
		opt.MemTableSizeMB = config.DefaultBadgerMemTableSizeMB
	}
	if opt.BlockCacheSizeMB <= 0 {
		opt.BlockCacheSizeMB = config.DefaultBadgerBlockCacheSizeMB
	}
	if opt.IndexCacheSizeMB <= 0 {
		opt.IndexCacheSizeMB = config.DefaultBadgerIndexCacheSizeMB
	}
}

// defaultDiskOptions returns BadgerDB options tuned for DNS cache workloads on
// small-memory / small-storage devices. Only memory budget knobs are exposed
// via Options; everything else is hardcoded.
func defaultDiskOptions(path string, opt *Options) badger.Options {
	return badger.DefaultOptions(path).
		// Hardcoded — correct for all DNS cache workloads
		WithNumVersionsToKeep(1).
		WithDetectConflicts(false).
		WithSyncWrites(false).
		WithCompression(options.ZSTD).
		WithZSTDCompressionLevel(zstdLevel).
		WithCompactL0OnClose(true).
		WithLogger(nil).
		WithBaseTableSize(baseTableSize).
		WithValueLogMaxEntries(valueLogMaxEntries).
		WithValueThreshold(valueThreshold).
		WithValueLogFileSize(valueLogFileSizeMB << 20).
		WithNumGoroutines(numGoroutines).
		WithNumMemtables(numMemtables).
		WithMaxLevels(maxLevels).
		WithBaseLevelSize(baseLevelSizeMB << 20).
		WithNumCompactors(numCompactors).
		WithNumLevelZeroTables(numLevelZeroTables).
		WithNumLevelZeroTablesStall(numLevelZeroTables * 2).
		// Memory (user-tunable)
		WithMemTableSize(int64(opt.MemTableSizeMB) << 20).
		WithBlockCacheSize(int64(opt.BlockCacheSizeMB) << 20).
		WithIndexCacheSize(int64(opt.IndexCacheSizeMB) << 20)
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
