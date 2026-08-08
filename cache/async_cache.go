package cache

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
)

// cacheWriteItem is one cache entry queued for batched SQLite writing.  The
// PTR data is pre-extracted at Set() time so the item does not retain the
// response RR slices.
type cacheWriteItem struct {
	key        string        // pending read-through key (exact ECS)
	pendingPtr *pendingEntry // pointer-compare target for read-through removal
	qname      string
	qtype      uint16
	qclass     uint16
	ecsAddr    string
	ecsPrefix  int
	dnssecInt  int
	now        int64
	ttl        int
	validated  bool
	msgWire    []byte
	ptrRecs    []ptrRec
}

// ptrRec is a single ptr_map row pre-extracted from a response.
type ptrRec struct {
	name    string
	ttl     int
	rdataIP string
}

// pendingEntry is the read-through layer: an entry awaiting its batch commit
// is visible to Get() from memory, so a re-query of the same name within the
// flush window still hits instead of re-resolving.  Entries leave this layer
// once their batch commits (the SQLite row takes over).
type pendingEntry struct {
	msgWire   []byte
	ts        int64
	ttl       int
	validated bool
}

// buildCacheKey is the pending read-through key — the exact cache key, no ECS
// fallback approximation (fallback candidates are served from SQLite once the
// exact row commits).
func buildCacheKey(qname string, qtype, qclass uint16, ecsAddr string, ecsPrefix, dnssecInt int) string {
	var b strings.Builder
	b.WriteString(qname)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(int(qtype)))
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(int(qclass)))
	b.WriteByte(0)
	b.WriteString(ecsAddr)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(ecsPrefix))
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(dnssecInt))
	return b.String()
}

// newCacheBatchWriter builds the BatchWriter that persists cache entries in
// transactions of DefaultAsyncCacheBatchSize rows.  The pending read-through
// map is owned by SQLiteCache and shared through the closures below.
func (s *SQLiteCache) newCacheBatchWriter() *BatchWriter[cacheWriteItem] {
	return NewBatchWriter(
		s.db.SQ,
		config.DefaultAsyncCacheBufferSize,
		config.DefaultAsyncCacheBatchSize,
		config.DefaultAsyncFlushInterval,
		config.DefaultCacheWriteTimeout,
		func(ctx context.Context, tx *sql.Tx, batch []cacheWriteItem) error {
			return s.flushCacheEntries(ctx, tx, batch)
		},
		func() { s.evictIfNeeded() },
	)
}

// flushCacheEntries persists one batch of entries inside a single transaction:
// per row EXISTS (for the entry counter) → INSERT OR REPLACE RETURNING id →
// ptr_map rows.  The read-through entry is removed once the row is written.
// Errors abort the batch — the BatchWriter drops it (best-effort).
func (s *SQLiteCache) flushCacheEntries(ctx context.Context, tx *sql.Tx, batch []cacheWriteItem) error {
	for i := range batch {
		item := &batch[i]

		// Distinguish a fresh insert from a REPLACE of an existing row so the
		// entry counter tracks the real row count (see Set for the original
		// rationale — this logic moved here with the async write-back).
		var exists bool
		// Raw SQL (not tx.Stmt): see flushStatsRecords — Tx.Stmt pins every
		// prepare in the statement's per-connection cache and accumulated
		// thousands of retained driverStmt objects under connection churn.
		if err := tx.QueryRowContext(ctx, database.EntryExistsSQL,
			item.qname, int(item.qtype), int(item.qclass), item.ecsAddr, item.ecsPrefix, item.dnssecInt,
		).Scan(&exists); err != nil {
			return err
		}

		var entryID int64
		if err := tx.QueryRowContext(ctx, database.EntryInsertSQL,
			item.qname, int(item.qtype), int(item.qclass), item.ecsAddr, item.ecsPrefix, item.dnssecInt,
			item.now, item.ttl, item.now+int64(item.ttl), database.BoolToInt(item.validated),
			item.msgWire,
		).Scan(&entryID); err != nil {
			return err
		}
		if !exists {
			s.db.AddEntryCount(1)
		}

		if len(item.ptrRecs) > 0 {
			if err := insertPtrRecs(ctx, tx, entryID, item.ptrRecs); err != nil {
				// Best-effort: a failure here must not abort the batch — the
				// cached entry is more valuable than reverse-lookup data.
				log.Warnf("CACHE: insert ptr_map failed (non-fatal): %v", err)
			}
		}

		// Hand the read-through entry over to SQLite.  Pointer comparison:
		// a newer Set for the same key (queued behind this item) must not be
		// removed by the older item's flush.
		s.removePending(item.key, item.pendingPtr)
	}
	return nil
}

// removePending deletes a read-through entry only if it is still the one this
// item stored (a re-Set may have replaced it with a newer entry).
func (s *SQLiteCache) removePending(key string, entry *pendingEntry) {
	if s.pending == nil {
		return
	}
	if cur, ok := s.pending.Get(key); ok && cur == entry {
		s.pending.Delete(key)
	}
}
