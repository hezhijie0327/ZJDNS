package cache

import (
	"database/sql"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
)

// newStatsBatchWriter builds the shared BatchWriter that offloads
// RecordRequest SQLite writes from the query hot path.  Every batch flushes
// in ONE transaction (amortising BEGIN/COMMIT + index seeks across records);
// a full channel drops records — stats are best-effort.
func newStatsBatchWriter(db *database.DB, bufferSize int) *BatchWriter[RequestRecord] {
	return NewBatchWriter(
		db.SQ,
		bufferSize,
		config.DefaultAsyncStatsBatchSize,
		config.DefaultAsyncFlushInterval,
		config.DefaultCacheWriteTimeout,
		func(tx *sql.Tx, batch []RequestRecord) error {
			return flushStatsRecords(tx, batch, db)
		},
		nil, // no post-commit hook — stats are fire-and-forget
	)
}

// flushStatsRecords upserts a batch of request records inside one transaction.
// Errors are returned to the BatchWriter, which drops the batch — stats are
// best-effort and must never block or fail the query path.
func flushStatsRecords(tx *sql.Tx, batch []RequestRecord, db *database.DB) error {
	for i := range batch {
		r := &batch[i]

		// Always upsert into query_stats (per-day aggregated counters).
		if _, err := tx.Stmt(db.StmtQueryStats).Exec(
			r.Result, r.Protocol, r.Rcode, r.DNSSECStatus,
			database.BoolToInt(r.Poisoned),
			r.ResponseTime,
		); err != nil {
			return err
		}

		// Non-hit results also go into query_log for the audit trail.
		if r.Result != "hit" {
			if _, err := tx.Stmt(db.StmtQueryLog).Exec(
				log.NowUnix(), r.Qname, int(r.Qtype), int(r.Qclass),
				r.Protocol, r.Result, r.Rcode, r.ResponseTime, r.Server,
				database.BoolToInt(r.Poisoned),
				r.DNSSECStatus,
			); err != nil {
				return err
			}
		}
	}
	return nil
}
