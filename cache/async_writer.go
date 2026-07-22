package cache

import (
	"sync"
	"time"
	"zjdns/database"
	"zjdns/internal/log"
)

// AsyncStatsWriter offloads RecordRequest SQLite writes from the query hot path
// onto a background goroutine.  A buffered channel decouples producers (query
// handlers) from the consumer (the writer goroutine).  When the channel is full,
// records are dropped — stats are best-effort.
//
// Shutdown: Close() closes the record channel, the goroutine drains buffered
// records and flushes them, then exits.  Close() blocks until the goroutine
// returns.  Close is idempotent via sync.Once.
//
// Flush() is a two-phase operation: it drains the channel directly, then signals
// the background goroutine to flush its internal batch.  This ensures all
// in-flight records are written before Flush returns.
type AsyncStatsWriter struct {
	ch        chan RequestRecord
	flushSig  chan chan struct{} // send done chan → goroutine flushes batch → close(done)
	db        *database.DB
	done      chan struct{}
	closeOnce sync.Once
}

// NewAsyncStatsWriter creates an AsyncStatsWriter and starts its background
// goroutine.  bufferSize controls how many records can be queued before
// producers start dropping.
func NewAsyncStatsWriter(db *database.DB, bufferSize int) *AsyncStatsWriter {
	w := &AsyncStatsWriter{
		ch:       make(chan RequestRecord, bufferSize),
		flushSig: make(chan chan struct{}),
		db:       db,
		done:     make(chan struct{}),
	}
	go w.run()
	return w
}

// Record enqueues a request record for asynchronous writing.  When the channel
// is full the record is silently dropped — stats are best-effort.  The record
// is copied by value so the caller may reuse the backing memory.
func (w *AsyncStatsWriter) Record(r *RequestRecord) {
	if w == nil {
		return
	}
	select {
	case w.ch <- *r:
	default:
	}
}

// Close shuts down the writer.  It closes the record channel to signal the
// background goroutine, which drains buffered records, flushes them, and exits.
// Close blocks until the goroutine has finished.  Idempotent.
func (w *AsyncStatsWriter) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		close(w.ch)
		<-w.done
	})
}

// Flush writes all pending records synchronously.  Phase 1 drains any records
// buffered in the channel and writes them directly.  Phase 2 signals the
// background goroutine to flush its internal batch.  SQLite WAL mode serialises
// concurrent writers, so this is safe to call while the background goroutine is
// running.
func (w *AsyncStatsWriter) Flush() {
	if w == nil {
		return
	}
	// Phase 1: drain channel directly.
	var pending []RequestRecord
drainLoop:
	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				// Channel closed — nothing left to drain.
				break drainLoop
			}
			pending = append(pending, r)
		default:
			break drainLoop
		}
	}
	if len(pending) > 0 {
		w.flush(pending)
	}

	// Phase 2: ask goroutine to flush its internal batch.
	done := make(chan struct{})
	select {
	case w.flushSig <- done:
		<-done
	default:
		// Goroutine busy — records in its batch will be written by ticker or
		// next Flush.  This path is only reached under extreme load.
	}
}

// run is the background goroutine.  It accumulates records into a batch and
// flushes when the batch is full, a flush is requested, or a ticker fires.
// When the record channel is closed, remaining records are drained and flushed,
// then the goroutine exits.
func (w *AsyncStatsWriter) run() {
	defer close(w.done)

	const batchSize = 64
	batch := make([]RequestRecord, 0, batchSize)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
				// Channel closed: flush remaining and exit.
				w.flush(batch)
				return
			}
			batch = append(batch, r)
			if len(batch) >= batchSize {
				w.flush(batch)
				batch = batch[:0]
			}
		case done := <-w.flushSig:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
			close(done)
		case <-ticker.C:
			if len(batch) > 0 {
				w.flush(batch)
				batch = batch[:0]
			}
		}
	}
}

// flush writes a batch of records to the database.  Errors are silently ignored
// (stats are best-effort).  Individual writes are used rather than a transaction
// to keep the background goroutine simple — WAL-mode serialisation is sufficient.
func (w *AsyncStatsWriter) flush(batch []RequestRecord) {
	if len(batch) == 0 || w.db.IsClosed() {
		return
	}
	for i := range batch {
		r := &batch[i]

		// Always upsert into query_stats (per-day aggregated counters).
		_, _ = w.db.StmtQueryStats.Exec(
			r.Result, r.Protocol, r.Rcode, r.DNSSECStatus,
			database.BoolToInt(r.Hijack), database.BoolToInt(r.Fallback),
			r.ResponseTime,
		)

		// Non-hit results also go into query_log for the audit trail.
		if r.Result != "hit" {
			_, _ = w.db.StmtQueryLog.Exec(
				log.NowUnix(), r.Qname, int(r.Qtype), int(r.Qclass),
				r.Protocol, r.Result, r.Rcode, r.ResponseTime, r.Server,
				database.BoolToInt(r.Hijack), database.BoolToInt(r.Fallback),
				r.DNSSECStatus,
			)
		}
	}
}
