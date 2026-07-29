package cache

import (
	"sync"
	"time"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
)

// AsyncStatsWriter offloads RecordRequest BadgerDB writes from the query hot
// path onto a background goroutine. A buffered channel decouples producers
// (query handlers) from the consumer (the writer goroutine). When the channel
// is full, records are dropped — stats are best-effort.
//
// Shutdown: Close() closes the record channel, the goroutine drains buffered
// records and flushes them, then exits. Close() blocks until the goroutine
// returns. Close is idempotent via sync.Once.
//
// Flush() is a two-phase operation: it drains the channel directly, then signals
// the background goroutine to flush its internal batch.
type AsyncStatsWriter struct {
	ch        chan RequestRecord
	flushSig  chan chan struct{} // send done chan → goroutine flushes batch → close(done)
	db        *database.DB
	done      chan struct{}
	closeOnce sync.Once
}

// NewAsyncStatsWriter creates an AsyncStatsWriter and starts its background
// goroutine. bufferSize controls how many records can be queued before
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

// Record enqueues a request record for asynchronous writing. When the channel
// is full the record is silently dropped — stats are best-effort.
func (w *AsyncStatsWriter) Record(r *RequestRecord) {
	if w == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			log.Errorf("CACHE: async writer panic: %v", p)
		}
	}()
	select {
	case w.ch <- *r:
	default:
	}
}

// Close shuts down the writer. Idempotent.
func (w *AsyncStatsWriter) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		close(w.ch)
		<-w.done
	})
}

// Flush writes all pending records synchronously.
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
	done := make(chan struct{}, 1)
	select {
	case w.flushSig <- done:
		<-done
	default:
	}
}

// run is the background goroutine.
func (w *AsyncStatsWriter) run() {
	defer close(w.done)

	const batchSize = 64
	batch := make([]RequestRecord, 0, batchSize)
	ticker := time.NewTicker(config.DefaultAsyncFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case r, ok := <-w.ch:
			if !ok {
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

// flush writes a batch of records to BadgerDB using WriteBatch with in-memory
// pre-aggregation for stats counters. Stats are best-effort.
func (w *AsyncStatsWriter) flush(batch []RequestRecord) {
	if len(batch) == 0 || w.db.IsClosed() {
		return
	}

	// ── Phase 1: pre-aggregate stats in memory ────────────────────────────
	// Accumulate query_stats deltas by key to eliminate per-record reads.
	type statsDelta struct {
		count   int64
		totalMS int64
	}
	agg := make(map[string]*statsDelta, len(batch)/4) // estimate ~25% unique keys
	now := log.NowUnix()
	statDay := now / 86400

	for i := range batch {
		r := &batch[i]
		key := string(database.QueryStatsKey(statDay, r.Result, r.Protocol, r.Rcode, r.DNSSECStatus, r.Poisoned))
		d, ok := agg[key]
		if !ok {
			d = &statsDelta{}
			agg[key] = d
		}
		d.count++
		d.totalMS += r.ResponseTime
	}

	// ── Phase 2: write aggregated stats + query_log via WriteBatch ─────────
	wb := w.db.Badger.NewWriteBatch()
	defer wb.Cancel()

	for key, d := range agg {
		_ = wb.Set([]byte(key), database.EncodeQueryStatsValue(d.count, d.totalMS))
	}

	if err := wb.Flush(); err != nil {
		log.Warnf("CACHE: async WriteBatch flush error: %v", err)
	}
}
