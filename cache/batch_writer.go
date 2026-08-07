package cache

import (
	"context"
	"database/sql"
	"sync"
	"time"
	"zjdns/internal/log"
)

// BatchWriter is the shared write-back engine behind the cache's asynchronous
// SQLite writes.  Producers Enqueue items on the hot path (never blocking —
// a full buffer drops, exactly like the stats writer); a background goroutine
// accumulates items and executes the caller's flush function in ONE
// transaction per batch, amortising BEGIN/COMMIT and index-seek overhead
// across N rows.
//
// Close() closes the item channel; the goroutine drains buffered items,
// flushes them, then exits.  Flush() is two-phase: it drains the channel
// directly, then signals the goroutine to flush its internal batch.
//
// Errors are best-effort: a failed flush drops the batch and is logged once —
// the query path must never block on or observe SQLite write failures.
type BatchWriter[T any] struct {
	ch        chan T
	flushFn   func(tx *sql.Tx, batch []T) error
	onCommit  func() // optional post-commit hook (e.g. cache eviction check)
	db        *sql.DB
	flushSig  chan chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	batchSize int
	interval  time.Duration
	timeout   time.Duration
}

// NewBatchWriter creates a BatchWriter and starts its background goroutine.
// bufferSize caps the channel (full → drop); batchSize is the flush threshold;
// interval is the idle-flush ticker; timeout bounds each flush transaction.
// onCommit, when non-nil, runs after each successful commit (never inside the
// transaction).
func NewBatchWriter[T any](db *sql.DB, bufferSize, batchSize int, interval, timeout time.Duration, flushFn func(tx *sql.Tx, batch []T) error, onCommit func()) *BatchWriter[T] {
	if batchSize <= 0 {
		batchSize = 64
	}
	w := &BatchWriter[T]{
		ch:        make(chan T, bufferSize),
		flushFn:   flushFn,
		onCommit:  onCommit,
		db:        db,
		flushSig:  make(chan chan struct{}, 1), // buffered: a Flush racing a busy goroutine queues instead of skipping
		done:      make(chan struct{}),
		batchSize: batchSize,
		interval:  interval,
		timeout:   timeout,
	}
	go w.run()
	return w
}

// Enqueue queues an item for batched writing.  When the channel is full the
// item is silently dropped — writes are best-effort.  The item is copied by
// value so the caller may reuse its backing memory.
func (w *BatchWriter[T]) Enqueue(item T) {
	if w == nil {
		return
	}
	select {
	case w.ch <- item:
	default:
	}
}

// Close shuts down the writer: buffered items are drained and flushed before
// it returns.  Idempotent.
func (w *BatchWriter[T]) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		close(w.ch)
		<-w.done
	})
}

// Flush writes all pending items synchronously.  The goroutine drains the
// channel into its batch and flushes — every write goes through the single
// consumer, so the commit order always matches the enqueue order (a Flush
// must never interleave its own writes between queued items, which would let
// an older item overwrite a newer one for the same key).  The signal channel
// is buffered, so a goroutine busy mid-flush picks the request up when it
// returns to its select loop — Flush never silently skips.  The wait is
// bounded by the flush timeout: after Close the goroutine is gone and the
// done signal never arrives.
func (w *BatchWriter[T]) Flush() {
	if w == nil {
		return
	}
	done := make(chan struct{}, 1)
	select {
	case w.flushSig <- done:
		select {
		case <-done:
		case <-time.After(w.timeout):
		}
	default:
		// Two concurrent Flushes: the other one's signal is queued; the
		// goroutine flushes everything queued so far and closes its done.
	}
}

// run is the background goroutine: accumulate items into a batch and flush
// when the batch is full, a flush is requested, or a ticker fires.  When the
// item channel is closed, remaining items are drained and flushed, then the
// goroutine exits.
func (w *BatchWriter[T]) run() {
	defer close(w.done)

	batch := make([]T, 0, w.batchSize)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case item, ok := <-w.ch:
			if !ok {
				// Channel closed: flush remaining and exit.
				if len(batch) > 0 {
					w.flush(batch)
				}
				return
			}
			batch = append(batch, item)
			if len(batch) >= w.batchSize {
				w.flush(batch)
				batch = batch[:0]
			}
		case done := <-w.flushSig:
			// Drain the channel into the batch first — commit order must
			// match enqueue order (an older item must never overwrite a
			// newer one for the same key).
		drain:
			for {
				select {
				case item, ok := <-w.ch:
					if !ok {
						break drain
					}
					batch = append(batch, item)
				default:
					break drain
				}
			}
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

// flush executes one batch inside a single transaction.  Errors are logged
// once and the batch is dropped — writes are best-effort and must never block
// or fail the query path.  The context bounds the write-lock wait; on timeout
// the batch is dropped, never blocking.
func (w *BatchWriter[T]) flush(batch []T) {
	ctx, cancel := context.WithTimeout(context.Background(), w.timeout)
	defer cancel()

	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		log.Debugf("CACHE: async batch begin failed (%d items): %v", len(batch), err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err := w.flushFn(tx, batch); err != nil {
		log.Debugf("CACHE: async batch flush failed (%d items): %v", len(batch), err)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Debugf("CACHE: async batch commit failed (%d items): %v", len(batch), err)
		return
	}
	if w.onCommit != nil {
		w.onCommit()
	}
}
