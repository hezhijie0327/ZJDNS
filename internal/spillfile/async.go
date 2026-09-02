package spillfile

import (
	"context"
	"sync"
	"sync/atomic"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"
)

// AsyncWriter drains spill writes on a dedicated goroutine.
//
// lrumap invokes OnEvict synchronously under the map mutex, which every
// Get/Set of that cache needs — a direct Store.Put there performed a
// WriteAt (and could queue behind a whole-file Compact) while the cache was
// frozen for the IO duration (2026-09 D2).  Enqueue is non-blocking and
// O(1); the single writer preserves per-key ordering because the enqueue
// happens under the same map mutex that ordered the evictions.
//
// Entries are re-derivable from upstream, so overflow drops the NEWEST
// eviction (bounded queue, counted) rather than blocking the caller.
type AsyncWriter struct {
	store   *Store
	ch      chan putRequest
	done    chan struct{}
	dropped atomic.Int64

	mu     sync.RWMutex
	closed bool
}

// putRequest is one queued Store.Put.
type putRequest struct {
	key       string
	ts        int64
	ttl       int
	validated bool
	wire      []byte
}

// DefaultAsyncQueueLen bounds the enqueue buffer.  At the ~500 B average
// record this is ~2 MB of in-flight wire data per tier.
const DefaultAsyncQueueLen = 4096

// NewAsyncWriter starts the writer goroutine for store.  The goroutine owns
// done; Close joins it.
func NewAsyncWriter(store *Store) *AsyncWriter {
	w := &AsyncWriter{
		store: store,
		ch:    make(chan putRequest, DefaultAsyncQueueLen),
		done:  make(chan struct{}),
	}
	go w.loop()
	return w
}

// Enqueue queues one write; false when the queue is full (dropped) or the
// writer is closed.  Never blocks — safe to call under a lrumap mutex.
func (w *AsyncWriter) Enqueue(key string, ts int64, ttl int, validated bool, wire []byte) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return false
	}
	select {
	case w.ch <- putRequest{key: key, ts: ts, ttl: ttl, validated: validated, wire: wire}:
		return true
	default:
		w.dropped.Add(1)
		return false
	}
}

// loop is the single drain goroutine.
func (w *AsyncWriter) loop() {
	defer zdnsutil.HandlePanic("spill async writer")
	defer close(w.done)
	for req := range w.ch {
		if err := w.store.Put(req.key, req.ts, req.ttl, req.validated, req.wire); err != nil {
			// Sampled: disk-full would otherwise log per write at full
			// eviction rate (R2/E8 — persistence errors must be visible).
			log.Debugf("CACHE: spill write %s failed: %v (dropped=%d)", req.key, err, w.dropped.Load())
		}
	}
}

// Dropped reports how many writes overflowed the queue so far.
func (w *AsyncWriter) Dropped() int64 { return w.dropped.Load() }

// Close drains the queue and joins the writer.  Idempotent; bounded by ctx
// (pass a timeout — a stalled disk must not hang shutdown indefinitely).
func (w *AsyncWriter) Close(ctx context.Context) {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.ch)
	}
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-ctx.Done():
	}
}
