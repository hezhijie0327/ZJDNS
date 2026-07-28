// Package ringbuffer provides a generic, concurrent-safe bounded ring buffer.
//
// Push overwrites the oldest entry when full.  Snapshots return a copy of
// current entries from newest to oldest without blocking writers.
package ringbuffer

import "sync"

// RingBuffer is a generic, bounded, thread-safe ring buffer.
// The zero value is not usable; use New to create one.
type RingBuffer[T any] struct {
	mu   sync.RWMutex
	buf  []T
	head int // next write position
	size int // number of elements currently stored (0 to cap)
	cap  int
}

// New creates a RingBuffer with the given capacity.  Capacity must be > 0.
func New[T any](capacity int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buf: make([]T, capacity),
		cap: capacity,
	}
}

// Push adds an item to the buffer.  When the buffer is full, the oldest entry
// is silently overwritten.
func (rb *RingBuffer[T]) Push(item T) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.buf[rb.head] = item
	rb.head = (rb.head + 1) % rb.cap
	if rb.size < rb.cap {
		rb.size++
	}
}

// Snapshot returns a copy of all buffered elements ordered newest-first.
func (rb *RingBuffer[T]) Snapshot() []T {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return nil
	}
	out := make([]T, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.head - 1 - i) % rb.cap
		if idx < 0 {
			idx += rb.cap
		}
		out[i] = rb.buf[idx]
	}
	return out
}

// SnapshotN returns at most n of the newest elements, newest-first.
// If n >= size, returns all elements.
func (rb *RingBuffer[T]) SnapshotN(n int) []T {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 || n <= 0 {
		return nil
	}
	if n > rb.size {
		n = rb.size
	}
	out := make([]T, n)
	for i := 0; i < n; i++ {
		idx := (rb.head - 1 - i) % rb.cap
		if idx < 0 {
			idx += rb.cap
		}
		out[i] = rb.buf[idx]
	}
	return out
}

// Len returns the number of elements currently in the buffer.
func (rb *RingBuffer[T]) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size
}

// Cap returns the maximum capacity of the buffer.
func (rb *RingBuffer[T]) Cap() int {
	return rb.cap
}
