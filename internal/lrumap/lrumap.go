// Package lrumap provides a generic, concurrent-safe bounded map that evicts
// entries in bulk when the capacity threshold is exceeded.  Unlike deleting a
// single random entry on overflow, bulk eviction (to 80% capacity) reduces
// contention and avoids thrashing under concurrent insertions.
package lrumap

import "sync"

// Map is a concurrent-safe bounded map with bulk eviction.
// The zero value is not usable; use New to create one.
type Map[K comparable, V any] struct {
	mu  sync.Mutex
	m   map[K]V
	cap int
}

// New creates a Map with the given capacity.  When the map size reaches cap,
// entries are evicted in bulk down to 80% of cap.
func New[K comparable, V any](capacity int) *Map[K, V] {
	if capacity <= 0 {
		capacity = 64
	}
	return &Map[K, V]{
		m:   make(map[K]V, capacity),
		cap: capacity,
	}
}

// Get returns the value for key and whether it was found.
func (m *Map[K, V]) Get(key K) (V, bool) {
	m.mu.Lock()
	v, ok := m.m[key]
	m.mu.Unlock()
	return v, ok
}

// Set stores the value under key, evicting entries in bulk if the map has
// reached its capacity.
func (m *Map[K, V]) Set(key K, val V) {
	m.mu.Lock()
	if len(m.m) >= m.cap {
		m.evictLocked()
	}
	m.m[key] = val
	m.mu.Unlock()
}

// Len returns the current number of entries.
func (m *Map[K, V]) Len() int {
	m.mu.Lock()
	n := len(m.m)
	m.mu.Unlock()
	return n
}

// Delete removes a key from the map.
func (m *Map[K, V]) Delete(key K) {
	m.mu.Lock()
	delete(m.m, key)
	m.mu.Unlock()
}

// evictLocked removes entries down to 80% capacity.  Must be called with m.mu held.
func (m *Map[K, V]) evictLocked() {
	target := m.cap * 8 / 10
	if target <= 0 {
		target = 1
	}
	// Delete random entries until we reach the target size.
	for k := range m.m {
		delete(m.m, k)
		if len(m.m) <= target {
			break
		}
	}
}
