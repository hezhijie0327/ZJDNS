// Package topk provides a generic, concurrent-safe bounded map that tracks
// per-key uint64 counters and retains the highest-count entries.
//
// It complements lrumap (access-time LRU eviction): when the map reaches
// capacity, the entry with the LOWEST count is evicted, so entries that were
// hot in the past but idle recently are kept. This is the right policy for
// "top-N by frequency" use cases (per-RCODE domain debug journals, stats
// dashboards), where lrumap's access-time eviction would drop long-lived
// high-count keys in favour of one-off newcomers.
//
// Inc is O(1) amortized; the O(N) minimum-scan eviction runs only on overflow.
// TopN sorts on demand (O(N log N)) — it is for periodic/administrative reads,
// not the hot path.
package topk

import (
	"slices"
	"sync"
)

// Entry is a single (key, count) pair returned by TopN, ordered by count
// descending.
type Entry[K comparable] struct {
	Key   K
	Count uint64
}

// Map is a bounded counter map with lowest-count eviction.
// The zero value is not usable; use New to create one.
type Map[K comparable] struct {
	mu       sync.Mutex
	m        map[K]uint64
	capacity int
}

// defaultCapacity is applied when New receives a capacity <= 0.
const defaultCapacity = 1000

// New creates a Map that retains at most capacity entries, evicting the
// lowest-count entry when full. A capacity <= 0 applies the package default.
func New[K comparable](capacity int) *Map[K] {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	return &Map[K]{
		m:        make(map[K]uint64, capacity),
		capacity: capacity,
	}
}

// Inc increments the counter for key by 1, creating the entry if absent.
// When the map is at capacity, the entry with the lowest count is evicted
// (ties break arbitrarily).
func (m *Map[K]) Inc(key K) {
	m.mu.Lock()
	if _, ok := m.m[key]; ok {
		m.m[key]++
		m.mu.Unlock()
		return
	}
	if len(m.m) >= m.capacity {
		m.evictMinLocked()
	}
	m.m[key] = 1
	m.mu.Unlock()
}

// evictMinLocked removes the entry with the lowest count. Caller holds mu.
func (m *Map[K]) evictMinLocked() {
	var minKey K
	var minCount uint64
	first := true
	for k, c := range m.m {
		if first || c < minCount {
			minKey, minCount = k, c
			first = false
		}
	}
	if !first {
		delete(m.m, minKey)
	}
}

// TopN returns the n entries with the highest counts, ordered by count
// descending. Fewer than n entries are returned when the map holds fewer.
// The result is a fresh slice — callers may keep it.
func (m *Map[K]) TopN(n int) []Entry[K] {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries := make([]Entry[K], 0, min(n, len(m.m)))
	for k, c := range m.m {
		entries = append(entries, Entry[K]{Key: k, Count: c})
	}
	slices.SortFunc(entries, func(a, b Entry[K]) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return 0
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// Len returns the number of tracked entries.
func (m *Map[K]) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

// Clear removes all entries.
func (m *Map[K]) Clear() {
	m.mu.Lock()
	clear(m.m)
	m.mu.Unlock()
}
