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
// The map is internally sharded (16 shards for string keys) so Inc from
// concurrent queries does not serialise on a single mutex — the counter path
// is the per-query stats hot path.
//
// Inc is O(1) amortized; the O(N) minimum-scan eviction runs only on overflow.
// TopN sorts on demand (O(N log N)) — it is for periodic/administrative reads,
// not the hot path.
package topk

import (
	"hash/maphash"
	"slices"
	"sync"
)

// Entry is a single (key, count) pair returned by TopN, ordered by count
// descending.
type Entry[K comparable] struct {
	Key   K
	Count uint64
}

// shard is one lock-slice of the counter map.
type shard[K comparable] struct {
	mu       sync.Mutex
	m        map[K]uint64
	capacity int
}

// Map is a bounded counter map with lowest-count eviction.
// The zero value is not usable; use New to create one.
type Map[K comparable] struct {
	shards  [shardCount]shard[K]
	hashKey func(K) uint64 // nil for non-string keys → all traffic on shard 0
}

// defaultCapacity is applied when New receives a capacity <= 0.
const defaultCapacity = 1000

// shardCount is the number of internal shards; a power of two so the shard
// pick is a mask. Each shard gets capacity/shardCount of the total budget, so
// aggregate eviction semantics stay approximately the same as the unsharded
// map (lowest-count eviction per shard).
const shardCount = 16

// New creates a Map that retains at most capacity entries, evicting the
// lowest-count entry when full. A capacity <= 0 applies the package default.
// Capacities below shardCount degenerate to a single shard so the bound stays
// exact (sharding rounds per-shard capacity up).
func New[K comparable](capacity int) *Map[K] {
	if capacity <= 0 {
		capacity = defaultCapacity
	}
	sharded := capacity >= shardCount
	perShard := capacity
	if sharded {
		perShard = capacity/shardCount + 1
	}
	m := &Map[K]{}
	if sharded {
		if _, isString := any(*new(K)).(string); isString {
			seed := maphash.MakeSeed()
			m.hashKey = func(k K) uint64 { return maphash.String(seed, any(k).(string)) } //nolint:forcetypeassert // guarded by isString above
		}
	}
	for i := range m.shards {
		if sharded || i == 0 {
			m.shards[i].m = make(map[K]uint64, perShard)
			m.shards[i].capacity = perShard
		}
	}
	return m
}

// Inc increments the counter for key by 1, creating the entry if absent.
// When the shard is at capacity, its entry with the lowest count is evicted
// (ties break arbitrarily).
func (m *Map[K]) Inc(key K) {
	h := uint64(0)
	if m.hashKey != nil {
		h = m.hashKey(key)
	}
	s := &m.shards[h%shardCount]
	s.mu.Lock()
	if _, ok := s.m[key]; ok {
		s.m[key]++
		s.mu.Unlock()
		return
	}
	if s.capacity <= 0 {
		s.mu.Unlock()
		return
	}
	if len(s.m) >= s.capacity {
		m.evictMinLocked(s)
	}
	s.m[key] = 1
	s.mu.Unlock()
}

// evictMinLocked removes the entry with the lowest count. Caller holds s.mu.
func (m *Map[K]) evictMinLocked(s *shard[K]) {
	var minKey K
	var minCount uint64
	first := true
	for k, c := range s.m {
		if first || c < minCount {
			minKey, minCount = k, c
			first = false
		}
	}
	if !first {
		delete(s.m, minKey)
	}
}

// TopN returns the n entries with the highest counts, ordered by count
// descending. Fewer than n entries are returned when the map holds fewer.
// The result is a fresh slice — callers may keep it.
func (m *Map[K]) TopN(n int) []Entry[K] {
	entries := make([]Entry[K], 0, n)
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		for k, c := range s.m {
			entries = append(entries, Entry[K]{Key: k, Count: c})
		}
		s.mu.Unlock()
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
	n := 0
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		n += len(s.m)
		s.mu.Unlock()
	}
	return n
}

// Clear removes all entries.
func (m *Map[K]) Clear() {
	for i := range m.shards {
		s := &m.shards[i]
		s.mu.Lock()
		clear(s.m)
		s.mu.Unlock()
	}
}
