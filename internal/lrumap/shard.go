// Sharded variant of Map: the hot caches (DNS response entries, latency
// table) serialise every Get/Set on a single mutex otherwise, which caps
// multi-core QPS. NewSharded splits the capacity across N shards picked by
// key hash; LRU eviction and the capacity bound apply per shard, so the
// aggregate bound is approximate (capacity + N - 1 entries worst case).
package lrumap

import "hash/maphash"

// defaultShards is the shard count used by NewSharded; a power of two so the
// shard pick is a mask. 64 matches typical L3-cache-sized critical sections
// under high core counts.
const defaultShards = 64

// NewSharded creates a Map whose storage is split across shards, each with
// its own mutex and LRU list. Keys of any comparable type are distributed via
// maphash.Comparable (struct keys — e.g. the cache's fixed-size cacheKey —
// hash by value, no stringification). Capacities below 2×defaultShards
// degenerate to a single shard so the capacity bound stays exact (sharding
// rounds per-shard capacity up).
func NewSharded[K comparable, V any](capacity int) *Map[K, V] {
	if capacity < 2*defaultShards {
		return New[K, V](capacity)
	}
	perShard := capacity/defaultShards + 1
	m := &Map[K, V]{}
	seed := maphash.MakeSeed()
	m.hashKey = func(k K) uint64 { return maphash.Comparable(seed, k) }
	for range defaultShards {
		m.shards = append(m.shards, newShardMap[K, V](perShard))
	}
	return m
}

// newShardMap builds a single (unsharded) Map of the given capacity.
func newShardMap[K comparable, V any](capacity int) *Map[K, V] {
	return New[K, V](capacity)
}

// shardFor returns the shard owning key (shard 0 when no hash function).
// Must only be called on a sharded map (len(m.shards) > 0).
func (m *Map[K, V]) shardFor(key K) *Map[K, V] {
	if m.hashKey == nil {
		return m.shards[0]
	}
	return m.shards[m.hashKey(key)%uint64(len(m.shards))]
}
