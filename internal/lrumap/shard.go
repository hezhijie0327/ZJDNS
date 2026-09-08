// Sharded variant of Map: the hot caches (DNS response entries, latency
// table) serialise every Get/Set on a single mutex otherwise, which caps
// multi-core QPS. NewSharded splits the capacity across N shards picked by
// key hash; LRU eviction and the capacity bound apply per shard, so the
// aggregate bound is approximate (capacity + N - 1 entries worst case).
package lrumap

import "hash/maphash"

const (
	// defaultShards caps the shard count; a power of two so the shard pick
	// is a mask.
	defaultShards = 64

	// minEntriesPerShard stops growing the shard count once shards would
	// hold fewer than this many entries — 64 shards over a 2000-entry cache
	// is 32 entries per shard, pure per-shard overhead (mutex, sentinels,
	// map) for critical sections that are already tiny.
	minEntriesPerShard = 64
)

// NewSharded creates a Map whose storage is split across shards, each with
// its own mutex and LRU list. Keys of any comparable type are distributed via
// maphash.Comparable (struct keys — e.g. the cache's fixed-size cacheKey —
// hash by value, no stringification). The shard count doubles while each new
// shard would still hold at least minEntriesPerShard entries (bounded by
// defaultShards), and tiny capacities degenerate to a single shard so the
// capacity bound stays exact.
func NewSharded[K comparable, V any](capacity int) *Map[K, V] {
	return NewShardedWithHash[K, V](capacity, nil)
}

// NewShardedWithHash is NewSharded with a caller-provided hash function
// (nil = maphash.Comparable).  The response cache passes a hand-rolled
// hash over its fixed-size key — faster than the generic comparable hash
// on the per-hit shard pick.
func NewShardedWithHash[K comparable, V any](capacity int, hash func(K) uint64) *Map[K, V] {
	if capacity < 2*minEntriesPerShard {
		return New[K, V](capacity)
	}
	shards := 1
	for shards < defaultShards && capacity/(shards*2) >= minEntriesPerShard {
		shards *= 2
	}
	perShard := capacity/shards + 1
	m := &Map[K, V]{}
	if hash != nil {
		m.hashKey = hash
	} else {
		seed := maphash.MakeSeed()
		m.hashKey = func(k K) uint64 { return maphash.Comparable(seed, k) }
	}
	for range shards {
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
