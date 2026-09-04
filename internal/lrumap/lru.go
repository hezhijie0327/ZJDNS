// Package lrumap provides generic, concurrent-safe map data structures with
// bounded capacity and LRU eviction.
//
// LRU ordering is maintained via an embedded doubly-linked list with sentinel
// head/tail nodes: Get and Set (update) move the accessed entry to the front
// (most-recent side); new entries are pushed to the front; eviction removes
// from the back (least-recent side, just before the tail sentinel).
//
// Unlike container/list, the list pointers are embedded directly in each entry,
// eliminating the separate *list.Element heap allocation and the interface
// boxing overhead.
package lrumap

import "sync"

// lruEntry holds a key-value pair with embedded doubly-linked list pointers.
type lruEntry[K comparable, V any] struct {
	key        K
	val        V
	prev, next *lruEntry[K, V]
}

// Map is a concurrent-safe bounded map with LRU eviction.
// The zero value is not usable; use New to create one.
// A Map created via NewSharded dispatches every method to the shard owning
// the key — mu/head/tail are unused in that case.
type Map[K comparable, V any] struct {
	mu   sync.Mutex
	m    map[K]*lruEntry[K, V]
	head *lruEntry[K, V] // sentinel: most-recent side
	tail *lruEntry[K, V] // sentinel: least-recent side
	len  int
	cap  int

	// Sharding (NewSharded): non-empty ⇒ every method dispatches to the
	// shard owning the key. Set before the map is published; read-only after.
	shards  []*Map[K, V]
	hashKey func(K) uint64

	// OnEvict, if set, is called with the key and value of an entry
	// that is evicted to make room.  It runs with the map mutex held,
	// so it must not call back into the map or block.
	OnEvict func(K, V)
}

// New creates a Map with the given capacity. When the map reaches capacity,
// the least recently used entry is evicted to make room for new entries.
func New[K comparable, V any](capacity int) *Map[K, V] {
	if capacity <= 0 {
		capacity = 64
	}
	head := &lruEntry[K, V]{} // sentinel
	tail := &lruEntry[K, V]{} // sentinel
	head.next = tail
	tail.prev = head
	return &Map[K, V]{
		m:    make(map[K]*lruEntry[K, V], capacity),
		head: head,
		tail: tail,
		cap:  capacity,
	}
}

// SetOnEvict configures the eviction callback. The assignment is performed
// under the map mutex so it cannot race a concurrent eviction read.  On a
// sharded map the callback is propagated to every shard.
func (m *Map[K, V]) SetOnEvict(fn func(K, V)) {
	if len(m.shards) > 0 {
		for _, s := range m.shards {
			s.SetOnEvict(fn)
		}
		return
	}
	m.mu.Lock()
	m.OnEvict = fn
	m.mu.Unlock()
}

// Get returns the value for key and whether it was found.
// Accessing an entry marks it as most recently used.
func (m *Map[K, V]) Get(key K) (V, bool) {
	if len(m.shards) > 0 {
		return m.shardFor(key).Get(key)
	}
	m.mu.Lock()
	if e, ok := m.m[key]; ok {
		m.moveToFront(e)
		v := e.val
		m.mu.Unlock()
		return v, true
	}
	m.mu.Unlock()
	var zero V
	return zero, false
}

// Set stores the value under key, evicting the least recently used entry
// if the map has reached its capacity and key is new.  Overwriting an
// existing key invokes OnEvict with the OLD value — resource-holding values
// (dialers, clients, sessions) must be released when replaced, exactly as
// capacity eviction releases them (R2 finding).
func (m *Map[K, V]) Set(key K, val V) {
	if len(m.shards) > 0 {
		m.shardFor(key).Set(key, val)
		return
	}
	m.mu.Lock()
	if e, ok := m.m[key]; ok {
		if m.OnEvict != nil {
			m.OnEvict(key, e.val)
		}
		e.val = val
		m.moveToFront(e)
		m.mu.Unlock()
		return
	}
	if m.len >= m.cap {
		m.evictLocked()
	}
	e := &lruEntry[K, V]{key: key, val: val}
	m.m[key] = e
	m.pushFront(e)
	m.len++
	m.mu.Unlock()
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the key was already present, false if
// the value was freshly stored.
func (m *Map[K, V]) LoadOrStore(key K, val V) (V, bool) {
	if len(m.shards) > 0 {
		return m.shardFor(key).LoadOrStore(key, val)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[key]; ok {
		m.moveToFront(e)
		return e.val, true
	}
	if m.len >= m.cap {
		m.evictLocked()
	}
	e := &lruEntry[K, V]{key: key, val: val}
	m.m[key] = e
	m.pushFront(e)
	m.len++
	return val, false
}

// Len returns the current number of entries.
func (m *Map[K, V]) Len() int {
	if len(m.shards) > 0 {
		n := 0
		for _, s := range m.shards {
			n += s.Len()
		}
		return n
	}
	m.mu.Lock()
	n := m.len
	m.mu.Unlock()
	return n
}

// Delete removes a key from the map.  OnEvict is invoked for the removed
// entry, mirroring eviction and overwrite semantics — resource-holding
// values (dialers, clients, sessions) must be released on every exit path.
func (m *Map[K, V]) Delete(key K) {
	if len(m.shards) > 0 {
		m.shardFor(key).Delete(key)
		return
	}
	m.mu.Lock()
	if e, ok := m.m[key]; ok {
		m.remove(e)
		delete(m.m, key)
		m.len--
		if m.OnEvict != nil {
			m.OnEvict(e.key, e.val)
		}
	}
	m.mu.Unlock()
}

// Clear removes all entries from the map.
// OnEvict is called for each evicted entry.
func (m *Map[K, V]) Clear() {
	if len(m.shards) > 0 {
		for _, s := range m.shards {
			s.Clear()
		}
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for e := m.head.next; e != m.tail; e = e.next {
		if m.OnEvict != nil {
			m.OnEvict(e.key, e.val)
		}
	}
	m.m = make(map[K]*lruEntry[K, V], m.cap)
	m.head.next = m.tail
	m.tail.prev = m.head
	m.len = 0
}

// CompareAndDelete removes the entry for key only if it currently holds val
// (interface equality — V must be a comparable type; slice/map/func values
// would panic here). It reports whether the entry was removed; a concurrent
// Set installing a different value for the same key is preserved.
func (m *Map[K, V]) CompareAndDelete(key K, val V) bool {
	if len(m.shards) > 0 {
		return m.shardFor(key).CompareAndDelete(key, val)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[key]; ok && any(e.val) == any(val) {
		m.remove(e)
		delete(m.m, key)
		m.len--
		if m.OnEvict != nil {
			m.OnEvict(e.key, e.val)
		}
		return true
	}
	return false
}

// Range calls fn for each entry in the map, from most recent to least recent
// (per shard on a sharded map; cross-shard ordering is not defined).
// Iteration stops if fn returns false.
func (m *Map[K, V]) Range(fn func(K, V) bool) {
	if len(m.shards) > 0 {
		for _, s := range m.shards {
			s.Range(fn)
		}
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for e := m.head.next; e != m.tail; e = e.next {
		if !fn(e.key, e.val) {
			return
		}
	}
}

// moveToFront moves e to the front (most-recent side) of the list.
// Skips the pointer manipulation when e is already at the front.
func (m *Map[K, V]) moveToFront(e *lruEntry[K, V]) {
	if e.prev == m.head {
		return // already at front — skip
	}
	// Unlink from current position.
	e.prev.next = e.next
	e.next.prev = e.prev
	// Insert after head.
	e.prev = m.head
	e.next = m.head.next
	m.head.next.prev = e
	m.head.next = e
}

// pushFront inserts e after the head sentinel.
func (m *Map[K, V]) pushFront(e *lruEntry[K, V]) {
	e.prev = m.head
	e.next = m.head.next
	m.head.next.prev = e
	m.head.next = e
}

// remove unlinks e from the list.
func (m *Map[K, V]) remove(e *lruEntry[K, V]) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = nil
	e.next = nil
}

// evictLocked removes the least recently used entry (just before the tail sentinel).
// Must be called with m.mu held and m.len >= m.cap > 0.
func (m *Map[K, V]) evictLocked() {
	if e := m.tail.prev; e != m.head {
		m.remove(e)
		delete(m.m, e.key)
		m.len--
		if m.OnEvict != nil {
			m.OnEvict(e.key, e.val)
		}
	}
}
