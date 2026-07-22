// Package lrumap provides a generic, concurrent-safe bounded map with LRU
// eviction. When the map reaches its capacity, the least recently used entry is
// evicted to make room for new entries.
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
type Map[K comparable, V any] struct {
	mu   sync.Mutex
	m    map[K]*lruEntry[K, V]
	head *lruEntry[K, V] // sentinel: most-recent side
	tail *lruEntry[K, V] // sentinel: least-recent side
	len  int
	cap  int
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

// Get returns the value for key and whether it was found.
// Accessing an entry marks it as most recently used.
func (m *Map[K, V]) Get(key K) (V, bool) {
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
// if the map has reached its capacity and key is new.
func (m *Map[K, V]) Set(key K, val V) {
	m.mu.Lock()
	if e, ok := m.m[key]; ok {
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

// Len returns the current number of entries.
func (m *Map[K, V]) Len() int {
	m.mu.Lock()
	n := m.len
	m.mu.Unlock()
	return n
}

// Delete removes a key from the map.
func (m *Map[K, V]) Delete(key K) {
	m.mu.Lock()
	if e, ok := m.m[key]; ok {
		m.remove(e)
		delete(m.m, key)
		m.len--
	}
	m.mu.Unlock()
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
	}
}
