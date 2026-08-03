// Package maps provides generic, concurrent-safe map data structures with
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
//
// Two optional capabilities can be configured after construction, both zero-cost
// when unused: weighted eviction (SetWeight — evict by total value weight
// instead of entry count) and file persistence (EnablePersist — snapshot to a
// zstd-compressed file with a per-map Codec, load at startup).
package lrumap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"zjdns/internal/persist"
)

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

	// onEvict, if set, is called with the key and value of an entry that is
	// evicted to make room. It runs with the map mutex held, so it must not
	// call back into the map or block. Configure it with SetOnEvict (which
	// assigns under the lock) — assigning the field directly races eviction.
	onEvict func(K, V)

	// Weighted eviction (SetWeight): when weightOf is set, capacity is
	// governed by totalWeight vs maxWeight instead of entry count.
	maxWeight   int64
	totalWeight int64
	weightOf    func(V) int64

	// Persistence (EnablePersist): fields are nil/empty when disabled.
	persistPath string
	codec       Codec[K, V]
	keep        func(K, V) bool
}

// Codec serializes map keys and values for persistence. Each persistent map
// supplies its own codec; the map owns the file management — version header,
// entry framing, zstd compression, atomic write (via internal/persist).
type Codec[K comparable, V any] interface {
	// Version gates the on-disk format. A mismatch skips the file (cold start).
	Version() uint16
	EncodeKey(k K) []byte
	EncodeValue(v V) []byte
	DecodeKey(b []byte) (K, error)
	// DecodeValue decodes a value; the bool reports whether the entry should
	// be inserted (false = skip, e.g. an entry that expired while on disk).
	DecodeValue(b []byte) (V, bool, error)
}

// PersistConfig configures optional file persistence for a Map.
type PersistConfig[K comparable, V any] struct {
	Path  string
	Codec Codec[K, V]
	// Keep, if non-nil, filters entries during Save (e.g. skip expired).
	Keep func(K, V) bool
}

// entryPair is a snapshot copy of one entry, used to encode outside the lock.
type entryPair[K comparable, V any] struct {
	key K
	val V
}

// defaultPrealloc bounds the initial hash-map allocation: entries beyond it
// are allocated on demand as the map grows.
const defaultPrealloc = 1024

// ErrVersionMismatch reports that a persist file uses a codec version other
// than the current one. The file has been backed up to path+".bak" and the
// map starts cold — a format upgrade never silently destroys the old data.
var ErrVersionMismatch = errors.New("lrumap: persist version mismatch (old file backed up)")

// SetOnEvict configures the eviction callback. The assignment is performed
// under the map mutex so it cannot race a concurrent eviction read.
func (m *Map[K, V]) SetOnEvict(fn func(K, V)) {
	m.mu.Lock()
	m.onEvict = fn
	m.mu.Unlock()
}

// SetWeight switches the map from count-based capacity to weight-based
// capacity: entries are evicted until totalWeight + incoming weight fits
// maxWeight. A single value heavier than maxWeight is still stored (the map
// evicts everything else first). The weight function must be cheap and pure
// — it runs on every insert, update, delete, and eviction under the lock.
func (m *Map[K, V]) SetWeight(maxWeight int64, fn func(V) int64) {
	m.mu.Lock()
	m.maxWeight = maxWeight
	m.weightOf = fn
	m.mu.Unlock()
}

// TotalWeight returns the sum of value weights (0 when weight-based eviction
// is not configured).
func (m *Map[K, V]) TotalWeight() int64 {
	m.mu.Lock()
	w := m.totalWeight
	m.mu.Unlock()
	return w
}

// New creates a Map with the given capacity. When the map reaches capacity,
// the least recently used entry is evicted to make room for new entries.
//
// The backing hash map is preallocated to a bounded size, NOT to the full
// capacity: capacity is the LRU eviction ceiling, and preallocating to it
// would pay for that ceiling up front (a 1M-entry ceiling would preallocate
// ~96MB for a mostly-empty map). The map grows on demand instead.
func New[K comparable, V any](capacity int) *Map[K, V] {
	if capacity <= 0 {
		capacity = 64
	}
	head := &lruEntry[K, V]{} // sentinel
	tail := &lruEntry[K, V]{} // sentinel
	head.next = tail
	tail.prev = head
	return &Map[K, V]{
		m:    make(map[K]*lruEntry[K, V], min(capacity, defaultPrealloc)),
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
	defer m.mu.Unlock() // a panic in OnEvict must not wedge the mutex
	if e, ok := m.m[key]; ok {
		if m.weightOf != nil {
			m.totalWeight += m.weightOf(val) - m.weightOf(e.val)
			// Update path: evicting on insert only would let totalWeight
			// drift over maxWeight while a heavy value is repeatedly
			// refreshed under the same key. The just-updated entry is at
			// the front, so evictLocked (LRU tail) never removes it while
			// len > 1.
			for m.totalWeight > m.maxWeight && m.len > 1 {
				m.evictLocked()
			}
		}
		e.val = val
		m.moveToFront(e)
		return
	}
	m.makeRoomLocked(val)
	e := &lruEntry[K, V]{key: key, val: val}
	m.m[key] = e
	m.pushFront(e)
	m.len++
	if m.weightOf != nil {
		m.totalWeight += m.weightOf(val)
	}
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the key was already present, false if
// the value was freshly stored.
func (m *Map[K, V]) LoadOrStore(key K, val V) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[key]; ok {
		m.moveToFront(e)
		return e.val, true
	}
	m.makeRoomLocked(val)
	e := &lruEntry[K, V]{key: key, val: val}
	m.m[key] = e
	m.pushFront(e)
	m.len++
	if m.weightOf != nil {
		m.totalWeight += m.weightOf(val)
	}
	return val, false
}

// makeRoomLocked evicts entries until a new entry with value val fits the
// capacity. Count-based: evicts one LRU entry at capacity. Weight-based:
// evicts until totalWeight + weight(val) <= maxWeight, stopping at an empty
// map so a value heavier than the whole budget is still stored.
// Must be called with m.mu held, only for keys not already present.
func (m *Map[K, V]) makeRoomLocked(val V) {
	if m.weightOf == nil {
		if m.len >= m.cap {
			m.evictLocked()
		}
		return
	}
	w := m.weightOf(val)
	for m.len > 0 && m.totalWeight+w > m.maxWeight {
		m.evictLocked()
	}
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
		if m.weightOf != nil {
			m.totalWeight -= m.weightOf(e.val)
		}
	}
	m.mu.Unlock()
}

// CompareAndDelete removes the entry for key only if it currently holds val.
// It reports whether the entry was removed. Atomic Get→compare→Delete: a
// concurrent Set installing a different value for the same key is preserved.
// CompareAndDelete deletes the entry for key only if its current value
// equals val (interface equality — V must be a comparable type; slice/map/
// func values would panic here).
func (m *Map[K, V]) CompareAndDelete(key K, val V) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[key]; ok && any(e.val) == any(val) {
		m.remove(e)
		delete(m.m, key)
		m.len--
		if m.weightOf != nil {
			m.totalWeight -= m.weightOf(e.val)
		}
		return true
	}
	return false
}

// Clear removes all entries from the map.
// OnEvict is called for each evicted entry.
func (m *Map[K, V]) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for e := m.head.next; e != m.tail; e = e.next {
		if m.onEvict != nil {
			m.onEvict(e.key, e.val)
		}
	}
	// Bound the preallocation like New — a large-capacity map must not pay
	// for its full ceiling on every Clear (memory spike on FlushDB).
	m.m = make(map[K]*lruEntry[K, V], min(m.cap, defaultPrealloc))
	m.head.next = m.tail
	m.tail.prev = m.head
	m.len = 0
	m.totalWeight = 0
}

// Range calls fn for each entry in the map, from most recent to least recent.
// Iteration stops if fn returns false.
//
// The callback runs with the map mutex held: it must not call back into the
// map (Get/Set/Delete deadlock) and should not block.
func (m *Map[K, V]) Range(fn func(K, V) bool) {
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
// Must be called with m.mu held and m.len > 0.
func (m *Map[K, V]) evictLocked() {
	if e := m.tail.prev; e != m.head {
		m.remove(e)
		delete(m.m, e.key)
		m.len--
		if m.weightOf != nil {
			m.totalWeight -= m.weightOf(e.val)
		}
		if m.onEvict != nil {
			m.onEvict(e.key, e.val)
		}
	}
}

// ── Persistence ──────────────────────────────────────────────────────────

// EnablePersist attaches file persistence to the map and eagerly loads any
// existing file, returning the number of entries restored. A missing file is
// a cold start (0, nil); a corrupt or version-mismatched file is returned as
// an error — the caller logs and continues with an empty map. The caller
// logs the restore (e.g. "CACHE: loaded N entries from ...").
func (m *Map[K, V]) EnablePersist(cfg PersistConfig[K, V]) (int, error) {
	m.mu.Lock()
	m.persistPath = cfg.Path
	m.codec = cfg.Codec
	m.keep = cfg.Keep
	m.mu.Unlock()
	return m.load()
}

// Save snapshots the map to its persist file (zstd + atomic write via
// internal/persist). Entries rejected by the Keep filter are omitted. No-op
// when persistence is not enabled. The snapshot is taken under the lock;
// encoding and writing happen outside it.
func (m *Map[K, V]) Save() error {
	m.mu.Lock()
	if m.persistPath == "" || m.codec == nil {
		m.mu.Unlock()
		return nil
	}
	entries := make([]entryPair[K, V], 0, m.len)
	keep := m.keep
	for e := m.tail.prev; e != m.head; e = e.prev {
		if keep != nil && !keep(e.key, e.val) {
			continue
		}
		entries = append(entries, entryPair[K, V]{key: e.key, val: e.val})
	}
	path := m.persistPath
	codec := m.codec
	m.mu.Unlock()

	// [2B version][8B count] then per entry: [4B key_len][key][4B val_len][val].
	// Written least-recently-used first: on Load, sequential front-insertion
	// leaves the most recently used entry (last in the file) at the front.
	var buf bytes.Buffer
	buf.Grow(10 + len(entries)*24)
	writeU16(&buf, codec.Version())
	writeU64(&buf, uint64(len(entries))) //nolint:gosec // G115: slice len bounded by memory
	for _, p := range entries {
		writeBytes(&buf, codec.EncodeKey(p.key))
		writeBytes(&buf, codec.EncodeValue(p.val))
	}
	return persist.Save(path, buf.Bytes())
}

// load populates the map from the persist file, reporting the number of
// entries restored. Entries are inserted in file order (most-recent first at
// save time, which is also the Range order), so hot entries stay hot after a
// restart. Expired entries — DecodeValue returning include=false — are
// skipped.
func (m *Map[K, V]) load() (int, error) {
	m.mu.Lock()
	path := m.persistPath
	codec := m.codec
	m.mu.Unlock()
	if path == "" || codec == nil {
		return 0, nil
	}
	raw, err := persist.Load(path)
	if err != nil {
		// Corrupt file (zstd framing or decompression failed) — preserve it
		// before the next Save would overwrite it.
		if berr := persist.Backup(path); berr != nil {
			return 0, errors.Join(err, fmt.Errorf("lrumap: backup %s: %w", path, berr))
		}
		return 0, err
	}
	if raw == nil {
		return 0, nil // cold start — no file yet
	}
	if len(raw) < 2+8 {
		_ = persist.Backup(path) // truncated file — preserve it
		return 0, errors.New("lrumap: persist file too short")
	}
	off := 0
	version := binary.BigEndian.Uint16(raw[off:])
	off += 2
	if version != codec.Version() {
		// Format upgrade — back the old file up instead of letting the next
		// Save overwrite it: the old data stays recoverable.
		_ = persist.Backup(path)
		return 0, ErrVersionMismatch
	}
	count := binary.BigEndian.Uint64(raw[off:])
	off += 8
	if count > uint64(len(raw)) { // each entry needs at least 8 bytes of framing
		_ = persist.Backup(path)
		return 0, errors.New("lrumap: persist entry count exceeds file size")
	}
	loaded := 0
	for range count { //nolint:gosec // count bounded by file size above
		var keyB, valB []byte
		var err error
		if keyB, off, err = takeBytes(raw, off); err != nil {
			return 0, m.abortPartialLoad(path, fmt.Errorf("lrumap: truncated key: %w", err))
		}
		if valB, off, err = takeBytes(raw, off); err != nil {
			return 0, m.abortPartialLoad(path, fmt.Errorf("lrumap: truncated value: %w", err))
		}
		key, err := codec.DecodeKey(keyB)
		if err != nil {
			return 0, m.abortPartialLoad(path, fmt.Errorf("lrumap: decode key: %w", err))
		}
		val, include, err := codec.DecodeValue(valB)
		if err != nil {
			return 0, m.abortPartialLoad(path, fmt.Errorf("lrumap: decode value: %w", err))
		}
		if include {
			m.Set(key, val)
			loaded++
		}
	}
	return loaded, nil
}

// abortPartialLoad handles a mid-file decode failure: back the corrupt file
// up (like the other corruption paths) and drop the partially restored
// entries — keeping them would let the next Save silently overwrite the old
// file with truncated data and no recoverable copy.
func (m *Map[K, V]) abortPartialLoad(path string, err error) error {
	_ = persist.Backup(path)
	m.Clear()
	return err
}

// writeU16 appends v as BigEndian uint16.
func writeU16(buf *bytes.Buffer, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	buf.Write(b[:])
}

// writeU64 appends v as BigEndian uint64.
func writeU64(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

// writeBytes appends b with a uint32 length prefix.
func writeBytes(buf *bytes.Buffer, b []byte) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) //nolint:gosec // G115: encoded keys/values bounded by uint32
	buf.Write(hdr[:])
	buf.Write(b)
}

// takeBytes reads a length-prefixed byte slice, returning the new offset.
func takeBytes(raw []byte, off int) (b []byte, next int, err error) {
	if off+4 > len(raw) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint32(raw[off:])) //nolint:gosec // G115: protocol-bounded uint32
	off += 4
	if off+n > len(raw) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return raw[off : off+n], off + n, nil
}
