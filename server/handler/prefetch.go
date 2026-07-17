package handler

import (
	"sync"
)

// PrefetchCooldown tracks per-cache-key timestamps to rate-limit cache
// prefetch attempts.  A key that was prefetched within the cooldown window
// is skipped.
type PrefetchCooldown struct {
	mu   sync.RWMutex
	data map[string]int64
}

// NewPrefetchCooldown returns an initialised PrefetchCooldown.
func NewPrefetchCooldown() *PrefetchCooldown {
	return &PrefetchCooldown{
		data: make(map[string]int64),
	}
}

// ShouldStart reports whether a prefetch may start for the given key.
// If allowed, the current timestamp is recorded and true is returned.
// Subsequent calls with the same key within the cooldown window return false.
//
// Uses double-checked locking: the common case (key still in cooldown) only
// acquires a read lock.  The write path falls back to an exclusive lock.
func (pc *PrefetchCooldown) ShouldStart(key string, now, cooldownNanos int64) bool {
	// Fast path: read-only check covers the common case where a key is
	// still within its cooldown window.
	pc.mu.RLock()
	last, exists := pc.data[key]
	pc.mu.RUnlock()
	if exists && now-last < cooldownNanos {
		return false
	}

	// Slow path: may need to record a new timestamp.  Acquire the write
	// lock and double-check — another goroutine may have recorded the
	// same key between the RUnlock and Lock.
	pc.mu.Lock()
	last, exists = pc.data[key]
	if exists && now-last < cooldownNanos {
		pc.mu.Unlock()
		return false
	}
	pc.data[key] = now
	pc.mu.Unlock()
	return true
}

// Cleanup removes entries that have aged past the cooldown window.
// Entries where now - timestamp > cooldownNanos are safe to evict.
func (pc *PrefetchCooldown) Cleanup(now, cooldownNanos int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for k, v := range pc.data {
		if now-v > cooldownNanos {
			delete(pc.data, k)
		}
	}
}
