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
func (pc *PrefetchCooldown) ShouldStart(key string, now, cooldownSec int64) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	last, exists := pc.data[key]
	if exists && now-last < cooldownSec {
		return false
	}
	pc.data[key] = now
	return true
}

// Cleanup removes all entries whose timestamp is before expiry (now-based).
func (pc *PrefetchCooldown) Cleanup(now int64) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	for k, v := range pc.data {
		if v < now {
			delete(pc.data, k)
		}
	}
}
