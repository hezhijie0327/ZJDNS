package handler

import (
	"zjdns/config"
	"zjdns/internal/lrumap"
)

// PrefetchCooldown tracks per-cache-key timestamps to rate-limit cache
// prefetch attempts. A key that was prefetched within the cooldown window
// is skipped. Backed by a bounded lrumap — capacity eviction replaces the
// old manual oldest-entry sweep.
type PrefetchCooldown struct {
	m *lrumap.Map[string, int64]
}

// NewPrefetchCooldown returns an initialised PrefetchCooldown.
func NewPrefetchCooldown() *PrefetchCooldown {
	return &PrefetchCooldown{m: lrumap.New[string, int64](config.DefaultPrefetchCooldownMaxEntries)}
}

// ShouldStart reports whether a prefetch may start for the given key.
// If allowed, the current timestamp is recorded and true is returned.
// Subsequent calls with the same key within the cooldown window return false.
//
// Expired entries are claimed exclusively via CompareAndDelete: only the
// goroutine that observes a given value can replace it, so concurrent
// starters cannot both pass. A missing key has a small Get→Set race window,
// but the refresh singleflight (pendingRefreshes) deduplicates the actual
// refresh work, so a double pass cannot double the work.
func (pc *PrefetchCooldown) ShouldStart(key string, now, cooldownNanos int64) bool {
	for {
		last, ok := pc.m.Get(key)
		if ok && now-last < cooldownNanos {
			return false
		}
		if ok {
			// Expired entry — claim it exclusively; failure means another
			// goroutine already replaced it, so re-check.
			if !pc.m.CompareAndDelete(key, last) {
				continue
			}
			pc.m.Set(key, now)
			return true
		}
		pc.m.Set(key, now)
		return true
	}
}

// Cleanup removes entries that have aged past the cooldown window, freeing
// their slots before LRU eviction would displace live keys. Capacity
// management itself is handled by the lrumap.
func (pc *PrefetchCooldown) Cleanup(now, cooldownNanos int64) {
	var stale []string
	pc.m.Range(func(k string, v int64) bool {
		if now-v > cooldownNanos {
			stale = append(stale, k)
		}
		return true
	})
	for _, k := range stale {
		pc.m.Delete(k)
	}
}
