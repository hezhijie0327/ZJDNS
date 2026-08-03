package cache

import (
	"fmt"
	"zjdns/internal/log"
	"zjdns/internal/pool"
)

// FlushDB truncates a table: "cache" clears all cached responses and derived
// state. "zone" and "ruleset" are no-ops — they never used the persist store.
func (c *Cache) FlushDB(target string) (int64, error) {
	switch target {
	case "cache":
		c.ptrIndex.Clear()
		c.store.Clear() // OnEvict → cleanupPtrIndex (no-op: ptrIndex already empty)
		c.latency.Clear()
		log.Infof("CACHE: flushDB %s: done", target)
		return 0, nil
	case "zone", "ruleset":
		log.Infof("CACHE: flushDB %s: done", target)
		return 0, nil
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
}

// Clear truncates cache entries.
func (c *Cache) Clear() (int64, error) { return c.FlushDB("cache") }

// ClearPtrIndex clears the PTR reverse index and persists the cleared state
// immediately (CHAOS zjdns.ptr.clear). The index is derived data: entries
// survive, so a restart re-derives the index from them.
func (c *Cache) ClearPtrIndex() error {
	c.ptrIndex.Clear()
	return c.ptrIndex.Save()
}

// ClearLatency clears the latency map and persists the cleared state
// immediately (CHAOS zjdns.latency.clear).
func (c *Cache) ClearLatency() error {
	c.latency.Clear()
	return c.latency.Save()
}

// Save snapshots the cache to the persist file (periodic + shutdown, driven
// by persist.Manager; the Keep filter skips expired entries).
func (c *Cache) Save() error {
	return c.store.Save()
}

// Close clears the cache. Persist timing is owned by persist.Manager — the
// final Save has already run when Close is called at shutdown, so a Clear
// here is a pure memory release.
func (c *Cache) Close() error {
	_, _ = c.Clear()
	return nil
}

// rebuildPtrIndex derives the PTR index from stored entries — used when the
// ptr.zst file is missing, corrupt, or empty. The index is derived data; the
// lrumap instances keep their own locks, so no cache-level lock is needed.
func (c *Cache) rebuildPtrIndex() {
	c.store.Range(func(k entryKey, e cacheEntry) bool {
		msg := pool.DefaultMessage.Get()
		msg.Data = e.value
		if err := msg.Unpack(); err != nil {
			pool.DefaultMessage.Put(msg)
			return true
		}
		c.ptrIndexFromWire(k, extractIPs(msg.Answer, msg.Ns, msg.Extra))
		pool.DefaultMessage.Put(msg)
		return true
	})
}

// ptrIndexFromWire records one loaded entry's IPs in the reverse index.
func (c *Cache) ptrIndexFromWire(owner entryKey, ips []string) {
	for _, ip := range ips {
		old, ok := c.ptrIndex.Get(ip)
		if !ok {
			c.ptrIndex.Set(ip, []entryKey{owner})
			continue
		}
		c.ptrIndex.Set(ip, append(old, owner))
	}
}
