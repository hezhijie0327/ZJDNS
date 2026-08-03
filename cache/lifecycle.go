package cache

import (
	"fmt"
	"zjdns/internal/log"
	"zjdns/internal/pool"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
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
		c.ptrIndexFromWire(k, e.ts, e.expiresAt, msg.Answer, msg.Ns, msg.Extra)
		pool.DefaultMessage.Put(msg)
		return true
	})
}

// ptrIndexFromWire inserts PTR records for one loaded entry. Dedup by
// (ip, name) within the entry, same as updatePtrIndex.
func (c *Cache) ptrIndexFromWire(owner entryKey, ts, expiresAt int64, sections ...[]dns.RR) {
	seen := make(map[string]bool)
	for _, rrs := range sections {
		for _, rr := range rrs {
			if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
				continue
			}
			ip, ok := zdnsutil.ExtractIPString(rr)
			if !ok {
				continue
			}
			name := dnsutil.Canonical(rr.Header().Name)
			if seen[ip+"\x00"+name] {
				continue
			}
			seen[ip+"\x00"+name] = true
			record := &ptrRecord{
				name: name, ttl: int32(rr.Header().TTL), //nolint:gosec // G115: protocol-bounded value fits target type
				ts:        ts,
				expiresAt: expiresAt,
				ownerKey:  owner,
			}
			old, ok := c.ptrIndex.Get(ip)
			if !ok {
				c.ptrIndex.Set(ip, []*ptrRecord{record})
				continue
			}
			c.ptrIndex.Set(ip, append(old, record))
		}
	}
}
