package cache

import (
	"slices"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// ptrIndexWeight estimates the in-memory footprint of one IP's entry-key
// mappings: fixed per-key overhead plus the qname/ecs strings. Used as the
// lrumap weight function for byte-budgeted eviction.
func ptrIndexWeight(keys []entryKey) int64 {
	const perKey = 32 // struct fields + string headers
	var w int64
	for _, k := range keys {
		w += perKey + int64(len(k.qname)) + int64(len(k.ecsAddr))
	}
	return w
}

// The PTR reverse index stores only entryKeys — the mapping ip → entries
// that contain that IP. All record data (name, TTL, expiry) is derived from
// the entry itself at query time, so the index never duplicates the wire
// data. Memory per mapping is ~40% smaller than storing full records.
//
// Invariant: an entryKey appears in the index iff the entry (or a
// not-yet-evicted predecessor) contained that IP. Maintained on Set
// (updatePtrIndex), on eviction (OnEvict → cleanupPtrIndex), and rebuilt
// from cache entries at startup when ptr.zst is missing.

// updatePtrIndex records the entry's IPs in the reverse index. oldIPs holds
// the previous entry's IP set (from a Get before the Set), enabling targeted
// cleanup instead of a full PTR-index Range scan. When oldIPs is unknown
// (startup/persist restore), pass nil to fall back to a full scan.
func (c *Cache) updatePtrIndex(owner entryKey, ips, oldIPs []string) {
	// Targeted cleanup from the previous entry's known IPs.
	c.cleanupPtrIndex(owner, oldIPs)
	if len(ips) == 0 {
		return
	}
	for _, ip := range ips {
		old, ok := c.ptrIndex.Get(ip)
		if !ok {
			c.ptrIndex.Set(ip, []entryKey{owner})
			continue
		}
		// Clone before append: lrumap.Get returns a slice sharing the map's
		// backing array — appending in place races concurrent ReverseLookup
		// iterations and a second updatePtrIndex on the same IP.
		c.ptrIndex.Set(ip, append(slices.Clone(old), owner))
	}
}

// extractIPs returns the distinct IPs in the given RR sections (in
// first-appearance order).
func extractIPs(sections ...[]dns.RR) []string {
	var ips []string
	seen := make(map[string]bool)
	for _, rrs := range sections {
		for _, rr := range rrs {
			if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
				continue
			}
			ip, ok := zdnsutil.ExtractIPString(rr)
			if !ok || seen[ip] {
				continue
			}
			seen[ip] = true
			ips = append(ips, ip)
		}
	}
	return ips
}

// cleanupPtrIndex removes all reverse mappings owned by the entry with the
// given key, deleting now-empty IP entries. When ips is non-empty (the
// eviction path — the store's OnEvict runs with the store lock held), only
// those IPs are touched: a full scan of the PTR index under the store write
// lock would otherwise cost O(index size) per eviction at steady-state cache
// pressure. Pass nil for the full scan (re-Set paths; entries restored from
// persist carry no IP set).
func (c *Cache) cleanupPtrIndex(owner entryKey, ips []string) {
	if len(ips) > 0 {
		for _, ip := range ips {
			old, ok := c.ptrIndex.Get(ip)
			if !ok {
				continue
			}
			// Copy-filter: never rewrite the map's shared backing array in
			// place (races ReverseLookup's lock-free iteration).
			kept := make([]entryKey, 0, len(old))
			for _, k := range old {
				if k != owner {
					kept = append(kept, k)
				}
			}
			switch {
			case len(kept) == 0:
				c.ptrIndex.Delete(ip)
			case len(kept) != len(old):
				c.ptrIndex.Set(ip, kept)
			}
		}
		return
	}

	type change struct {
		ip   string
		keys []entryKey
	}
	changes := make([]change, 0, 8)
	c.ptrIndex.Range(func(ip string, keys []entryKey) bool {
		// Copy-filter: keys[:0] compaction would rewrite the map's shared
		// backing array in place, racing ReverseLookup's lock-free
		// iteration of a previously returned slice header.
		kept := make([]entryKey, 0, len(keys))
		for _, k := range keys {
			if k != owner {
				kept = append(kept, k)
			}
		}
		if len(kept) != len(keys) {
			changes = append(changes, change{ip: ip, keys: kept})
		}
		return true
	})
	// Range holds the map lock; apply outside it.
	for _, ch := range changes {
		if len(ch.keys) == 0 {
			c.ptrIndex.Delete(ch.ip)
		} else {
			c.ptrIndex.Set(ch.ip, ch.keys)
		}
	}
}

// ReverseLookup returns all cached domain names mapped to the given IP.
// Names and TTLs are derived from the owning entries at query time — the
// index itself holds only the ip → entryKey mappings.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil //nolint:nilerr // key not found
	}
	keys, ok := c.ptrIndex.Get(ip)
	if !ok {
		return nil
	}
	now := log.NowUnix()
	var results []LookupResult
	for _, key := range keys {
		e, ok := c.store.Get(key)
		if !ok {
			continue // entry evicted between index update and query — defensive
		}
		if e.expiresAt > 0 && e.expiresAt < now {
			continue
		}
		msg := pool.DefaultMessage.Get()
		msg.Data = e.value
		if err := msg.Unpack(); err != nil {
			pool.DefaultMessage.Put(msg)
			continue
		}
		for _, rrs := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
			for _, rr := range rrs {
				if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
					continue
				}
				ip2, ok := zdnsutil.ExtractIPString(rr)
				if !ok || ip2 != ip {
					continue
				}
				// DNS names are case-insensitive (RFC 4343): canonicalise so
				// case-variant records collapse into one row.
				results = append(results, LookupResult{
					Name: dnsutil.Canonical(rr.Header().Name),
					TTL:  ttl.RemainingTTL(e.ts, int(rr.Header().TTL), uint32(config.DefaultStaleTTL)),
				})
			}
		}
		pool.DefaultMessage.Put(msg)
	}
	return results
}
