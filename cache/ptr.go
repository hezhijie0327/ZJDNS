package cache

import (
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// updatePtrIndex appends reverse-lookup records for a cache entry's A/AAAA
// records. Re-Setting the same entry replaces its old records (no growth on
// repeated probes). Deduplicates by (ip, name) — the same IP can appear
// across multiple sections in a single response.
func (c *Cache) updatePtrIndex(owner entryKey, answer, authority, additional []dns.RR, ts, expiresAt int64) {
	type rec struct {
		ip   string
		name string
		ttl  int32
	}
	var recs []rec
	seen := make(map[string]bool)
	for _, rrs := range [][]dns.RR{answer, authority, additional} {
		for _, rr := range rrs {
			if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
				continue
			}
			ip, ok := zdnsutil.ExtractIPString(rr)
			if !ok {
				continue
			}
			// DNS names are case-insensitive (RFC 4343): canonicalise so
			// case-variant records collapse into one row.
			name := dnsutil.Canonical(rr.Header().Name)
			key := ip + "\x00" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			recs = append(recs, rec{ip: ip, name: name, ttl: int32(rr.Header().TTL)}) //nolint:gosec // G115: protocol-bounded value fits target type
		}
	}
	if len(recs) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.cleanupPtrIndexLocked(owner)
	for _, r := range recs {
		c.ptrIndex[r.ip] = append(c.ptrIndex[r.ip], &ptrRecord{
			name:      r.name,
			ttl:       r.ttl,
			ts:        ts,
			expiresAt: expiresAt,
			ownerKey:  owner,
		})
	}
}

// cleanupPtrIndexLocked removes all PTR records owned by the entry with the
// given key. Must hold c.mu.
func (c *Cache) cleanupPtrIndexLocked(owner entryKey) {
	for ip, recs := range c.ptrIndex {
		kept := recs[:0]
		for _, r := range recs {
			if r.ownerKey != owner {
				kept = append(kept, r)
			}
		}
		if len(kept) == 0 {
			delete(c.ptrIndex, ip)
		} else {
			c.ptrIndex[ip] = kept
		}
	}
}

// ReverseLookup returns all cached domain names mapped to the given IP.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil //nolint:nilerr // key not found
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := log.NowUnix()
	recs := c.ptrIndex[ip]
	if len(recs) == 0 {
		return nil
	}
	results := make([]LookupResult, 0, len(recs))
	for _, r := range recs {
		if r.expiresAt > 0 && r.expiresAt < now {
			continue
		}
		results = append(results, LookupResult{
			Name: r.name,
			TTL:  ttl.RemainingTTL(r.ts, int(r.ttl), uint32(config.DefaultStaleTTL)),
		})
	}
	return results
}
