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

	// Replace this owner's records across all IPs, then append the new ones.
	c.cleanupPtrIndex(owner)
	for _, r := range recs {
		record := &ptrRecord{
			name:      r.name,
			ttl:       r.ttl,
			ts:        ts,
			expiresAt: expiresAt,
			ownerKey:  owner,
		}
		old, ok := c.ptrIndex.Get(r.ip)
		if !ok {
			c.ptrIndex.Set(r.ip, []*ptrRecord{record})
			continue
		}
		c.ptrIndex.Set(r.ip, append(old, record))
	}
}

// cleanupPtrIndex removes all PTR records owned by the entry with the given
// key, deleting now-empty IP entries. Runs from the store's OnEvict callback
// (store lock held) — it must not touch the store itself.
func (c *Cache) cleanupPtrIndex(owner entryKey) {
	type change struct {
		ip   string
		recs []*ptrRecord
	}
	changes := make([]change, 0, 8)
	c.ptrIndex.Range(func(ip string, recs []*ptrRecord) bool {
		kept := recs[:0]
		for _, r := range recs {
			if r.ownerKey != owner {
				kept = append(kept, r)
			}
		}
		if len(kept) != len(recs) {
			changes = append(changes, change{ip: ip, recs: kept})
		}
		return true
	})
	// Range holds the map lock; apply outside it.
	for _, ch := range changes {
		if len(ch.recs) == 0 {
			c.ptrIndex.Delete(ch.ip)
		} else {
			c.ptrIndex.Set(ch.ip, ch.recs)
		}
	}
}

// ptrRecordsWeight estimates the in-memory footprint of one IP's derived
// records: fixed per-record overhead plus the name and owner-key strings.
// Used as the lrumap weight function for byte-budgeted eviction.
func ptrRecordsWeight(recs []*ptrRecord) int64 {
	const perRecord = 48 // struct fields + string headers + slice pointers
	var w int64
	for _, r := range recs {
		w += perRecord + int64(len(r.name)) + int64(len(r.ownerKey.qname)) + int64(len(r.ownerKey.ecsAddr))
	}
	return w
}

// ReverseLookup returns all cached domain names mapped to the given IP.
func (c *Cache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil //nolint:nilerr // key not found
	}
	recs, ok := c.ptrIndex.Get(ip)
	if !ok {
		return nil
	}
	now := log.NowUnix()
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
