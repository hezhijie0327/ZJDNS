package cache

import (
	"time"
	"zjdns/database"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"github.com/dgraph-io/badger/v4"
)

// insertPtrMap inserts reverse-lookup entries into BadgerDB for a cache entry.
// Deduplicates by (rdata_ip, name) — the same IP can appear across multiple
// sections in a single response. Each ptr_map entry inherits the cache entry's
// physical expiry so BadgerDB compaction can reclaim orphaned keys.
func insertPtrMap(txn *badger.Txn, entryID uint64, rrs []dns.RR, now, ttlDuration int64) error {
	type rec struct {
		name    string
		ttl     int32
		rdataIP string
	}
	var recs []rec
	for _, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		ip, ok := zdnsutil.ExtractIPString(rr)
		if !ok {
			continue
		}
		recs = append(recs, rec{
			name: rr.Header().Name, ttl: int32(rr.Header().TTL), rdataIP: ip, //nolint:gosec // G115: protocol-bounded value fits target type
		})
	}
	if len(recs) == 0 {
		return nil
	}

	// Deduplicate by (rdata_ip, name).
	seen := make(map[string]bool, len(recs))
	for _, r := range recs {
		key := r.rdataIP + "\x00" + r.name
		if !seen[key] {
			seen[key] = true
			k := database.EIPReverseKey(r.rdataIP, entryID, r.name)
			v := database.EncodePtrMapValue(r.ttl)
			e := badger.NewEntry(k, v).
				WithTTL(time.Duration(ttlDuration) * time.Second)
			if err := txn.SetEntry(e); err != nil {
				return err
			}
		}
	}
	return nil
}
