package cache

import (
	"database/sql"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// insertPtrMap inserts reverse-lookup entries into ptr_map for a cache entry.
// Deduplicates by (rdata_ip, name) — the same IP can appear across multiple
// sections in a single response.
func insertPtrMap(tx *sql.Tx, entryID int64, rrs []dns.RR) {
	type rec struct {
		name    string
		ttl     int
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
			name: rr.Header().Name, ttl: int(rr.Header().TTL), rdataIP: ip,
		})
	}
	if len(recs) == 0 {
		return
	}

	// Deduplicate by (rdata_ip, name) — same IP can appear in the same section.
	seen := make(map[string]bool, len(recs))
	var unique []rec
	for _, r := range recs {
		key := r.rdataIP + "\x00" + r.name
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}

	placeholders := make([]string, len(unique))
	args := make([]any, 0, len(unique)*4)
	for i, r := range unique {
		placeholders[i] = "(?, ?, ?, ?)"
		args = append(args, r.rdataIP, entryID, r.name, r.ttl)
	}
	stmt := `INSERT OR REPLACE INTO ptr_map (rdata_ip, entry_id, name, ttl) VALUES ` + //nolint:gosec // G202: parameterized placeholders, no user input
		zdnsutil.JoinPlaceholders(placeholders, ",")
	if _, err := tx.Exec(stmt, args...); err != nil {
		log.Warnf("CACHE: insert ptr_map failed: %v", err)
	}
}
