package cache

import (
	"database/sql"
	"strings"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// extractPtrRecs extracts reverse-lookup rows from a response's RRs,
// deduplicated by (rdata_ip, name) — the same IP can appear across multiple
// sections in a single response.  Extraction happens at Set() time so the
// queued write item does not retain the response slices.
func extractPtrRecs(rrs []dns.RR) []ptrRec {
	var recs []ptrRec
	for _, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		ip, ok := zdnsutil.ExtractIPString(rr)
		if !ok {
			continue
		}
		recs = append(recs, ptrRec{
			name: rr.Header().Name, ttl: int(rr.Header().TTL), rdataIP: ip,
		})
	}
	if len(recs) == 0 {
		return nil
	}

	// Deduplicate by (rdata_ip, name) — same IP can appear in the same section.
	seen := make(map[string]bool, len(recs))
	unique := recs[:0]
	for _, r := range recs {
		key := r.rdataIP + "\x00" + r.name
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}
	return unique
}

// insertPtrRecs inserts pre-extracted reverse-lookup rows into ptr_map for a
// cache entry, inside the caller's transaction.
func insertPtrRecs(tx *sql.Tx, entryID int64, recs []ptrRec) error {
	if len(recs) == 0 {
		return nil
	}
	placeholders := make([]string, len(recs))
	args := make([]any, 0, len(recs)*4)
	for i, r := range recs {
		placeholders[i] = "(?, ?, ?, ?)"
		args = append(args, r.rdataIP, entryID, r.name, r.ttl)
	}
	stmt := `INSERT OR REPLACE INTO ptr_map (rdata_ip, entry_id, name, ttl) VALUES ` + //nolint:gosec // G202: parameterized placeholders, no user input
		strings.Join(placeholders, ",")
	if _, err := tx.Exec(stmt, args...); err != nil {
		// Callers (async_cache.go flushCacheEntries) log the failure with
		// their own context — do not double-report the same event.
		return err
	}
	return nil
}
