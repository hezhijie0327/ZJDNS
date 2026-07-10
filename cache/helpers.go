package cache

import (
	"database/sql"
	"zjdns/config"
	"zjdns/internal/log"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

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

func minTTL(answer, authority, additional []dns.RR) int {
	minT := -1
	for _, rr := range answer {
		if rr != nil {
			if t := int(rr.Header().TTL); t > 0 && (minT < 0 || t < minT) {
				minT = t
			}
		}
	}
	for _, rr := range authority {
		if rr != nil {
			if t := int(rr.Header().TTL); t > 0 && (minT < 0 || t < minT) {
				minT = t
			}
		}
	}
	for _, rr := range additional {
		if rr != nil {
			if t := int(rr.Header().TTL); t > 0 && (minT < 0 || t < minT) {
				minT = t
			}
		}
	}
	if minT <= 0 {
		return config.DefaultTTL
	}
	return minT
}

func hasNSECOrNSEC3(authority []dns.RR) bool {
	for _, rr := range authority {
		if rr == nil {
			continue
		}
		switch dns.RRToType(rr) {
		case dns.TypeNSEC, dns.TypeNSEC3:
			return true
		}
	}
	return false
}

func negativeTTLCap(authority []dns.RR) int {
	capTTL := config.DefaultMaxNegativeTTL
	for _, rr := range authority {
		if rr == nil {
			continue
		}
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		soaTTL := int(soa.Header().TTL)
		soaMin := int(soa.Minttl)
		soaBased := soaTTL
		if soaMin < soaBased {
			soaBased = soaMin
		}
		if soaBased < capTTL {
			capTTL = soaBased
		}
		break
	}
	return capTTL
}

func ecsParams(ecs *config.ECSOption) (addr string, prefix int) {
	if ecs == nil {
		return "", 0
	}
	return ecs.Address.String(), int(ecs.SourcePrefix)
}
