package cache

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// RecordRequest logs a request outcome. Hit path upserts hit counters; miss/
// stale/zone/error/blocked paths insert a log row with entry_id FK.
func (s *SQLiteCache) RecordRequest(r *RequestRecord) {
	if s.db.IsClosed() {
		return
	}

	r.Qname = zdnsutil.NormalizeDomain(r.Qname)
	ecsAddr, ecsPrefix := ecsParams(r.ECS)
	dnssecInt := database.BoolToInt(r.DNSSECOK)

	entryID := s.db.EnsureEntry(r.Qname, int(r.Qtype), int(r.Qclass), ecsAddr, ecsPrefix, dnssecInt)

	if r.Result == "hit" {
		_, _ = s.db.StmtHitCounter.Exec(entryID, r.Protocol, r.Rcode, r.ResponseTime)
		return
	}

	_, _ = s.db.StmtInsertLog.Exec(
		log.NowUnix(), entryID,
		r.Protocol, r.Result, r.ResponseTime, r.Rcode, r.Server,
		database.BoolToInt(r.Hijack), database.BoolToInt(r.Fallback), r.DNSSECStatus,
	)
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil
	}

	// Precompute the serve-stale cutoff so the comparison e.expires_at >= ?
	// avoids a per-row arithmetic expression and can use idx_entries_expires.
	staleCutoff := log.NowUnix() - defaultStaleMaxAge
	rows, err := s.db.SQ.Query(
		`SELECT pm.name, pm.ttl, e.timestamp, MAX(e.timestamp + pm.ttl)
		 FROM ptr_map pm
		 JOIN entries e ON pm.entry_id = e.id
		 WHERE pm.rdata_ip = ? AND e.expires_at >= ?
		 GROUP BY pm.name
		 ORDER BY pm.name`,
		ip, staleCutoff,
	)
	if err != nil {
		log.Warnf("CACHE: PTR lookup failed for %s: %v", ip, err)
		return nil
	}
	defer func() { _ = rows.Close() }()

	var results []LookupResult
	for rows.Next() {
		var name string
		var rawTTL int
		var ts int64
		var dummy int64
		if err := rows.Scan(&name, &rawTTL, &ts, &dummy); err != nil {
			continue
		}
		results = append(results, LookupResult{
			Name: name,
			TTL:  ttl.RemainingTTL(ts, rawTTL, uint32(config.DefaultStaleTTL)),
		})
	}
	return results
}

// FlushDB truncates a single table: "stats" (resets stats_meta.cleared_before),
// "cache" (entries), or "latency" (ip_latency).
func (s *SQLiteCache) FlushDB(target string) (int64, error) {
	if s.db.IsClosed() {
		return 0, errors.New("cache closed")
	}
	var result sql.Result
	var err error
	switch target {
	case "stats":
		var tx *sql.Tx
		tx, err = s.db.SQ.Begin()
		if err != nil {
			return 0, fmt.Errorf("flushDB stats begin tx: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err = tx.Exec(`DELETE FROM entry_hit_counters`); err != nil {
			return 0, fmt.Errorf("flushDB stats: %w", err)
		}
		result, err = tx.Exec(
			`UPDATE stats_meta SET cleared_before = (SELECT COALESCE(MAX(id), 0) FROM request_log) WHERE id = 1`,
		)
		if err != nil {
			return 0, fmt.Errorf("flushDB stats: %w", err)
		}
		if err = tx.Commit(); err != nil {
			return 0, fmt.Errorf("flushDB stats commit: %w", err)
		}
	case "cache":
		result, err = s.db.SQ.Exec(`DELETE FROM entries`)
		if err == nil {
			s.db.SetEntryCount(0)
		}
	case "latency":
		result, err = s.db.SQ.Exec(`DELETE FROM ip_latency`)
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
	if err != nil {
		return 0, fmt.Errorf("flushDB %s: %w", target, err)
	}
	n, _ := result.RowsAffected()
	log.Infof("CACHE: flushDB %s: %d rows", target, n)
	return n, nil
}

// Clear truncates all tables: entries, request_log, and ip_latency.
func (s *SQLiteCache) Clear() (int64, error) {
	n1, err := s.FlushDB("cache")
	if err != nil {
		return 0, err
	}
	n2, err := s.FlushDB("stats")
	if err != nil {
		return n1, err
	}
	n3, err := s.FlushDB("latency")
	if err != nil {
		return n1 + n2, err
	}
	// Clear request_log, entry_hit_counters, and reset stats_meta.
	_, _ = s.db.SQ.Exec(`DELETE FROM entry_hit_counters`)
	result, err := s.db.SQ.Exec(`DELETE FROM request_log`)
	if err != nil {
		return n1 + n2 + n3, fmt.Errorf("clear request_log: %w", err)
	}
	n4, _ := result.RowsAffected()
	_, _ = s.db.SQ.Exec(`UPDATE stats_meta SET cleared_before = 0 WHERE id = 1`)
	return n1 + n2 + n3 + n4, nil
}

// Stats returns aggregated cache statistics as formatted TXT records.
func (s *SQLiteCache) Stats() []string {
	if s.db.IsClosed() {
		return nil
	}

	var entries int64
	_ = s.db.SQ.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&entries)

	var avgMs float64
	var total, hits, misses, stales, zones, errCount, blockedCount, badcookieCount int64
	var hcUDP, hcTCP, hcDOT, hcDOQ, hcDOH, hcDOH3, hcDNSCrypt, hcDNSCryptTCP int64
	var rlUDP, rlTCP, rlDOT, rlDOQ, rlDOH, rlDOH3, rlDNSCrypt, rlDNSCryptTCP int64
	var hijack, fallback, totalMS, hitTotalMS int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var secureCount, insecureCount, bogusCount int64

	// Hits come from entry_hit_counters (aggregated, no cleared_before filter).
	// Single scan: hit counts by protocol + total response time for avg calculation.
	_ = s.db.SQ.QueryRow(
		"SELECT COALESCE(SUM(hit_count), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dot' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doq' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh3' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(total_response_ms), 0)"+
			" FROM entry_hit_counters",
	).Scan(&hits, &hcUDP, &hcTCP, &hcDOT, &hcDOQ, &hcDOH, &hcDOH3, &hcDNSCrypt, &hcDNSCryptTCP, &hitTotalMS)

	// Detail rows from request_log since last stats clear.
	_ = s.db.SQ.QueryRow(
		"SELECT COUNT(*),"+
			" COALESCE(SUM(CASE WHEN result='miss' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='stale' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='zone' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='error' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='blocked' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='badcookie' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dot' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doq' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh3' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN hijack THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN fallback THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(response_time_ms), 0)"+
			" FROM request_log WHERE id > (SELECT cleared_before FROM stats_meta)",
	).Scan(
		&total,
		&misses, &stales, &zones, &errCount, &blockedCount, &badcookieCount,
		&rlUDP, &rlTCP, &rlDOT, &rlDOQ, &rlDOH, &rlDOH3, &rlDNSCrypt, &rlDNSCryptTCP,
		&hijack, &fallback, &totalMS,
	)

	total += hits
	udp := hcUDP + rlUDP
	tcp := hcTCP + rlTCP
	dot := hcDOT + rlDOT
	doq := hcDOQ + rlDOQ
	doh := hcDOH + rlDOH
	doh3 := hcDOH3 + rlDOH3
	dnscrypt := hcDNSCrypt + rlDNSCrypt
	dnscryptTCP := hcDNSCryptTCP + rlDNSCryptTCP

	// Average across all request types (hit + miss + stale + zone + error).
	if total > 0 {
		avgMs = float64(totalMS+hitTotalMS) / float64(total)
	}

	// Rcode distribution: request_log + entry_hit_counters.
	rows, err := s.db.SQ.Query(
		`SELECT rcode, SUM(cnt) FROM (
			SELECT rcode, COUNT(*) AS cnt FROM request_log
			 WHERE id > (SELECT cleared_before FROM stats_meta) GROUP BY rcode
			UNION ALL
			SELECT rcode, SUM(hit_count) AS cnt FROM entry_hit_counters GROUP BY rcode
		) GROUP BY rcode`,
	)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var rc, cnt int64
			if err := rows.Scan(&rc, &cnt); err == nil {
				switch rc {
				case 0:
					noerr = cnt
				case 1:
					formerr = cnt
				case 2:
					servfail = cnt
				case 3:
					nxdomain = cnt
				case 4:
					notimp = cnt
				case 5:
					refused = cnt
				default:
					other += cnt
				}
			}
		}
	}

	// DNSSEC status distribution.
	dnssecRows, err := s.db.SQ.Query(
		`SELECT dnssec_status, COUNT(*) FROM request_log
		 WHERE id > (SELECT cleared_before FROM stats_meta)
		 GROUP BY dnssec_status`,
	)
	if err == nil {
		defer func() { _ = dnssecRows.Close() }()
		for dnssecRows.Next() {
			var status string
			var cnt int64
			if err := dnssecRows.Scan(&status, &cnt); err == nil {
				switch status {
				case config.DNSSECStatusSecure:
					secureCount = cnt
				case config.DNSSECStatusInsecure:
					insecureCount = cnt
				case config.DNSSECStatusBogus:
					bogusCount = cnt
				}
			}
		}
	}

	return []string{
		fmt.Sprintf("entries=%d total=%d avg=%.1fms",
			entries, total, avgMs),
		fmt.Sprintf("hits=%d misses=%d stales=%d zones=%d",
			hits, misses, stales, zones),
		fmt.Sprintf("errors=%d blocked=%d badcookie=%d",
			errCount, blockedCount, badcookieCount),
		fmt.Sprintf("noerr=%d formerr=%d servfail=%d nx=%d nimp=%d ref=%d other=%d",
			noerr, formerr, servfail, nxdomain, notimp, refused, other),
		fmt.Sprintf("hijack=%d fallback=%d",
			hijack, fallback),
		fmt.Sprintf("udp=%d tcp=%d",
			udp, tcp),
		fmt.Sprintf("dot=%d doq=%d doh=%d doh3=%d dnscrypt=%d dnscrypt-tcp=%d",
			dot, doq, doh, doh3, dnscrypt, dnscryptTCP),
		fmt.Sprintf("secure=%d insecure=%d bogus=%d",
			secureCount, insecureCount, bogusCount),
	}
}

// UpdateLatency stores a latency measurement keyed by IP only. All domains
// sharing the same IP reuse the same row — latency is measured once, not
// once per domain. qtype is inferred from the IP address format.
func (s *SQLiteCache) UpdateLatency(ip string, latencyMS int) {
	if s.db.IsClosed() {
		return
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}
	qtype := dns.TypeAAAA
	if parsedIP.To4() != nil {
		qtype = dns.TypeA
	}
	_, _ = s.db.StmtInsertLatency.Exec(ip, qtype, latencyMS)
}

// GetLatencyLastProbe returns the last probe time for an IP. Returns (0, false)
// if the IP has never been probed.
func (s *SQLiteCache) GetLatencyLastProbe(ip string) (int64, bool) {
	if s.db.IsClosed() {
		return 0, false
	}
	var ts int64
	if err := s.db.StmtGetLastProbe.QueryRow(ip).Scan(&ts); err != nil || ts == 0 {
		return 0, false
	}
	return ts, true
}
