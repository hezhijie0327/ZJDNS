package cache

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// RecordRequest logs a request outcome. Hit path upserts hit counters; miss/
// stale/zone/error/blocked paths insert a log row with qname/qtype/qclass stored
// directly (denormalized) so no JOIN is needed for debugging queries. entry_id is
// set when available (cache-backed paths); NULL otherwise.
func (s *SQLiteCache) RecordRequest(r *RequestRecord) {
	if s.db.IsClosed() {
		return
	}

	r.Qname = zdnsutil.NormalizeDomain(r.Qname)

	if r.Result == "hit" {
		entryID := r.EntryID
		if entryID <= 0 {
			// Fallback: lookup entry by key (zone/error-in-hit-clothing, test helpers).
			// Does NOT create stub entries.
			ecsAddr, ecsPrefix := ecsParams(r.ECS)
			dnssecInt := zdnsutil.BoolToInt(r.DNSSECOK)
			entryID = s.db.EnsureEntry(r.Qname, int(r.Qtype), int(r.Qclass), ecsAddr, ecsPrefix, dnssecInt)
		}
		_, _ = s.db.StmtHitCounter.Exec(entryID, r.Protocol, r.Rcode, r.ResponseTime)
		return
	}

	entryID := max(r.EntryID,
		// sentinel for "no cache entry" → stored as 0 (NULL in DB)
		0)
	_, _ = s.db.StmtInsertLog.Exec(
		log.NowUnix(), r.Qname, int(r.Qtype), int(r.Qclass), entryID,
		r.Protocol, r.Result, r.ResponseTime, r.Rcode, r.Server,
		zdnsutil.BoolToInt(r.Hijack), zdnsutil.BoolToInt(r.Fallback), r.DNSSECStatus,
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
		`SELECT pm.name, pm.ttl, e.timestamp, MAX(e.timestamp + pm.ttl), pm.entry_id
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
		var entryID int64
		if err := rows.Scan(&name, &rawTTL, &ts, &dummy, &entryID); err != nil {
			continue
		}
		results = append(results, LookupResult{
			Name:    name,
			TTL:     ttl.RemainingTTL(ts, rawTTL, uint32(config.DefaultStaleTTL)),
			EntryID: entryID,
		})
	}
	return results
}

// FlushDB truncates a single table: "stats" (resets stats_meta.cleared_before),
// "cache" (entries), "latency" (ip_latency),
// "zone" (zone_entries), or "ruleset" (ruleset_entries).
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
	case "zone":
		result, err = s.db.SQ.Exec(`DELETE FROM zone_entries`)
	case "ruleset":
		result, err = s.db.SQ.Exec(`DELETE FROM ruleset_entries`)
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

// Clear truncates all tables: entries, request_log, entry_hit_counters, ip_latency,
// and resets stats_meta.
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
//
// Uses two SQL queries (down from five): one scan of entry_hit_counters and one
// scan of request_log. Rcode and DNSSEC distributions are computed as extra CASE
// columns in the same scans, eliminating the old standalone UNION ALL and GROUP BY
// queries that re-scanned both tables.
func (s *SQLiteCache) Stats() []string {
	if s.db.IsClosed() {
		return nil
	}

	entries := s.db.EntryCount()

	var avgMs float64
	var total, hits, misses, stales, zones, errCount, blockedCount, badcookieCount int64
	var hcUDP, hcTCP, hcTLS, hcQUIC, hcHTTPS, hcHTTP3, hcDTLS, hcDNSCrypt, hcDNSCryptTCP, hcTLCP, hcHTTPTLCP, hcDTLCP int64
	var rlUDP, rlTCP, rlTLS, rlQUIC, rlHTTPS, rlHTTP3, rlDTLS, rlDNSCrypt, rlDNSCryptTCP, rlTLCP, rlHTTPTLCP, rlDTLCP int64
	var hijack, fallback, totalMS, hitTotalMS int64
	var hcNoerr, hcFormerr, hcServfail, hcNxdomain, hcNotimp, hcRefused, hcOther int64
	var rlNoerr, rlFormerr, rlServfail, rlNxdomain, rlNotimp, rlRefused, rlOther int64
	var secureCount, insecureCount, bogusCount int64

	// Query 1: single scan of entry_hit_counters — protocol breakdown + rcode distribution + totals.
	_ = s.db.SQ.QueryRow(
		"SELECT COALESCE(SUM(hit_count), 0),"+
			// protocol breakdown
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tls' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='quic' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='https' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='http3' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dtls' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tlcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='http-tlcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dtlcp' THEN hit_count ELSE 0 END), 0),"+
			// rcode distribution (was a separate UNION ALL query)
			" COALESCE(SUM(CASE WHEN rcode=0 THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=1 THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=2 THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=3 THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=4 THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=5 THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode NOT IN (0,1,2,3,4,5) THEN hit_count ELSE 0 END), 0),"+
			// total response time
			" COALESCE(SUM(total_response_ms), 0)"+
			" FROM entry_hit_counters",
	).Scan(&hits,
		&hcUDP, &hcTCP, &hcTLS, &hcQUIC, &hcHTTPS, &hcHTTP3, &hcDTLS, &hcDNSCrypt, &hcDNSCryptTCP, &hcTLCP, &hcHTTPTLCP, &hcDTLCP,
		&hcNoerr, &hcFormerr, &hcServfail, &hcNxdomain, &hcNotimp, &hcRefused, &hcOther,
		&hitTotalMS,
	)

	// Query 2: single scan of request_log — result+protocol breakdown + rcode + DNSSEC + misc.
	_ = s.db.SQ.QueryRow(
		"SELECT COUNT(*),"+
			// result breakdown
			" COALESCE(SUM(CASE WHEN result='miss' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='stale' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='zone' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='error' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='blocked' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='badcookie' THEN 1 ELSE 0 END), 0),"+
			// protocol breakdown
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tls' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='quic' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='https' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='http3' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dtls' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tlcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='http-tlcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dtlcp' THEN 1 ELSE 0 END), 0),"+
			// rcode distribution (was a separate UNION ALL query)
			" COALESCE(SUM(CASE WHEN rcode=0 THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=1 THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=2 THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=3 THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=4 THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=5 THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode NOT IN (0,1,2,3,4,5) THEN 1 ELSE 0 END), 0),"+
			// DNSSEC status (was a separate GROUP BY query)
			" COALESCE(SUM(CASE WHEN dnssec_status='"+config.DNSSECStatusSecure+"' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN dnssec_status='"+config.DNSSECStatusInsecure+"' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN dnssec_status='"+config.DNSSECStatusBogus+"' THEN 1 ELSE 0 END), 0),"+
			// misc
			" COALESCE(SUM(CASE WHEN hijack THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN fallback THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(response_time_ms), 0)"+
			" FROM request_log WHERE id > (SELECT cleared_before FROM stats_meta)",
	).Scan(
		&total,
		&misses, &stales, &zones, &errCount, &blockedCount, &badcookieCount,
		&rlUDP, &rlTCP, &rlTLS, &rlQUIC, &rlHTTPS, &rlHTTP3, &rlDTLS, &rlDNSCrypt, &rlDNSCryptTCP, &rlTLCP, &rlHTTPTLCP, &rlDTLCP,
		&rlNoerr, &rlFormerr, &rlServfail, &rlNxdomain, &rlNotimp, &rlRefused, &rlOther,
		&secureCount, &insecureCount, &bogusCount,
		&hijack, &fallback, &totalMS,
	)

	total += hits

	udp := hcUDP + rlUDP
	tcp := hcTCP + rlTCP

	tls := hcTLS + rlTLS
	quic := hcQUIC + rlQUIC
	https := hcHTTPS + rlHTTPS
	http3 := hcHTTP3 + rlHTTP3
	dtls := hcDTLS + rlDTLS

	dnscrypt := hcDNSCrypt + rlDNSCrypt
	dnscryptTCP := hcDNSCryptTCP + rlDNSCryptTCP

	tlcp := hcTLCP + rlTLCP
	httpTLCP := hcHTTPTLCP + rlHTTPTLCP
	dtlcp := hcDTLCP + rlDTLCP

	// Rcode sums — combine hit counters and request log.
	noerr := hcNoerr + rlNoerr
	formerr := hcFormerr + rlFormerr
	servfail := hcServfail + rlServfail
	nxdomain := hcNxdomain + rlNxdomain
	notimp := hcNotimp + rlNotimp
	refused := hcRefused + rlRefused
	other := hcOther + rlOther

	// Average across all request types (hit + miss + stale + zone + error).
	if total > 0 {
		avgMs = float64(totalMS+hitTotalMS) / float64(total)
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
		fmt.Sprintf("tls=%d quic=%d https=%d http3=%d, dtls=%d",
			tls, quic, https, http3, dtls),
		fmt.Sprintf("dnscrypt=%d dnscrypt-tcp=%d",
			dnscrypt, dnscryptTCP),
		fmt.Sprintf("tlcp=%d http-tlcp=%d dtlcp=%d",
			tlcp, httpTLCP, dtlcp),
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

// LatencyLastProbe returns the last probe time for an IP. Returns (0, false)
// if the IP has never been probed.
func (s *SQLiteCache) LatencyLastProbe(ip string) (int64, bool) {
	if s.db.IsClosed() {
		return 0, false
	}
	var ts int64
	if err := s.db.StmtLastProbe.QueryRow(ip).Scan(&ts); err != nil || ts == 0 {
		return 0, false
	}
	return ts, true
}
