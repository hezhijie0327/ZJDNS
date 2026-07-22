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

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// RecordRequest logs a request outcome asynchronously. The record is queued
// into a background writer goroutine that upserts into query_stats (per-day
// aggregated counters) and, for non-hit results, inserts a row into query_log
// for the audit trail.  Hits are only in query_stats.
//
// When the async writer's channel is full the record is silently dropped —
// stats are best-effort and must never block the query hot path.
//
// When the async writer is nil (e.g. in tests), RecordRequest falls back to
// synchronous writes so callers can observe results immediately.
func (s *SQLiteCache) RecordRequest(r *RequestRecord) {
	if r == nil {
		return
	}
	r.Qname = dnsutil.Canonical(r.Qname)
	if s.asyncWriter != nil {
		s.asyncWriter.Record(r)
		return
	}

	// Synchronous fallback when no async writer is configured.
	if s.db.IsClosed() {
		return
	}
	_, _ = s.db.StmtQueryStats.Exec(r.Result, r.Protocol, r.Rcode, r.DNSSECStatus,
		database.BoolToInt(r.Poisoned), database.BoolToInt(r.Fallback), r.ResponseTime)
	if r.Result != "hit" {
		_, _ = s.db.StmtQueryLog.Exec(
			log.NowUnix(), r.Qname, int(r.Qtype), int(r.Qclass),
			r.Protocol, r.Result, r.Rcode, r.ResponseTime, r.Server,
			database.BoolToInt(r.Poisoned), database.BoolToInt(r.Fallback), r.DNSSECStatus,
		)
	}
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil
	}

	// Precompute the serve-stale cutoff so the comparison e.expires_at >= ?
	// avoids a per-row arithmetic expression and can use idx_entries_expires.
	staleCutoff := log.NowUnix() - defaultStaleMaxAge
	// Use a correlated subquery to pick the row with the latest expiry for each
	// name, avoiding the non-deterministic GROUP BY on unaggregated columns.
	rows, err := s.db.SQ.Query(
		`SELECT pm.name, pm.ttl, e.timestamp, pm.entry_id
		 FROM ptr_map pm
		 JOIN entries e ON pm.entry_id = e.id
		 WHERE pm.rdata_ip = ? AND e.expires_at >= ?
		 AND (e.timestamp + pm.ttl) = (
		     SELECT MAX(e2.timestamp + pm2.ttl)
		     FROM ptr_map pm2
		     JOIN entries e2 ON pm2.entry_id = e2.id
		     WHERE pm2.name = pm.name AND pm2.rdata_ip = ?
		 )
		 ORDER BY pm.name`,
		ip, staleCutoff, ip,
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
		var entryID int64
		if err := rows.Scan(&name, &rawTTL, &ts, &entryID); err != nil {
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

// FlushDB truncates a single table: "stats" (query_stats), "querylog" (query_log),
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
		result, err = s.db.SQ.Exec(`DELETE FROM query_stats`)
		if err != nil {
			return 0, fmt.Errorf("flushDB stats: %w", err)
		}
	case "querylog":
		result, err = s.db.SQ.Exec(`DELETE FROM query_log`)
		if err != nil {
			return 0, fmt.Errorf("flushDB querylog: %w", err)
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

// Clear truncates all tables: entries, query_stats, query_log, ip_latency.
func (s *SQLiteCache) Clear() (int64, error) {
	n1, err := s.FlushDB("cache")
	if err != nil {
		return 0, err
	}
	n2, err := s.FlushDB("stats")
	if err != nil {
		return n1, err
	}
	n3, err := s.FlushDB("querylog")
	if err != nil {
		return n1 + n2, err
	}
	n4, err := s.FlushDB("latency")
	if err != nil {
		return n1 + n2 + n3, err
	}
	return n1 + n2 + n3 + n4, nil
}

// Stats returns aggregated cache statistics as formatted TXT records.
//
// Uses a single scan of query_stats — the per-day aggregated table.  query_stats
// is bounded at ~500 rows (DefaultQueryJournalRetention × ~72 combinations/day), so Stats() is O(1)
// regardless of query volume.
func (s *SQLiteCache) Stats() []string {
	if s.db.IsClosed() {
		return nil
	}

	entries := s.db.EntryCount()

	var total, hits, misses, stales, zones, errCount, blockedCount, badcookieCount int64
	var udp, tcp, tls, quic, https, http3, dtls, dnscrypt, dnscryptTCP, tlcp, httpTLCP, dtlcp int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var secureCount, insecureCount, bogusCount, poisoned, fallback int64
	var totalMS int64

	// Single scan of query_stats — result+protocol+rcode breakdown + totals.
	_ = s.db.SQ.QueryRow(
		"SELECT COALESCE(SUM(query_count), 0),"+
			// result breakdown
			" COALESCE(SUM(CASE WHEN result='hit' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='miss' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='stale' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='zone' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='error' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='blocked' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='badcookie' THEN query_count ELSE 0 END), 0),"+
			// protocol breakdown
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tls' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='quic' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='https' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='http3' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dtls' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tlcp' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='http-tlcp' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dtlcp' THEN query_count ELSE 0 END), 0),"+
			// rcode distribution
			" COALESCE(SUM(CASE WHEN rcode=0 THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=1 THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=2 THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=3 THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=4 THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode=5 THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN rcode NOT IN (0,1,2,3,4,5) THEN query_count ELSE 0 END), 0),"+
			// DNSSEC (non-hit only; hits always have dnssec='')
			" COALESCE(SUM(CASE WHEN dnssec='"+config.DNSSECStatusSecure+"' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN dnssec='"+config.DNSSECStatusInsecure+"' THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN dnssec='"+config.DNSSECStatusBogus+"' THEN query_count ELSE 0 END), 0),"+
			// misc
			" COALESCE(SUM(CASE WHEN poisoned THEN query_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN fallback THEN query_count ELSE 0 END), 0),"+
			// total response time
			" COALESCE(SUM(total_ms), 0)"+
			" FROM query_stats",
	).Scan(
		&total,
		&hits, &misses, &stales, &zones, &errCount, &blockedCount, &badcookieCount,
		&udp, &tcp, &tls, &quic, &https, &http3, &dtls, &dnscrypt, &dnscryptTCP, &tlcp, &httpTLCP, &dtlcp,
		&noerr, &formerr, &servfail, &nxdomain, &notimp, &refused, &other,
		&secureCount, &insecureCount, &bogusCount,
		&poisoned, &fallback,
		&totalMS,
	)

	var avgMs float64
	if total > 0 {
		avgMs = float64(totalMS) / float64(total)
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
		fmt.Sprintf("udp=%d tcp=%d",
			udp, tcp),
		fmt.Sprintf("tls=%d quic=%d https=%d http3=%d dtls=%d",
			tls, quic, https, http3, dtls),
		fmt.Sprintf("dnscrypt=%d dnscrypt-tcp=%d",
			dnscrypt, dnscryptTCP),
		fmt.Sprintf("tlcp=%d http-tlcp=%d dtlcp=%d",
			tlcp, httpTLCP, dtlcp),
		fmt.Sprintf("poisoned=%d fallback=%d",
			poisoned, fallback),
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
