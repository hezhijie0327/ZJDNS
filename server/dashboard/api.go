package dashboard

import (
	"net/http"
	"time"
)

// ── API response types ──────────────────────────────────────────────────────

// overviewResponse is the JSON payload for GET /api/overview.
type overviewResponse struct {
	Entries       int64   `json:"entries"`
	TotalQueries  int64   `json:"total_queries"`
	Hits          int64   `json:"hits"`
	Misses        int64   `json:"misses"`
	Stales        int64   `json:"stales"`
	Zones         int64   `json:"zones"`
	Errors        int64   `json:"errors"`
	Blocked       int64   `json:"blocked"`
	Badcookie     int64   `json:"badcookie"`
	AvgResponseMs float64 `json:"avg_response_ms"`
	HitRate       float64 `json:"hit_rate"`
	Hijack        int64   `json:"hijack"`
	Fallback      int64   `json:"fallback"`
}

type rcodesResponse struct {
	NOERROR  int64 `json:"noerror"`
	FORMERR  int64 `json:"formerr"`
	SERVFAIL int64 `json:"servfail"`
	NXDOMAIN int64 `json:"nxdomain"`
	NOTIMP   int64 `json:"notimp"`
	REFUSED  int64 `json:"refused"`
	Other    int64 `json:"other"`
}

type protocolsResponse struct {
	UDP         int64 `json:"udp"`
	TCP         int64 `json:"tcp"`
	DOT         int64 `json:"dot"`
	DOQ         int64 `json:"doq"`
	DOH         int64 `json:"doh"`
	DOH3        int64 `json:"doh3"`
	DNSCrypt    int64 `json:"dnscrypt"`
	DNSCryptTCP int64 `json:"dnscrypt_tcp"`
}

type dnssecResponse struct {
	Secure   int64 `json:"secure"`
	Insecure int64 `json:"insecure"`
	Bogus    int64 `json:"bogus"`
}

type topDomainEntry struct {
	Qname string `json:"qname"`
	Count int64  `json:"count"`
}

type queryLogEntry struct {
	ID             int64  `json:"id"`
	Timestamp      int64  `json:"timestamp"`
	Qname          string `json:"qname"`
	Qtype          int    `json:"qtype"`
	Protocol       string `json:"protocol"`
	Result         string `json:"result"`
	ResponseTimeMs int    `json:"response_time_ms"`
	Rcode          int    `json:"rcode"`
	Server         string `json:"server"`
	Hijack         bool   `json:"hijack"`
	Fallback       bool   `json:"fallback"`
	DNSSECStatus   string `json:"dnssec_status"`
}

type latencyEntry struct {
	IP            string `json:"ip"`
	Qtype         int    `json:"qtype"`
	LatencyMs     int    `json:"latency_ms"`
	LastProbeTime int64  `json:"last_probe_time"`
}

type timeseriesBucket struct {
	Timestamp int64   `json:"ts"`
	Count     int64   `json:"count"`
	AvgMs     float64 `json:"avg_ms"`
}

// ── /api/overview ──────────────────────────────────────────────────────────

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	var resp overviewResponse

	// entries count
	_ = s.db.SQ.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&resp.Entries)

	// hit counters
	var hits, hitTotalMS int64
	_ = s.db.SQ.QueryRow(
		`SELECT COALESCE(SUM(hit_count), 0), COALESCE(SUM(total_response_ms), 0) FROM entry_hit_counters`,
	).Scan(&hits, &hitTotalMS)

	// request_log aggregates (since last stats clear)
	var total, misses, stales, zones, errs, blocked, badcookie int64
	var hijack, fallback, totalMS int64
	_ = s.db.SQ.QueryRow(
		`SELECT COUNT(*),
			COALESCE(SUM(CASE WHEN result='miss' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN result='stale' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN result='zone' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN result='error' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN result='blocked' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN result='badcookie' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN hijack THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN fallback THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(response_time_ms), 0)
		FROM request_log WHERE id > (SELECT cleared_before FROM stats_meta)`,
	).Scan(&total, &misses, &stales, &zones, &errs, &blocked, &badcookie,
		&hijack, &fallback, &totalMS)

	resp.Hits = hits
	resp.Misses = misses
	resp.Stales = stales
	resp.Zones = zones
	resp.Errors = errs
	resp.Blocked = blocked
	resp.Badcookie = badcookie
	resp.Hijack = hijack
	resp.Fallback = fallback
	resp.TotalQueries = hits + total

	if resp.TotalQueries > 0 {
		resp.AvgResponseMs = float64(totalMS+hitTotalMS) / float64(resp.TotalQueries)
		resp.HitRate = float64(hits) / float64(resp.TotalQueries)
	}

	writeJSON(w, &resp)
}

// ── /api/rcodes ────────────────────────────────────────────────────────────

func (s *Server) handleRCodes(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	var resp rcodesResponse
	rows, err := s.db.SQ.Query(
		`SELECT rcode, SUM(cnt) FROM (
			SELECT rcode, COUNT(*) AS cnt FROM request_log
			 WHERE id > (SELECT cleared_before FROM stats_meta) GROUP BY rcode
			UNION ALL
			SELECT rcode, SUM(hit_count) AS cnt FROM entry_hit_counters GROUP BY rcode
		) GROUP BY rcode`,
	)
	if err != nil {
		writeJSON(w, &resp)
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var rc, cnt int64
		if err := rows.Scan(&rc, &cnt); err == nil {
			switch rc {
			case 0:
				resp.NOERROR = cnt
			case 1:
				resp.FORMERR = cnt
			case 2:
				resp.SERVFAIL = cnt
			case 3:
				resp.NXDOMAIN = cnt
			case 4:
				resp.NOTIMP = cnt
			case 5:
				resp.REFUSED = cnt
			default:
				resp.Other += cnt
			}
		}
	}
	writeJSON(w, &resp)
}

// ── /api/protocols ─────────────────────────────────────────────────────────

func (s *Server) handleProtocols(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	var resp protocolsResponse

	// hit counters by protocol
	var hcUDP, hcTCP, hcDOT, hcDOQ, hcDOH, hcDOH3, hcDNSCrypt, hcDNSCryptTCP int64
	_ = s.db.SQ.QueryRow(
		`SELECT
			COALESCE(SUM(CASE WHEN protocol='udp' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='tcp' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='dot' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='doq' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='doh' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='doh3' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN hit_count ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN hit_count ELSE 0 END), 0)
		FROM entry_hit_counters`,
	).Scan(&hcUDP, &hcTCP, &hcDOT, &hcDOQ, &hcDOH, &hcDOH3, &hcDNSCrypt, &hcDNSCryptTCP)

	// request_log by protocol
	var rlUDP, rlTCP, rlDOT, rlDOQ, rlDOH, rlDOH3, rlDNSCrypt, rlDNSCryptTCP int64
	_ = s.db.SQ.QueryRow(
		`SELECT
			COALESCE(SUM(CASE WHEN protocol='udp' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='tcp' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='dot' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='doq' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='doh' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='doh3' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='dnscrypt' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN protocol='dnscrypt-tcp' THEN 1 ELSE 0 END), 0)
		FROM request_log WHERE id > (SELECT cleared_before FROM stats_meta)`,
	).Scan(&rlUDP, &rlTCP, &rlDOT, &rlDOQ, &rlDOH, &rlDOH3, &rlDNSCrypt, &rlDNSCryptTCP)

	resp.UDP = hcUDP + rlUDP
	resp.TCP = hcTCP + rlTCP
	resp.DOT = hcDOT + rlDOT
	resp.DOQ = hcDOQ + rlDOQ
	resp.DOH = hcDOH + rlDOH
	resp.DOH3 = hcDOH3 + rlDOH3
	resp.DNSCrypt = hcDNSCrypt + rlDNSCrypt
	resp.DNSCryptTCP = hcDNSCryptTCP + rlDNSCryptTCP

	writeJSON(w, &resp)
}

// ── /api/dnssec ────────────────────────────────────────────────────────────

func (s *Server) handleDNSSEC(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	var resp dnssecResponse
	rows, err := s.db.SQ.Query(
		`SELECT dnssec_status, COUNT(*) FROM request_log
		 WHERE id > (SELECT cleared_before FROM stats_meta)
		 GROUP BY dnssec_status`,
	)
	if err != nil {
		writeJSON(w, &resp)
		return
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var status string
		var cnt int64
		if err := rows.Scan(&status, &cnt); err == nil {
			switch status {
			case "secure":
				resp.Secure = cnt
			case "insecure":
				resp.Insecure = cnt
			case "bogus":
				resp.Bogus = cnt
			}
		}
	}
	writeJSON(w, &resp)
}

// ── /api/top-domains ───────────────────────────────────────────────────────

func (s *Server) handleTopDomains(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	limit := min(parseQueryInt(r, "limit", 20), 200)

	rows, err := s.db.SQ.Query(
		`SELECT qname, SUM(cnt) AS total FROM (
			SELECT e.qname, SUM(hc.hit_count) AS cnt
			FROM entry_hit_counters hc JOIN entries e ON hc.entry_id = e.id
			GROUP BY e.qname
			UNION ALL
			SELECT qname, COUNT(*) AS cnt FROM request_log
			WHERE id > (SELECT cleared_before FROM stats_meta) AND qname != ''
			GROUP BY qname
		) GROUP BY qname ORDER BY total DESC LIMIT ?`, limit,
	)
	if err != nil {
		writeJSON(w, []topDomainEntry{})
		return
	}
	defer func() { _ = rows.Close() }()

	var result []topDomainEntry
	for rows.Next() {
		var e topDomainEntry
		if err := rows.Scan(&e.Qname, &e.Count); err == nil {
			result = append(result, e)
		}
	}
	if result == nil {
		result = []topDomainEntry{}
	}
	writeJSON(w, result)
}

// ── /api/query-log ─────────────────────────────────────────────────────────

func (s *Server) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	limit := min(parseQueryInt(r, "limit", 50), 500)
	offset := parseQueryInt(r, "offset", 0)
	search := r.URL.Query().Get("search")
	resultFilter := r.URL.Query().Get("result")

	// Build query with optional search and result filter.
	// SQLite requires separate bind params for each OR branch (CASE trick).
	query := `SELECT id, timestamp, qname, qtype, protocol, result,
			response_time_ms, rcode, server, hijack, fallback, dnssec_status
		FROM request_log
		WHERE (CASE WHEN ?3 != '' THEN qname LIKE '%' || ?3 || '%' ELSE 1 END)
		AND (CASE WHEN ?4 != '' THEN result = ?4 ELSE 1 END)
		ORDER BY id DESC LIMIT ?1 OFFSET ?2`

	rows, err := s.db.SQ.Query(query, limit, offset, search, resultFilter)
	if err != nil {
		writeJSON(w, []queryLogEntry{})
		return
	}
	defer func() { _ = rows.Close() }()

	var result []queryLogEntry
	for rows.Next() {
		var e queryLogEntry
		var hijack, fallback int
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Qname, &e.Qtype, &e.Protocol,
			&e.Result, &e.ResponseTimeMs, &e.Rcode, &e.Server, &hijack, &fallback,
			&e.DNSSECStatus); err == nil {
			e.Hijack = hijack != 0
			e.Fallback = fallback != 0
			result = append(result, e)
		}
	}
	if result == nil {
		result = []queryLogEntry{}
	}
	writeJSON(w, result)
}

// ── /api/latency ───────────────────────────────────────────────────────────

func (s *Server) handleLatency(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	limit := min(parseQueryInt(r, "limit", 50), 500)

	rows, err := s.db.SQ.Query(
		`SELECT rdata_ip, qtype, latency_ms, last_probe_time
		FROM ip_latency ORDER BY latency_ms ASC LIMIT ?`, limit,
	)
	if err != nil {
		writeJSON(w, []latencyEntry{})
		return
	}
	defer func() { _ = rows.Close() }()

	var result []latencyEntry
	for rows.Next() {
		var e latencyEntry
		if err := rows.Scan(&e.IP, &e.Qtype, &e.LatencyMs, &e.LastProbeTime); err == nil {
			result = append(result, e)
		}
	}
	if result == nil {
		result = []latencyEntry{}
	}
	writeJSON(w, result)
}

// ── /api/timeseries ────────────────────────────────────────────────────────

func (s *Server) handleTimeseries(w http.ResponseWriter, r *http.Request) {
	if s.db.IsClosed() {
		http.Error(w, `{"error":"database closed"}`, http.StatusServiceUnavailable)
		return
	}

	minutes := parseQueryInt(r, "minutes", 60)
	if minutes <= 0 || minutes > 1440 {
		minutes = 60
	}
	seconds := int64(minutes * 60)
	bucketSize := int64(60) // 1-minute buckets
	cutoff := nowUnix() - seconds

	rows, err := s.db.SQ.Query(
		`SELECT (timestamp / ?) * ? AS bucket, COUNT(*) AS cnt,
			ROUND(AVG(response_time_ms), 1) AS avg_ms
		FROM request_log WHERE timestamp > ?
		GROUP BY bucket ORDER BY bucket`,
		bucketSize, bucketSize, cutoff,
	)
	if err != nil {
		writeJSON(w, []timeseriesBucket{})
		return
	}
	defer func() { _ = rows.Close() }()

	var result []timeseriesBucket
	for rows.Next() {
		var b timeseriesBucket
		if err := rows.Scan(&b.Timestamp, &b.Count, &b.AvgMs); err == nil {
			result = append(result, b)
		}
	}
	if result == nil {
		result = []timeseriesBucket{}
	}
	writeJSON(w, result)
}

func nowUnix() int64 { return time.Now().Unix() }
