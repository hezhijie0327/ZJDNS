package database

func (db *DB) prepareStatements() error {
	var err error

	// Cache statements.
	db.StmtEntry, err = db.SQ.Prepare(
		`SELECT id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
	)
	if err != nil {
		return err
	}
	db.StmtQueryLog, err = db.SQ.Prepare(
		`INSERT INTO query_log (timestamp, qname, qtype, qclass, protocol, result,
			rcode, response_ms, server, hijack, fallback, dnssec)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`,
	)
	if err != nil {
		return err
	}
	db.StmtQueryStats, err = db.SQ.Prepare(
		`INSERT INTO query_stats (stat_day, result, protocol, rcode, dnssec, hijack, fallback, query_count, total_ms)
		 VALUES (unixepoch() / 86400, ?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
		 ON CONFLICT(stat_day, result, protocol, rcode, dnssec, hijack, fallback) DO UPDATE
		 SET query_count = query_stats.query_count + 1,
		     total_ms = query_stats.total_ms + ?7`,
	)
	if err != nil {
		return err
	}
	db.StmtInsertLatency, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO ip_latency (rdata_ip, qtype, latency_ms, last_probe_time)
		 VALUES (?, ?, ?, unixepoch())`,
	)
	if err != nil {
		return err
	}
	db.StmtLastProbe, err = db.SQ.Prepare(
		`SELECT last_probe_time FROM ip_latency WHERE rdata_ip = ?`,
	)
	if err != nil {
		return err
	}
	// Zone statements.
	db.StmtZoneExact, err = db.SQ.Prepare(
		`SELECT rcode, answer, authority, additional, match_tags
		 FROM zone_entries
		 WHERE is_wildcard = 0 AND qname = ? AND qtype = ? AND qclass = ?`,
	)
	if err != nil {
		return err
	}

	db.StmtZoneWildcard, err = db.SQ.Prepare(
		`SELECT qname, rcode, answer, authority, additional, match_tags
		 FROM zone_entries WHERE is_wildcard = 1 AND qname IN (
		 ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 AND ((qtype = ? AND qclass = ?) OR (qtype = 0 AND qclass = 0))
		 ORDER BY length(qname) DESC, qtype DESC`,
	)
	if err != nil {
		return err
	}

	// ipLatencyQuery uses 64 fixed placeholders so SQLite reuses the
	// compiled query plan across all lookupIPLatencies calls.
	db.StmtIPLatency, err = db.SQ.Prepare(
		`SELECT rdata_ip, latency_ms FROM ip_latency WHERE rdata_ip IN (` +
			`?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,` +
			`?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
	)
	if err != nil {
		return err
	}

	return nil
}
