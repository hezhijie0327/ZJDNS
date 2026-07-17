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
	db.StmtInsertLog, err = db.SQ.Prepare(
		`INSERT INTO request_log (timestamp, qname, qtype, qclass, entry_id, protocol, result,
			response_time_ms, rcode, server, hijack, fallback, dnssec_status)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)`,
	)
	if err != nil {
		return err
	}
	db.StmtHitCounter, err = db.SQ.Prepare(
		`INSERT INTO entry_hit_counters (entry_id, protocol, rcode, hit_count, total_response_ms)
		 VALUES (?1, ?2, ?3, 1, ?4)
		 ON CONFLICT(entry_id, protocol, rcode) DO UPDATE
		 SET hit_count = entry_hit_counters.hit_count + 1,
		     total_response_ms = entry_hit_counters.total_response_ms + ?4`,
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
	// EnsureEntry fallback — only triggered when RecordRequest has no pre-resolved EntryID
	// (zone/error/badcookie paths in production, plus test helpers).
	db.StmtEnsureEntry, err = db.SQ.Prepare(
		`SELECT id FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
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
