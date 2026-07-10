package cache

func (s *SQLiteCache) prepareStatements() error {
	var err error
	s.stmtGetEntry, err = s.db.Prepare(
		`SELECT id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
	)
	if err != nil {
		return err
	}
	s.stmtInsertLog, err = s.db.Prepare(
		`INSERT INTO request_log (timestamp, entry_id, protocol, result,
			response_time_ms, rcode, server, hijack, fallback, dnssec_status)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
	)
	if err != nil {
		return err
	}
	s.stmtHitCounter, err = s.db.Prepare(
		`INSERT INTO entry_hit_counters (entry_id, protocol, rcode, hit_count, total_response_ms)
		 VALUES (?1, ?2, ?3, 1, ?4)
		 ON CONFLICT(entry_id, protocol, rcode) DO UPDATE
		 SET hit_count = entry_hit_counters.hit_count + 1,
		     total_response_ms = entry_hit_counters.total_response_ms + ?4`,
	)
	if err != nil {
		return err
	}
	s.stmtInsertLatency, err = s.db.Prepare(
		`INSERT OR REPLACE INTO ip_latency (rdata_ip, qtype, latency_ms, last_probe_time)
		 VALUES (?, ?, ?, unixepoch())`,
	)
	if err != nil {
		return err
	}
	s.stmtGetLastProbe, err = s.db.Prepare(
		`SELECT last_probe_time FROM ip_latency WHERE rdata_ip = ?`,
	)
	if err != nil {
		return err
	}
	s.stmtEnsureEntry, err = s.db.Prepare(
		`SELECT id FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
	)
	if err != nil {
		return err
	}
	return nil
}
