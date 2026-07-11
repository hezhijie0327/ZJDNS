package database

func (db *DB) prepareStatements() error {
	var err error

	// Cache statements.
	db.StmtGetEntry, err = db.SQ.Prepare(
		`SELECT id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
	)
	if err != nil {
		return err
	}
	db.StmtInsertLog, err = db.SQ.Prepare(
		`INSERT INTO request_log (timestamp, entry_id, protocol, result,
			response_time_ms, rcode, server, hijack, fallback, dnssec_status)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
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
	db.StmtGetLastProbe, err = db.SQ.Prepare(
		`SELECT last_probe_time FROM ip_latency WHERE rdata_ip = ?`,
	)
	if err != nil {
		return err
	}
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
		 WHERE qname = ? AND qtype = ? AND qclass = ? AND is_wildcard = 0`,
	)
	if err != nil {
		return err
	}
	db.StmtZoneWild, err = db.SQ.Prepare(
		`SELECT rcode, answer, authority, additional, match_tags
		 FROM zone_entries
		 WHERE qname = ? AND qtype = ? AND qclass = ? AND is_wildcard = 1`,
	)
	if err != nil {
		return err
	}
	db.StmtZoneInsert, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO zone_entries
		 (qname, qtype, qclass, rcode, answer, authority, additional, match_tags, is_wildcard)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}

	// NSEC negative cache statements.
	db.StmtNsecInsert, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO nsec_chain
		 (zone_name, owner_name, next_name, types, entry_id)
		 VALUES (?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	db.StmtNsecLookup, err = db.SQ.Prepare(
		`SELECT owner_name, next_name, types FROM nsec_chain
		 WHERE zone_name = CAST(? AS BLOB)
		 ORDER BY owner_name ASC`,
	)
	if err != nil {
		return err
	}

	// RuleSet statements.
	db.StmtRuleSetInsert, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO ruleset_entries (tag, type, value) VALUES (?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	db.StmtRuleSetLoad, err = db.SQ.Prepare(
		`SELECT tag, type, value FROM ruleset_entries ORDER BY tag, type, value`,
	)
	if err != nil {
		return err
	}

	// Infra cache statements.
	db.StmtInfraGet, err = db.SQ.Prepare(
		`SELECT rtt_ms, edns_version, timeout_count, last_timeout, last_success
		 FROM infra_cache WHERE server_addr = ?`,
	)
	if err != nil {
		return err
	}
	db.StmtInfraUpsert, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO infra_cache
		 (server_addr, rtt_ms, edns_version, timeout_count, last_timeout, last_success)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}

	return nil
}
