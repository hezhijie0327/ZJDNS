package database

import "context"

func (db *DB) prepareStatements() error {
	ctx := context.Background()
	var err error

	// Cache statements.
	db.StmtGetEntry, err = db.conn.PrepareContext(ctx,
		`SELECT id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
	)
	if err != nil {
		return err
	}
	db.StmtInsertLog, err = db.conn.PrepareContext(ctx,
		`INSERT INTO request_log (timestamp, entry_id, protocol, result,
			response_time_ms, rcode, server, hijack, fallback, dnssec_status)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`,
	)
	if err != nil {
		return err
	}
	db.StmtHitCounter, err = db.conn.PrepareContext(ctx,
		`INSERT INTO entry_hit_counters (entry_id, protocol, rcode, hit_count, total_response_ms)
		 VALUES (?1, ?2, ?3, 1, ?4)
		 ON CONFLICT(entry_id, protocol, rcode) DO UPDATE
		 SET hit_count = entry_hit_counters.hit_count + 1,
		     total_response_ms = entry_hit_counters.total_response_ms + ?4`,
	)
	if err != nil {
		return err
	}
	db.StmtInsertLatency, err = db.conn.PrepareContext(ctx,
		`INSERT OR REPLACE INTO ip_latency (rdata_ip, qtype, latency_ms, last_probe_time)
		 VALUES (?, ?, ?, unixepoch())`,
	)
	if err != nil {
		return err
	}
	db.StmtGetLastProbe, err = db.conn.PrepareContext(ctx,
		`SELECT last_probe_time FROM ip_latency WHERE rdata_ip = ?`,
	)
	if err != nil {
		return err
	}
	db.StmtEnsureEntry, err = db.conn.PrepareContext(ctx,
		`SELECT id FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
	)
	if err != nil {
		return err
	}

	// Zone statements.
	db.StmtZoneExact, err = db.conn.PrepareContext(ctx,
		`SELECT rcode, answer, authority, additional, match_tags
		 FROM zone_entries
		 WHERE qname = ?1 AND qtype = ?2 AND qclass = ?3 AND is_wildcard = 0`,
	)
	if err != nil {
		return err
	}
	db.StmtZoneWild, err = db.conn.PrepareContext(ctx,
		`SELECT rcode, answer, authority, additional, match_tags
		 FROM zone_entries
		 WHERE qname = ?1 AND qtype = ?2 AND qclass = ?3 AND is_wildcard = 1`,
	)
	if err != nil {
		return err
	}
	db.StmtZoneInsert, err = db.conn.PrepareContext(ctx,
		`INSERT OR REPLACE INTO zone_entries
		 (qname, qtype, qclass, rcode, answer, authority, additional, match_tags, is_wildcard)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
	)
	if err != nil {
		return err
	}

	return nil
}
