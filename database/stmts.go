package database

import "strings"

const (
	// ZoneWildcardPlaceholders is the number of qname ? placeholders in
	// StmtZoneWildcard's IN clause. Must match zone.maxWildcardLabels
	// (zone/zone.go) — guarded by the zone package test
	// TestStmtZoneWildcardPlaceholderCount.
	ZoneWildcardPlaceholders = 16

	// DelegationLookupZones is the number of zone ? placeholders in
	// StmtDelegationLookup's IN clause. Must match
	// config.DefaultDelegationLookupZones (config/defaults.go) — guarded
	// by the resolver package test TestStmtDelegationLookupZoneCount.
	DelegationLookupZones = 16

	// IPLatencyPlaceholders is the number of rdata_ip ? placeholders in
	// StmtIPLatency's IN clause. Must match cache.maxLatencyLookupIPs
	// (cache/store.go) — guarded by the cache package test
	// TestStmtIPLatencyPlaceholderCount.
	IPLatencyPlaceholders = 64
)

var (
	zoneWildcardPlaceholdersSQL     = strings.Repeat("?,", ZoneWildcardPlaceholders-1) + "?"
	delegationLookupPlaceholdersSQL = strings.Repeat("?,", DelegationLookupZones-1) + "?"
	ipLatencyPlaceholdersSQL        = strings.Repeat("?,", IPLatencyPlaceholders-1) + "?"
)

func (db *DB) prepareStatements() error {
	var err error

	// Cache statements.
	db.StmtEntryExists, err = db.SQ.Prepare(
		`SELECT EXISTS(SELECT 1 FROM entries
			WHERE qname = ? AND qtype = ? AND qclass = ? AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?)`,
	)
	if err != nil {
		return err
	}
	// StmtEntryFallback resolves a Get over all ECS fallback candidates in a
	// single round trip (cache.Get used to run up to 5 sequential queries).
	// The OR covers exactly the 5 candidates ecsFallbackCandidates produces
	// (exact + 4 standard prefixes); unused slots bind a sentinel addr that
	// can never match.  No ORDER BY: an expression sort makes SQLite build a
	// temporary btree per execution (16% CPU in load tests); the caller
	// scans the (≤5) rows and picks the most specific candidate itself.
	db.StmtEntryFallback, err = db.SQ.Prepare(
		`SELECT ecs_prefix, id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ?1 AND qtype = ?2 AND qclass = ?3 AND dnssec_ok = ?4
		 AND ((ecs_addr = ?5 AND ecs_prefix = ?6) OR (ecs_addr = ?7 AND ecs_prefix = ?8) OR
		      (ecs_addr = ?9 AND ecs_prefix = ?10) OR (ecs_addr = ?11 AND ecs_prefix = ?12) OR
		      (ecs_addr = ?13 AND ecs_prefix = ?14))`,
	)
	if err != nil {
		return err
	}
	// StmtEntryBatch resolves several qtypes of one qname in a single query —
	// NS A/AAAA address lookups never carry ECS, so a single ""/0 candidate
	// is bound instead of the 5-way fallback OR in StmtEntryFallback.
	db.StmtEntryBatch, err = db.SQ.Prepare(
		`SELECT qtype, id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ?1 AND qclass = ?2 AND dnssec_ok = ?3
		 AND ecs_addr = ?4 AND ecs_prefix = ?5
		 AND qtype IN (?6, ?7)`,
	)
	if err != nil {
		return err
	}
	db.StmtEntryInsert, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, msg_wire)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 RETURNING id`,
	)
	if err != nil {
		return err
	}
	db.StmtQueryLog, err = db.SQ.Prepare(
		`INSERT INTO query_log (timestamp, qname, qtype, qclass, protocol, result,
			rcode, response_ms, server, poisoned, dnssec)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
	)
	if err != nil {
		return err
	}
	db.StmtQueryStats, err = db.SQ.Prepare(
		`INSERT INTO query_stats (stat_day, result, protocol, rcode, dnssec, poisoned, query_count, total_ms)
		 VALUES (unixepoch() / 86400, ?1, ?2, ?3, ?4, ?5, 1, ?6)
		 ON CONFLICT(stat_day, result, protocol, rcode, dnssec, poisoned) DO UPDATE
		 SET query_count = query_stats.query_count + 1,
		     total_ms = query_stats.total_ms + ?6`,
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

	// Placeholder count must match zone.maxWildcardLabels — guarded by the
	// zone package test TestStmtZoneWildcardPlaceholderCount.
	db.StmtZoneWildcard, err = db.SQ.Prepare(
		"SELECT qname, rcode, answer, authority, additional, match_tags " + //nolint:gosec // G202: parameterized placeholders, no user input
			"FROM zone_entries WHERE is_wildcard = 1 AND qname IN (" +
			zoneWildcardPlaceholdersSQL + ") " +
			"AND ((qtype = ? AND qclass = ?) OR (qtype = 0 AND qclass = 0)) " +
			"ORDER BY length(qname) DESC, qtype DESC",
	)
	if err != nil {
		return err
	}

	// Ruleset statements
	db.StmtRulesetDomain, err = db.SQ.Prepare(
		`SELECT tag FROM ruleset_entries WHERE type='domain' AND value=?`,
	)
	if err != nil {
		return err
	}

	// StmtIPLatency has IPLatencyPlaceholders ? placeholders — must match
	// cache.maxLatencyLookupIPs (guarded by the cache package test
	// TestStmtIPLatencyPlaceholderCount). Changing one without the other
	// silently drops or truncates lookup IPs.
	db.StmtIPLatency, err = db.SQ.Prepare(
		"SELECT rdata_ip, latency_ms FROM ip_latency WHERE rdata_ip IN (" + //nolint:gosec // G202: parameterized placeholders, no user input
			ipLatencyPlaceholdersSQL + ")",
	)
	if err != nil {
		return err
	}

	// Delegation cache statements.
	db.StmtDelegationStore, err = db.SQ.Prepare(
		`INSERT OR REPLACE INTO delegations (zone, parent, ns_names, addrs, ds_wire, timestamp, ttl, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	// StmtDelegationLookup queries the deepest fresh delegation among ancestor
	// zones. The IN clause has DelegationLookupZones placeholders — the caller
	// binds unused slots to empty string. ORDER BY LENGTH(zone) DESC returns
	// the deepest match first; LIMIT 1 picks the best candidate.
	db.StmtDelegationLookup, err = db.SQ.Prepare(
		"SELECT zone, parent, ns_names, addrs, ds_wire " + //nolint:gosec // G202: parameterized placeholders, no user input
			"FROM delegations WHERE zone IN (" +
			delegationLookupPlaceholdersSQL + ") AND expires_at > unixepoch() " +
			"ORDER BY LENGTH(zone) DESC LIMIT 1",
	)
	if err != nil {
		return err
	}

	// DNSCrypt state statements.
	db.StmtDNSCryptLoad, err = db.SQ.Prepare(
		`SELECT identity, windows FROM dnscrypt_state WHERE id = 1`,
	)
	if err != nil {
		return err
	}
	db.StmtDNSCryptSave, err = db.SQ.Prepare(
		`INSERT INTO dnscrypt_state (id, identity, windows) VALUES (1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET identity = excluded.identity, windows = excluded.windows`,
	)
	if err != nil {
		return err
	}

	return nil
}
