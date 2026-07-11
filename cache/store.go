package cache

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
)

// SQLiteCache is a DNS response cache backed by a SQLite database managed by
// the database package. It implements the Store interface.
type SQLiteCache struct {
	db         *database.DB
	evictCount atomic.Int64
}

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap IN-clause IPs to bound SQL compilation overhead
)

// New creates a cache backed by the given database. The caller is responsible
// for opening the database via database.Open() before calling New.
func New(db *database.DB) *SQLiteCache {
	return &SQLiteCache{db: db}
}

// Close closes the database.
func (s *SQLiteCache) Close() error {
	return s.db.Close()
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
func (s *SQLiteCache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	if s.db.IsClosed() {
		return nil, false, false
	}

	qname = zdnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)

	var id int64
	var ts int64
	var entryTTL int
	var validated int
	var msgWire []byte
	err := s.db.StmtGetEntry.QueryRow(
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, zdnsutil.BoolToInt(dnssecOK),
	).Scan(&id, &ts, &entryTTL, &validated, &msgWire)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, false
	}
	if err != nil {
		log.Warnf("CACHE: get query failed: %v", err)
		return nil, false, false
	}

	if len(msgWire) == 0 {
		return nil, false, false
	}

	// Decompress and unpack the wire format into a dns.Msg.
	wire, err := zdnsutil.Decompress(msgWire)
	if err != nil {
		log.Warnf("CACHE: decompress wire for entry %d: %v", id, err)
		return nil, false, false
	}

	msg := pool.DefaultMessagePool.Get()
	msg.Data = wire
	if err := msg.Unpack(); err != nil {
		pool.DefaultMessagePool.Put(msg)
		log.Warnf("CACHE: unpack wire for entry %d: %v", id, err)
		return nil, false, false
	}
	defer pool.DefaultMessagePool.Put(msg)

	entry := &Entry{
		Answer:     msg.Answer,
		Authority:  msg.Ns,
		Additional: msg.Extra,
		Timestamp:  ts,
		TTL:        entryTTL,
		Validated:  validated != 0,
	}

	// Sort A/AAAA answer records by latency from ip_latency so the
	// fastest IP is returned first. Latency is per-IP — all domains
	// sharing the same IP reuse the same row.
	s.sortAnswerByLatency(entry)

	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records (CNAME, etc.) at the
// front in their original wire-format order. Latency is per-IP — all domains
// sharing the same IP reuse the same row. Idempotent when ≤1 A/AAAA.
func (s *SQLiteCache) sortAnswerByLatency(entry *Entry) {
	if len(entry.Answer) <= 1 {
		return
	}

	// Fast check: count A/AAAA records and collect their IPs in one pass.
	aCount := 0
	ips := make([]string, 0, len(entry.Answer))
	for _, rr := range entry.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			aCount++
			if ip, ok := zdnsutil.ExtractIPString(rr); ok {
				ips = append(ips, ip)
			}
		}
	}
	if aCount <= 1 {
		return
	}

	// Batch lookup: WHERE rdata_ip IN (?,?,...). Single query replaces N
	// per-IP round-trips on the cache Get() hot path.
	latencies := s.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return
	}

	// Separate A/AAAA from non-A/AAAA (CNAME, etc.).
	var aRecs []dns.RR
	var other []dns.RR
	for _, rr := range entry.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			aRecs = append(aRecs, rr)
		default:
			other = append(other, rr)
		}
	}

	// Sort A/AAAA: probed first (fastest → slowest), unprobed last.
	slices.SortStableFunc(aRecs, func(a, b dns.RR) int {
		aIP, _ := zdnsutil.ExtractIPString(a)
		bIP, _ := zdnsutil.ExtractIPString(b)
		aLat, aOK := latencies[aIP]
		bLat, bOK := latencies[bIP]
		switch {
		case aOK && !bOK:
			return -1
		case !aOK && bOK:
			return 1
		case aOK && bOK:
			return aLat - bLat
		default:
			return 0
		}
	})

	result := make([]dns.RR, 0, len(entry.Answer))
	result = append(result, other...)
	result = append(result, aRecs...)
	entry.Answer = result
}

// lookupIPLatencies fetches latencies for a batch of IPs in a single query.
// Caps at maxLatencyLookupIPs to bound SQL compilation overhead on unusually
// large answer sets (64+ A/AAAA records).
func (s *SQLiteCache) lookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}

	// Build WHERE rdata_ip IN (?,?,...)
	var buf strings.Builder
	buf.WriteString("SELECT rdata_ip, latency_ms FROM ip_latency WHERE rdata_ip IN (")
	for i := range ips {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteByte('?')
	}
	buf.WriteByte(')')

	args := make([]any, len(ips))
	for i, ip := range ips {
		args[i] = ip
	}

	rows, err := s.db.SQ.Query(buf.String(), args...)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	latencies := make(map[string]int, len(ips))
	for rows.Next() {
		var ip string
		var lat int
		if err := rows.Scan(&ip, &lat); err == nil {
			latencies[ip] = lat
		}
	}
	return latencies
}

// Set stores a DNS response in the cache. Wire format is zstd-compressed.
// The transaction itself is serialized via writeMu to prevent SQLite
// write-lock contention (WAL mode permits only one writer at a time);
// prep work (TTL calculation, wire packing, zstd compression) runs outside
// the lock so CPU-heavy steps can overlap across goroutines.
func (s *SQLiteCache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool,
) {
	if s.db.IsClosed() {
		return
	}

	// ── Prep work (parallel-safe, outside writeMu) ──────────────────────────
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)
	if hasNSECOrNSEC3(authority) {
		if capTTL := negativeTTLCap(authority); capTTL < entryTTL {
			entryTTL = capTTL
		}
	}

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = zdnsutil.NormalizeDomain(qname)
	dnssecInt := zdnsutil.BoolToInt(dnssecOK)

	// Pack wire format and compress.
	msg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
	var msgWire []byte
	if err := msg.Pack(); err == nil {
		msgWire = zdnsutil.Compress(msg.Data)
	}

	// ── Transaction (serialized via writeMu) ──────────────────────────────
	s.db.WriteLock()

	tx, err := s.db.SQ.Begin()
	if err != nil {
		s.db.WriteUnlock()
		log.Warnf("CACHE: begin tx failed: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	var entryID int64
	if err := tx.QueryRow(
		`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, msg_wire)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 RETURNING id`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
		now, entryTTL, now+int64(entryTTL), zdnsutil.BoolToInt(validated),
		msgWire,
	).Scan(&entryID); err != nil {
		s.db.WriteUnlock()
		log.Warnf("CACHE: insert entry failed: %v", err)
		return
	}

	// Populate ptr_map for reverse (PTR) lookups.
	insertPtrMap(tx, entryID, answer)
	insertPtrMap(tx, entryID, authority)
	insertPtrMap(tx, entryID, additional)

	if err := tx.Commit(); err != nil {
		s.db.WriteUnlock()
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}

	s.db.AddEntryCount(1)
	s.db.WriteUnlock()

	// Run eviction outside writeMu — evictIfNeeded re-syncs the entry count
	// from the DB via SELECT COUNT(*) before deciding whether to evict, so
	// any TOCTOU drift from concurrent inserts is corrected.
	s.evictIfNeeded()
}

// ── Eviction ─────────────────────────────────────────────────────────────────

func (s *SQLiteCache) evictIfNeeded() {
	if s.db.MaxEntries() <= 0 {
		return
	}

	// Re-sync the entry count from the database to correct any drift from
	// INSERT OR REPLACE (which may replace existing entries without changing
	// the row count). COUNT(*) on the PK is a fast B-tree leaf walk; only
	// runs when the atomic counter suggests we may be near or over the limit.
	var count int64
	if err := s.db.SQ.QueryRow("SELECT COUNT(*) FROM entries").Scan(&count); err == nil {
		s.db.SetEntryCount(count)
	}

	excess := count - int64(s.db.MaxEntries())
	if excess <= 0 {
		return
	}

	s.evictOldest(excess)

	// Throttle PRAGMA optimize to every 10th eviction to avoid per-eviction overhead.
	if s.evictCount.Add(1)%10 == 0 {
		_, _ = s.db.SQ.Exec("PRAGMA optimize")
	}
}

func (s *SQLiteCache) evictOldest(toEvict int64) {
	tx, err := s.db.SQ.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Clean up latency rows not probed within staleMaxAge.
	if _, err := tx.Exec(
		`DELETE FROM ip_latency WHERE last_probe_time > 0 AND last_probe_time < unixepoch() - ?`,
		defaultStaleMaxAge,
	); err != nil {
		log.Debugf("CACHE: ip_latency cleanup failed (non-fatal): %v", err)
	}

	// Clean up old request_log rows to prevent unbounded growth.
	// request_log rows for active entries are cleaned by ON DELETE CASCADE;
	// this handles orphaned rows (e.g. from cleared cache entries).
	if _, err := tx.Exec(
		`DELETE FROM request_log WHERE timestamp < unixepoch() - ?`,
		defaultStaleMaxAge,
	); err != nil {
		log.Debugf("CACHE: request_log cleanup failed (non-fatal): %v", err)
	}

	// Two-phase eviction:
	// Phase 1 — entries past serve-stale (expires_at < staleCutoff). These
	// can no longer serve stale and are worthless. idx_entries_expires
	// enables an index-assisted range scan for the WHERE filter.
	// Phase 2 — if still over limit, evict the oldest entries regardless.
	staleCutoff := log.NowUnix() - defaultStaleMaxAge
	result, err := tx.Exec(
		`DELETE FROM entries WHERE id IN (
			SELECT id FROM entries WHERE expires_at < ?
			ORDER BY timestamp ASC LIMIT ?
		)`, staleCutoff, toEvict,
	)
	if err != nil {
		return
	}
	phase1, _ := result.RowsAffected()
	remaining := toEvict - phase1

	if remaining > 0 {
		result2, err2 := tx.Exec(
			`DELETE FROM entries WHERE id IN (
				SELECT id FROM entries ORDER BY timestamp ASC LIMIT ?
			)`, remaining,
		)
		if err2 != nil {
			return
		}
		phase2, _ := result2.RowsAffected()
		totalEvicted := phase1 + phase2
		if err := tx.Commit(); err != nil {
			log.Warnf("CACHE: commit tx failed: %v", err)
			return
		}
		s.db.AddEntryCount(-totalEvicted)
		log.Debugf("CACHE: evicted %d entries (serve-stale=%d, oldest=%d, max=%d)", totalEvicted, phase1, phase2, s.db.MaxEntries())
		return
	}

	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}
	s.db.AddEntryCount(-phase1)
	log.Debugf("CACHE: evicted %d entries (all serve-stale, max=%d)", phase1, s.db.MaxEntries())
}
