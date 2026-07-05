package cache

import (
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"

	"codeberg.org/miekg/dns"
	_ "github.com/ncruces/go-sqlite3/driver"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
)

const defaultStaleMaxAge = int64(config.DefaultStaleMaxAge)

// SQLiteCache is a DNS response cache backed entirely by SQLite.
type SQLiteCache struct {
	db          *sql.DB
	maxEntries  int
	mmapSizeMB  int
	cacheSizeMB int
	closed      int32
	entryCount  atomic.Int64
}

// NewSQLiteCache opens or creates a SQLite database and returns a ready-to-use
// cache. path is the database file path; an empty string uses an in-memory
// database. mmapSizeMB and cacheSizeMB are SQLite PRAGMA tunables; zero means use defaults.
func NewSQLiteCache(path string, maxEntries, mmapSizeMB, cacheSizeMB int) (*SQLiteCache, error) {
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxCacheEntries
	}
	if mmapSizeMB <= 0 {
		mmapSizeMB = config.DefaultCacheMMapSizeMB
	}
	if cacheSizeMB <= 0 {
		cacheSizeMB = config.DefaultCacheCacheSizeMB
	}

	params := "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000&_foreign_keys=ON&_txlock=immediate"
	var dsn string
	if path == "" {
		dsn = "file::memory:?" + params
	} else {
		dsn = "file:" + path + "?" + params
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(config.DefaultCacheMaxOpenConns)
	db.SetMaxIdleConns(config.DefaultCacheMaxIdleConns)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}

	s := &SQLiteCache{
		db:          db,
		maxEntries:  maxEntries,
		mmapSizeMB:  mmapSizeMB,
		cacheSizeMB: cacheSizeMB,
	}

	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}

	// Initialize entryCount from existing rows before cleanup.
	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err == nil {
		s.entryCount.Store(count)
	}

	persistLabel := path
	if persistLabel == "" {
		persistLabel = "memory"
	}
	log.Infof("CACHE: SQLite cache enabled (db=%s, max_entries=%d, mmap_size=%dMB, cache_size=%dMB)",
		persistLabel, maxEntries, mmapSizeMB, cacheSizeMB)
	return s, nil
}

func (s *SQLiteCache) migrate() error {
	// 2.8: WAL autocheckpoint tuning
	pragmaSQL := fmt.Sprintf(
		"PRAGMA mmap_size = %d; PRAGMA cache_size = %d; PRAGMA page_size = 4096; PRAGMA temp_store = MEMORY; PRAGMA wal_autocheckpoint = 500;",
		s.mmapSizeMB*1024*1024, -s.cacheSizeMB*1024,
	)
	if _, err := s.db.Exec(pragmaSQL); err != nil {
		log.Warnf("CACHE: pragma failed (non-fatal): %v", err)
	}

	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			-- Lookup key (UNIQUE)
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL,
			qclass     INTEGER NOT NULL DEFAULT 1,
			ecs_addr   TEXT NOT NULL DEFAULT '',
			ecs_prefix INTEGER NOT NULL DEFAULT 0,
			dnssec_ok  INTEGER NOT NULL DEFAULT 0,
			-- Lifecycle
			timestamp  INTEGER NOT NULL,
			ttl        INTEGER NOT NULL,
			expires_at INTEGER NOT NULL DEFAULT 0,
			-- Flags
			validated  INTEGER NOT NULL DEFAULT 0,
			cacheable  INTEGER NOT NULL DEFAULT 1,
			msg_wire   BLOB,
			-- PK + constraint
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		CREATE TABLE IF NOT EXISTS metadata (
			entry_id         INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
			-- Resolution metadata (written once by Set)
			rcode            INTEGER NOT NULL DEFAULT 0,
			response_time_ms INTEGER NOT NULL DEFAULT 0,
			server           TEXT NOT NULL DEFAULT '',
			dnssec           TEXT NOT NULL DEFAULT "",
			fallback         INTEGER NOT NULL DEFAULT 0,
			prefetch         INTEGER NOT NULL DEFAULT 0,
			hijack           INTEGER NOT NULL DEFAULT 0,
			-- Serving counters (updated by RecordServe / RecordRewrite)
			last_hit_time    INTEGER NOT NULL DEFAULT 0,
			hit_udp          INTEGER NOT NULL DEFAULT 0,
			hit_tcp          INTEGER NOT NULL DEFAULT 0,
			hit_dot          INTEGER NOT NULL DEFAULT 0,
			hit_doq          INTEGER NOT NULL DEFAULT 0,
			hit_doh          INTEGER NOT NULL DEFAULT 0,
			hit_doh3         INTEGER NOT NULL DEFAULT 0,
			stale_count      INTEGER NOT NULL DEFAULT 0,
			rewrite_count    INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS records (
			-- Reference
			entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			-- Record identity
			section    TEXT NOT NULL,
			seq        INTEGER NOT NULL DEFAULT 0,
			name       TEXT NOT NULL,
			rtype      INTEGER NOT NULL,
			ttl        INTEGER NOT NULL,
			-- Data
			rr_text    TEXT NOT NULL,
			rdata_ip   TEXT,
			-- Probe latency
			latency_ms INTEGER,
			-- PK
			id         INTEGER PRIMARY KEY AUTOINCREMENT
		);

		CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_entries_expires_at ON entries(expires_at);
		CREATE INDEX IF NOT EXISTS idx_records_entry_section_seq ON records(entry_id, section, seq);
		CREATE INDEX IF NOT EXISTS idx_records_ip_entry ON records(rdata_ip, entry_id) WHERE rdata_ip IS NOT NULL;
	`)
	return err
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by query parameters.
func (s *SQLiteCache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return nil, false, false
	}

	qname = dnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)

	var id int64
	var ts int64
	var entryTTL int
	var validated int
	var msgWire []byte
	err := s.db.QueryRow(
		`SELECT id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?
		 AND cacheable = 1`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, boolToInt(dnssecOK),
	).Scan(&id, &ts, &entryTTL, &validated, &msgWire)
	if err == sql.ErrNoRows {
		return nil, false, false
	}
	if err != nil {
		log.Warnf("CACHE: get query failed: %v", err)
		return nil, false, false
	}

	entry, err := s.loadRecords(id)
	if err != nil {
		log.Warnf("CACHE: load records failed for entry %d: %v", id, err)
		return nil, false, false
	}
	entry.Timestamp = ts
	entry.TTL = entryTTL
	entry.Validated = validated != 0

	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// Set stores a DNS response in the cache.
func (s *SQLiteCache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool, opts SetOptions) {

	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)
	if hasNSECOrNSEC3(authority) {
		if capTTL := negativeTTLCap(authority); capTTL < entryTTL {
			entryTTL = capTTL
		}
	}

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = dnsutil.NormalizeDomain(qname)
	dnssecInt := boolToInt(dnssecOK)

	tx, err := s.db.Begin()
	if err != nil {
		log.Warnf("CACHE: begin tx failed: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated,
			cacheable)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
		now, entryTTL, now+int64(entryTTL), boolToInt(validated), boolToInt(!opts.Uncacheable),
	); err != nil {
		log.Warnf("CACHE: insert entry failed: %v", err)
		return
	}

	var entryID int64
	if err := tx.QueryRow(
		`SELECT id FROM entries WHERE qname=? AND qtype=? AND qclass=? AND ecs_addr=? AND ecs_prefix=? AND dnssec_ok=?`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&entryID); err != nil {
		log.Warnf("CACHE: select entry id failed: %v", err)
		return
	}

	// Upsert metadata for analytics.
	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO metadata (entry_id, rcode, response_time_ms, server, dnssec, fallback, prefetch, hijack)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entryID, opts.Rcode, opts.ResponseTime, opts.Server, opts.Dnssec, boolToInt(opts.Fallback), boolToInt(opts.Prefetch), boolToInt(opts.Hijack),
	); err != nil {
		log.Warnf("CACHE: insert metadata failed: %v", err)
	}

	// Only insert records for cacheable entries; error entries have no RRs.
	if !opts.Uncacheable {
		insertRecords(tx, entryID, "answer", answer)
		insertRecords(tx, entryID, "authority", authority)
		insertRecords(tx, entryID, "additional", additional)
		// Store packed wire format for fast Get().
		msg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
		if err := msg.Pack(); err == nil {
			_, _ = tx.Exec(`UPDATE entries SET msg_wire = ? WHERE id = ?`, msg.Data, entryID)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}

	s.entryCount.Add(1)
	s.evictIfNeeded()
}

// RecordServe updates metadata hit counters and last_hit_time in a single
// UPDATE.  Called once per cache hit to minimize SQL round-trips.
func (s *SQLiteCache) RecordServe(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, protocol string, stale bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}

	qname = dnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)

	col := hitColumn(protocol)
	staleSQL := ""
	if stale {
		staleSQL = ", stale_count = stale_count + 1"
	}

	_, _ = s.db.Exec(
		`UPDATE metadata SET `+col+` = `+col+` + 1, last_hit_time = ?`+staleSQL+` WHERE entry_id = (
			SELECT id FROM entries WHERE qname = ? AND qtype = ? AND qclass = ?
			 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?)`,
		log.NowUnix(), qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, boolToInt(dnssecOK),
	)
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil
	}

	rows, err := s.db.Query(
		`SELECT DISTINCT r.name, r.ttl, e.timestamp FROM records r
		 JOIN entries e ON r.entry_id = e.id
		 WHERE r.rdata_ip = ? AND e.expires_at + ? >= ?
		 ORDER BY r.name`,
		ip, defaultStaleMaxAge, log.NowUnix(),
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
		if err := rows.Scan(&name, &rawTTL, &ts); err != nil {
			continue
		}
		results = append(results, LookupResult{
			Name: name,
			TTL:  ttl.RemainingTTL(ts, rawTTL, uint32(config.DefaultStaleTTL)),
		})
	}
	return results
}

func hitColumn(protocol string) string {
	switch {
	case len(protocol) >= 3 && (protocol[0] == 'u' || protocol[0] == 'U'):
		return "hit_udp"
	case len(protocol) >= 3 && (protocol[0] == 't' || protocol[0] == 'T'):
		return "hit_tcp"
	case len(protocol) >= 3 && (protocol[1] == 'o' || protocol[1] == 'O'):
		switch protocol[2] {
		case 't', 'T':
			return "hit_dot"
		case 'q', 'Q':
			return "hit_doq"
		case 'h', 'H':
			if len(protocol) >= 4 && protocol[3] == '3' {
				return "hit_doh3"
			}
			return "hit_doh"
		}
	}
	return ""
}

// RecordRewrite increments the rewrite counter. Since rewrite responses bypass
// the cache, this creates a lightweight entry if one doesn't already exist.
func (s *SQLiteCache) RecordRewrite(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	qname = dnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)
	// Upsert a stub entry so rewrite counts survive eviction cycles.
	now := log.NowUnix()
	dnssecInt := boolToInt(dnssecOK)
	_, _ = s.db.Exec(
		"INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok, timestamp, ttl, expires_at, validated, cacheable) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt, now, config.DefaultStaleTTL, now+int64(config.DefaultStaleTTL), 0, 1,
	)
	var entryID int64
	if err := s.db.QueryRow("SELECT id FROM entries WHERE qname=? AND qtype=? AND qclass=? AND ecs_addr=? AND ecs_prefix=? AND dnssec_ok=?", qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt).Scan(&entryID); err == nil {
		_, _ = s.db.Exec("INSERT OR REPLACE INTO metadata (entry_id, rcode, response_time_ms, server, dnssec, fallback, prefetch, hijack) VALUES (?,?,?,?,?,?,?,?)", entryID, 0, 0, "rewrite", "", 0, 0, 0)
		_, _ = s.db.Exec("UPDATE metadata SET rewrite_count = rewrite_count + 1 WHERE entry_id = ?", entryID)
	}
}

// Summary returns a one-line stats summary from the metadata table.
func (s *SQLiteCache) Summary() string {
	if atomic.LoadInt32(&s.closed) != 0 {
		return ""
	}
	var entries, hits, udp, tcp, dot, doq, doh, doh3 int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var hijack, fallback, prefetch, stale, rewrite int64
	var avgMs float64

	// Entries
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE cacheable = 1").Scan(&entries)
	// Hits
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hit_udp+hit_tcp+hit_dot+hit_doq+hit_doh+hit_doh3),0) FROM metadata").Scan(&hits)
	// Avg response time
	_ = s.db.QueryRow("SELECT COALESCE(AVG(response_time_ms),0) FROM metadata WHERE response_time_ms > 0").Scan(&avgMs)
	// Protocol breakdown
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hit_udp),0), COALESCE(SUM(hit_tcp),0), COALESCE(SUM(hit_dot),0), COALESCE(SUM(hit_doq),0), COALESCE(SUM(hit_doh),0), COALESCE(SUM(hit_doh3),0) FROM metadata").Scan(&udp, &tcp, &dot, &doq, &doh, &doh3)
	// Rcode distribution
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode = 0").Scan(&noerr)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode = 1").Scan(&formerr)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode = 2").Scan(&servfail)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode = 3").Scan(&nxdomain)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode = 4").Scan(&notimp)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode = 5").Scan(&refused)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE rcode NOT IN (0,1,2,3,4,5)").Scan(&other)
	// Flags & counters
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE hijack = 1").Scan(&hijack)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE fallback = 1").Scan(&fallback)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM metadata WHERE prefetch = 1").Scan(&prefetch)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(stale_count),0) FROM metadata").Scan(&stale)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(rewrite_count),0) FROM metadata").Scan(&rewrite)

	return fmt.Sprintf("entries=%d hits=%d avg=%.1fms udp=%d tcp=%d dot=%d doq=%d doh=%d doh3=%d noerr=%d formerr=%d servfail=%d nx=%d nimp=%d ref=%d other=%d hijack=%d fallback=%d prefetch=%d stale=%d rewrite=%d",
		entries, hits, avgMs, udp, tcp, dot, doq, doh, doh3,
		noerr, formerr, servfail, nxdomain, notimp, refused, other,
		hijack, fallback, prefetch, stale, rewrite)
}

// Close closes the database.
func (s *SQLiteCache) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	if err := s.db.Close(); err != nil {
		log.Errorf("CACHE: sqlite close failed: %v", err)
		return err
	}
	log.Infof("CACHE: SQLite cache shut down")
	return nil
}

// ── Eviction ─────────────────────────────────────────────────────────────────

func (s *SQLiteCache) evictIfNeeded() {
	if s.maxEntries <= 0 {
		return
	}

	count := s.entryCount.Load()
	excess := count - int64(s.maxEntries)
	if excess <= 0 {
		return
	}

	s.evictOldest(excess)
}

func (s *SQLiteCache) evictOldest(n int64) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Prefer evicting entries that can no longer serve-stale (expires_at +
	// staleMaxAge < now), then fall back to the oldest-by-insertion entries.
	if _, err := tx.Exec(
		`DELETE FROM entries WHERE id IN (
			SELECT id FROM entries
			ORDER BY
				CASE WHEN expires_at + ? < unixepoch() THEN 0 ELSE 1 END,
				timestamp ASC
			LIMIT ?
		)`, defaultStaleMaxAge, n,
	); err != nil {
		return
	}
	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}

	s.entryCount.Add(-n)
	log.Debugf("CACHE: evicted %d entries (max=%d)", n, s.maxEntries)
}

// UpdateLatency sets the latency for a specific record identified by entry lookup
// key + IP address. Used by the probe engine after measuring A/AAAA response times.
func (s *SQLiteCache) UpdateLatency(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, ip string, latencyMS int) {
	qname = dnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)

	var entryID int64
	err := s.db.QueryRow(
		`SELECT id FROM entries WHERE qname=? AND qtype=? AND qclass=? AND ecs_addr=? AND ecs_prefix=? AND dnssec_ok=?`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, boolToInt(dnssecOK),
	).Scan(&entryID)
	if err != nil {
		return
	}

	_, _ = s.db.Exec(
		`UPDATE records SET latency_ms = ? WHERE entry_id = ? AND rdata_ip = ?`,
		latencyMS, entryID, ip,
	)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (s *SQLiteCache) loadRecords(entryID int64) (*Entry, error) {
	rows, err := s.db.Query(
		`SELECT section, name, rtype, ttl, rr_text FROM records WHERE entry_id = ? ORDER BY CASE WHEN rtype IN (1, 28) THEN 1 ELSE 0 END, latency_ms IS NULL, latency_ms ASC, section, seq`, entryID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	entry := &Entry{}
	for rows.Next() {
		var section, name, rrText string
		var rtype int
		var recTTL int
		if err := rows.Scan(&section, &name, &rtype, &recTTL, &rrText); err != nil {
			continue
		}
		rr, err := dns.New(rrText)
		if err != nil {
			continue
		}
		switch section {
		case "answer":
			entry.Answer = append(entry.Answer, rr)
		case "authority":
			entry.Authority = append(entry.Authority, rr)
		case "additional":
			entry.Additional = append(entry.Additional, rr)
		}
	}
	return entry, rows.Err()
}

func insertRecords(tx *sql.Tx, entryID int64, section string, rrs []dns.RR) {
	// Filter and collect valid records.
	type rec struct {
		seq     int
		name    string
		rtype   int
		ttl     int
		rrText  string
		rdataIP string
	}
	var recs []rec
	for i, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		recs = append(recs, rec{
			seq: i, name: rr.Header().Name, rtype: int(dns.RRToType(rr)),
			ttl: int(rr.Header().TTL), rrText: rr.String(), rdataIP: extractIP(rr),
		})
	}
	if len(recs) == 0 {
		return
	}

	// Build multi-row INSERT.
	placeholders := make([]string, len(recs))
	args := make([]any, 0, len(recs)*8)
	for i, r := range recs {
		placeholders[i] = "(?, ?, ?, ?, ?, ?, ?, ?)"
		args = append(args, entryID, section, r.seq, r.name, r.rtype, r.ttl, r.rrText, r.rdataIP)
	}
	stmt := `INSERT INTO records (entry_id, section, seq, name, rtype, ttl, rr_text, rdata_ip) VALUES ` +
		join(placeholders, ",")
	if _, err := tx.Exec(stmt, args...); err != nil {
		log.Warnf("CACHE: insert records failed: %v", err)
	}
}

func extractIP(rr dns.RR) string {
	ip, _ := dnsutil.ExtractIPString(rr)
	return ip
}

func join(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(parts[0])
	for _, p := range parts[1:] {
		b.WriteString(sep)
		b.WriteString(p)
	}
	return b.String()
}

func minTTL(answer, authority, additional []dns.RR) int {
	minT := -1
	for _, rrs := range [][]dns.RR{answer, authority, additional} {
		for _, rr := range rrs {
			if rr == nil {
				continue
			}
			if t := int(rr.Header().TTL); t > 0 && (minT < 0 || t < minT) {
				minT = t
			}
		}
	}
	if minT <= 0 {
		return config.DefaultTTL
	}
	return minT
}

func hasNSECOrNSEC3(authority []dns.RR) bool {
	for _, rr := range authority {
		if rr == nil {
			continue
		}
		switch dns.RRToType(rr) {
		case dns.TypeNSEC, dns.TypeNSEC3:
			return true
		}
	}
	return false
}

func negativeTTLCap(authority []dns.RR) int {
	capTTL := config.DefaultMaxNegativeTTL
	for _, rr := range authority {
		if rr == nil {
			continue
		}
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		soaTTL := int(soa.Header().TTL)
		soaMin := int(soa.Minttl)
		soaBased := soaTTL
		if soaMin < soaBased {
			soaBased = soaMin
		}
		if soaBased < capTTL {
			capTTL = soaBased
		}
		break
	}
	return capTTL
}

func ecsParams(ecs *config.ECSOption) (addr string, prefix int) {
	if ecs == nil {
		return "", 0
	}
	return ecs.Address.String(), int(ecs.SourcePrefix)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// deduplicateRRs removes duplicate records from a slice by their presentation
// format, preserving order. OPT records are always excluded.
