package cache

import (
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	_ "modernc.org/sqlite"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
)

const (
	defaultCleanupInterval = 5 * time.Minute
	defaultStaleMaxAge     = int64(config.DefaultStaleMaxAge)
	defaultCacheLowWater   = 0.9
)

// SQLiteCache is a DNS response cache backed entirely by SQLite.
type SQLiteCache struct {
	db          *sql.DB
	maxEntries  int
	mmapSizeMB  int
	cacheSizeMB int
	staleMaxAge int64
	closed      int32
	stopCh      chan struct{}
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

	dsn := path
	if dsn == "" {
		dsn = ":memory:"
	}
	dsn += "?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000&_foreign_keys=ON"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite open: %w", err)
	}
	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite ping: %w", err)
	}

	s := &SQLiteCache{
		db:          db,
		maxEntries:  maxEntries,
		mmapSizeMB:  mmapSizeMB,
		cacheSizeMB: cacheSizeMB,
		staleMaxAge: defaultStaleMaxAge,
		stopCh:      make(chan struct{}),
	}

	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite migrate: %w", err)
	}

	s.deleteExpiredEntries()
	s.startPeriodicCleanup()

	persistLabel := path
	if persistLabel == "" {
		persistLabel = "memory"
	}
	log.Infof("CACHE: SQLite cache enabled (db=%s, max_entries=%d, mmap_size=%dMB, cache_size=%dMB)",
		persistLabel, maxEntries, mmapSizeMB, cacheSizeMB)
	return s, nil
}

func (s *SQLiteCache) migrate() error {
	pragmas := []string{
		fmt.Sprintf("PRAGMA mmap_size = %d", s.mmapSizeMB*1024*1024),
		fmt.Sprintf("PRAGMA cache_size = %d", -s.cacheSizeMB*1024),
		"PRAGMA page_size = 4096",
		"PRAGMA temp_store = MEMORY",
	}
	for _, p := range pragmas {
		if _, err := s.db.Exec(p); err != nil {
			log.Warnf("CACHE: pragma failed (non-fatal): %s: %v", p, err)
		}
	}

	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS entries (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL,
			qclass     INTEGER NOT NULL DEFAULT 1,
			ecs_addr   TEXT NOT NULL DEFAULT '',
			ecs_prefix INTEGER NOT NULL DEFAULT 0,
			dnssec_ok  INTEGER NOT NULL DEFAULT 0,
			timestamp  INTEGER NOT NULL,
			ttl        INTEGER NOT NULL,
			validated  INTEGER NOT NULL DEFAULT 0,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		CREATE TABLE IF NOT EXISTS records (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			section    TEXT NOT NULL,
			seq        INTEGER NOT NULL DEFAULT 0,
			name       TEXT NOT NULL,
			rtype      INTEGER NOT NULL,
			ttl        INTEGER NOT NULL,
			rr_text    TEXT NOT NULL,
			rdata_ip   TEXT,
			latency_ms INTEGER
		);

		CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_entries_lookup ON entries(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok);
		CREATE INDEX IF NOT EXISTS idx_records_entry ON records(entry_id);
		CREATE INDEX IF NOT EXISTS idx_records_ip ON records(rdata_ip) WHERE rdata_ip IS NOT NULL;

		CREATE TABLE IF NOT EXISTS stats (
			key       TEXT PRIMARY KEY,
			data      BLOB NOT NULL,
			ttl       INTEGER NOT NULL,
			timestamp INTEGER NOT NULL
		);
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
	err := s.db.QueryRow(
		`SELECT id, timestamp, ttl, validated FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, boolToInt(dnssecOK),
	).Scan(&id, &ts, &entryTTL, &validated)
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
	answer, authority, additional []dns.RR, validated bool) {

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
		`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok, timestamp, ttl, validated)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt, now, entryTTL, boolToInt(validated),
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

	// Old records were cascade-deleted by INSERT OR REPLACE. Insert new ones.
	insertRecords(tx, entryID, "answer", answer)
	insertRecords(tx, entryID, "authority", authority)
	insertRecords(tx, entryID, "additional", additional)

	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}

	s.evictIfNeeded()
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil
	}

	rows, err := s.db.Query(
		`SELECT DISTINCT r.name, r.ttl, e.timestamp FROM records r
		 JOIN entries e ON r.entry_id = e.id
		 WHERE r.rdata_ip = ? AND e.timestamp + e.ttl > ? AND e.timestamp + e.ttl + ? >= ?
		 ORDER BY r.name`,
		ip, log.NowUnix(), s.staleMaxAge, log.NowUnix(),
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

// Close stops the periodic cleanup goroutine, performs final cleanup, and
// closes the database.
func (s *SQLiteCache) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	close(s.stopCh)
	s.deleteExpiredEntries()
	if err := s.db.Close(); err != nil {
		log.Errorf("CACHE: sqlite close failed: %v", err)
		return err
	}
	log.Infof("CACHE: SQLite cache shut down")
	return nil
}

// ── Stats persistence ────────────────────────────────────────────────────────

// SaveStats stores a JSON stats snapshot in the stats table.
func (s *SQLiteCache) SaveStats(data []byte, ttlSeconds int) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO stats (key, data, ttl, timestamp) VALUES (?, ?, ?, ?)`,
		config.StatsPersistKey, data, ttlSeconds, log.NowUnix(),
	)
	if err != nil {
		log.Warnf("CACHE: save stats failed: %v", err)
	}
}

// LoadStats retrieves a non-expired stats snapshot from the stats table.
func (s *SQLiteCache) LoadStats() ([]byte, bool) {
	var data []byte
	var ts int64
	var ttlSeconds int
	err := s.db.QueryRow(
		`SELECT data, timestamp, ttl FROM stats WHERE key = ?`, config.StatsPersistKey,
	).Scan(&data, &ts, &ttlSeconds)
	if err == sql.ErrNoRows {
		return nil, false
	}
	if err != nil {
		log.Warnf("CACHE: load stats failed: %v", err)
		return nil, false
	}
	if ttl.IsExpired(ts, ttlSeconds) {
		return nil, false
	}
	return data, true
}

// ── Eviction ─────────────────────────────────────────────────────────────────

func (s *SQLiteCache) evictIfNeeded() {
	if s.maxEntries <= 0 {
		return
	}

	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err != nil {
		return
	}
	if count <= int64(s.maxEntries) {
		return
	}

	excess := count - int64(float64(s.maxEntries)*defaultCacheLowWater)
	if excess <= 0 {
		excess = 1
	}
	s.evictOldest(excess)
}

func (s *SQLiteCache) evictOldest(n int64) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT id FROM entries ORDER BY timestamp ASC LIMIT ?`, n)
	if err != nil {
		return
	}

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	_ = rows.Close()

	if len(ids) == 0 {
		return
	}

	// Build IN clause. Records cascade-delete automatically.
	stmt := `DELETE FROM entries WHERE id IN (?` + strings.Repeat(`,?`, len(ids)-1) + `)`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	if _, err := tx.Exec(stmt, args...); err != nil {
		return
	}
	_ = tx.Commit()

	log.Debugf("CACHE: evicted %d oldest entries (max=%d)", len(ids), s.maxEntries)
}

// ── Periodic cleanup ─────────────────────────────────────────────────────────

func (s *SQLiteCache) startPeriodicCleanup() {
	go func() {
		ticker := time.NewTicker(defaultCleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-s.stopCh:
				return
			}
			if atomic.LoadInt32(&s.closed) != 0 {
				return
			}
			s.deleteExpiredEntries()
		}
	}()
}

func (s *SQLiteCache) deleteExpiredEntries() {
	cutoff := log.NowUnix() - s.staleMaxAge
	res, err := s.db.Exec(`DELETE FROM entries WHERE timestamp + ttl < ?`, cutoff)
	if err != nil {
		log.Warnf("CACHE: expired entry cleanup failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Debugf("CACHE: cleaned %d expired entries", n)
	}
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
		`SELECT section, name, rtype, ttl, rr_text FROM records WHERE entry_id = ? ORDER BY latency_ms IS NULL, latency_ms ASC, section, seq`, entryID,
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
	for i, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		rrText := rr.String()
		_, err := tx.Exec(
			`INSERT INTO records (entry_id, section, seq, name, rtype, ttl, rr_text, rdata_ip)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			entryID, section, i, rr.Header().Name, int(dns.RRToType(rr)), int(rr.Header().TTL), rrText, extractIP(rr),
		)
		if err != nil {
			log.Warnf("CACHE: insert record failed: %v", err)
		}
	}
}

func extractIP(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	}
	return ""
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
