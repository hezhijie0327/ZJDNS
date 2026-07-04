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
	entryCount  atomic.Int64
	stats       statsAccumulator
}

type statsAccumulator struct {
	totalRequests       atomic.Int64
	cacheHits           atomic.Int64
	cacheMisses         atomic.Int64
	prefetchRequests    atomic.Int64
	errorResponses      atomic.Int64
	staleResponses      atomic.Int64
	fallbackRequests    atomic.Int64
	totalResponseTimeMs atomic.Int64
	lastResponseTimeMs  atomic.Int64
	udpRequests         atomic.Int64
	tcpRequests         atomic.Int64
	dotRequests         atomic.Int64
	doqRequests         atomic.Int64
	dohRequests         atomic.Int64
	doh3Requests        atomic.Int64
	rewriteRequests     atomic.Int64
	hijackDetections    atomic.Int64
	dnssecSecure        atomic.Int64
	dnssecBogus         atomic.Int64
	dnssecInsecure      atomic.Int64
	rcodeNOERROR        atomic.Int64
	rcodeFORMERR        atomic.Int64
	rcodeSERVFAIL       atomic.Int64
	rcodeNXDOMAIN       atomic.Int64
	rcodeNotImp         atomic.Int64
	rcodeREFUSED        atomic.Int64
	rcodeOther          atomic.Int64
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

	// Initialize entryCount from existing rows before cleanup.
	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err == nil {
		s.entryCount.Store(count)
	}
	s.deleteExpiredEntries()
	s.flushStats()
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
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL,
			qclass     INTEGER NOT NULL DEFAULT 1,
			ecs_addr   TEXT NOT NULL DEFAULT '',
			ecs_prefix INTEGER NOT NULL DEFAULT 0,
			dnssec_ok  INTEGER NOT NULL DEFAULT 0,
			timestamp  INTEGER NOT NULL,
			ttl        INTEGER NOT NULL,
			expires_at INTEGER NOT NULL DEFAULT 0,
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
		CREATE INDEX IF NOT EXISTS idx_entries_expires_at ON entries(expires_at);
		CREATE INDEX IF NOT EXISTS idx_records_entry_section_seq ON records(entry_id, section, seq);
		CREATE INDEX IF NOT EXISTS idx_records_ip_entry ON records(rdata_ip, entry_id) WHERE rdata_ip IS NOT NULL;

		CREATE TABLE IF NOT EXISTS stats (
			id                    INTEGER PRIMARY KEY CHECK (id = 1),
			total_requests        INTEGER NOT NULL DEFAULT 0,
			cache_hits            INTEGER NOT NULL DEFAULT 0,
			cache_misses          INTEGER NOT NULL DEFAULT 0,
			prefetch_requests     INTEGER NOT NULL DEFAULT 0,
			error_responses       INTEGER NOT NULL DEFAULT 0,
			stale_responses       INTEGER NOT NULL DEFAULT 0,
			fallback_requests     INTEGER NOT NULL DEFAULT 0,
			total_response_time_ms INTEGER NOT NULL DEFAULT 0,
			last_response_time_ms  INTEGER NOT NULL DEFAULT 0,
			udp_requests          INTEGER NOT NULL DEFAULT 0,
			tcp_requests          INTEGER NOT NULL DEFAULT 0,
			dot_requests          INTEGER NOT NULL DEFAULT 0,
			doq_requests          INTEGER NOT NULL DEFAULT 0,
			doh_requests          INTEGER NOT NULL DEFAULT 0,
			doh3_requests         INTEGER NOT NULL DEFAULT 0,
			rewrite_requests      INTEGER NOT NULL DEFAULT 0,
			hijack_detections     INTEGER NOT NULL DEFAULT 0,
			dnssec_secure         INTEGER NOT NULL DEFAULT 0,
			dnssec_bogus          INTEGER NOT NULL DEFAULT 0,
			dnssec_insecure       INTEGER NOT NULL DEFAULT 0,
			rcode_noerror         INTEGER NOT NULL DEFAULT 0,
			rcode_formerr         INTEGER NOT NULL DEFAULT 0,
			rcode_servfail        INTEGER NOT NULL DEFAULT 0,
			rcode_nxdomain        INTEGER NOT NULL DEFAULT 0,
			rcode_notimp          INTEGER NOT NULL DEFAULT 0,
			rcode_refused         INTEGER NOT NULL DEFAULT 0,
			rcode_other           INTEGER NOT NULL DEFAULT 0,
			updated_at            INTEGER NOT NULL DEFAULT 0
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
		`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok, timestamp, ttl, expires_at, validated)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt, now, entryTTL, now+int64(entryTTL), boolToInt(validated),
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

	s.entryCount.Add(1)
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
		 WHERE r.rdata_ip = ? AND e.expires_at + ? >= ?
		 ORDER BY r.name`,
		ip, s.staleMaxAge, log.NowUnix(),
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
	s.flushStats()
	s.deleteExpiredEntries()
	s.flushStats()
	if err := s.db.Close(); err != nil {
		log.Errorf("CACHE: sqlite close failed: %v", err)
		return err
	}
	log.Infof("CACHE: SQLite cache shut down")
	return nil
}

// ── Stats ──────────────────────────────────────────────────────────────────

// IncrementStats atomically increments the stats counters for a single DNS
// request. All counters are updated in a single UPDATE for efficiency.
func (s *SQLiteCache) IncrementStats(durationMs int64, cacheHit, hadError bool, protocol string,
	rewrote, hijackDetected, staleServed, fallbackUsed, prefetchTriggered bool,
	dnssecStatus string, rcode int) {

	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}

	a := &s.stats
	a.totalRequests.Add(1)
	a.totalResponseTimeMs.Add(durationMs)
	for {
		old := a.lastResponseTimeMs.Load()
		if durationMs <= old || a.lastResponseTimeMs.CompareAndSwap(old, durationMs) {
			break
		}
	}

	if cacheHit {
		a.cacheHits.Add(1)
	} else {
		a.cacheMisses.Add(1)
	}
	if hadError {
		a.errorResponses.Add(1)
	}
	if staleServed {
		a.staleResponses.Add(1)
	}
	if fallbackUsed {
		a.fallbackRequests.Add(1)
	}
	if prefetchTriggered {
		a.prefetchRequests.Add(1)
	}
	if rewrote {
		a.rewriteRequests.Add(1)
	}
	if hijackDetected {
		a.hijackDetections.Add(1)
	}

	switch dnssecStatus {
	case config.DNSSECStatusSecure:
		a.dnssecSecure.Add(1)
	case config.DNSSECStatusBogus:
		a.dnssecBogus.Add(1)
	case config.DNSSECStatusInsecure:
		a.dnssecInsecure.Add(1)
	}

	switch rcode {
	case dns.RcodeSuccess:
		a.rcodeNOERROR.Add(1)
	case dns.RcodeFormatError:
		a.rcodeFORMERR.Add(1)
	case dns.RcodeServerFailure:
		a.rcodeSERVFAIL.Add(1)
	case dns.RcodeNameError:
		a.rcodeNXDOMAIN.Add(1)
	case dns.RcodeNotImplemented:
		a.rcodeNotImp.Add(1)
	case dns.RcodeRefused:
		a.rcodeREFUSED.Add(1)
	default:
		a.rcodeOther.Add(1)
	}

	pb := protoBits(protocol)
	if pb.udp != 0 {
		a.udpRequests.Add(1)
	}
	if pb.tcp != 0 {
		a.tcpRequests.Add(1)
	}
	if pb.dot != 0 {
		a.dotRequests.Add(1)
	}
	if pb.doq != 0 {
		a.doqRequests.Add(1)
	}
	if pb.doh != 0 {
		a.dohRequests.Add(1)
	}
	if pb.doh3 != 0 {
		a.doh3Requests.Add(1)
	}
}

type protoBitsStruct struct {
	udp, tcp, dot, doq, doh, doh3 int
}

func protoBits(protocol string) protoBitsStruct {
	var p protoBitsStruct
	switch {
	case len(protocol) >= 3 && (protocol[0] == 'u' || protocol[0] == 'U'):
		p.udp = 1
	case len(protocol) >= 3 && (protocol[0] == 't' || protocol[0] == 'T'):
		p.tcp = 1
	case len(protocol) >= 3 && (protocol[1] == 'o' || protocol[1] == 'O'):
		switch protocol[2] {
		case 't', 'T':
			p.dot = 1
		case 'q', 'Q':
			p.doq = 1
		case 'h', 'H':
			if len(protocol) >= 4 && (protocol[3] == '3') {
				p.doh3 = 1
			} else {
				p.doh = 1
			}
		}
	}
	return p
}

// ── Stats persistence ────────────────────────────────────────────────────────

// SaveStats writes a StatsRow to the stats table.

// flushStats writes the in-memory stats accumulator to the SQLite stats table
// in a single atomic operation.
func (s *SQLiteCache) flushStats() {
	row := s.stats.toRow()
	if _, err := s.db.Exec(
		`INSERT OR REPLACE INTO stats (id,
			total_requests, cache_hits, cache_misses, prefetch_requests,
			error_responses, stale_responses, fallback_requests,
			total_response_time_ms, last_response_time_ms,
			udp_requests, tcp_requests, dot_requests, doq_requests, doh_requests, doh3_requests,
			rewrite_requests, hijack_detections,
			dnssec_secure, dnssec_bogus, dnssec_insecure,
			rcode_noerror, rcode_formerr, rcode_servfail, rcode_nxdomain,
			rcode_notimp, rcode_refused, rcode_other, updated_at
		) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		1,
		row.TotalRequests, row.CacheHits, row.CacheMisses, row.PrefetchRequests,
		row.ErrorResponses, row.StaleResponses, row.FallbackRequests,
		row.TotalResponseTimeMs, row.LastResponseTimeMs,
		row.UDPRequests, row.TCPRequests, row.DOTRequests, row.DOQRequests, row.DOHRequests, row.DOH3Requests,
		row.RewriteRequests, row.HijackDetections,
		row.DNSSECSecure, row.DNSSECBogus, row.DNSSECInsecure,
		row.RCODENOERROR, row.RCODEFORMERR, row.RCODESERVFAIL, row.RCODENXDOMAIN,
		row.RCODENotImp, row.RCODEREFUSED, row.RCODEOther, row.UpdatedAt,
	); err != nil {
		log.Warnf("CACHE: flush stats failed: %v", err)
	}
}

func (a *statsAccumulator) toRow() config.StatsRow {
	return config.StatsRow{
		TotalRequests:       a.totalRequests.Load(),
		CacheHits:           a.cacheHits.Load(),
		CacheMisses:         a.cacheMisses.Load(),
		PrefetchRequests:    a.prefetchRequests.Load(),
		ErrorResponses:      a.errorResponses.Load(),
		StaleResponses:      a.staleResponses.Load(),
		FallbackRequests:    a.fallbackRequests.Load(),
		TotalResponseTimeMs: a.totalResponseTimeMs.Load(),
		LastResponseTimeMs:  a.lastResponseTimeMs.Load(),
		UDPRequests:         a.udpRequests.Load(),
		TCPRequests:         a.tcpRequests.Load(),
		DOTRequests:         a.dotRequests.Load(),
		DOQRequests:         a.doqRequests.Load(),
		DOHRequests:         a.dohRequests.Load(),
		DOH3Requests:        a.doh3Requests.Load(),
		RewriteRequests:     a.rewriteRequests.Load(),
		HijackDetections:    a.hijackDetections.Load(),
		DNSSECSecure:        a.dnssecSecure.Load(),
		DNSSECBogus:         a.dnssecBogus.Load(),
		DNSSECInsecure:      a.dnssecInsecure.Load(),
		RCODENOERROR:        a.rcodeNOERROR.Load(),
		RCODEFORMERR:        a.rcodeFORMERR.Load(),
		RCODESERVFAIL:       a.rcodeSERVFAIL.Load(),
		RCODENXDOMAIN:       a.rcodeNXDOMAIN.Load(),
		RCODENotImp:         a.rcodeNotImp.Load(),
		RCODEREFUSED:        a.rcodeREFUSED.Load(),
		RCODEOther:          a.rcodeOther.Load(),
		UpdatedAt:           log.NowUnix(),
	}
}

func (s *SQLiteCache) SaveStats(row config.StatsRow) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO stats (id,
			total_requests, cache_hits, cache_misses, prefetch_requests,
			error_responses, stale_responses, fallback_requests,
			total_response_time_ms, last_response_time_ms,
			udp_requests, tcp_requests, dot_requests, doq_requests, doh_requests, doh3_requests,
			rewrite_requests, hijack_detections,
			dnssec_secure, dnssec_bogus, dnssec_insecure,
			rcode_noerror, rcode_formerr, rcode_servfail, rcode_nxdomain,
			rcode_notimp, rcode_refused, rcode_other, updated_at
		) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		1,
		row.TotalRequests, row.CacheHits, row.CacheMisses, row.PrefetchRequests,
		row.ErrorResponses, row.StaleResponses, row.FallbackRequests,
		row.TotalResponseTimeMs, row.LastResponseTimeMs,
		row.UDPRequests, row.TCPRequests, row.DOTRequests, row.DOQRequests, row.DOHRequests, row.DOH3Requests,
		row.RewriteRequests, row.HijackDetections,
		row.DNSSECSecure, row.DNSSECBogus, row.DNSSECInsecure,
		row.RCODENOERROR, row.RCODEFORMERR, row.RCODESERVFAIL, row.RCODENXDOMAIN,
		row.RCODENotImp, row.RCODEREFUSED, row.RCODEOther, row.UpdatedAt,
	)
	if err != nil {
		log.Warnf("CACHE: save stats failed: %v", err)
	}
}

// LoadStats retrieves the persisted stats row. Returns zero value and false
// if no row exists.
func (s *SQLiteCache) LoadStats() (config.StatsRow, bool) {
	s.flushStats()
	var row config.StatsRow
	err := s.db.QueryRow(
		`SELECT total_requests, cache_hits, cache_misses, prefetch_requests,
			error_responses, stale_responses, fallback_requests,
			total_response_time_ms, last_response_time_ms,
			udp_requests, tcp_requests, dot_requests, doq_requests, doh_requests, doh3_requests,
			rewrite_requests, hijack_detections,
			dnssec_secure, dnssec_bogus, dnssec_insecure,
			rcode_noerror, rcode_formerr, rcode_servfail, rcode_nxdomain,
			rcode_notimp, rcode_refused, rcode_other, updated_at
		FROM stats`,
	).Scan(
		&row.TotalRequests, &row.CacheHits, &row.CacheMisses, &row.PrefetchRequests,
		&row.ErrorResponses, &row.StaleResponses, &row.FallbackRequests,
		&row.TotalResponseTimeMs, &row.LastResponseTimeMs,
		&row.UDPRequests, &row.TCPRequests, &row.DOTRequests, &row.DOQRequests, &row.DOHRequests, &row.DOH3Requests,
		&row.RewriteRequests, &row.HijackDetections,
		&row.DNSSECSecure, &row.DNSSECBogus, &row.DNSSECInsecure,
		&row.RCODENOERROR, &row.RCODEFORMERR, &row.RCODESERVFAIL, &row.RCODENXDOMAIN,
		&row.RCODENotImp, &row.RCODEREFUSED, &row.RCODEOther, &row.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return row, false
	}
	if err != nil {
		log.Warnf("CACHE: load stats failed: %v", err)
		return row, false
	}
	return row, true
}

// ── Eviction ─────────────────────────────────────────────────────────────────

func (s *SQLiteCache) evictIfNeeded() {
	if s.maxEntries <= 0 {
		return
	}

	count := s.entryCount.Load()
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

	_ = rows.Close()

	if _, err := tx.Exec(
		`DELETE FROM entries WHERE id IN (SELECT id FROM entries ORDER BY timestamp ASC LIMIT ?)`, n,
	); err != nil {
		return
	}
	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed: %v", err)
	}

	s.entryCount.Add(-n)
	log.Debugf("CACHE: evicted %d oldest entries (max=%d)", n, s.maxEntries)
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
			s.flushStats()
		}
	}()
}

func (s *SQLiteCache) deleteExpiredEntries() {
	cutoff := log.NowUnix() - s.staleMaxAge
	res, err := s.db.Exec(`DELETE FROM entries WHERE expires_at < ?`, cutoff)
	if err != nil {
		log.Warnf("CACHE: expired entry cleanup failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		s.entryCount.Add(-n)
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
