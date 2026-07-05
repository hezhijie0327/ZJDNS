package cache

import (
	"database/sql"
	"fmt"
	"slices"
	"sync/atomic"

	"codeberg.org/miekg/dns"
	"github.com/klauspost/compress/zstd"
	_ "github.com/ncruces/go-sqlite3/driver"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
)

const (
	defaultStaleMaxAge = int64(config.DefaultStaleMaxAge)
	zstdCompressLevel  = zstd.SpeedDefault
)

// zstd encoder/decoder for wire format compression. Created once, reused forever.
var (
	zstdEncoder *zstd.Encoder
	zstdDecoder *zstd.Decoder
)

func init() {
	var err error
	zstdEncoder, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstdCompressLevel))
	if err != nil {
		panic(fmt.Sprintf("zstd encoder init: %v", err))
	}
	zstdDecoder, err = zstd.NewReader(nil)
	if err != nil {
		panic(fmt.Sprintf("zstd decoder init: %v", err))
	}
}

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
	// WAL autocheckpoint tuning + page size.
	pragmaSQL := fmt.Sprintf(
		"PRAGMA mmap_size = %d; PRAGMA cache_size = %d; PRAGMA page_size = 4096; PRAGMA temp_store = MEMORY; PRAGMA wal_autocheckpoint = 500; PRAGMA optimize;",
		s.mmapSizeMB*1024*1024, -s.cacheSizeMB*1024,
	)
	if _, err := s.db.Exec(pragmaSQL); err != nil {
		log.Warnf("CACHE: pragma failed (non-fatal): %v", err)
	}

	_, err := s.db.Exec(`
		-- Single table: entries + metadata merged, wire format for RR storage.
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
			-- Resolution metadata (written once by Set)
			rcode            INTEGER NOT NULL DEFAULT 0,
			response_time_ms INTEGER NOT NULL DEFAULT 0,
			server           TEXT NOT NULL DEFAULT '',
			dnssec           TEXT NOT NULL DEFAULT '',
			fallback         INTEGER NOT NULL DEFAULT 0,
			prefetch         INTEGER NOT NULL DEFAULT 0,
			hijack           INTEGER NOT NULL DEFAULT 0,
			-- Serving counters (updated by RecordServe / RecordRewrite)
			last_hit_time INTEGER NOT NULL DEFAULT 0,
			hit_udp       INTEGER NOT NULL DEFAULT 0,
			hit_tcp       INTEGER NOT NULL DEFAULT 0,
			hit_dot       INTEGER NOT NULL DEFAULT 0,
			hit_doq       INTEGER NOT NULL DEFAULT 0,
			hit_doh       INTEGER NOT NULL DEFAULT 0,
			hit_doh3      INTEGER NOT NULL DEFAULT 0,
			stale_count   INTEGER NOT NULL DEFAULT 0,
			rewrite_count INTEGER NOT NULL DEFAULT 0,
			-- zstd-compressed wire format (Answer+Authority+Additional)
			msg_wire BLOB,
			-- PK + constraint
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		-- Lightweight PTR reverse-lookup table (IP → domain name).
		CREATE TABLE IF NOT EXISTS ptr_map (
			rdata_ip TEXT NOT NULL,
			entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			name     TEXT NOT NULL,
			ttl      INTEGER NOT NULL,
			PRIMARY KEY (rdata_ip, entry_id, name)
		) WITHOUT ROWID;

		-- Per-record latency measurements from probe engine (analytics + sorting).
		CREATE TABLE IF NOT EXISTS record_latency (
			entry_id   INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			rdata_ip   TEXT NOT NULL,
			latency_ms INTEGER NOT NULL,
			PRIMARY KEY (entry_id, rdata_ip)
		) WITHOUT ROWID;

		-- Eviction index: only covers cacheable entries (partial index).
		CREATE INDEX IF NOT EXISTS idx_entries_expires ON entries(expires_at) WHERE cacheable = 1;
		CREATE INDEX IF NOT EXISTS idx_ptr_ip ON ptr_map(rdata_ip);
	`)
	return err
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
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

	if len(msgWire) == 0 {
		return nil, false, false
	}

	// Decompress and unpack the wire format into a dns.Msg.
	wire, err := decompress(msgWire)
	if err != nil {
		log.Warnf("CACHE: decompress wire for entry %d: %v", id, err)
		return nil, false, false
	}

	msg := new(dns.Msg)
	msg.Data = wire
	if err := msg.Unpack(); err != nil {
		log.Warnf("CACHE: unpack wire for entry %d: %v", id, err)
		return nil, false, false
	}

	entry := &Entry{
		Answer:     msg.Answer,
		Authority:  msg.Ns,
		Additional: msg.Extra,
		Timestamp:  ts,
		TTL:        entryTTL,
		Validated:  validated != 0,
	}

	// Sort A/AAAA answer records by latency from record_latency so the
	// fastest IP is returned first (replaces the old records ORDER BY).
	s.sortAnswerByLatency(id, entry)

	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records (CNAME, etc.) at the
// front in their original wire-format order. Idempotent when ≤1 A/AAAA.
func (s *SQLiteCache) sortAnswerByLatency(entryID int64, entry *Entry) {
	if len(entry.Answer) <= 1 {
		return
	}

	// Fast check: count A/AAAA records.
	aCount := 0
	for _, rr := range entry.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			aCount++
		}
	}
	if aCount <= 1 {
		return
	}

	// Fetch latency data for this entry.
	rows, err := s.db.Query(
		`SELECT rdata_ip, latency_ms FROM record_latency WHERE entry_id = ?`, entryID,
	)
	if err != nil {
		return
	}
	defer func() { _ = rows.Close() }()

	latencies := make(map[string]int)
	for rows.Next() {
		var ip string
		var lat int
		if err := rows.Scan(&ip, &lat); err == nil {
			latencies[ip] = lat
		}
	}
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
		aIP, _ := dnsutil.ExtractIPString(a)
		bIP, _ := dnsutil.ExtractIPString(b)
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

// Set stores a DNS response in the cache. Wire format is zstd-compressed.
func (s *SQLiteCache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool, opts SetOptions,
) {
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

	// Pack wire format and compress.
	msg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
	var msgWire []byte
	if err := msg.Pack(); err == nil {
		msgWire = compress(msg.Data)
	}

	tx, err := s.db.Begin()
	if err != nil {
		log.Warnf("CACHE: begin tx failed: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	var entryID int64
	if err := tx.QueryRow(
		`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, cacheable,
			rcode, response_time_ms, server, dnssec, fallback, prefetch, hijack,
			msg_wire)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 RETURNING id`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
		now, entryTTL, now+int64(entryTTL), boolToInt(validated), boolToInt(!opts.Uncacheable),
		opts.Rcode, opts.ResponseTime, opts.Server, opts.Dnssec,
		boolToInt(opts.Fallback), boolToInt(opts.Prefetch), boolToInt(opts.Hijack),
		msgWire,
	).Scan(&entryID); err != nil {
		log.Warnf("CACHE: insert entry failed: %v", err)
		return
	}

	// Populate ptr_map for reverse (PTR) lookups on cacheable entries.
	if !opts.Uncacheable {
		insertPtrMap(tx, entryID, answer)
		insertPtrMap(tx, entryID, authority)
		insertPtrMap(tx, entryID, additional)
	}

	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}

	s.entryCount.Add(1)
	s.evictIfNeeded()
}

// RecordServe updates hit counters and last_hit_time directly in the entries table.
func (s *SQLiteCache) RecordServe(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, protocol string, stale bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}

	qname = dnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)

	col := hitColumn(protocol)
	if col == "" {
		return
	}

	staleSQL := ""
	if stale {
		staleSQL = ", stale_count = stale_count + 1"
	}

	_, _ = s.db.Exec(
		`UPDATE entries SET `+col+` = `+col+` + 1, last_hit_time = ?`+staleSQL+
			` WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
		log.NowUnix(), qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, boolToInt(dnssecOK),
	)
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil
	}

	rows, err := s.db.Query(
		`SELECT DISTINCT pm.name, pm.ttl, e.timestamp FROM ptr_map pm
		 JOIN entries e ON pm.entry_id = e.id
		 WHERE pm.rdata_ip = ? AND e.expires_at + ? >= ?
		 ORDER BY pm.name`,
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

// RecordRewrite increments the rewrite counter. Since rewrite responses bypass
// the cache, this creates a lightweight entry if one doesn't already exist.
func (s *SQLiteCache) RecordRewrite(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	qname = dnsutil.NormalizeDomain(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)
	now := log.NowUnix()
	dnssecInt := boolToInt(dnssecOK)
	// INSERT OR IGNORE: stub entry must not overwrite an existing real entry
	// (which would reset hit counters and resolution metadata to zero).
	_, _ = s.db.Exec(
		`INSERT OR IGNORE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, cacheable, server)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
		now, config.DefaultStaleTTL, now+int64(config.DefaultStaleTTL), 0, 1, "rewrite",
	)
	_, _ = s.db.Exec(
		`UPDATE entries SET rewrite_count = rewrite_count + 1
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
	)
}

// Summary returns a one-line stats summary from the entries table.
func (s *SQLiteCache) Summary() string {
	if atomic.LoadInt32(&s.closed) != 0 {
		return ""
	}
	var entries, hits, udp, tcp, dot, doq, doh, doh3 int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var hijack, fallback, prefetch, stale, rewrite int64
	var avgMs float64

	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE cacheable = 1").Scan(&entries)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hit_udp+hit_tcp+hit_dot+hit_doq+hit_doh+hit_doh3),0) FROM entries").Scan(&hits)
	_ = s.db.QueryRow("SELECT COALESCE(AVG(response_time_ms),0) FROM entries WHERE response_time_ms > 0").Scan(&avgMs)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hit_udp),0), COALESCE(SUM(hit_tcp),0), COALESCE(SUM(hit_dot),0), COALESCE(SUM(hit_doq),0), COALESCE(SUM(hit_doh),0), COALESCE(SUM(hit_doh3),0) FROM entries").Scan(&udp, &tcp, &dot, &doq, &doh, &doh3)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode = 0").Scan(&noerr)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode = 1").Scan(&formerr)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode = 2").Scan(&servfail)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode = 3").Scan(&nxdomain)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode = 4").Scan(&notimp)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode = 5").Scan(&refused)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE rcode NOT IN (0,1,2,3,4,5)").Scan(&other)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE hijack = 1").Scan(&hijack)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE fallback = 1").Scan(&fallback)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE prefetch = 1").Scan(&prefetch)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(stale_count),0) FROM entries").Scan(&stale)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(rewrite_count),0) FROM entries").Scan(&rewrite)

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
		return fmt.Errorf("sqlite close: %w", err)
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

// UpdateLatency stores a latency measurement for a specific record, keyed by
// entry lookup key + IP address.
func (s *SQLiteCache) UpdateLatency(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, ip string, latencyMS int) {
	qname = dnsutil.NormalizeDomain(qname)

	// Latency is a property of the IP, not of the ECS subnet. Update all
	// entries matching (qname, qtype, qclass, dnssec_ok) regardless of ECS
	// so sortAnswerByLatency can find the data for whichever ECS variant
	// is served from Get().
	//
	// Collect entry IDs first, then INSERT outside the rows loop: in-memory
	// SQLite databases are per-connection, and db.Exec may use a different
	// connection than the one holding rows open.
	rows, err := s.db.Query(
		`SELECT id FROM entries WHERE qname=? AND qtype=? AND qclass=? AND dnssec_ok=?`,
		qname, int(qtype), int(qclass), boolToInt(dnssecOK),
	)
	if err != nil {
		return
	}

	var entryIDs []int64
	for rows.Next() {
		var entryID int64
		if err := rows.Scan(&entryID); err == nil {
			entryIDs = append(entryIDs, entryID)
		}
	}
	_ = rows.Close()

	for _, entryID := range entryIDs {
		_, _ = s.db.Exec(
			`INSERT OR REPLACE INTO record_latency (entry_id, rdata_ip, latency_ms) VALUES (?, ?, ?)`,
			entryID, ip, latencyMS,
		)
	}
}

// ── Wire format compression ──────────────────────────────────────────────────

func compress(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	return zstdEncoder.EncodeAll(data, nil)
}

func decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return zstdDecoder.DecodeAll(data, nil)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func insertPtrMap(tx *sql.Tx, entryID int64, rrs []dns.RR) {
	type rec struct {
		name    string
		ttl     int
		rdataIP string
	}
	var recs []rec
	for _, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		ip, ok := dnsutil.ExtractIPString(rr)
		if !ok {
			continue
		}
		recs = append(recs, rec{
			name: rr.Header().Name, ttl: int(rr.Header().TTL), rdataIP: ip,
		})
	}
	if len(recs) == 0 {
		return
	}

	// Deduplicate by (rdata_ip, name) — same IP can appear in the same section.
	seen := make(map[string]bool, len(recs))
	var unique []rec
	for _, r := range recs {
		key := r.rdataIP + "\x00" + r.name
		if !seen[key] {
			seen[key] = true
			unique = append(unique, r)
		}
	}

	placeholders := make([]string, len(unique))
	args := make([]any, 0, len(unique)*4)
	for i, r := range unique {
		placeholders[i] = "(?, ?, ?, ?)"
		args = append(args, r.rdataIP, entryID, r.name, r.ttl)
	}
	stmt := `INSERT OR REPLACE INTO ptr_map (rdata_ip, entry_id, name, ttl) VALUES ` +
		joinPlaceholders(placeholders, ",")
	if _, err := tx.Exec(stmt, args...); err != nil {
		log.Warnf("CACHE: insert ptr_map failed: %v", err)
	}
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

func joinPlaceholders(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	total := 0
	for _, p := range parts {
		total += len(p) + len(sep)
	}
	b := make([]byte, 0, total-len(sep))
	b = append(b, parts[0]...)
	for _, p := range parts[1:] {
		b = append(b, sep...)
		b = append(b, p...)
	}
	return string(b)
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
