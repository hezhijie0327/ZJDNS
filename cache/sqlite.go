package cache

import (
	"database/sql"
	"fmt"
	"slices"
	"sync"
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

	// writeMu serializes Set() and RecordRewrite() calls to prevent SQLite
	// write-lock contention under concurrent cache-miss resolution.
	// WAL mode allows only one writer at a time; without this mutex,
	// multiple BEGIN IMMEDIATE transactions queue up in the busy handler
	// and can exceed busy_timeout, producing SQLITE_IOERR.
	writeMu sync.Mutex
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

	params := "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&_foreign_keys=ON&_txlock=immediate"
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
		"PRAGMA mmap_size = %d; PRAGMA cache_size = %d; PRAGMA page_size = 4096; PRAGMA temp_store = MEMORY; PRAGMA wal_autocheckpoint = 5000; PRAGMA optimize;",
		s.mmapSizeMB*1024*1024, -s.cacheSizeMB*1024,
	)
	if _, err := s.db.Exec(pragmaSQL); err != nil {
		log.Warnf("CACHE: pragma failed (non-fatal): %v", err)
	}

	_, err := s.db.Exec(`
		-- Core cache entries: read-heavy, large msg_wire BLOBs. Lookup-key
		-- columns and resolution metadata live here; hot counters are split
		-- into hit_counters to avoid write amplification on cache hits.
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
			-- zstd-compressed wire format (Answer+Authority+Additional)
			msg_wire BLOB,
			-- PK + constraint
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		-- Hot serving counters: updated on every cache hit. Split from entries
		-- to avoid rewriting pages that contain large msg_wire BLOBs.
		-- WITHOUT ROWID: the entry_id IS the row; no separate B-tree lookup.
		CREATE TABLE IF NOT EXISTS hit_counters (
			entry_id      INTEGER PRIMARY KEY REFERENCES entries(id) ON DELETE CASCADE,
			last_hit_time INTEGER NOT NULL DEFAULT 0,
			hit_udp       INTEGER NOT NULL DEFAULT 0,
			hit_tcp       INTEGER NOT NULL DEFAULT 0,
			hit_dot       INTEGER NOT NULL DEFAULT 0,
			hit_doq       INTEGER NOT NULL DEFAULT 0,
			hit_doh       INTEGER NOT NULL DEFAULT 0,
			hit_doh3      INTEGER NOT NULL DEFAULT 0,
			stale_count   INTEGER NOT NULL DEFAULT 0,
			rewrite_count INTEGER NOT NULL DEFAULT 0
		) WITHOUT ROWID;

		-- ECS-agnostic per-IP latency measurements. Keyed by (qname, qtype,
		-- qclass, rdata_ip) — latency is a property of the IP, not the ECS
		-- subnet or DNSSEC state. Survives cache refreshes (not tied to entry_id).
		CREATE TABLE IF NOT EXISTS ip_latency (
			qname      TEXT NOT NULL,
			qtype      INTEGER NOT NULL,
			qclass     INTEGER NOT NULL DEFAULT 1,
			rdata_ip   TEXT NOT NULL,
			latency_ms INTEGER NOT NULL,
			PRIMARY KEY (qname, qtype, qclass, rdata_ip)
		) WITHOUT ROWID;

		-- Lightweight PTR reverse-lookup table (IP → domain name).
		CREATE TABLE IF NOT EXISTS ptr_map (
			rdata_ip TEXT NOT NULL,
			entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			name     TEXT NOT NULL,
			ttl      INTEGER NOT NULL,
			PRIMARY KEY (rdata_ip, entry_id, name)
		) WITHOUT ROWID;

		-- Eviction index: only covers cacheable entries (partial index).
		CREATE INDEX IF NOT EXISTS idx_entries_expires ON entries(expires_at) WHERE cacheable = 1;
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

	// Sort A/AAAA answer records by latency from ip_latency so the
	// fastest IP is returned first. Latency is ECS-agnostic — we query
	// by (qname, qtype, qclass) without ecs/dnssec filters.
	s.sortAnswerByLatency(qname, qtype, qclass, entry)

	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records (CNAME, etc.) at the
// front in their original wire-format order. Latency data is looked up by
// (qname, qtype, qclass) — ECS-agnostic and dnssec-agnostic. Idempotent
// when ≤1 A/AAAA.
func (s *SQLiteCache) sortAnswerByLatency(qname string, qtype, qclass uint16, entry *Entry) {
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

	// Fetch latency data — ECS-agnostic, shared across all ECS/dnssec variants.
	rows, err := s.db.Query(
		`SELECT rdata_ip, latency_ms FROM ip_latency WHERE qname = ? AND qtype = ? AND qclass = ?`,
		qname, int(qtype), int(qclass),
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
// The transaction itself is serialized via writeMu to prevent SQLite
// write-lock contention (WAL mode permits only one writer at a time);
// prep work (TTL calculation, wire packing, zstd compression) runs outside
// the lock so CPU-heavy steps can overlap across goroutines.
func (s *SQLiteCache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool, opts SetOptions,
) {
	if atomic.LoadInt32(&s.closed) != 0 {
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
	qname = dnsutil.NormalizeDomain(qname)
	dnssecInt := boolToInt(dnssecOK)

	// Pack wire format and compress.
	msg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
	var msgWire []byte
	if err := msg.Pack(); err == nil {
		msgWire = compress(msg.Data)
	}

	// ── Transaction (serialized via writeMu) ──────────────────────────────
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

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

	// Create hit_counters row for the new entry. INSERT OR REPLACE does
	// DELETE + INSERT internally, so the old counters row (if any) was
	// CASCADE-deleted and we always need a fresh row.
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO hit_counters (entry_id) VALUES (?)`, entryID,
	); err != nil {
		log.Warnf("CACHE: insert hit_counters failed: %v", err)
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

// RecordServe updates hit counters and last_hit_time in the hit_counters
// table, avoiding write amplification on the entries table which contains
// large msg_wire BLOBs.
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
		`UPDATE hit_counters SET `+col+` = `+col+` + 1, last_hit_time = ?`+staleSQL+
			` WHERE entry_id = (SELECT id FROM entries
			   WHERE qname = ? AND qtype = ? AND qclass = ?
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
// Serialized via writeMu to avoid contention with concurrent Set() calls.
func (s *SQLiteCache) RecordRewrite(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
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
	// Ensure a hit_counters row exists for the stub entry, then increment
	// rewrite_count in the counters table.
	_, _ = s.db.Exec(
		`INSERT OR IGNORE INTO hit_counters (entry_id)
		 SELECT id FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
	)
	_, _ = s.db.Exec(
		`UPDATE hit_counters SET rewrite_count = rewrite_count + 1
		 WHERE entry_id = (SELECT id FROM entries
		   WHERE qname = ? AND qtype = ? AND qclass = ?
		   AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?)`,
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
	)
}

// Summary returns a one-line stats summary from the entries and hit_counters tables.
func (s *SQLiteCache) Summary() string {
	if atomic.LoadInt32(&s.closed) != 0 {
		return ""
	}
	var entries, hits, udp, tcp, dot, doq, doh, doh3 int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var hijack, fallback, prefetch, stale, rewrite int64
	var avgMs float64

	_ = s.db.QueryRow("SELECT COUNT(*) FROM entries WHERE cacheable = 1").Scan(&entries)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hc.hit_udp+hc.hit_tcp+hc.hit_dot+hc.hit_doq+hc.hit_doh+hc.hit_doh3),0) FROM hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.cacheable = 1").Scan(&hits)
	_ = s.db.QueryRow("SELECT COALESCE(AVG(response_time_ms),0) FROM entries WHERE response_time_ms > 0").Scan(&avgMs)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hc.hit_udp),0), COALESCE(SUM(hc.hit_tcp),0), COALESCE(SUM(hc.hit_dot),0), COALESCE(SUM(hc.hit_doq),0), COALESCE(SUM(hc.hit_doh),0), COALESCE(SUM(hc.hit_doh3),0) FROM hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.cacheable = 1").Scan(&udp, &tcp, &dot, &doq, &doh, &doh3)
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
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hc.stale_count),0) FROM hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.cacheable = 1").Scan(&stale)
	_ = s.db.QueryRow("SELECT COALESCE(SUM(hc.rewrite_count),0) FROM hit_counters hc JOIN entries e ON hc.entry_id = e.id WHERE e.cacheable = 1").Scan(&rewrite)

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

	// Re-sync the entry count from the database to correct any drift from
	// INSERT OR REPLACE (which increments entryCount even on replacements).
	// COUNT(*) on the PK is a fast B-tree leaf walk; only runs when the
	// atomic counter suggests we may be near or over the limit.
	var count int64
	if err := s.db.QueryRow("SELECT COUNT(*) FROM entries").Scan(&count); err == nil {
		s.entryCount.Store(count)
	}

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

// UpdateLatency stores a latency measurement in the ECS-agnostic ip_latency
// table. Latency is a property of the IP, not the ECS subnet or DNSSEC state,
// so we key by (qname, qtype, qclass, rdata_ip) only. A single INSERT OR
// REPLACE replaces the old per-entry_id iteration over all ECS variants.
func (s *SQLiteCache) UpdateLatency(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool, ip string, latencyMS int) {
	qname = dnsutil.NormalizeDomain(qname)
	_, _ = s.db.Exec(
		`INSERT OR REPLACE INTO ip_latency (qname, qtype, qclass, rdata_ip, latency_ms)
		 VALUES (?, ?, ?, ?, ?)`,
		qname, int(qtype), int(qclass), ip, latencyMS,
	)
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
