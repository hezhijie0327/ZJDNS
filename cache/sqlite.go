package cache

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"codeberg.org/miekg/dns"
	"github.com/klauspost/compress/zstd"
	_ "github.com/ncruces/go-sqlite3/driver"

	"zjdns/config"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"
)

const (
	defaultStaleMaxAge = int64(config.DefaultStaleMaxAge)
	zstdCompressLevel  = zstd.SpeedDefault
	schemaVersion      = 5 // increment to drop and recreate all tables on schema change
	dsnParams          = "_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=10000&_foreign_keys=ON&_txlock=immediate"
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
	dbPath      string // database file path; empty = in-memory
	maxEntries  int
	mmapSizeMB  int
	cacheSizeMB int
	closed      int32
	entryCount  atomic.Int64

	// writeMu serializes Set() calls to prevent SQLite write-lock contention
	// under concurrent cache-miss resolution. WAL mode allows only one writer
	// at a time; without this mutex, multiple BEGIN IMMEDIATE transactions
	// queue up in the busy handler and can exceed busy_timeout, producing
	// SQLITE_IOERR. RecordRequest is append-only (no conflict) and does not
	// need this mutex.
	writeMu sync.Mutex

	// Hot-path prepared statements — compiled once, reused forever.
	stmtGetEntry      *sql.Stmt
	stmtInsertLog     *sql.Stmt
	stmtHitCounter    *sql.Stmt
	stmtInsertLatency *sql.Stmt
	stmtGetLastProbe  *sql.Stmt
}

// NewSQLiteCache opens or creates a SQLite database and returns a ready-to-use
// cache. path is the database file path; an empty string uses an in-memory
// database. mmapSizeMB and cacheSizeMB are SQLite PRAGMA tunables; zero means
// use defaults. maxRequestLog is the ring-buffer size for request_log.
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

	var dsn string
	if path == "" {
		dsn = "file::memory:?" + dsnParams
	} else {
		dsn = "file:" + path + "?" + dsnParams
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
		dbPath:      path,
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

	if err := s.prepareStatements(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite prepare: %w", err)
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

	// Schema versioning: bump schemaVersion to drop and recreate all tables.
	// The migration unconditionally drops old tables when versions differ,
	// then recreates from scratch — no in-place migration logic needed.
	var version int
	_ = s.db.QueryRow("SELECT version FROM schema_version").Scan(&version)
	if version != schemaVersion {
		log.Infof("CACHE: schema v%d → v%d, rebuilding all tables", version, schemaVersion)
		if s.dbPath != "" {
			// Disk-backed: close, delete the file, reopen. O(1).
			_ = s.db.Close()
			_ = os.Remove(s.dbPath)
			db, err := sql.Open("sqlite3", "file:"+s.dbPath+"?"+dsnParams)
			if err != nil {
				return fmt.Errorf("sqlite reopen: %w", err)
			}
			db.SetMaxOpenConns(config.DefaultCacheMaxOpenConns)
			db.SetMaxIdleConns(config.DefaultCacheMaxIdleConns)
			s.db = db
			// Reapply pragmas on the fresh database.
			if _, err := s.db.Exec(pragmaSQL); err != nil {
				log.Warnf("CACHE: pragma failed on reopen (non-fatal): %v", err)
			}
		}
		// In-memory: nothing to drop — the DB is fresh on every process start.
	}

	_, err := s.db.Exec(`
		-- ── Schema versioning ───────────────────────────────────────────────
		-- Single-row table that tracks the current schema version. When the
		-- version changes, old tables are dropped and recreated cleanly.

		CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
		INSERT OR REPLACE INTO schema_version (rowid, version) VALUES (1, ` + fmt.Sprint(schemaVersion) + `);

		-- ── Core DNS response cache ─────────────────────────────────────────
		-- Every row is a cacheable DNS response. The unique lookup key is
		-- (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok). Wire
		-- format is zstd-compressed and stored in msg_wire; Get() decompresses
		-- and unpacks in a single step.

		CREATE TABLE IF NOT EXISTS entries (
			-- Lookup key (UNIQUE constraint below)
			qname      TEXT NOT NULL,       -- normalized FQDN (dnsutil.NormalizeDomain)
			qtype      INTEGER NOT NULL,    -- dns.TypeA=1, AAAA=28, DNSKEY=48, ...
			qclass     INTEGER NOT NULL DEFAULT 1,
			ecs_addr   TEXT NOT NULL DEFAULT '',
			ecs_prefix INTEGER NOT NULL DEFAULT 0,
			dnssec_ok  INTEGER NOT NULL DEFAULT 0 CHECK (dnssec_ok IN (0, 1)),
			-- Lifecycle
			timestamp  INTEGER NOT NULL,    -- insertion time (unix seconds)
			ttl        INTEGER NOT NULL,    -- entry TTL (min of all RR TTLs, floor 10s)
			expires_at INTEGER NOT NULL DEFAULT 0,
			-- Flags
			validated  INTEGER NOT NULL DEFAULT 0 CHECK (validated IN (0, 1)),
			-- zstd-compressed wire format (Answer + Authority + Additional)
			msg_wire   BLOB,
			-- PK + constraint
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			UNIQUE(qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok)
		);

		-- Eviction index: sorted by expires_at for efficient range scans when
		-- selecting candidates to evict (oldest expire-first, then by
		-- insertion timestamp).

		CREATE INDEX IF NOT EXISTS idx_entries_expires ON entries(expires_at);

		-- ── PTR reverse lookup (depends on entries) ────────────────────────
		-- Lightweight IP→domain mapping. WITHOUT ROWID uses the clustered PK
		-- directly — no separate index B-tree. ON DELETE CASCADE from entries
		-- keeps ptr_map automatically clean when cache entries are evicted.

		CREATE TABLE IF NOT EXISTS ptr_map (
			rdata_ip TEXT NOT NULL,
			entry_id INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			name     TEXT NOT NULL,
			ttl      INTEGER NOT NULL,
			PRIMARY KEY (rdata_ip, entry_id, name)
		) WITHOUT ROWID;

		-- ── Request journal (depends on entries via FK) ──────────────────
		-- Append-only log of every served query. One row per request.
		-- Stats() aggregates from this table; per-request debugging queries
		-- against qname/qtype/rcode/protocol. Survives FlushDB("stats").
		-- entry_id links to the cache entry that owns this request.
		-- ensureEntry guarantees every row has a valid FK. ON DELETE
		-- CASCADE keeps log size bounded by the cache — when an entry is
		-- evicted, its associated log rows go with it.

		CREATE TABLE IF NOT EXISTS request_log (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp       INTEGER NOT NULL,
			entry_id        INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			protocol        TEXT NOT NULL,
			result          TEXT NOT NULL,
			response_time_ms INTEGER NOT NULL DEFAULT 0,
			rcode           INTEGER NOT NULL DEFAULT 0,
			server          TEXT NOT NULL DEFAULT '',
			hijack          INTEGER NOT NULL DEFAULT 0,
			fallback        INTEGER NOT NULL DEFAULT 0,
			dnssec_status   TEXT NOT NULL DEFAULT ''
		);

		-- Time-range scans: Stats() filtering and time-windowed debugging
		-- queries (e.g. "last hour").

		CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_request_log_entry ON request_log(entry_id);

		-- ── Hit counters (depends on entries via FK) ─────────────────────
		-- Aggregated hit counts per entry+protocol. Each cache hit upserts
		-- here instead of inserting into request_log. ON DELETE CASCADE
		-- keeps counters bounded by cache eviction.

		CREATE TABLE IF NOT EXISTS entry_hit_counters (
			entry_id  INTEGER NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
			protocol  TEXT NOT NULL,
			rcode     INTEGER NOT NULL DEFAULT 0,
			hit_count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (entry_id, protocol, rcode)
		) WITHOUT ROWID;

		-- ── Stats metadata (depends on request_log semantically) ───────────
		-- Single row tracking the last request_log.id that was "cleared" by
		-- FlushDB("stats"). Stats() only considers request_log rows with
		-- id > cleared_before. Resetting stats is O(1): just UPDATE this row.

		CREATE TABLE IF NOT EXISTS stats_meta (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			cleared_before INTEGER NOT NULL DEFAULT 0
		);
		INSERT OR IGNORE INTO stats_meta (id, cleared_before) VALUES (1, 0);

		-- ── Per-IP latency (independent, no FK) ────────────────────────────
		-- Keyed by rdata_ip only — latency is a property of the IP address,
		-- not the domain name. All domains sharing the same CDN IP reuse the
		-- same row. qtype is inferred from IP format (A=1, AAAA=28) for
		-- address-family analytics. Rows with last_probe_time older than
		-- defaultStaleMaxAge (30 days) are cleaned up during eviction.

		CREATE TABLE IF NOT EXISTS ip_latency (
			rdata_ip        TEXT NOT NULL,
			qtype           INTEGER NOT NULL DEFAULT 0,
			latency_ms      INTEGER NOT NULL,
			last_probe_time INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (rdata_ip)
		) WITHOUT ROWID;
	`)
	return err
}

func (s *SQLiteCache) prepareStatements() error {
	var err error
	s.stmtGetEntry, err = s.db.Prepare(
		`SELECT id, timestamp, ttl, validated, msg_wire FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`)
	if err != nil {
		return err
	}
	s.stmtInsertLog, err = s.db.Prepare(
		`INSERT INTO request_log (timestamp, entry_id, protocol, result,
			response_time_ms, rcode, server, hijack, fallback, dnssec_status)
		 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)`)
	if err != nil {
		return err
	}
	s.stmtHitCounter, err = s.db.Prepare(
		`INSERT INTO entry_hit_counters (entry_id, protocol, rcode, hit_count)
		 VALUES (?1, ?2, ?3, 1)
		 ON CONFLICT(entry_id, protocol, rcode) DO UPDATE
		 SET hit_count = entry_hit_counters.hit_count + 1`)
	if err != nil {
		return err
	}
	s.stmtInsertLatency, err = s.db.Prepare(
		`INSERT OR REPLACE INTO ip_latency (rdata_ip, qtype, latency_ms, last_probe_time)
		 VALUES (?, ?, ?, unixepoch())`)
	if err != nil {
		return err
	}
	s.stmtGetLastProbe, err = s.db.Prepare(
		`SELECT last_probe_time FROM ip_latency WHERE rdata_ip = ?`)
	if err != nil {
		return err
	}
	return nil
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
	err := s.stmtGetEntry.QueryRow(
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
			if ip, ok := dnsutil.ExtractIPString(rr); ok {
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

// lookupIPLatencies fetches latencies for a batch of IPs in a single query.
func (s *SQLiteCache) lookupIPLatencies(ips []string) map[string]int {
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

	rows, err := s.db.Query(buf.String(), args...)
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

	tx, err := s.db.Begin()
	if err != nil {
		s.writeMu.Unlock()
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
		now, entryTTL, now+int64(entryTTL), boolToInt(validated),
		msgWire,
	).Scan(&entryID); err != nil {
		s.writeMu.Unlock()
		log.Warnf("CACHE: insert entry failed: %v", err)
		return
	}

	// Populate ptr_map for reverse (PTR) lookups.
	insertPtrMap(tx, entryID, answer)
	insertPtrMap(tx, entryID, authority)
	insertPtrMap(tx, entryID, additional)

	if err := tx.Commit(); err != nil {
		s.writeMu.Unlock()
		log.Warnf("CACHE: commit tx failed: %v", err)
		return
	}

	s.entryCount.Add(1)

	// Release writeMu BEFORE eviction — eviction is a separate transaction
	// that only deletes old rows and does not conflict with concurrent
	// inserts. Holding writeMu across eviction serializes all cache writes
	// behind potentially slow DELETE + CASCADE operations.
	s.writeMu.Unlock()
	s.evictIfNeeded()
}

// per-request debugging. Every log row has an entry_id FK — ensureEntry
// creates a lightweight stub for rewrite/error paths so the FK is always
// satisfied and ON DELETE CASCADE applies uniformly.
func (s *SQLiteCache) RecordRequest(r RequestRecord) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return
	}

	r.Qname = dnsutil.NormalizeDomain(r.Qname)
	ecsAddr, ecsPrefix := ecsParams(r.ECS)
	dnssecInt := boolToInt(r.DNSSECOK)

	entryID := s.ensureEntry(r.Qname, int(r.Qtype), int(r.Qclass), ecsAddr, ecsPrefix, dnssecInt)

	if r.Result == "hit" {
		_, _ = s.stmtHitCounter.Exec(entryID, r.Protocol, r.Rcode)
		return
	}

	_, _ = s.stmtInsertLog.Exec(
		log.NowUnix(), entryID,
		r.Protocol, r.Result, r.ResponseTime, r.Rcode, r.Server,
		boolToInt(r.Hijack), boolToInt(r.Fallback), r.DNSSECStatus,
	)
}

// ensureEntry returns the entry ID for the given cache key, creating a
// lightweight stub if one doesn't exist. The stub has DefaultStaleTTL
// lifetime and empty msg_wire; it will be replaced if Set() later fills
// this key with real data (INSERT OR REPLACE).
func (s *SQLiteCache) ensureEntry(qname string, qtype, qclass int, ecsAddr string, ecsPrefix, dnssecInt int) int64 {
	// Fast path: entry already exists.
	var id int64
	err := s.db.QueryRow(
		`SELECT id FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&id)
	if err == nil {
		return id
	}

	// Slow path: create stub. Serialized via writeMu to avoid racing with
	// concurrent Set() on the same key.
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Double-check after acquiring the lock.
	err = s.db.QueryRow(
		`SELECT id FROM entries
		 WHERE qname = ? AND qtype = ? AND qclass = ?
		 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
	).Scan(&id)
	if err == nil {
		return id
	}

	now := log.NowUnix()
	err = s.db.QueryRow(
		`INSERT OR IGNORE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
			timestamp, ttl, expires_at, validated, msg_wire)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 RETURNING id`,
		qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
		now, config.DefaultStaleTTL, now+int64(config.DefaultStaleTTL), 0,
	).Scan(&id)
	if err != nil {
		// INSERT OR IGNORE silently skipped — a concurrent Set() won.
		_ = s.db.QueryRow(
			`SELECT id FROM entries
			 WHERE qname = ? AND qtype = ? AND qclass = ?
			 AND ecs_addr = ? AND ecs_prefix = ? AND dnssec_ok = ?`,
			qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt,
		).Scan(&id)
	}
	return id
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip string) []LookupResult {
	if ip == "" {
		return nil
	}

	rows, err := s.db.Query(
		`SELECT pm.name, pm.ttl, e.timestamp, MAX(e.timestamp + pm.ttl)
		 FROM ptr_map pm
		 JOIN entries e ON pm.entry_id = e.id
		 WHERE pm.rdata_ip = ? AND e.expires_at + ? >= ?
		 GROUP BY pm.name
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
		var dummy int64
		if err := rows.Scan(&name, &rawTTL, &ts, &dummy); err != nil {
			continue
		}
		results = append(results, LookupResult{
			Name: name,
			TTL:  ttl.RemainingTTL(ts, rawTTL, uint32(config.DefaultStaleTTL)),
		})
	}
	return results
}

// FlushDB truncates a single table: "stats" (resets stats_meta.cleared_before),
// "cache" (entries), or "latency" (ip_latency).
func (s *SQLiteCache) FlushDB(target string) (int64, error) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return 0, errors.New("cache closed")
	}
	var result sql.Result
	var err error
	switch target {
	case "stats":
		_, _ = s.db.Exec(`DELETE FROM entry_hit_counters`)
		result, err = s.db.Exec(
			`UPDATE stats_meta SET cleared_before = (SELECT COALESCE(MAX(id), 0) FROM request_log) WHERE id = 1`)
	case "cache":
		result, err = s.db.Exec(`DELETE FROM entries`)
		if err == nil {
			s.entryCount.Store(0)
		}
	case "latency":
		result, err = s.db.Exec(`DELETE FROM ip_latency`)
	default:
		return 0, fmt.Errorf("flushDB: unknown target %q", target)
	}
	if err != nil {
		return 0, fmt.Errorf("flushDB %s: %w", target, err)
	}
	n, _ := result.RowsAffected()
	log.Infof("CACHE: flushDB %s: %d rows", target, n)
	return n, nil
}

// Clear truncates all tables: entries, request_log, and ip_latency.
func (s *SQLiteCache) Clear() (int64, error) {
	n1, err := s.FlushDB("cache")
	if err != nil {
		return 0, err
	}
	n2, err := s.FlushDB("stats")
	if err != nil {
		return n1, err
	}
	n3, err := s.FlushDB("latency")
	if err != nil {
		return n1 + n2, err
	}
	// Clear request_log, entry_hit_counters, and reset stats_meta.
	_, _ = s.db.Exec(`DELETE FROM entry_hit_counters`)
	result, err := s.db.Exec(`DELETE FROM request_log`)
	if err != nil {
		return n1 + n2 + n3, fmt.Errorf("clear request_log: %w", err)
	}
	n4, _ := result.RowsAffected()
	_, _ = s.db.Exec(`UPDATE stats_meta SET cleared_before = 0 WHERE id = 1`)
	return n1 + n2 + n3 + n4, nil
}

// Stats returns 6 TXT records grouped by theme (overview, sources, rcodes,
// anomalies, protocols, DNSSEC), aggregated from request_log since the last
// FlushDB("stats").
func (s *SQLiteCache) Stats() []string {
	if atomic.LoadInt32(&s.closed) != 0 {
		return nil
	}

	var entries int64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&entries)

	var avgMs float64
	var total, hits, misses, stales, rewrites, errors int64
	var hcUDP, hcTCP, hcDOT, hcDOQ, hcDOH, hcDOH3 int64
	var rlUDP, rlTCP, rlDOT, rlDOQ, rlDOH, rlDOH3 int64
	var hijack, fallback, totalMS int64
	var noerr, formerr, servfail, nxdomain, notimp, refused, other int64
	var secureCount, insecureCount, bogusCount int64

	// Hits come from entry_hit_counters (aggregated, no cleared_before filter).
	_ = s.db.QueryRow(
		"SELECT COALESCE(SUM(hit_count), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dot' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doq' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh' THEN hit_count ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh3' THEN hit_count ELSE 0 END), 0)"+
			" FROM entry_hit_counters",
	).Scan(&hits, &hcUDP, &hcTCP, &hcDOT, &hcDOQ, &hcDOH, &hcDOH3)

	// Detail rows from request_log since last stats clear.
	_ = s.db.QueryRow(
		"SELECT COUNT(*),"+
			" COALESCE(AVG(response_time_ms), 0),"+
			" COALESCE(SUM(CASE WHEN result='miss' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='stale' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='rewrite' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN result='error' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='udp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='tcp' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='dot' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doq' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN protocol='doh3' THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN hijack THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(CASE WHEN fallback THEN 1 ELSE 0 END), 0),"+
			" COALESCE(SUM(response_time_ms), 0)"+
			" FROM request_log WHERE id > (SELECT cleared_before FROM stats_meta)",
	).Scan(&total, &avgMs,
		&misses, &stales, &rewrites, &errors,
		&rlUDP, &rlTCP, &rlDOT, &rlDOQ, &rlDOH, &rlDOH3,
		&hijack, &fallback, &totalMS,
	)

	total += hits
	udp := hcUDP + rlUDP
	tcp := hcTCP + rlTCP
	dot := hcDOT + rlDOT
	doq := hcDOQ + rlDOQ
	doh := hcDOH + rlDOH
	doh3 := hcDOH3 + rlDOH3
	// avg := totalMS / (misses + errors), but use per-row avg for now
	if misses+errors > 0 && avgMs == 0 {
		avgMs = float64(totalMS) / float64(misses+errors)
	}

	// Rcode distribution: request_log + entry_hit_counters.
	rows, err := s.db.Query(
		`SELECT rcode, SUM(cnt) FROM (
			SELECT rcode, COUNT(*) AS cnt FROM request_log
			 WHERE id > (SELECT cleared_before FROM stats_meta) GROUP BY rcode
			UNION ALL
			SELECT rcode, SUM(hit_count) AS cnt FROM entry_hit_counters GROUP BY rcode
		) GROUP BY rcode`)
	if err == nil {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var rc, cnt int64
			if err := rows.Scan(&rc, &cnt); err == nil {
				switch rc {
				case 0:
					noerr = cnt
				case 1:
					formerr = cnt
				case 2:
					servfail = cnt
				case 3:
					nxdomain = cnt
				case 4:
					notimp = cnt
				case 5:
					refused = cnt
				default:
					other += cnt
				}
			}
		}
	}

	// DNSSEC status distribution.
	dnssecRows, err := s.db.Query(
		`SELECT dnssec_status, COUNT(*) FROM request_log
		 WHERE id > (SELECT cleared_before FROM stats_meta)
		 GROUP BY dnssec_status`)
	if err == nil {
		defer func() { _ = dnssecRows.Close() }()
		for dnssecRows.Next() {
			var status string
			var cnt int64
			if err := dnssecRows.Scan(&status, &cnt); err == nil {
				switch status {
				case config.DNSSECStatusSecure:
					secureCount = cnt
				case config.DNSSECStatusInsecure:
					insecureCount = cnt
				case config.DNSSECStatusBogus:
					bogusCount = cnt
				}
			}
		}
	}

	return []string{
		fmt.Sprintf("entries=%d total=%d avg=%.1fms",
			entries, total, avgMs),
		fmt.Sprintf("hits=%d misses=%d stales=%d rewrites=%d errors=%d",
			hits, misses, stales, rewrites, errors),
		fmt.Sprintf("noerr=%d formerr=%d servfail=%d nx=%d nimp=%d ref=%d other=%d",
			noerr, formerr, servfail, nxdomain, notimp, refused, other),
		fmt.Sprintf("hijack=%d fallback=%d",
			hijack, fallback),
		fmt.Sprintf("udp=%d tcp=%d dot=%d doq=%d doh=%d doh3=%d",
			udp, tcp, dot, doq, doh, doh3),
		fmt.Sprintf("secure=%d insecure=%d bogus=%d",
			secureCount, insecureCount, bogusCount),
	}
}

// Close closes the database.
func (s *SQLiteCache) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closed, 0, 1) {
		return nil
	}
	// Close prepared statements before the database.
	for _, stmt := range []*sql.Stmt{s.stmtGetEntry, s.stmtInsertLog, s.stmtHitCounter, s.stmtInsertLatency, s.stmtGetLastProbe} {
		if stmt != nil {
			_ = stmt.Close()
		}
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

	// Clean up latency rows not probed within staleMaxAge.
	if _, err := tx.Exec(
		`DELETE FROM ip_latency WHERE last_probe_time > 0 AND last_probe_time < unixepoch() - ?`,
		defaultStaleMaxAge,
	); err != nil {
		log.Debugf("CACHE: ip_latency cleanup failed (non-fatal): %v", err)
	}

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

// UpdateLatency stores a latency measurement keyed by IP only. All domains
// sharing the same IP reuse the same row — latency is measured once, not
// once per domain. qtype is inferred from the IP address format.
func (s *SQLiteCache) UpdateLatency(ip string, latencyMS int) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return
	}
	qtype := dns.TypeAAAA
	if parsedIP.To4() != nil {
		qtype = dns.TypeA
	}
	_, _ = s.stmtInsertLatency.Exec(ip, qtype, latencyMS)
}

// GetLatencyLastProbe returns the last probe time for an IP. Returns (0, false)
// if the IP has never been probed.
func (s *SQLiteCache) GetLatencyLastProbe(ip string) (int64, bool) {
	var ts int64
	if err := s.stmtGetLastProbe.QueryRow(ip).Scan(&ts); err != nil || ts == 0 {
		return 0, false
	}
	return ts, true
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
