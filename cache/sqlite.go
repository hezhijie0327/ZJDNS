package cache

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"
	_ "modernc.org/sqlite"

	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
)

const (
	defaultCleanupInterval = 5 * time.Minute
	defaultStaleMaxAge     = int64(config.DefaultStaleMaxAge)
	defaultCacheLowWater   = 0.9 // evict down to 90% of max when over limit
)

// ptrRecord holds an extracted PTR mapping for reverse lookup indexing.
type ptrRecord struct {
	IP   string
	Name string
	TTL  uint32
}

// SQLiteCache is a DNS response cache backed entirely by SQLite.
// WAL mode enables concurrent reads alongside a single serialized writer.
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
// database. maxEntries controls the size-based eviction ceiling.
// mmapSizeMB and cacheSizeMB are SQLite PRAGMA tunables; zero means use defaults.
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
	dsn += "?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000"

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

	// One-time cleanup of entries that expired beyond the serve-stale window
	// (possible after unclean shutdown).
	s.deleteExpiredEntries()

	s.startPeriodicCleanup()

	persistLabel := path
	if persistLabel == "" {
		persistLabel = "memory"
	}
	log.Infof("CACHE: SQLite cache enabled (db=%s, max_entries=%d, mmap_size=%dMB, cache_size=%dMB)", persistLabel, maxEntries, mmapSizeMB, cacheSizeMB)
	return s, nil
}

// migrate creates the schema and sets performance PRAGMAs. It is idempotent.
func (s *SQLiteCache) migrate() error {
	// Performance PRAGMAs — applied once at connection open.
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
			key       TEXT PRIMARY KEY,
			data      BLOB NOT NULL,
			timestamp INTEGER NOT NULL DEFAULT 0,
			ttl       INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS ptr_index (
			ip        TEXT NOT NULL,
			name      TEXT NOT NULL,
			ttl       INTEGER NOT NULL DEFAULT 0,
			timestamp INTEGER NOT NULL DEFAULT 0,
			cache_key TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (ip, name)
		);

		CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp);
	`)
	return err
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cache entry by key, returning the entry, whether found,
// and whether the entry is expired.
func (s *SQLiteCache) Get(key string) (*Entry, bool, bool) {
	if atomic.LoadInt32(&s.closed) != 0 {
		return nil, false, false
	}

	var data []byte
	var ts int64
	var ttlSeconds int
	err := s.db.QueryRow(
		`SELECT data, timestamp, ttl FROM entries WHERE key = ?`, key,
	).Scan(&data, &ts, &ttlSeconds)
	if err == sql.ErrNoRows {
		return nil, false, false
	}
	if err != nil {
		log.Warnf("CACHE: sqlite get failed: %v", err)
		return nil, false, false
	}

	var entry Entry
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&entry); err != nil {
		log.Warnf("CACHE: gob decode failed for %s: %v", key, err)
		return nil, false, false
	}

	// Use denormalised timestamp/ttl from the row — they are canonical.
	entry.Timestamp = ts
	entry.TTL = ttlSeconds

	isExpired := ttl.IsExpired(ts, ttlSeconds)
	return &entry, true, isExpired
}

// Set stores a DNS response in the cache.
func (s *SQLiteCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *config.ECSOption) {
	s.SetWithDNSSEC(key, answer, authority, additional, validated, false, ecs)
}

// SetWithDNSSEC stores a DNS response with explicit DNSSEC cryptographic
// validation status.
func (s *SQLiteCache) SetWithDNSSEC(key string, answer, authority, additional []dns.RR, validated bool, dnssecValidated bool, ecs *config.ECSOption) {
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

	entry := &Entry{
		Answer:          compact(answer),
		Authority:       compact(authority),
		Additional:      compact(additional),
		TTL:             entryTTL,
		Timestamp:       now,
		Validated:       validated,
		DNSSECValidated: dnssecValidated,
	}
	if ecs != nil {
		entry.ECSFamily = ecs.Family
		entry.ECSSourcePrefix = ecs.SourcePrefix
		entry.ECSScopePrefix = ecs.ScopePrefix
		entry.ECSAddress = ecs.Address.String()
	}

	s.setEntryInternal(key, entry)
}

// SetEntry stores a pre-built Entry in the cache under the given key.
// The entry is deep-cloned so the caller retains ownership of the original.
func (s *SQLiteCache) SetEntry(key string, entry *Entry) {
	if atomic.LoadInt32(&s.closed) != 0 || entry == nil {
		return
	}
	s.setEntryInternal(key, cloneEntry(entry))
}

// setEntryInternal gob-encodes the entry and writes it to SQLite along with
// denormalised timestamp/ttl columns and PTR index rows. Ownership of the
// entry is transferred — the caller must not retain a reference.
func (s *SQLiteCache) setEntryInternal(key string, entry *Entry) {
	cloned := cloneEntryForPersist(entry)

	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(cloned); err != nil {
		log.Warnf("CACHE: gob encode failed for %s: %v", key, err)
		return
	}
	data := buf.Bytes()

	ptrs := extractPTRRecords(entry)

	tx, err := s.db.Begin()
	if err != nil {
		log.Warnf("CACHE: begin tx failed: %v", err)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO entries (key, data, timestamp, ttl) VALUES (?, ?, ?, ?)`,
		key, data, entry.Timestamp, entry.TTL,
	); err != nil {
		log.Warnf("CACHE: insert entry failed for %s: %v", key, err)
		return
	}

	// Delete old PTR rows for this key, then insert current ones.
	if _, err := tx.Exec(`DELETE FROM ptr_index WHERE cache_key = ?`, key); err != nil {
		log.Warnf("CACHE: delete ptrs failed for %s: %v", key, err)
		return
	}
	for _, pr := range ptrs {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO ptr_index (ip, name, ttl, timestamp, cache_key) VALUES (?, ?, ?, ?, ?)`,
			pr.IP, pr.Name, pr.TTL, entry.Timestamp, key,
		); err != nil {
			log.Warnf("CACHE: insert ptr failed for %s/%s: %v", pr.IP, pr.Name, err)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: commit tx failed for %s: %v", key, err)
		return
	}

	s.evictIfNeeded()
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (s *SQLiteCache) ReverseLookup(ip net.IP) []LookupResult {
	if ip == nil {
		return nil
	}

	rows, err := s.db.Query(
		`SELECT name, ttl, timestamp FROM ptr_index WHERE ip = ? ORDER BY name`, ip.String(),
	)
	if err != nil {
		log.Warnf("CACHE: PTR lookup failed for %s: %v", ip.String(), err)
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

// Close stops the periodic cleanup goroutine, performs final expiry cleanup,
// and closes the database.
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

// ── Eviction ─────────────────────────────────────────────────────────────────

// evictIfNeeded checks whether the entry count exceeds the configured limit and
// evicts the oldest entries (by timestamp) down to the low-water mark.
func (s *SQLiteCache) evictIfNeeded() {
	if s.maxEntries <= 0 {
		return
	}

	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&count); err != nil {
		log.Warnf("CACHE: count query failed during eviction: %v", err)
		return
	}

	if count <= int64(s.maxEntries) {
		return
	}

	excess := count - int64(float64(s.maxEntries)*defaultCacheLowWater)
	if excess <= 0 {
		excess = 1
	}

	s.evictOldestEntries(excess)
}

// evictOldestEntries removes the N oldest entries (by timestamp) along with
// their PTR index rows, in a single transaction.
func (s *SQLiteCache) evictOldestEntries(n int64) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT key FROM entries ORDER BY timestamp ASC LIMIT ?`, n)
	if err != nil {
		log.Warnf("CACHE: select for eviction failed: %v", err)
		return
	}

	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			continue
		}
		keys = append(keys, k)
	}
	_ = rows.Close()

	if len(keys) == 0 {
		return
	}

	// Delete PTR rows first (no foreign key cascade — manual cleanup).
	for _, k := range keys {
		if _, err := tx.Exec(`DELETE FROM ptr_index WHERE cache_key = ?`, k); err != nil {
			log.Warnf("CACHE: evict ptr cleanup failed for %s: %v", k, err)
		}
	}

	// Delete entries in a single statement using IN clause.
	// SQLite supports up to ~999 parameters; eviction batches are small.
	stmt := `DELETE FROM entries WHERE key IN (?` + strings.Repeat(`,?`, len(keys)-1) + `)`
	args := make([]any, len(keys))
	for i, k := range keys {
		args[i] = k
	}
	if _, err := tx.Exec(stmt, args...); err != nil {
		log.Warnf("CACHE: evict delete failed: %v", err)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Warnf("CACHE: evict commit failed: %v", err)
		return
	}

	log.Debugf("CACHE: evicted %d oldest entries (count=%d, max=%d)", len(keys), s.entryCount(), s.maxEntries)
}

// entryCount returns the current number of entries (for logging).
func (s *SQLiteCache) entryCount() int64 {
	var n int64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM entries`).Scan(&n)
	return n
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
			s.cleanOrphanedPTRs()
		}
	}()
}

// deleteExpiredEntries removes entries whose TTL has elapsed beyond the
// serve-stale window.
func (s *SQLiteCache) deleteExpiredEntries() {
	cutoff := log.NowUnix() - s.staleMaxAge
	res, err := s.db.Exec(
		`DELETE FROM entries WHERE timestamp + ttl < ?`, cutoff,
	)
	if err != nil {
		log.Warnf("CACHE: expired entry cleanup failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Debugf("CACHE: cleaned %d expired entries", n)
	}
}

// cleanOrphanedPTRs removes ptr_index rows whose parent cache entry no longer
// exists (e.g. after eviction or expiry if the delete missed them).
func (s *SQLiteCache) cleanOrphanedPTRs() {
	res, err := s.db.Exec(
		`DELETE FROM ptr_index WHERE cache_key NOT IN (SELECT key FROM entries)`,
	)
	if err != nil {
		log.Warnf("CACHE: orphan PTR cleanup failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Debugf("CACHE: cleaned %d orphaned PTR entries", n)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// compact converts DNS resource records to space-efficient CompactRecords.
func compact(rrs []dns.RR) []*CompactRecord {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]*CompactRecord, 0, len(rrs))
	seen := make(map[string]struct{}, len(rrs))
	for _, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		rrText := rr.String()
		if _, dup := seen[rrText]; dup {
			continue
		}
		seen[rrText] = struct{}{}
		if cr := newCompactRecord(rr); cr != nil {
			result = append(result, cr)
		}
	}
	return result
}

// expand converts a CompactRecord back to a DNS resource record.
func expand(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.New(cr.Text)
	return rr
}

// cloneEntry deep-copies an Entry so the caller can safely retain the original.
func cloneEntry(entry *Entry) *Entry {
	if entry == nil {
		return nil
	}
	cloned := *entry
	cloned.Answer = cloneRecords(entry.Answer)
	cloned.Authority = cloneRecords(entry.Authority)
	cloned.Additional = cloneRecords(entry.Additional)
	return &cloned
}

// cloneRecords deep-copies a slice of CompactRecords.
func cloneRecords(records []*CompactRecord) []*CompactRecord {
	if len(records) == 0 {
		return nil
	}
	cloned := make([]*CompactRecord, len(records))
	for i, r := range records {
		if r == nil {
			continue
		}
		rr := *r
		cloned[i] = &rr
	}
	return cloned
}

// cloneEntryForPersist deep-copies an Entry and clears cached RR fields for
// gob encoding without type registration.
func cloneEntryForPersist(entry *Entry) *Entry {
	cloned := cloneEntry(entry)
	if cloned == nil {
		return nil
	}
	clearRRFields(cloned.Answer)
	clearRRFields(cloned.Authority)
	clearRRFields(cloned.Additional)
	return cloned
}

// clearRRFields nils the cached RR field in CompactRecords so gob can encode.
func clearRRFields(records []*CompactRecord) {
	for _, r := range records {
		if r != nil {
			r.RR = nil
		}
	}
}

// minTTL returns the minimum positive TTL across all record sections.
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

// hasNSECOrNSEC3 reports whether any record in the authority section is an
// NSEC or NSEC3 record, indicating a negative (NXDOMAIN/NODATA) response.
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

// negativeTTLCap returns the maximum TTL for a negative cache entry per
// RFC 9077: min(SOA.MINIMUM, SOA.TTL), capped at DefaultMaxNegativeTTL.
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

// extractPTRRecords extracts A and AAAA records from an entry's answer section
// for building the reverse-lookup (PTR) index.
func extractPTRRecords(entry *Entry) []ptrRecord {
	if entry == nil {
		return nil
	}
	records := make([]ptrRecord, 0, len(entry.Answer))
	for _, cr := range entry.Answer {
		if cr == nil {
			continue
		}
		rr := expand(cr)
		if rr == nil {
			continue
		}
		var ip net.IP
		var name string
		var ttlVal uint32
		switch r := rr.(type) {
		case *dns.A:
			ip, name, ttlVal = net.IP(r.Addr.AsSlice()), r.Hdr.Name, r.Hdr.TTL
		case *dns.AAAA:
			ip, name, ttlVal = net.IP(r.Addr.AsSlice()), r.Hdr.Name, r.Hdr.TTL
		default:
			continue
		}
		if ip == nil || name == "" {
			continue
		}
		records = append(records, ptrRecord{IP: ip.String(), Name: dnsutilv2.Fqdn(name), TTL: ttlVal})
	}
	return records
}
