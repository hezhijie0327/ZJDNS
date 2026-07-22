package cache

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// dnsL1Key is the cache key for the DNS L1 memory cache.
type dnsL1Key struct {
	qname     string
	qtype     uint16
	qclass    uint16
	ecsAddr   string
	ecsPrefix int
	dnssecOK  bool
}

// SQLiteCache is a DNS response cache backed by a SQLite database managed by
// the database package. It implements the Store interface.
type SQLiteCache struct {
	db          *database.DB
	evictCount  atomic.Int64
	asyncWriter *AsyncStatsWriter
	dnsL1       *lrumap.Map[dnsL1Key, *Entry] // bounded memory L1 for hot entries
	latencyL1   *lrumap.Map[string, int]      // bounded memory cache for IP latency
}

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap IN-clause IPs to bound SQL compilation overhead
	decompressBufCap    = 4096
)

// decompressBufPool reuses byte slices for zstd decompression on the
// cache-hit hot path, reducing GC pressure (P3).
var decompressBufPool = sync.Pool{
	New: func() any { b := make([]byte, decompressBufCap); return &b },
}

// latencyArgsPool reuses [64]any arrays for the batched latency lookup query.
// The fixed-size array is reused across calls so the per-Get() heap allocation
// is eliminated.
var latencyArgsPool = sync.Pool{
	New: func() any { return new([maxLatencyLookupIPs]any) },
}

// New creates a cache backed by the given database. The caller is responsible
// for opening the database via database.Open() before calling New.
func New(db *database.DB, dnsL1Entries, ipLatencyEntries int) *SQLiteCache {
	c := &SQLiteCache{
		db:          db,
		asyncWriter: NewAsyncStatsWriter(db, config.DefaultAsyncStatsBufferSize),
	}
	if dnsL1Entries > 0 {
		c.dnsL1 = lrumap.New[dnsL1Key, *Entry](dnsL1Entries)
	}
	if ipLatencyEntries > 0 {
		c.latencyL1 = lrumap.New[string, int](ipLatencyEntries)
	}
	return c
}

// Close shuts down the async stats writer and then closes the database.
func (s *SQLiteCache) Close() error {
	s.asyncWriter.Close()
	return s.db.Close()
}

// Flush forces the async stats writer to write any buffered records immediately.
// Primarily for tests that need to observe RecordRequest results synchronously.
func (s *SQLiteCache) Flush() {
	s.asyncWriter.Flush()
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
func (s *SQLiteCache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	if s.db.IsClosed() {
		return nil, false, false
	}

	qname = dnsutil.Canonical(qname)
	ecsAddr, ecsPrefix := ecsParams(ecs)

	// Check bounded memory L1 cache before hitting SQLite.
	l1Key := dnsL1Key{qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecOK}
	if s.dnsL1 != nil {
		if entry, ok := s.dnsL1.Get(l1Key); ok && entry != nil {
			if !ttl.IsExpired(entry.Timestamp, entry.TTL) {
				// Shallow-copy entry to re-sort by latest latency
				// without mutating the cached *Entry.
				if len(entry.Answer) > 1 {
					e := *entry
					e.Answer = make([]dns.RR, len(entry.Answer))
					copy(e.Answer, entry.Answer)
					s.sortAnswerByLatency(&e)
					return &e, true, false
				}
				return entry, true, false
			}
			// Expired in L1 — fall through to SQLite.
		}
	}

	var id int64
	var ts int64
	var entryTTL int
	var validated int
	var msgWire []byte
	err := s.db.StmtEntry.QueryRow(
		qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, database.BoolToInt(dnssecOK),
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
	// Use a pooled buffer as the decompression destination to reduce
	// per-cache-hit heap allocations (P3).  The buffer is returned to
	// the pool after entry fields are extracted and msg.Data is cleared.
	dbuf := decompressBufPool.Get().(*[]byte)
	wire, err := zdnsutil.DecompressTo(msgWire, *dbuf)
	if err != nil {
		decompressBufPool.Put(dbuf)
		log.Warnf("CACHE: decompress wire for entry %d: %v", id, err)
		return nil, false, false
	}
	defer decompressBufPool.Put(dbuf) // runs after msg.Put (LIFO ensures msg.Data is nil'd first)

	msg := pool.DefaultMessage.Get()
	// Safety: msg.Data aliases the decompression buffer.  The LIFO defer
	// chain guarantees msg.Put (which zeroes Data) runs before dbuf is
	// returned to decompressBufPool.  Do not insert new logic between
	// the msg.Get and this line without understanding the ordering.
	msg.Data = wire
	if err := msg.Unpack(); err != nil {
		pool.DefaultMessage.Put(msg)
		log.Warnf("CACHE: unpack wire for entry %d: %v", id, err)
		return nil, false, false
	}
	defer pool.DefaultMessage.Put(msg)

	entry := &Entry{
		ID:         id,
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

	// Populate L1 memory cache for future queries.
	if s.dnsL1 != nil {
		s.dnsL1.Set(l1Key, entry)
	}

	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records (CNAME, etc.) at the
// front in their original wire-format order. Latency is per-IP — all domains
// sharing the same IP reuse the same row. Idempotent when ≤1 A/AAAA.
//
// Uses a single pass over entry.Answer to separate A/AAAA from non-A/AAAA
// records and collect IPs simultaneously, halving the iteration overhead.
func (s *SQLiteCache) sortAnswerByLatency(entry *Entry) {
	if len(entry.Answer) <= 1 {
		return
	}

	// Collect IPs from A/AAAA records in a single pass.
	ips := make([]string, 0, len(entry.Answer))
	for _, rr := range entry.Answer {
		if ip, ok := zdnsutil.ExtractIPString(rr); ok {
			ips = append(ips, ip)
		}
	}
	if len(ips) <= 1 {
		return
	}

	// Batch lookup: WHERE rdata_ip IN (?,?,...).
	latencies := s.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return
	}

	// In-place sort: non-A/AAAA before A/AAAA; A/AAAA sorted by latency.
	// SortStableFunc avoids allocating temporary aRecs/other/result slices.
	slices.SortStableFunc(entry.Answer, func(a, b dns.RR) int {
		aIP, aIsAddr := zdnsutil.ExtractIPString(a)
		bIP, bIsAddr := zdnsutil.ExtractIPString(b)
		if aIsAddr != bIsAddr {
			if !aIsAddr {
				return -1
			}
			return 1
		}
		if !aIsAddr {
			return 0
		}
		aLat, aOK := latencies[aIP]
		bLat, bOK := latencies[bIP]
		switch {
		case aOK != bOK:
			if aOK {
				return -1
			}
			return 1
		case aOK:
			if aLat != bLat {
				return aLat - bLat
			}
		}
		return dns.Compare(a, b)
	})
}

// lookupIPLatencies fetches latencies for a batch of IPs in a single query.
// Caps at maxLatencyLookupIPs to bound SQL compilation overhead on unusually
// large answer sets (64+ A/AAAA records).
func (s *SQLiteCache) lookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}

	// Check bounded memory L1 cache first.
	latencies := make(map[string]int, len(ips))
	misses := ips
	if s.latencyL1 != nil {
		misses = nil
		for _, ip := range ips {
			if lat, ok := s.latencyL1.Get(ip); ok {
				latencies[ip] = lat
			} else {
				misses = append(misses, ip)
			}
		}
		if len(misses) == 0 {
			return latencies
		}
	}

	// Query SQLite for cache misses.
	argsPtr := latencyArgsPool.Get().(*[maxLatencyLookupIPs]any)
	defer func() {
		for i := range maxLatencyLookupIPs {
			argsPtr[i] = nil
		}
		latencyArgsPool.Put(argsPtr)
	}()
	for i := range maxLatencyLookupIPs {
		if i < len(misses) {
			argsPtr[i] = misses[i]
		} else {
			argsPtr[i] = ""
		}
	}

	rows, err := s.db.StmtIPLatency.Query(argsPtr[:]...)
	if err != nil {
		return latencies // return L1 hits even if SQLite fails
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var ip string
		var lat int
		if err := rows.Scan(&ip, &lat); err == nil {
			latencies[ip] = lat
			if s.latencyL1 != nil {
				s.latencyL1.Set(ip, lat)
			}
		}
	}
	return latencies
}

// Set stores a DNS response in the cache. Wire format is zstd-compressed.
// SQLite WAL mode serializes concurrent writers, so no app-level mutex is
// needed.  Prep work (TTL calculation, wire packing, zstd compression) runs
// outside the transaction so CPU-heavy steps can overlap across goroutines.
func (s *SQLiteCache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool,
) int64 {
	if s.db.IsClosed() {
		return 0
	}

	// ── Prep work (parallel-safe) ─────────────────────────────────────────
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = dnsutil.Canonical(qname)
	dnssecInt := database.BoolToInt(dnssecOK)

	// Strip EDNS OPT pseudo-record from additional before caching,
	// since padding and other EDNS options have no semantic value and
	// waste storage space (up to 468 bytes per encrypted response).
	additional = stripOPT(additional)

	// Pack wire format and compress.
	msg := &dns.Msg{Answer: answer, Ns: authority, Extra: additional}
	var msgWire []byte
	if err := msg.Pack(); err == nil {
		msgWire = zdnsutil.Compress(msg.Data)
	}

	// ── Transaction ──────────────────────────────────────────────────────
	// SQLite WAL mode serializes writers, so no application-level mutex is
	// needed for concurrent Set() calls.
	var entryID int64
	tx, txErr := s.db.SQ.Begin()
	if txErr == nil {
		defer func() { _ = tx.Rollback() }()

		if txErr = tx.QueryRow(
			`INSERT OR REPLACE INTO entries (qname, qtype, qclass, ecs_addr, ecs_prefix, dnssec_ok,
				timestamp, ttl, expires_at, validated, msg_wire)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			 RETURNING id`,
			qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
			now, entryTTL, now+int64(entryTTL), database.BoolToInt(validated),
			msgWire,
		).Scan(&entryID); txErr == nil {

			// Populate ptr_map for reverse (PTR) lookups.
			if txErr = insertPtrMap(tx, entryID, answer); txErr == nil {
				if txErr = insertPtrMap(tx, entryID, authority); txErr == nil {
					txErr = insertPtrMap(tx, entryID, additional)
				}
			}

			if txErr == nil {
				if txErr = tx.Commit(); txErr == nil {
					s.db.AddEntryCount(1)
				} else {
					log.Warnf("CACHE: commit tx failed: %v", txErr)
				}
			}
		}
		if txErr != nil && entryID == 0 {
			log.Warnf("CACHE: insert entry failed: %v", txErr)
		}
	}
	if txErr != nil && entryID == 0 {
		return 0
	}

	// Populate L1 memory cache so subsequent Get() calls skip SQLite.
	// No need to pre-sort here — L1 hit path re-sorts with latest latency.
	if entryID != 0 && s.dnsL1 != nil {
		s.dnsL1.Set(dnsL1Key{qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt != 0}, &Entry{
			ID:         entryID,
			Answer:     answer,
			Authority:  authority,
			Additional: additional,
			Timestamp:  now,
			TTL:        entryTTL,
			Validated:  validated,
		})
	}

	// evictIfNeeded re-syncs the entry count from the DB via SELECT COUNT(*)
	// before deciding whether to evict, so any TOCTOU drift from concurrent
	// inserts is corrected.
	s.evictIfNeeded()
	return entryID
}

// ── Eviction ─────────────────────────────────────────────────────────────────

func (s *SQLiteCache) evictIfNeeded() {
	if s.db.MaxEntries() <= 0 {
		return
	}

	// Fast path: the atomic counter is accurate for new-key inserts (the common
	// case). Skip the DB COUNT(*) when comfortably below limit. INSERT OR REPLACE
	// drift (replacing an existing row) is rare and self-correcting.
	count := s.db.EntryCount()
	maxEntries := int64(s.db.MaxEntries())
	if count < maxEntries*9/10 {
		return
	}

	// Near or over the limit — resync from DB to correct any drift, then evict.
	if err := s.db.SQ.QueryRow("SELECT COUNT(*) FROM entries").Scan(&count); err == nil {
		s.db.SetEntryCount(count)
	}

	excess := count - maxEntries
	if excess <= 0 {
		return
	}

	s.evictOldest(excess)

	// Throttle PRAGMA optimize to every 10th eviction to avoid per-eviction overhead.
	if s.evictCount.Add(1)%10 == 0 {
		_, _ = s.db.SQ.Exec("PRAGMA optimize")
	}
}

// PruneQueryJournal removes query_stats rows with stat_day older than the
// retention window (config.DefaultQueryJournalRetention) and query_log rows
// with timestamp older than retentionSec.  Called periodically via the server
// background ticker (config.DefaultPruneInterval).
//
// query_stats uses the PK prefix (stat_day is the leading column) for efficient
// range deletion.  query_log deletion is batched (config.DefaultPruneBatchSize
// rows per iteration) to avoid holding a write transaction open too long on
// busy servers.
func (s *SQLiteCache) PruneQueryJournal(retentionSec int64) (int64, error) {
	batchSize := int64(config.DefaultPruneBatchSize)
	dayCutoff := log.NowUnix()/86400 - retentionSec/86400

	// query_stats: single DELETE using PK prefix seek (stat_day is leading column).
	var totalDeleted int64
	qsResult, err := s.db.SQ.Exec(`DELETE FROM query_stats WHERE stat_day < ?`, dayCutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup query_stats: %w", err)
	}
	qsN, _ := qsResult.RowsAffected()
	totalDeleted += qsN

	// query_log: batched DELETE to avoid long write transactions under heavy load.
	for {
		result, err := s.db.SQ.Exec(
			`DELETE FROM query_log WHERE rowid IN (`+
				`SELECT rowid FROM query_log WHERE timestamp < unixepoch() - ? LIMIT ?`+
				`)`, retentionSec, batchSize,
		)
		if err != nil {
			return totalDeleted, fmt.Errorf("cleanup query_log: %w", err)
		}
		n, _ := result.RowsAffected()
		totalDeleted += n
		if n < batchSize {
			break
		}
	}

	return totalDeleted, nil
}

func (s *SQLiteCache) evictOldest(toEvict int64) {
	tx, err := s.db.SQ.Begin()
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	// Clean up stale rows from tables with no FK cascade to entries.
	// All three use the same staleMaxAge cutoff — batched into a single Exec.
	if _, err := tx.Exec(
		`DELETE FROM ip_latency WHERE last_probe_time > 0 AND last_probe_time < unixepoch() - ?;`+
			`DELETE FROM query_log WHERE timestamp < unixepoch() - ?`,
		defaultStaleMaxAge, defaultStaleMaxAge,
	); err != nil {
		log.Debugf("CACHE: stale cleanup failed (non-fatal): %v", err)
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

// ── Set-path helpers ──────────────────────────────────────────────────────

// minTTL returns the smallest positive TTL across all RR sections, falling
// back to DefaultTTL when no TTLs are found.
func minTTL(sections ...[]dns.RR) int {
	minT := -1
	for _, rrs := range sections {
		for _, rr := range rrs {
			if rr != nil {
				if t := int(rr.Header().TTL); t > 0 && (minT < 0 || t < minT) {
					minT = t
				}
			}
		}
	}
	if minT <= 0 {
		return config.DefaultTTL
	}
	return minT
}

// ecsParams extracts the normalised ECS address and source prefix for use as
// cache lookup/store key columns.
func ecsParams(ecs *config.ECSOption) (addr string, prefix int) {
	if ecs == nil {
		return "", 0
	}
	return ecs.Address.String(), int(ecs.SourcePrefix)
}

// stripOPT removes EDNS OPT pseudo-records (TypeOPT) from an RR slice in-place.
// These carry transport-layer padding which has no semantic value but can
// occupy up to 468 bytes per encrypted response.
func stripOPT(rrs []dns.RR) []dns.RR {
	n := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			rrs[n] = rr
			n++
		}
	}
	return rrs[:n]
}
