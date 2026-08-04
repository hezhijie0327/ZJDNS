package cache

import (
	"database/sql"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// SQLiteCache is a DNS response cache backed by a SQLite database managed by
// the database package. It implements the Store interface.
type SQLiteCache struct {
	db          *database.DB
	evictCount  atomic.Int64
	asyncWriter *AsyncStatsWriter

	// hasLatencyData gates sortAnswerByLatency: when false (no latency data has
	// ever been written), the per-hit ip_latency query is skipped entirely,
	// saving a SQLite round trip on the cache-hit hot path.
	hasLatencyData atomic.Bool
}

// ecsCandidate is a single ECS cache-key candidate used during fallback lookup.
type ecsCandidate struct {
	addr   string
	prefix int
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

// ECS fallback prefix boundaries — standard CIDR granularities most commonly
// used by CDN and authoritative DNS operators (RFC 7871).
var (
	ipv4FallbackPrefixes = []int{24, 16, 8, 0}
	ipv6FallbackPrefixes = []int{56, 48, 32, 0}
)

// ecsCandidatesPool reuses the per-lookup fallback candidate slice (at most
// 5 entries) on the cache.Get hot path. Stored as *[]ecsCandidate to avoid
// interface boxing (SA6002).
var ecsCandidatesPool = sync.Pool{New: func() any { c := make([]ecsCandidate, 0, 5); return &c }}

// isZstdCompressed reports whether data starts with the zstd frame magic
// (0x28 0xB5 0x2F 0xFD).  Used to distinguish compressed from raw BLOBs
// without a prefix byte, preserving backward compatibility with entries
// written before threshold compression was introduced.
func isZstdCompressed(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD
}

// New creates a cache backed by the given database. The caller is responsible
// for opening the database via database.Open() before calling New.
// New creates a SQLite-backed DNS cache.  Panics if db is nil (caller must
// provide a valid database handle — the server wiring always does).
func New(db *database.DB) *SQLiteCache {
	if db == nil {
		panic("cache: nil database")
	}
	return &SQLiteCache{
		db:          db,
		asyncWriter: NewAsyncStatsWriter(db, config.DefaultAsyncStatsBufferSize),
	}
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
// The caller must pass a canonical qname (dnsutil.Canonical).
func (s *SQLiteCache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	if s.db.IsClosed() {
		return nil, false, false
	}

	dnssecInt := database.BoolToInt(dnssecOK)
	var id int64
	var ts int64
	var entryTTL int
	var validated int
	var msgWire []byte
	found := false
	candidates := ecsFallbackCandidates(ecs)
	defer releaseECSCandidates(candidates)
	for _, c := range candidates {
		err := s.db.StmtEntry.QueryRow(
			qname, int(qtype), int(qclass), c.addr, c.prefix, dnssecInt,
		).Scan(&id, &ts, &entryTTL, &validated, &msgWire)
		if err == nil {
			found = true
			break
		}
		if !errors.Is(err, sql.ErrNoRows) {
			log.Warnf("CACHE: get query failed for %s (type=%d): %v", qname, qtype, err)
			return nil, false, false
		}
	}
	if !found {
		log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
		return nil, false, false
	}

	if len(msgWire) == 0 {
		return nil, false, false
	}

	// If the BLOB is zstd-compressed (starts with zstd frame magic),
	// decompress it.  Entries below DefaultCompressionThreshold are
	// stored raw — the wire format is already compact and small entries
	// don't benefit from compression.
	var wire []byte
	if isZstdCompressed(msgWire) {
		// Use a pooled buffer as the decompression destination to reduce
		// per-cache-hit heap allocations (P3).  The buffer is returned to
		// the pool after entry fields are extracted and msg.Data is cleared.
		dbuf, ok := decompressBufPool.Get().(*[]byte)
		if !ok {
			b := make([]byte, 0, decompressBufCap)
			dbuf = &b
		}
		var err error
		wire, err = zdnsutil.DecompressTo(msgWire, *dbuf)
		if err != nil {
			clear(*dbuf)
			decompressBufPool.Put(dbuf)
			log.Warnf("CACHE: decompress wire for entry %d (name=%s type=%d): %v", id, qname, qtype, err)
			return nil, false, false
		}
		defer func() { clear(*dbuf); decompressBufPool.Put(dbuf) }()
	} else {
		wire = msgWire
	}

	msg := pool.DefaultMessage.Get()
	// Safety: msg.Data aliases the decompression buffer.  The LIFO defer
	// chain guarantees msg.Put (which zeroes Data) runs before dbuf is
	// returned to decompressBufPool.  Do not insert new logic between
	// the msg.Get and this line without understanding the ordering.
	msg.Data = wire
	if err := msg.Unpack(); err != nil {
		// Deferred Put (line below) returns msg to the pool — do not
		// double-Put here.
		log.Warnf("CACHE: unpack wire for entry %d (name=%s type=%d): %v", id, qname, qtype, err)
		return nil, false, false
	}
	defer pool.DefaultMessage.Put(msg)

	// Detach RR name strings from msg.Data (which aliases the decompress
	// buffer) so the returned Entry is self-contained.  This enables the
	// ProcessRecords fast path when elapsed==0 — no RR clones needed when
	// TTL is unchanged.
	detachRRNames(msg.Answer)
	detachRRNames(msg.Ns)
	detachRRNames(msg.Extra)

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
	if !s.hasLatencyData.Load() || len(entry.Answer) <= 1 {
		return
	}

	// Single pass: extract IP strings + collect for batch lookup.
	rrToIP := make(map[dns.RR]string, len(entry.Answer))
	ips := make([]string, 0, len(entry.Answer))
	for _, rr := range entry.Answer {
		if ip, ok := zdnsutil.ExtractIPString(rr); ok {
			rrToIP[rr] = ip
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

	// In-place sort using pre-computed IP strings — avoids O(n log n)
	// type-switch calls inside the comparator.
	slices.SortStableFunc(entry.Answer, func(a, b dns.RR) int {
		aIP, aIsAddr := rrToIP[a]
		bIP, bIsAddr := rrToIP[b]
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

	// Query SQLite for latency data.
	latencies := make(map[string]int, min(len(ips), maxLatencyLookupIPs))
	argsPtr, ok := latencyArgsPool.Get().(*[maxLatencyLookupIPs]any)
	if !ok {
		a := [maxLatencyLookupIPs]any{}
		argsPtr = &a
	}
	defer func() {
		for i := range maxLatencyLookupIPs {
			argsPtr[i] = nil
		}
		latencyArgsPool.Put(argsPtr)
	}()
	for i := range maxLatencyLookupIPs {
		if i < len(ips) {
			argsPtr[i] = ips[i]
		} else {
			argsPtr[i] = ""
		}
	}

	rows, err := s.db.StmtIPLatency.Query(argsPtr[:]...)
	if err != nil {
		return latencies
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var ip string
		var lat int
		if err := rows.Scan(&ip, &lat); err == nil {
			latencies[ip] = lat
		}
	}
	if err := rows.Err(); err != nil {
		log.Warnf("CACHE: latency rows iteration failed: %v", err)
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

	// Strip EDNS OPT pseudo-record from additional before caching
	// (padding and other EDNS options have no semantic value and waste
	// storage space, up to 468 bytes per encrypted response). The
	// single-pass clone+filter below avoids the double deep copy of the
	// previous stripOPT(zdnsutil.CloneRRs(x)) then zdnsutil.CloneRRs(x).
	additional = cloneRRsNoOPT(additional)

	// Clone records to prevent downstream mutations (e.g. restoreDomain
	// rewriting rr.Header().Name) from corrupting the cache.
	answer = zdnsutil.CloneRRs(answer)
	authority = zdnsutil.CloneRRs(authority)

	// Pack wire format and compress.
	msg := pool.DefaultMessage.Get()
	msg.Answer = answer
	msg.Ns = authority
	msg.Extra = additional
	if err := msg.Pack(); err != nil {
		// Uncacheable response (e.g. oversized): skip the insert entirely —
		// a NULL msg_wire row can never be served (Get treats it as a miss)
		// yet occupies a slot and would inflate the entry counter.
		log.Debugf("CACHE: skipping cache write for %s (type=%d): pack failed: %v", qname, qtype, err)
		pool.DefaultMessage.Put(msg)
		return 0
	}
	// Compress only entries above the threshold — small entries
	// (simple A/AAAA) don't compress well and the per-hit decompression
	// cost outweighs the negligible storage savings.
	var msgWire []byte
	if len(msg.Data) > config.DefaultCompressionThreshold {
		msgWire = zdnsutil.Compress(msg.Data)
	} else {
		msgWire = make([]byte, len(msg.Data))
		copy(msgWire, msg.Data)
	}
	pool.DefaultMessage.Put(msg)

	// ── Transaction ──────────────────────────────────────────────────────
	// SQLite WAL mode serializes writers, so no application-level mutex is
	// needed for concurrent Set() calls.
	var entryID int64
	tx, txErr := s.db.SQ.Begin()
	if txErr == nil {
		defer func() { _ = tx.Rollback() }()

		// Distinguish a fresh insert from a REPLACE of an existing row:
		// REPLACE deletes and reinserts, leaving the row count unchanged, so
		// only new rows may increment the entry counter. (Previously the
		// counter was incremented unconditionally, drifting above the real
		// row count on every refresh of an expired-but-present key and
		// evicting valid entries prematurely.) Both statements are prepared
		// in database/stmts.go — QueryRow on raw SQL would prepare per call.
		var exists bool
		txErr = tx.Stmt(s.db.StmtEntryExists).QueryRow(
			qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
		).Scan(&exists)

		if txErr == nil {
			if txErr = tx.Stmt(s.db.StmtEntryInsert).QueryRow(
				qname, int(qtype), int(qclass), ecsAddr, ecsPrefix, dnssecInt,
				now, entryTTL, now+int64(entryTTL), database.BoolToInt(validated),
				msgWire,
			).Scan(&entryID); txErr == nil {

				// Populate ptr_map for reverse (PTR) lookups — best-effort:
				// a failure here must not abort the transaction, because the
				// cached entry is more valuable than reverse-lookup data.
				allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
				allRRs = append(allRRs, answer...)
				allRRs = append(allRRs, authority...)
				allRRs = append(allRRs, additional...)
				if err := insertPtrMap(tx, entryID, allRRs); err != nil {
					log.Warnf("CACHE: insert ptr_map failed (non-fatal): %v", err)
				}

				if txErr = tx.Commit(); txErr == nil {
					if !exists {
						s.db.AddEntryCount(1)
					}
				} else {
					log.Warnf("CACHE: commit tx failed: %v", txErr)
				}
			}
		}
		if txErr != nil {
			entryID = 0
			log.Warnf("CACHE: insert entry failed: %v", txErr)
		}
	}
	if txErr != nil {
		return 0
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

	// Fast path: the atomic counter is accurate — Set() only increments it for
	// fresh inserts, so it tracks the real row count. Skip the DB COUNT(*) when
	// comfortably below limit.
	count := s.db.EntryCount()
	maxEntries := int64(s.db.MaxEntries())
	if count < maxEntries*9/10 {
		return
	}

	// Use the atomic entry counter for fast-path checks; resync from DB
	// every 20 evictions to correct drift from concurrent writers.
	count = s.db.EntryCount()
	if count < 0 || s.evictCount.Load()%20 == 0 {
		if err := s.db.SQ.QueryRow("SELECT COUNT(*) FROM entries").Scan(&count); err == nil {
			s.db.SetEntryCount(count)
		}
	}

	excess := count - maxEntries
	if excess <= 0 {
		return
	}

	s.evictOldest(excess)

	// Throttle PRAGMA optimize to every 10th eviction to avoid per-eviction overhead.
	if s.evictCount.Add(1)%10 == 0 {
		_, _ = s.db.SQ.Exec("PRAGMA optimize") // _, _ = result, error: PRAGMA optimize is best-effort
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

	// Common cutoff: now minus staleMaxAge — used by all cleanup
	// statements below to identify rows past the retention window.
	staleCutoff := log.NowUnix() - defaultStaleMaxAge

	// Clean up stale rows from tables with no FK cascade to entries.
	// All three use the same staleCutoff — batched into a single Exec.
	if _, err := tx.Exec(
		`DELETE FROM ip_latency WHERE last_probe_time > 0 AND last_probe_time < ?; `+
			`DELETE FROM query_log WHERE timestamp < ?`,
		staleCutoff, staleCutoff,
	); err != nil {
		log.Debugf("CACHE: stale cleanup failed (non-fatal): %v", err)
	}

	// Two-phase eviction:
	// Phase 1 — entries past serve-stale (expires_at < staleCutoff). These
	// can no longer serve stale and are worthless. idx_entries_expires
	// enables an index-assisted range scan for the WHERE filter.
	// Phase 2 — if still over limit, evict the oldest entries regardless.
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
// back to DefaultTTL when no TTLs are found.  The result is capped at
// config.DefaultMaxCacheableTTL to prevent unbounded caching (RFC 8767 §4).
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
	if minT > config.DefaultMaxCacheableTTL {
		return config.DefaultMaxCacheableTTL
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

// maskIP applies a CIDR mask to ip, returning a new net.IP with its own
// backing array so the caller cannot inadvertently mutate the original IP.
func maskIP(ip net.IP, prefixBits int) net.IP {
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	mask := net.CIDRMask(prefixBits, bits)
	if mask == nil {
		return ip
	}
	masked := ip.Mask(mask)
	result := make(net.IP, len(masked))
	copy(result, masked)
	return result
}

// ecsFallbackCandidates generates ECS cache-key candidates from most specific
// to least specific, on a pooled slice (every returned slice is pool-owned —
// never a shared static, so a concurrent Get can safely reuse the backing
// array after release). nil ECS returns only the zero-value candidate (no
// fallback). IPv4 falls back through /24, /16, /8, /0; IPv6 through /56,
// /48, /32, /0.
func ecsFallbackCandidates(ecs *config.ECSOption) []ecsCandidate {
	candidates := (*ecsCandidatesPool.Get().(*[]ecsCandidate))[:0]
	if ecs == nil {
		return append(candidates, ecsCandidate{"", 0})
	}
	candidates = append(candidates, ecsCandidate{ecs.Address.String(), int(ecs.SourcePrefix)})
	standardPrefixes := ipv4FallbackPrefixes
	if ecs.Address.To4() == nil {
		standardPrefixes = ipv6FallbackPrefixes
	}
	for _, p := range standardPrefixes {
		if p < int(ecs.SourcePrefix) {
			masked := maskIP(ecs.Address, p)
			candidates = append(candidates, ecsCandidate{masked.String(), p})
		}
	}
	return candidates
}

// releaseECSCandidates returns a pooled candidate slice to the pool.
func releaseECSCandidates(candidates []ecsCandidate) {
	// Pool entries are capped at 5 elements; anything larger (never in
	// practice) is dropped rather than grown in place.
	if cap(candidates) <= 5 {
		ecsCandidatesPool.Put(&candidates)
	}
}

// detachRRNames copies the Header().Name of each RR to a new string so the
// name no longer aliases the decompression buffer.  After detachment the RRs
// are self-contained and safe to use after the buffer is returned to the pool.
func detachRRNames(rrs []dns.RR) {
	for _, rr := range rrs {
		rr.Header().Name = strings.Clone(rr.Header().Name)
	}
}

// cloneRRsNoOPT returns a deep copy of rrs excluding OPT pseudo-records.
// These carry transport-layer padding which has no semantic value but can
// occupy up to 468 bytes per encrypted response. The input slice belongs to
// the caller, so filtering must not modify it in place (the previous stripOPT
// required a pre-clone that doubled the deep copy on the cache write path).
func cloneRRsNoOPT(rrs []dns.RR) []dns.RR {
	n := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	out := make([]dns.RR, n)
	j := 0
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			out[j] = rr.Clone()
			j++
		}
	}
	return out
}
