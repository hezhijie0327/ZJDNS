package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
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

// SQLiteCache is a DNS response cache backed by a SQLite database managed by
// the database package. It implements the Store interface.
type SQLiteCache struct {
	db          *database.DB
	evictCount  atomic.Int64
	statsWriter *BatchWriter[RequestRecord]
	cacheWriter *BatchWriter[cacheWriteItem]

	// pending is the read-through layer for entries awaiting their batch
	// commit: Set() makes an entry visible here immediately; Get() checks it
	// before SQLite; flushCacheEntries removes it once the row lands.
	// nil in tests that hand-construct SQLiteCache.
	pending *lrumap.Map[string, *pendingEntry]

	// optimizeDone stops the background PRAGMA optimize loop (see New).
	optimizeDone chan struct{}

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

	// cacheFormatPrePacked is the BLOB format marker for pre-packed response
	// wire with TTL offset table (format 0x02).
	cacheFormatPrePacked = 0x02

	// fallbackSentinelAddr fills unused ECS fallback slots in StmtEntryFallback.
	// It can never match a stored row — ecs_addr values are IP strings ("" or
	// dotted/colon notation), and "\x00" is not a valid IP string.
	fallbackSentinelAddr = "\x00"

	// maxTTLOffsets caps pooled TTL-offset slices: responses beyond this RR
	// count allocate fresh instead of growing the pool entry (large
	// DNSSEC/ANY responses exceed it routinely).
	maxTTLOffsets = 16
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

// ttloOffsetsPool reuses the per-hit TTL-offset slice (2 bytes per RR).
// Stored as *[]uint16 to avoid interface boxing (SA6002).
var ttloOffsetsPool = sync.Pool{New: func() any { s := make([]uint16, 0, 8); return &s }}

// AcquireTTLOffsets returns a slice of length n from the pool.  The pool
// entries are NOT zeroed on reuse — callers must overwrite every element
// before use (Get writes all n offsets before serving).
func AcquireTTLOffsets(n int) []uint16 {
	s := *ttloOffsetsPool.Get().(*[]uint16)
	if cap(s) < n {
		return make([]uint16, n)
	}
	return s[:n]
}

// ReleaseTTLOffsets returns a pooled offset slice.  Slices grown beyond the
// pool cap are dropped rather than grown in place.
func ReleaseTTLOffsets(s []uint16) {
	if cap(s) <= maxTTLOffsets {
		ttloOffsetsPool.Put(&s)
	}
}

// isZstdCompressed reports whether data starts with the zstd frame magic
// (0x28 0xB5 0x2F 0xFD).  Used to distinguish compressed from raw BLOBs
// without a prefix byte, preserving backward compatibility with entries
// written before threshold compression was introduced.
func isZstdCompressed(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 0x28 && data[1] == 0xB5 && data[2] == 0x2F && data[3] == 0xFD
}

// scanTTLOffsets walks the answer, authority and additional sections of a
// packed DNS message and returns the byte offset of every TTL field.  The
// question section (bytes 12..questionEnd) is skipped.  The returned slice
// is pool-owned — release with ReleaseTTLOffsets when done.
func scanTTLOffsets(wire []byte, questionEnd int) []uint16 {
	offsets := AcquireTTLOffsets(0)
	pos := questionEnd
	for pos+10 <= len(wire) {
		// Skip the owner name (may include compression pointers).
		off, ok := zdnsutil.SkipWireName(wire, pos)
		if !ok || off+10 > len(wire) {
			break
		}
		ttlOff := off + 4                         // TYPE(2) + CLASS(2) = 4 bytes after name
		offsets = append(offsets, uint16(ttlOff)) //nolint:gosec // G115: wire format offset bounded by message size
		rdLen := int(binary.BigEndian.Uint16(wire[off+8:]))
		pos = off + 10 + rdLen // name + TYPE/CLASS/TTL/RDLENGTH(10) + RDATA
	}
	return offsets
}

// WireHasDNSSEC reports whether a packed DNS message contains DNSSEC record
// types (RRSIG/NSEC/NSEC3/DNSKEY/DS) in its answer, authority or additional
// sections.  Used by the Response middleware fast path: a dnssec_ok=0 entry
// stores whatever the DO=1 upstream returned, and a DO=0 client must not
// receive those proofs — if the wire carries any, the response takes the
// unpack+filter path instead of being served directly.
func WireHasDNSSEC(wire []byte) bool {
	// Skip the 12-byte header + question section.
	pos := 12
	questions := int(binary.BigEndian.Uint16(wire[4:6]))
	for range questions {
		off, ok := zdnsutil.SkipWireName(wire, pos)
		if !ok {
			return false
		}
		pos = off + 4 // QTYPE(2) + QCLASS(2)
	}
	// Walk the RR sections checking TYPE codes.
	for pos+10 <= len(wire) {
		off, ok := zdnsutil.SkipWireName(wire, pos)
		if !ok || off+10 > len(wire) {
			return false
		}
		switch binary.BigEndian.Uint16(wire[off:]) {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeDNSKEY, dns.TypeDS:
			return true
		}
		rdLen := int(binary.BigEndian.Uint16(wire[off+8:]))
		pos = off + 10 + rdLen // name + TYPE/CLASS/TTL/RDLENGTH(10) + RDATA
	}
	return false
}

// New creates a cache backed by the given database. The caller is responsible
// for opening the database via database.Open() before calling New.
// New creates a SQLite-backed DNS cache.  Panics if db is nil (caller must
// provide a valid database handle — the server wiring always does).
func New(db *database.DB) *SQLiteCache {
	if db == nil {
		panic("cache: nil database")
	}
	s := &SQLiteCache{
		db:           db,
		optimizeDone: make(chan struct{}),
		pending:      lrumap.New[string, *pendingEntry](config.DefaultCachePendingCapacity),
	}
	// The cache writer's closures capture s, so it is constructed after s.
	s.statsWriter = newStatsBatchWriter(db, config.DefaultAsyncStatsBufferSize)
	s.cacheWriter = s.newCacheBatchWriter()
	go s.optimizeLoop()
	return s
}

// Close flushes and shuts down both async writers, then closes the database.
func (s *SQLiteCache) Close() error {
	// optimizeDone is nil for hand-constructed caches (tests) that never
	// started the optimize loop; the writers are nil there too.
	if s.optimizeDone != nil {
		close(s.optimizeDone)
	}
	if s.cacheWriter != nil {
		s.cacheWriter.Flush()
		s.cacheWriter.Close()
	}
	if s.statsWriter != nil {
		s.statsWriter.Close()
	}
	return s.db.Close()
}

// optimizeLoop refreshes SQLite planner statistics in the background.
// PRAGMA optimize used to run inline in evictIfNeeded on the Set() hot path,
// where it competed for the write lock right at the moment of peak load.
func (s *SQLiteCache) optimizeLoop() {
	defer zdnsutil.HandlePanic("Cache PRAGMA optimize")
	ticker := time.NewTicker(config.DefaultCacheOptimizeInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.db.IsClosed() {
				return
			}
			if _, err := s.db.SQ.Exec("PRAGMA optimize"); err != nil {
				log.Debugf("CACHE: PRAGMA optimize failed: %v", err)
			}
		case <-s.optimizeDone:
			return
		}
	}
}

// Flush forces both async writers (stats records and cache entries) to write
// buffered items immediately.  Primarily for tests that need to observe
// RecordRequest / SQLite results synchronously.
func (s *SQLiteCache) Flush() {
	if s.cacheWriter != nil {
		s.cacheWriter.Flush()
	}
	if s.statsWriter != nil {
		s.statsWriter.Flush()
	}
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

	// Pending read-through: entries awaiting their batch commit are served
	// from memory first (exact key only — ECS fallback candidates are served
	// from SQLite once the exact row commits).
	if s.pending != nil {
		ecsAddr, ecsPrefix := ecsParams(ecs)
		if pe, ok := s.pending.Get(buildCacheKey(qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt)); ok {
			// pe.msgWire is shared with the queued cacheWriteItem AND with
			// concurrent queries.  The serve path mutates the wire in place
			// (TTL deduction, ID/RD patch, TC truncation), so handing out
			// the raw slice would let one query corrupt another's response
			// and commit serve-time bytes as the canonical SQLite row
			// (H7/H10).  The pending window is short — the clone is cheap.
			return s.buildEntry(0, pe.ts, pe.ttl, database.BoolToInt(pe.validated), slices.Clone(pe.msgWire), qname, qtype)
		}
	}

	var id int64
	var ts int64
	var entryTTL int
	var validated int
	var msgWire []byte
	// Single-round-trip lookup over all ECS fallback candidates (exact +
	// standard prefixes), instead of up to 5 sequential QueryRow calls.
	// StmtEntryFallback binds exactly 5 (addr, prefix) pairs with slot order
	// = candidate specificity; unused slots bind a sentinel addr that can
	// never match a stored row.
	candidates := ecsFallbackCandidates(ecs)
	defer releaseECSCandidates(candidates)
	var args [14]any
	args[0], args[1], args[2], args[3] = qname, int(qtype), int(qclass), dnssecInt
	for i := range 5 {
		idx := 4 + i*2
		if i < len(candidates) {
			args[idx], args[idx+1] = candidates[i].addr, candidates[i].prefix
		} else {
			args[idx], args[idx+1] = fallbackSentinelAddr, 0
		}
	}
	// Scan every matching row and keep the most specific candidate (largest
	// ecs_prefix).  StmtEntryFallback carries no ORDER BY — an expression
	// sort built a temporary btree per execution (~16% CPU in load tests);
	// at most 5 rows match, so the winner is picked here.
	rows, err := s.db.StmtEntryFallback.Query(args[:]...)
	if err != nil {
		log.Warnf("CACHE: get query failed for %s (type=%d): %v", qname, qtype, err)
		return nil, false, false
	}
	defer func() { _ = rows.Close() }()
	var rid int64
	var rts int64
	var rttl int
	var rval int
	var rwire []byte
	bestPrefix := -1
	for rows.Next() {
		var rowPrefix int
		if err := rows.Scan(&rowPrefix, &rid, &rts, &rttl, &rval, &rwire); err != nil {
			log.Warnf("CACHE: get scan failed for %s (type=%d): %v", qname, qtype, err)
			return nil, false, false
		}
		if rowPrefix > bestPrefix {
			bestPrefix = rowPrefix
			id, ts, entryTTL, validated, msgWire = rid, rts, rttl, rval, rwire
		}
	}
	if bestPrefix == -1 {
		log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
		return nil, false, false
	}

	return s.buildEntry(id, ts, entryTTL, validated, msgWire, qname, qtype)
}

// GetTypes retrieves the entries for exactly two qtypes of one qname in a
// single query (NS A/AAAA address lookups).  ECS is not supported — entries
// are matched on the empty ECS candidate, and the caller must pass a
// canonical qname.  The pending read-through layer is consulted first (fresh
// entries awaiting their batch commit); SQLite rows fill only the slots the
// pending layer did not serve, so a pending hit is never shadowed by an
// older committed row.
func (s *SQLiteCache) GetTypes(qname string, qclass uint16, qtypes [2]uint16, dnssecOK bool) (entries [2]*Entry, found, expired [2]bool) {
	if s.db.IsClosed() {
		return entries, found, expired
	}

	dnssecInt := database.BoolToInt(dnssecOK)

	if s.pending != nil {
		for i, qt := range qtypes {
			if pe, ok := s.pending.Get(buildCacheKey(qname, qt, qclass, "", 0, dnssecInt)); ok {
				e, f, ex := s.buildEntry(0, pe.ts, pe.ttl, database.BoolToInt(pe.validated), pe.msgWire, qname, qt)
				entries[i], found[i], expired[i] = e, f, ex
			}
		}
	}

	missing := false
	for i := range found {
		if !found[i] {
			missing = true
			break
		}
	}
	if !missing {
		return entries, found, expired
	}

	rows, err := s.db.StmtEntryBatch.Query(qname, int(qclass), dnssecInt, "", 0, int(qtypes[0]), int(qtypes[1]))
	if err != nil {
		log.Warnf("CACHE: two-types get failed for %s: %v", qname, err)
		return entries, found, expired
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var qt int
		var id int64
		var ts int64
		var entryTTL int
		var validated int
		var msgWire []byte
		if err := rows.Scan(&qt, &id, &ts, &entryTTL, &validated, &msgWire); err != nil {
			log.Warnf("CACHE: two-types get scan failed for %s: %v", qname, err)
			return entries, found, expired
		}
		for i := range qtypes {
			if found[i] || int(qtypes[i]) != qt {
				continue
			}
			e, f, ex := s.buildEntry(id, ts, entryTTL, validated, msgWire, qname, qtypes[i])
			entries[i], found[i], expired[i] = e, f, ex
		}
	}
	return entries, found, expired
}

// buildEntry parses a stored BLOB (pre-packed or legacy) into an Entry,
// applying latency sorting.  Shared by the SQLite and pending read-through
// paths.  Returns (entry, found, expired); found=false on corrupt data.
func (s *SQLiteCache) buildEntry(id, ts int64, entryTTL, validated int, msgWire []byte, qname string, qtype uint16) (*Entry, bool, bool) {
	if len(msgWire) < 3 {
		return nil, false, false
	}

	// Format dispatch: pre-packed (0x02) carries a TTL offset table before
	// the DNS wire; legacy entries (<= v3.11.11) are a bare zstd-compressed
	// or raw DNS wire with no marker.  Entries are read without a format
	// check previously — a legacy raw wire whose ID high byte happens to be
	// 0x02 was parsed as pre-packed, and the garbage numOffsets drove the
	// offset-table loop out of bounds (upgrade panic window: entries survive
	// up to DefaultMaxCacheableTTL + DefaultStaleMaxAge = 10 days).
	// msgWire[1] discriminates the collision: it is the high byte of
	// numOffsets (0 for any real entry — responses store fewer than 256
	// RRs), while byte[1] of a raw DNS response is the low byte of the
	// query ID.  If a legacy raw wire slips through (ID low byte 0), the
	// flags bytes are read as numOffsets — always >= 0x8000 because the QR
	// flag is set — which the bounds check below rejects (> (len-3)/2 for
	// any legal message size), so no legacy row can ever be misparsed.
	var (
		wire    []byte
		offsets []uint16
	)
	if msgWire[0] == cacheFormatPrePacked && msgWire[1] == 0 {
		numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]))
		// Bounds check: a corrupt row must not drive the offset table past
		// the BLOB end (previously a slice-bounds panic).
		if numOffsets > (len(msgWire)-3)/2 {
			log.Warnf("CACHE: entry %d (name=%s type=%d) offset table out of bounds: %d offsets in %d bytes", id, qname, qtype, numOffsets, len(msgWire))
			return nil, false, false
		}
		offsets = AcquireTTLOffsets(numOffsets)
		for i := range numOffsets {
			offsets[i] = binary.BigEndian.Uint16(msgWire[3+i*2:])
		}
		wire = msgWire[3+numOffsets*2:]
	} else {
		// Legacy format (<= v3.11.11): zstd-compressed or raw DNS wire
		// without a marker.  No TTL offset table — TTLs are served at their
		// stored values, expiring naturally within the migration window.
		wire = msgWire
	}

	// Threshold decompression.
	var owned []byte
	if isZstdCompressed(wire) {
		dbuf, ok := decompressBufPool.Get().(*[]byte)
		if !ok {
			b := make([]byte, 0, decompressBufCap)
			dbuf = &b
		}
		var err error
		wire, err = zdnsutil.DecompressTo(wire, *dbuf)
		if err != nil {
			ReleaseTTLOffsets(offsets)
			clear(*dbuf)
			decompressBufPool.Put(dbuf)
			log.Warnf("CACHE: decompress wire for entry %d (name=%s type=%d): %v", id, qname, qtype, err)
			return nil, false, false
		}
		defer func() { clear(*dbuf); decompressBufPool.Put(dbuf) }()
		// Copy out of the pool buffer — it is cleared when Get() returns.
		owned = make([]byte, len(wire))
		copy(owned, wire)
	} else {
		// Uncompressed: wire is a slice of the fresh per-row msgWire buffer
		// allocated by the SQLite driver — safe to keep by reference, no copy.
		// For the pending read-through path the buffer is shared with the
		// queued write item — callers only read ResponseWire (rebuilds
		// allocate fresh), so aliasing is safe.
		owned = wire
	}
	entry := &Entry{
		ID:           id,
		Timestamp:    ts,
		TTL:          entryTTL,
		Validated:    validated != 0,
		ResponseWire: owned,
		TTLOffsets:   offsets,
	}
	// When latency data is available, sort A/AAAA records and
	// rebuild ResponseWire so the pre-packed response serves IPs
	// in latency order.  This is the only path that mutates
	// ResponseWire after Set() — latency data may arrive after the
	// entry was stored.
	if s.hasLatencyData.Load() {
		_ = entry.Unpack()
		s.sortAnswerByLatency(entry)
		if len(entry.Answer) > 0 {
			entry.rebuildResponseWire()
		}
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
	answer, authority, additional []dns.RR, validated bool, rcode uint16,
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

	// Clone records to prevent downstream mutations (e.g. TTL deduction in
	// the response path rewriting rr.Header()) from corrupting the cache.
	answer = zdnsutil.CloneRRs(answer)
	authority = zdnsutil.CloneRRs(authority)

	// NOTE: the stored wire keeps the RAW records (DNSSEC proofs included —
	// upstream queries always carry DO=1 per RFC 6840 §5.9).  DNSSEC
	// filtering for dnssec_ok=0 entries happens at SERVE time (WireHasDNSSEC
	// gate + ProcessRecords in the Response middleware) so the zone-key cache
	// (CacheZoneKeys, which stores verified DNSKEYs under dnssec_ok=0) keeps
	// its raw content.

	// Build a complete DNS response message and pack it so the
	// cache-hit path can serve the wire directly (skipping Unpack+Pack).
	// The question section uses the canonical qname and the original
	// qtype/qclass — the response echoes them exactly per RFC 1035 §4.1.1.
	queryMsg := new(dns.Msg)
	dnsutil.SetQuestion(queryMsg, qname, qtype)
	// Pack the query just to get the wire-format question section length.
	if err := queryMsg.Pack(); err != nil {
		log.Debugf("CACHE: skipping cache write for %s (type=%d): query pack failed: %v", qname, qtype, err)
		return 0
	}

	// Sort A/AAAA records by latency before packing — the pre-packed
	// wire preserves this order and serves it directly without re-sorting.
	if s.hasLatencyData.Load() && len(answer) > 1 {
		tmp := &Entry{Answer: answer}
		s.sortAnswerByLatency(tmp)
		answer = tmp.Answer
	}

	msg := pool.DefaultMessage.Get()
	dnsutil.SetReply(msg, queryMsg)
	// The pre-packed wire is served verbatim on cache hits (both the
	// direct-wire fast path and the Unpack path re-derive header flags from
	// the stored wire) — complete the fields SetReply leaves wrong: RA
	// (recursion available), AD (authenticated data for validated entries)
	// and the RCODE (SetReply always resets it to NOERROR — NXDOMAIN
	// entries would otherwise be served as NODATA on every cache hit).
	msg.RecursionAvailable = true
	if validated {
		msg.AuthenticatedData = true
	}
	msg.Rcode = rcode
	msg.Answer = answer
	msg.Ns = authority
	msg.Extra = additional
	if err := msg.Pack(); err != nil {
		log.Debugf("CACHE: skipping cache write for %s (type=%d): pack failed: %v", qname, qtype, err)
		pool.DefaultMessage.Put(msg)
		return 0
	}

	// Scan TTL offsets in the packed response, skipping the 12-byte
	// header plus the question section.  queryMsg.Data = query_header(12)
	// + question_wire, so len(queryMsg.Data) = response_header(12) +
	// question_wire — the exact offset where the answer section begins.
	ttlOffsets := scanTTLOffsets(msg.Data, len(queryMsg.Data))

	// Build the pre-packed BLOB:
	//   [0x02] [2:num_offsets] [2 each:offset] [wire]
	// The wire portion may be zstd-compressed if above threshold.
	wire := msg.Data
	if len(wire) > config.DefaultCompressionThreshold {
		wire = zdnsutil.Compress(wire)
	}
	pool.DefaultMessage.Put(msg)

	// Build the BLOB with exact-size preallocation — a bytes.Buffer would
	// grow geometrically and copy.  [0x02] [2:num_offsets] [2 each:offset] [wire]
	msgWire := make([]byte, 0, 3+2*len(ttlOffsets)+len(wire))
	msgWire = append(msgWire, cacheFormatPrePacked)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(ttlOffsets))) //nolint:gosec // G115: offset count bounded by RR count
	msgWire = append(msgWire, lenBuf[:]...)
	for _, off := range ttlOffsets {
		binary.BigEndian.PutUint16(lenBuf[:], off)
		msgWire = append(msgWire, lenBuf[:]...)
	}
	msgWire = append(msgWire, wire...)
	ReleaseTTLOffsets(ttlOffsets)

	// ── Async write-back ─────────────────────────────────────────────────
	// The entry is committed to SQLite in a background batched transaction
	// (amortising BEGIN/COMMIT + index seeks across rows — one transaction
	// per DefaultAsyncCacheBatchSize entries instead of one per entry).  It
	// is made visible to Get() immediately through the pending read-through
	// layer, so a re-query within the flush window still hits.  A saturated
	// write queue drops the entry (best-effort); the query path never blocks.
	allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
	allRRs = append(allRRs, answer...)
	allRRs = append(allRRs, authority...)
	allRRs = append(allRRs, additional...)
	recs := extractPtrRecs(allRRs)

	key := buildCacheKey(qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt)
	pe := &pendingEntry{msgWire: msgWire, ts: now, ttl: entryTTL, validated: validated}
	if s.cacheWriter != nil {
		if s.pending != nil {
			s.pending.Set(key, pe)
		}
		s.cacheWriter.Enqueue(cacheWriteItem{
			key:        key,
			pendingPtr: pe,
			qname:      qname,
			qtype:      qtype,
			qclass:     qclass,
			ecsAddr:    ecsAddr,
			ecsPrefix:  ecsPrefix,
			dnssecInt:  dnssecInt,
			now:        now,
			ttl:        entryTTL,
			validated:  validated,
			msgWire:    msgWire,
			ptrRecs:    recs,
		})
		return 0
	}

	// Synchronous fallback when no async writer is configured (tests that
	// hand-construct SQLiteCache) — same semantics as RecordRequest's
	// fallback: callers observe results immediately.
	return s.setSync(qname, qtype, qclass, ecsAddr, ecsPrefix, dnssecInt, now, entryTTL, validated, msgWire, recs)
}

// setSync performs the original synchronous write transaction.  Used only
// when no async writer is configured (tests); the production path enqueues.
func (s *SQLiteCache) setSync(qname string, qtype, qclass uint16, ecsAddr string, ecsPrefix, dnssecInt int,
	now int64, entryTTL int, validated bool, msgWire []byte, recs []ptrRec,
) int64 {
	writeCtx, cancel := context.WithTimeout(context.Background(), config.DefaultCacheWriteTimeout)
	defer cancel()
	var entryID int64
	tx, txErr := s.db.SQ.BeginTx(writeCtx, nil)
	if txErr == nil {
		defer func() { _ = tx.Rollback() }()

		// Distinguish a fresh insert from a REPLACE of an existing row:
		// REPLACE deletes and reinserts, leaving the row count unchanged, so
		// only new rows may increment the entry counter.
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

				if len(recs) > 0 {
					if err := insertPtrRecs(tx, entryID, recs); err != nil {
						// Best-effort: a failure here must not abort the
						// transaction — the cached entry is more valuable
						// than reverse-lookup data.
						log.Warnf("CACHE: insert ptr_map failed (non-fatal): %v", err)
					}
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
	// every 20 evictions to correct drift from concurrent writers.  The
	// counter can only drift upward (TOCTOU duplicate inserts), never below
	// zero — the resync is purely periodic (R3-L25).
	count = s.db.EntryCount()
	if s.evictCount.Load()%20 == 0 {
		if err := s.db.SQ.QueryRow("SELECT COUNT(*) FROM entries").Scan(&count); err == nil {
			s.db.SetEntryCount(count)
		}
	}

	excess := count - maxEntries
	if excess <= 0 {
		return
	}

	s.evictCount.Add(1)
	s.evictOldest(excess)
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
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultCacheWriteTimeout)
	defer cancel()
	batchSize := int64(config.DefaultPruneBatchSize)
	dayCutoff := log.NowUnix()/86400 - retentionSec/86400

	// query_stats and query_log: bounded deletes.  A single unbounded DELETE
	// of the accumulated rows holds the write lock past the
	// DefaultCacheWriteTimeout; the stuck transaction then occupies a pool
	// connection and every subsequent SQLite write (cache flush, stats)
	// hits busy — queries fail until the process restarts.  Each bounded
	// batch commits quickly and a timeout only aborts the current batch
	// (retried on the next ticker run).
	var totalDeleted int64

	// query_stats is WITHOUT ROWID (composite PK) — no rowid to batch on.
	// Delete one day per iteration: rows are aggregated per
	// result×protocol×rcode×dnssec×poisoned combination, so a single day
	// is tiny and the loop is bounded by the accumulated history.
	var minDay int64
	if err := s.db.SQ.QueryRow(
		`SELECT COALESCE(MIN(stat_day), 0) FROM query_stats`,
	).Scan(&minDay); err != nil {
		return 0, fmt.Errorf("cleanup query_stats: %w", err)
	}
	for day := dayCutoff - 1; day >= minDay; day-- {
		result, err := s.db.SQ.ExecContext(
			ctx, `DELETE FROM query_stats WHERE stat_day = ?`, day,
		)
		if err != nil {
			return totalDeleted, fmt.Errorf("cleanup query_stats: %w", err)
		}
		n, _ := result.RowsAffected()
		totalDeleted += n
	}

	for {
		result, err := s.db.SQ.ExecContext(
			ctx,
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
	// Bounded like Set(): eviction must never hang the query path.
	ctx, cancel := context.WithTimeout(context.Background(), config.DefaultCacheWriteTimeout)
	defer cancel()
	tx, err := s.db.SQ.BeginTx(ctx, nil)
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
