package cache

import (
	"encoding/binary"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"
	"zjdns/internal/spillfile"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// Cache is an in-memory DNS response cache backed by an LRU map, with an
// optional disk spill tier.  It implements the Store interface.  The name
// is historical — there is no SQLite involvement.
type Cache struct {
	entries    *lrumap.Map[string, *cacheEntry] // cache key → entry
	maxEntries int
	statsMgr   *Manager // in-memory query stats + per-RCODE top-N journal

	// spill is the second-tier disk store: evicted-but-fresh entries land
	// here and are promoted back on a memory miss.  nil when no state_file
	// is configured (single-tier mode).
	spill    *spillfile.Store
	spillCap int // spill file record cap (≤0 = unbounded)

	// hasLatencyData gates sortAnswerByLatency: when false (no latency data has
	// ever been written), the per-hit latency lookup is skipped entirely.
	hasLatencyData atomic.Bool

	// latencies holds per-IP latency data — written by background latency
	// probes, read on the cache-hit hot path (sortAnswerByLatency).  LRU-
	// bounded (latencyMax), TTL-expired lazily on read and physically
	// cleaned by CleanupLatency.
	latencies  *lrumap.Map[string, latEntry]
	latencyMax int

	// spillLat is the latency-table spill tier (same role as spill).
	spillLat    *spillfile.Store
	spillLatCap int
}

// cacheEntry is one cached DNS response.  msgWire is the pre-packed response
// (format 0x02) with TTL-offset table.  TTL expiry is checked lazily on read.
type cacheEntry struct {
	msgWire   []byte
	ts        int64 // log.NowUnix() at store
	ttl       int
	validated bool
}

// latEntry is the in-memory form of the former ip_latency table row.
type latEntry struct {
	latency   int   // measured latency in ms
	lastProbe int64 // log.NowUnix() at probe time; 0 = never probed
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
// sections.  Used by the Response middleware fast path: entries store
// whatever the DO=1 upstream returned (the key never splits on the client's
// DO bit), and a DO=0 client must not receive those proofs — if the wire
// carries any, the response takes the unpack+filter path instead of being
// served directly.
func WireHasDNSSEC(wire []byte) bool {
	// buildEntry only guarantees len >= 3 — a corrupt/truncated wire must
	// not index out of range (M-low).
	if len(wire) < 12 {
		return false
	}
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

// New creates a two-tier cache with the given entry and latency capacities
// (<= 0 applies the config defaults).  A non-empty spill path enables the
// disk tier for that store: the spill file is opened and its hottest
// entries (by store timestamp) are loaded into memory, up to the mem cap;
// the rest stay on disk and are promoted back on a memory miss.
func New(entriesLimit, latencyLimit config.LimitSettings, spillPath, latencySpillPath string) *Cache {
	maxEntries := entriesLimit.Mem
	if maxEntries <= 0 {
		maxEntries = config.DefaultMaxCacheEntries
	}
	latencyMax := latencyLimit.Mem
	if latencyMax <= 0 {
		latencyMax = config.DefaultMaxLatencyEntries
	}
	c := &Cache{
		entries:    lrumap.New[string, *cacheEntry](maxEntries),
		maxEntries: maxEntries,
		statsMgr:   newStatsJournal(0),
		latencies:  lrumap.New[string, latEntry](latencyMax),
		latencyMax: latencyMax,
	}
	c.loadSpill(spillPath, entriesLimit.Disk, maxEntries)
	c.loadLatencySpill(latencySpillPath, latencyLimit.Disk, latencyMax)
	return c
}

// loadSpill opens the entries spill store and warms memory with its hottest
// entries.  On failure (foreign/corrupt file) the disk tier is disabled —
// the cache still works, just single-tier.
func (s *Cache) loadSpill(path string, diskCap, maxEntries int) {
	if path == "" {
		return
	}
	spill, err := spillfile.Open(path)
	if err != nil {
		log.Warnf("CACHE: spill store open failed (disk tier disabled): %v", err)
		return
	}
	s.spill = spill
	s.spillCap = diskCap

	entries := spill.Entries()
	sort.Slice(entries, func(i, j int) bool { return entries[i].Ts < entries[j].Ts })
	n := 0
	for _, e := range entries {
		if n >= maxEntries {
			break
		}
		if !ttl.CanServeExpired(e.Ts, e.Ttl, config.DefaultStaleMaxAge) {
			spill.Delete(e.Key) // past the stale window — dead weight
			continue
		}
		ts, entryTTL, validated, wire, ok := spill.Get(e.Key)
		if !ok {
			continue
		}
		// Coldest first so the hottest entry ends up at the LRU front.
		s.entries.Set(e.Key, &cacheEntry{msgWire: wire, ts: ts, ttl: entryTTL, validated: validated})
		n++
	}
	// Spill-on-evict registered AFTER the warm-up load — load-time capacity
	// evictions must not re-spill the very entries just read back.
	s.entries.SetOnEvict(func(key string, ce *cacheEntry) {
		if ce.ts > 0 && ttl.CanServeExpired(ce.ts, ce.ttl, config.DefaultStaleMaxAge) {
			_ = s.spill.Put(key, ce.ts, ce.ttl, ce.validated, ce.msgWire)
		}
	})
	log.Infof("CACHE: spill store ready: %d records on disk, %d loaded to memory", spill.EntryCount(), n)
}

// Close flushes and closes the spill stores (the in-memory LRUs need no
// cleanup).
func (s *Cache) Close() error {
	var err error
	if s.spill != nil {
		if e := s.spill.Close(); e != nil && err == nil {
			err = e
		}
	}
	if s.spillLat != nil {
		if e := s.spillLat.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// Flush pushes every in-memory entry to its spill store (skipping records
// already on disk unchanged) and fsyncs — called at shutdown so a restart
// warms from disk.  No-op without a disk tier.
func (s *Cache) Flush() {
	if s.spill != nil {
		s.entries.Range(func(key string, ce *cacheEntry) bool {
			if ce.ts > 0 && ttl.CanServeExpired(ce.ts, ce.ttl, config.DefaultStaleMaxAge) && !s.spill.Indexed(key, ce.ts) {
				_ = s.spill.Put(key, ce.ts, ce.ttl, ce.validated, ce.msgWire)
			}
			return true
		})
	}
	if s.spillLat != nil {
		s.latencies.Range(func(key string, e latEntry) bool {
			if e.lastProbe > 0 && !s.spillLat.Indexed(key, e.lastProbe) {
				_ = s.spillLat.Put(key, e.lastProbe, 0, false, marshalLatency(e))
			}
			return true
		})
	}
	if s.spill != nil {
		_ = s.spill.Flush()
	}
	if s.spillLat != nil {
		_ = s.spillLat.Flush()
	}
}

// EntryCount returns the number of cached entries.
func (s *Cache) EntryCount() int { return s.entries.Len() }

// LatencyCount returns the number of per-IP latency entries.
func (s *Cache) LatencyCount() int { return s.latencies.Len() }

// buildCacheKey is the exact cache key: the composite (qname, qtype, qclass,
// ecs_addr, ecs_prefix) flattened to a string for the LRU map.  The key
// excludes the client's DO bit: outbound queries always carry DO=1
// (RFC 6840 §5.9) and DO=0 filtering happens at serve time — a DO-split key
// would store the identical raw wire twice per name.
func buildCacheKey(qname string, qtype, qclass uint16, ecsAddr string, ecsPrefix int) string {
	var b strings.Builder
	b.WriteString(qname)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(int(qtype)))
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(int(qclass)))
	b.WriteByte(0)
	b.WriteString(ecsAddr)
	b.WriteByte(0)
	b.WriteString(strconv.Itoa(ecsPrefix))
	return b.String()
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
// The caller must pass a canonical qname (dnsutil.Canonical).
//
// On a memory miss the disk spill tier is consulted; a fresh spill hit is
// promoted back into memory (which may itself evict the LRU tail — that
// entry spills to disk in turn).
func (s *Cache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption) (*Entry, bool, bool) {
	// ECS fallback candidates from most to least specific — the first hit is
	// the most specific match (the former SQL picked max(ecs_prefix) over the
	// 5-candidate lookup).
	candidates := ecsFallbackCandidates(ecs)
	defer releaseECSCandidates(candidates)
	for _, c := range candidates {
		key := buildCacheKey(qname, qtype, qclass, c.addr, c.prefix)
		if ce, ok := s.entries.Get(key); ok {
			return s.buildEntry(ce.ts, ce.ttl, ce.validated, ce.msgWire, qname, qtype)
		}
		if s.spill != nil {
			if entry, found := s.getFromSpill(key); found {
				return s.buildEntry(entry.ts, entry.ttl, entry.validated, entry.msgWire, qname, qtype)
			}
		}
	}
	log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
	return nil, false, false
}

// getFromSpill reads a spill record by key and promotes it to memory.  An
// expired record is dropped from the index (the file record lingers until
// compaction).  Returns (entry, false) on miss or expiry.
func (s *Cache) getFromSpill(key string) (*cacheEntry, bool) {
	ts, entryTTL, validated, wire, ok := s.spill.Get(key)
	if !ok {
		return nil, false
	}
	if !ttl.CanServeExpired(ts, entryTTL, config.DefaultStaleMaxAge) {
		s.spill.Delete(key)
		return nil, false
	}
	ce := &cacheEntry{msgWire: wire, ts: ts, ttl: entryTTL, validated: validated}
	s.entries.Set(key, ce)
	return ce, true
}

// GetTypes retrieves the entries for exactly two qtypes of one qname (NS
// A/AAAA address lookups).  ECS is not supported — entries are matched on
// the empty ECS candidate, and the caller must pass a canonical qname.
func (s *Cache) GetTypes(qname string, qclass uint16, qtypes [2]uint16) (entries [2]*Entry, found, expired [2]bool) {
	for i, qt := range qtypes {
		key := buildCacheKey(qname, qt, qclass, "", 0)
		if ce, ok := s.entries.Get(key); ok {
			entries[i], found[i], expired[i] = s.buildEntry(ce.ts, ce.ttl, ce.validated, ce.msgWire, qname, qt)
			continue
		}
		if s.spill != nil {
			if ce, ok := s.getFromSpill(key); ok {
				entries[i], found[i], expired[i] = s.buildEntry(ce.ts, ce.ttl, ce.validated, ce.msgWire, qname, qt)
			}
		}
	}
	return entries, found, expired
}

// SpillStore returns the entries spill store (nil in single-tier mode) —
// used by the server's state maintenance for compaction.
func (s *Cache) SpillStore() *spillfile.Store { return s.spill }

// SpillCap returns the entries spill record cap (≤0 = unbounded).
func (s *Cache) SpillCap() int { return s.spillCap }

// LatencySpillStore returns the latency spill store (nil in single-tier
// mode).
func (s *Cache) LatencySpillStore() *spillfile.Store { return s.spillLat }

// LatencySpillCap returns the latency spill record cap (≤0 = unbounded).
func (s *Cache) LatencySpillCap() int { return s.spillLatCap }

// buildEntry parses a stored BLOB (pre-packed) into an Entry, applying
// latency sorting.  Returns (entry, found, expired); found=false on corrupt
// data.
func (s *Cache) buildEntry(ts int64, entryTTL int, validated bool, msgWire []byte, qname string, qtype uint16) (*Entry, bool, bool) {
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
			log.Warnf("CACHE: entry (name=%s type=%d) offset table out of bounds: %d offsets in %d bytes", qname, qtype, numOffsets, len(msgWire))
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
		wire, err = zdnsutil.Decompress(wire, *dbuf)
		if err != nil {
			ReleaseTTLOffsets(offsets)
			clear(*dbuf)
			decompressBufPool.Put(dbuf)
			log.Warnf("CACHE: decompress wire for entry (name=%s type=%d): %v", qname, qtype, err)
			return nil, false, false
		}
		defer func() { clear(*dbuf); decompressBufPool.Put(dbuf) }()
		// Copy out of the pool buffer — it is cleared when Get() returns.
		owned = make([]byte, len(wire))
		copy(owned, wire)
	} else {
		// The cache entry's msgWire is SHARED across concurrent Gets (one
		// *cacheEntry per LRU slot) and the serve path mutates it in place
		// (buildFromPrePacked deducts TTLs via the offset table) — handing
		// out the shared slice would let one query corrupt another's TTLs
		// and race its writes.  Clone per hit (H7/H10).
		owned = slices.Clone(wire)
	}
	entry := &Entry{
		Timestamp:    ts,
		TTL:          entryTTL,
		Validated:    validated,
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
		if s.sortAnswerByLatency(entry) && len(entry.Answer) > 0 {
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
// sortAnswerByLatency reorders A/AAAA records by latency and reports whether
// the order actually changed — when it did not, the pre-packed wire is
// already optimal and the caller can skip the repack.
func (s *Cache) sortAnswerByLatency(entry *Entry) bool {
	if !s.hasLatencyData.Load() || len(entry.Answer) <= 1 {
		return false
	}
	original := slices.Clone(entry.Answer) // pointer copy — no RR deep clone

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
		return false
	}

	// Batch latency lookup from the in-memory map.
	latencies := s.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return false
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
	for i := range entry.Answer {
		if entry.Answer[i] != original[i] {
			return true
		}
	}
	return false
}

// lookupIPLatencies fetches latencies for a batch of IPs from the in-memory
// latency map.  Caps at maxLatencyLookupIPs for symmetry with the former
// SQL IN-clause bound (unusually large answer sets of 64+ A/AAAA records).
func (s *Cache) lookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}

	latencies := make(map[string]int, min(len(ips), maxLatencyLookupIPs))
	for _, ip := range ips {
		if e, ok := s.latencies.Get(ip); ok {
			latencies[ip] = e.latency
		}
	}
	return latencies
}

// Set stores a DNS response in the cache. Wire format is zstd-compressed.
// Set stores a DNS response in the cache.  Wire format is zstd-compressed
// above the threshold.  Prep work (TTL calculation, wire packing, zstd
// compression) runs before the synchronous in-memory write.
func (s *Cache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption,
	answer, authority, additional []dns.RR, validated bool, rcode uint16,
) int64 {
	// ── Prep work ────────────────────────────────────────────────────────
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)
	if entryTTL <= 0 {
		// Zero TTL (incl. RFC 2181 §8 MSB-set values) — nothing to cache.
		return 0
	}

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = dnsutil.Canonical(qname)

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

	// The upstream may echo a CapsGuard-randomized question case into record
	// owners via compression pointers (draft-vixie-dnsext-dns0x20-00 §5.4) —
	// canonicalize owners so that random case never reaches the cache or
	// subsequent responses.  additional was already deep-cloned above.
	canonicalizeOwners(answer)
	canonicalizeOwners(authority)
	canonicalizeOwners(additional)

	// NOTE: the stored wire keeps the RAW records (DNSSEC proofs included —
	// upstream queries always carry DO=1 per RFC 6840 §5.9, and the cache key
	// never splits on the client's DO bit — see buildCacheKey).  DNSSEC
	// filtering for DO=0 clients happens at SERVE time (WireHasDNSSEC gate +
	// ProcessRecords in the Response middleware) so the zone-key cache
	// (CacheZoneKeys) keeps its raw content.

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

	// ── Synchronous memory write ───────────────────────────────────────────
	// Set is immediately visible to Get — no async layer needed.
	s.entries.Set(buildCacheKey(qname, qtype, qclass, ecsAddr, ecsPrefix),
		&cacheEntry{msgWire: msgWire, ts: now, ttl: entryTTL, validated: validated})
	return 0
}

// ── Set-path helpers ──────────────────────────────────────────────────────

// canonicalizeOwners lowercases every record owner name and the embedded
// rdata names in place.  An upstream may echo a CapsGuard-randomized
// question case into record owners and rdata names via compression pointers
// (draft-vixie-dnsext-dns0x20-00 §5.4); that random case must not leak into
// the cache and subsequent responses.  Lowercasing rdata names also lets the
// packed wire compress them against the canonical question — a mixed-case
// target would miss the case-sensitive compression map and stay fully
// encoded, showing a different case than the owner on cache hits.
//
// The rdata name fields cover every RR type of the miekg fork: they mirror
// the compare methods generated into zcompare.go, the same source of truth
// as the wire format — a new RR type gets its compare method generated from
// the same table, so the coverage cannot drift from the wire format.
func canonicalizeOwners(rrs []dns.RR) {
	for i, rr := range rrs {
		if rr == nil {
			continue
		}
		rrs[i] = canonicalizeRR(rr)
	}
}

// canonicalizeRR folds the owner and every embedded rdata name of an RR to
// lowercase, type-agnostically: in the presentation form (RFC 4343 §3) a
// whitespace-separated token ending in '.' and not quoted is a domain name,
// so folding it cannot touch data (TXT/URI/CAA values are always quoted).
// The record is rebuilt via the zone parser — the same self-describing
// grammar — so any RR type, including future ones, is covered without a
// per-type field table (draft-vixie-dnsext-dns0x20-00 §5.4: the randomized
// case must not leak into the cache; mixed-case rdata names also miss the
// case-sensitive compression map and stay fully encoded, showing a
// different case than the owner on cache hits).  Returns the input
// unchanged when there is nothing to fold.
func canonicalizeRR(rr dns.RR) dns.RR {
	s := rr.String()
	fields := strings.Fields(s)
	folded := false
	for i, tok := range fields {
		if strings.HasSuffix(tok, ".") && !strings.HasPrefix(tok, "\"") && !strings.HasSuffix(tok, "\"") {
			if low := asciiFold(tok); low != tok {
				fields[i] = low
				folded = true
			}
		}
	}
	if !folded {
		return rr
	}
	zp := dns.NewZoneParser(strings.NewReader(strings.Join(fields, " ")), ".", "")
	parsed, ok := zp.Next()
	if !ok || zp.Err() != nil {
		return rr // defensive — serve the original
	}
	return parsed
}

// asciiFold lowercases only ASCII letters — RFC 4343 §3 folds exactly the
// 0x20 bit of A-Z; non-ASCII bytes are case-sensitive in DNS and must stay
// untouched.  Returns the input unchanged (no allocation) when there is
// nothing to fold.
func asciiFold(name string) string {
	needsFold := false
	for i := 0; i < len(name); i++ {
		if name[i] >= 'A' && name[i] <= 'Z' {
			needsFold = true
			break
		}
	}
	if !needsFold {
		return name
	}
	b := []byte(name)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 0x20
		}
	}
	return string(b)
}

// minTTL returns the smallest positive TTL across all RR sections, falling
// back to DefaultTTL when no TTLs are found.  The result is capped at
// config.DefaultMaxCacheableTTL to prevent unbounded caching (RFC 8767 §4).
func minTTL(sections ...[]dns.RR) int {
	minT := -1
	for _, rrs := range sections {
		for _, rr := range rrs {
			if rr == nil {
				continue
			}
			if t := rr.Header().TTL; t&0x80000000 != 0 {
				// RFC 2181 §8: TTL values with the most significant bit set
				// are treated as if the entire value were zero — an
				// attacker-controlled huge TTL must not be cached for its
				// raw value (previously capped at 7 days).
				return 0
			} else if t > 0 && (minT < 0 || int(t) < minT) {
				minT = int(t)
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
