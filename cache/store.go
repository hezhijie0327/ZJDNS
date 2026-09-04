package cache

import (
	"context"
	"encoding/binary"
	"slices"
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
// optional disk spill tier.  It implements the Store interface.
type Cache struct {
	entries    *lrumap.Map[cacheKey, *cacheEntry] // cache key → entry
	maxEntries int
	statsMgr   *Manager // in-memory query stats + per-RCODE top-N journal

	// spill is the second-tier disk store: evicted-but-fresh entries land
	// here and are promoted back on a memory miss.  nil when no state_file
	// is configured (single-tier mode).
	spill    *spillfile.Store
	spillCap int // spill file record cap (≤0 = unbounded)

	// spillW drains eviction writes off the entries-mutex: OnEvict runs
	// under the lrumap lock, where a synchronous WriteAt froze every
	// concurrent Get/Set for the IO duration (2026-09 D2).
	spillW *spillfile.AsyncWriter

	// hasLatencyData gates sortAnswerByLatency: when false (no latency data has
	// ever been written), the per-hit latency lookup is skipped entirely.
	hasLatencyData atomic.Bool

	// latencyGen is the latency-table generation: bumped on every
	// UpdateLatency so per-entry sorted-wire caches can detect staleness
	// without re-reading the latency map.
	latencyGen atomic.Uint64

	// latencies holds per-IP latency data — written by background latency
	// probes, read on the cache-hit hot path (sortAnswerByLatency).  LRU-
	// bounded (latencyMax), TTL-expired lazily on read and physically
	// cleaned by CleanupLatency.
	latencies  *lrumap.Map[string, latEntry]
	latencyMax int

	// spillLat is the latency-table spill tier (same role as spill).
	spillLat    *spillfile.Store
	spillLatCap int

	// spillLatW drains latency-tier eviction writes (same reason as spillW).
	spillLatW *spillfile.AsyncWriter

	closeOnce sync.Once
}

// cacheEntry is one cached DNS response.  msgWire is the pre-packed response
// (format 0x02) with TTL-offset table.  TTL expiry is checked lazily on read.
type cacheEntry struct {
	msgWire   []byte
	ts        int64 // log.NowUnix() at store
	ttl       int
	validated bool

	// sorted caches the latency-sorted wire for A/AAAA entries so every
	// cache hit skips the Unpack + sort + maps; rebuilt whenever the
	// latency-table generation moves.  The offsets copy is NOT pool-owned —
	// readers clone into the TTL-offset pool per hit.
	sorted atomic.Pointer[latencySortedWire]
}

// latencySortedWire is the cached latency-sort result for one entry.
type latencySortedWire struct {
	wire    []byte
	offsets []uint16
	version uint64 // Cache.latencyGen when built
}

// latEntry is one per-IP latency record.
type latEntry struct {
	latency   int   // measured latency in ms
	lastProbe int64 // log.NowUnix() at probe time; 0 = never probed
}

// cacheKey is the exact cache key: (qname, qtype, qclass, ECS address,
// ECS prefix) as one comparable struct — constructed in place on the lookup
// path with zero allocations (the former strings.Builder key allocated on
// every Get, once per ECS candidate).  ecsAddr holds the address bytes with
// ecsLen 4 = IPv4 (first 4 bytes), 16 = IPv6, 0 = no ECS.  The key excludes
// the client's DO bit: outbound queries always carry DO=1 (RFC 6840 §5.9)
// and DO=0 filtering happens at serve time — a DO-split key would store the
// identical raw wire twice per name.
type cacheKey struct {
	qname   string
	qtype   uint16
	qclass  uint16
	ecsPref uint8
	ecsLen  uint8
	ecsAddr [16]byte
}

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap batched IPs per latency lookup
	decompressBufCap    = 4096

	// cacheFormatPrePacked is the BLOB format marker for pre-packed response
	// wire with TTL offset table (format 0x02).
	cacheFormatPrePacked = 0x02

	// dnssecFlagMask is the top bit of the 2-byte num_offsets field in the
	// pre-packed BLOB (bit 7 of msgWire[1]): set when the wire carries
	// DNSSEC record types.  The remaining 15 bits hold the offset count.
	dnssecFlagMask = 0x8000

	// maxSortedWireCache bounds the per-entry latency-sorted wire cache:
	// responses above this size skip caching (a second copy would double
	// large-entry memory) and re-sort per hit instead.
	maxSortedWireCache = 1024

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
		// Sharded: every query's Get/Set (hit or miss) touches these maps —
		// a single LRU mutex serialised the whole server at high QPS.
		entries:    lrumap.NewSharded[cacheKey, *cacheEntry](maxEntries),
		maxEntries: maxEntries,
		statsMgr:   newStatsJournal(0),
		latencies:  lrumap.NewSharded[string, latEntry](latencyMax),
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

	// Single-pass warm-up: top-maxEntries newest records, wires read by
	// exact offset (see Store.Warm).  Stale records are skipped in-memory —
	// their disk weight is reclaimed by the periodic compaction.
	warmed, onDisk := spill.Warm(maxEntries, func(ts int64, entryTTL int) bool {
		return ttl.CanServeExpired(ts, entryTTL, config.DefaultStaleMaxAge)
	})
	for _, w := range warmed {
		// Coldest first so the hottest entry ends up at the LRU front.
		// Keys were encoded by cacheKey.encode on eviction; undecodable
		// (pre-struct-key legacy) records stay unread until compaction.
		key, ok := decodeCacheKey(w.Key)
		if !ok {
			continue
		}
		s.entries.Set(key, &cacheEntry{msgWire: w.Wire, ts: w.Ts, ttl: w.Ttl, validated: w.Validated})
	}
	// Spill-on-evict registered AFTER the warm-up load — load-time capacity
	// evictions must not re-spill the very entries just read back.  The
	// write itself is queued to the async writer: OnEvict runs under the
	// entries mutex and a synchronous Put here froze all cache lookups
	// during the write (and queued behind a Compact for its whole rewrite)
	// (2026-09 D2).  Queue-full drops are counted and re-derivable.
	s.spillW = spillfile.NewAsyncWriter(spill)
	s.entries.SetOnEvict(func(key cacheKey, ce *cacheEntry) {
		if ce.ts > 0 && ttl.CanServeExpired(ce.ts, ce.ttl, config.DefaultStaleMaxAge) {
			s.spillW.Enqueue(key.encode(), ce.ts, ce.ttl, ce.validated, ce.msgWire)
		}
	})
	log.Infof("CACHE: spill store ready: %d records on disk, %d loaded to memory", onDisk, len(warmed))
}

// Close flushes and closes the spill stores (the in-memory LRUs need no
// cleanup).  Idempotent — a second Close returns nil instead of
// os.ErrClosed from the spill stores (2026-09 D15).
func (s *Cache) Close() error {
	var err error
	s.closeOnce.Do(func() {
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
	})
	return err
}

// Flush pushes every in-memory entry to its spill store (skipping records
// already on disk unchanged) and fsyncs — called at shutdown so a restart
// warms from disk.  No-op without a disk tier.
func (s *Cache) Flush() {
	// Drain the async writers first so the Indexed check below sees the
	// queued eviction writes; bounded by the shutdown timeout — a stalled
	// disk must not hang shutdown indefinitely (2026-09 D6).
	drainCtx, drainCancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
	defer drainCancel()
	if s.spillW != nil {
		s.spillW.Close(drainCtx)
	}
	if s.spillLatW != nil {
		s.spillLatW.Close(drainCtx)
	}
	// Snapshot the maps under their locks, run the disk IO outside them —
	// Flush overlaps the drain window where in-flight queries still look
	// up the cache (holding the lock per entry stalled them all).
	if s.spill != nil {
		type row struct {
			key cacheKey
			ce  *cacheEntry
		}
		var rows []row
		s.entries.Range(func(key cacheKey, ce *cacheEntry) bool {
			rows = append(rows, row{key, ce})
			return true
		})
		for _, r := range rows {
			if r.ce.ts > 0 && ttl.CanServeExpired(r.ce.ts, r.ce.ttl, config.DefaultStaleMaxAge) && !s.spill.Indexed(r.key.encode(), r.ce.ts) {
				if err := s.spill.Put(r.key.encode(), r.ce.ts, r.ce.ttl, r.ce.validated, r.ce.msgWire); err != nil {
					log.Debugf("CACHE: spill flush: %v", err)
				}
			}
		}
	}
	if s.spillLat != nil {
		type row struct {
			key string
			e   latEntry
		}
		var rows []row
		s.latencies.Range(func(key string, e latEntry) bool {
			rows = append(rows, row{key, e})
			return true
		})
		for _, r := range rows {
			if r.e.lastProbe > 0 && !s.spillLat.Indexed(r.key, r.e.lastProbe) {
				if err := s.spillLat.Put(r.key, r.e.lastProbe, 0, false, marshalLatency(r.e)); err != nil {
					log.Debugf("CACHE: latency spill flush %s: %v", r.key, err)
				}
			}
		}
	}
	if s.spill != nil {
		_ = s.spill.Flush() // _ = error: best-effort fsync, Close reports hard errors
	}
	if s.spillLat != nil {
		_ = s.spillLat.Flush() // _ = error: best-effort fsync, Close reports hard errors
	}
}

// EntryCount returns the number of cached entries.
func (s *Cache) EntryCount() int { return s.entries.Len() }

// LatencyCount returns the number of per-IP latency entries.
func (s *Cache) LatencyCount() int { return s.latencies.Len() }

// encode renders the deterministic spill-store form of the key:
// qname \x00 qtype(2) qclass(2) ecsLen ecsAddr[:ecsLen] ecsPref.
// Used only at the spill boundary (eviction write, promotion read) — one
// small allocation per miss-path spill touch.
func (k cacheKey) encode() string {
	buf := make([]byte, 0, len(k.qname)+7+int(k.ecsLen))
	buf = append(buf, k.qname...)
	buf = append(buf, 0, byte(k.qtype>>8), byte(k.qtype), byte(k.qclass>>8), byte(k.qclass), k.ecsLen) //nolint:gosec // G115: qtype/qclass are protocol-bounded uint16 wire fields
	buf = append(buf, k.ecsAddr[:k.ecsLen]...)
	return string(append(buf, k.ecsPref))
}

// decodeCacheKey parses the spill-store key form; ok=false on malformed or
// pre-struct-key (string-built) records — those stay on disk unread until
// compaction reclaims them.
func decodeCacheKey(s string) (cacheKey, bool) {
	var k cacheKey
	zero := 0
	for zero < len(s) && s[zero] != 0 {
		zero++
	}
	if zero == 0 || zero >= len(s)-5 { // need name + type/class/len/prefix
		return k, false
	}
	k.qname = s[:zero]
	rest := s[zero+1:]
	k.qtype = uint16(rest[0])<<8 | uint16(rest[1])  //nolint:gosec // G115: DNS type fits uint16
	k.qclass = uint16(rest[2])<<8 | uint16(rest[3]) //nolint:gosec // G115: DNS class fits uint16
	l := int(rest[4])
	if l != 0 && l != 4 && l != 16 || 5+l >= len(rest) {
		return k, false
	}
	k.ecsLen = uint8(l) //nolint:gosec // G115: bounded to 0/4/16 above
	copy(k.ecsAddr[:l], rest[5:5+l])
	k.ecsPref = rest[5+l]
	return k, true
}

// setECS fills the ECS part from the client option (nil → no ECS) with the
// FULL (unmasked) address — the exact-match key form; fallback candidates
// derive masked copies via mask.
func (k *cacheKey) setECS(ecs *config.ECSOption) {
	if ecs == nil || len(ecs.Address) == 0 {
		k.ecsLen, k.ecsPref = 0, 0
		return
	}
	if v4 := ecs.Address.To4(); v4 != nil {
		k.ecsLen = 4
		copy(k.ecsAddr[:4], v4)
	} else {
		k.ecsLen = 16
		copy(k.ecsAddr[:], ecs.Address.To16())
	}
	k.ecsPref = ecs.SourcePrefix
}

// mask zeroes the address bits below prefix in place (inline CIDR mask —
// the former maskIP + net.IP.String() allocated per fallback candidate).
func (k *cacheKey) mask(prefix int) {
	bits := int(k.ecsLen) * 8
	if prefix >= bits {
		return
	}
	for i := 0; i < int(k.ecsLen); i++ {
		r := prefix - i*8
		if r <= 0 {
			k.ecsAddr[i] = 0
		} else if r < 8 {
			k.ecsAddr[i] &= byte(0xFF) << (8 - r)
		}
	}
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
	// the most specific match.  Stack-allocated (1 exact + up to 4 masked
	// standard prefixes); the former pooled candidate slice plus per-key
	// strings.Builder allocation is gone.
	var cand [5]cacheKey
	cand[0].setECS(ecs)
	n := 1
	if ecs != nil {
		standardPrefixes := ipv4FallbackPrefixes
		if ecs.Address.To4() == nil {
			standardPrefixes = ipv6FallbackPrefixes
		}
		for _, p := range standardPrefixes {
			if p >= int(ecs.SourcePrefix) {
				continue
			}
			c := cand[0]
			c.ecsPref = uint8(p) //nolint:gosec // G115: bounded by the standard-prefix tables
			c.mask(p)
			cand[n] = c
			n++
		}
	}
	for i := range n {
		key := cand[i]
		key.qname, key.qtype, key.qclass = qname, qtype, qclass
		if ce, ok := s.entries.Get(key); ok {
			entry, found, expired := s.buildEntry(ce, ce.ts, ce.ttl, ce.validated, ce.msgWire, qname, qtype)
			if !found {
				// Corrupt BLOB — self-heal instead of warn-per-read: the
				// next query for this key re-fetches from upstream (D8).
				s.entries.Delete(key)
			}
			return entry, found, expired
		}
		if s.spill != nil {
			if entry, found := s.getFromSpill(key); found {
				e, ok2, expired := s.buildEntry(entry, entry.ts, entry.ttl, entry.validated, entry.msgWire, qname, qtype)
				if !ok2 {
					s.spill.Delete(key.encode())
					s.entries.Delete(key)
				}
				return e, ok2, expired
			}
		}
	}
	log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
	return nil, false, false
}

// getFromSpill reads a spill record by key and promotes it to memory.  An
// expired record is dropped from the index (the file record lingers until
// compaction).  Returns (entry, false) on miss or expiry.
func (s *Cache) getFromSpill(key cacheKey) (*cacheEntry, bool) {
	enc := key.encode()
	ts, entryTTL, validated, wire, ok := s.spill.Get(enc)
	if !ok {
		return nil, false
	}
	if !ttl.CanServeExpired(ts, entryTTL, config.DefaultStaleMaxAge) {
		s.spill.Delete(enc)
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
		key := cacheKey{qname: qname, qtype: qt, qclass: qclass}
		if ce, ok := s.entries.Get(key); ok {
			entries[i], found[i], expired[i] = s.buildEntry(ce, ce.ts, ce.ttl, ce.validated, ce.msgWire, qname, qt)
			if !found[i] {
				s.entries.Delete(key) // corrupt BLOB — self-heal (D8)
			}
			continue
		}
		if s.spill != nil {
			if ce, ok := s.getFromSpill(key); ok {
				entries[i], found[i], expired[i] = s.buildEntry(ce, ce.ts, ce.ttl, ce.validated, ce.msgWire, qname, qt)
				if !found[i] {
					s.spill.Delete(key.encode())
					s.entries.Delete(key)
				}
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
func (s *Cache) buildEntry(ce *cacheEntry, ts int64, entryTTL int, validated bool, msgWire []byte, qname string, qtype uint16) (*Entry, bool, bool) {
	if len(msgWire) < 3 {
		return nil, false, false
	}

	// Single live format: [0x02] [2:num_offsets|hasDNSSEC flag] [2 each:
	// TTL offset] [wire].  No legacy compatibility is kept — a foreign or
	// corrupt BLOB is treated as a miss.  The marker byte plus the
	// structural checks (table fit; every offset addressing a full TTL
	// field inside the FINAL wire, post-decompression) reject
	// raw/misparsed wires and accept the writer's full domain, including
	// entries with more than 255 RRs (D3).
	if msgWire[0] != cacheFormatPrePacked {
		return nil, false, false
	}
	entryHasDNSSEC := msgWire[1]&0x80 != 0
	numOffsets := int(binary.BigEndian.Uint16(msgWire[1:3]) &^ dnssecFlagMask)
	wireStart := 3 + numOffsets*2
	if wireStart > len(msgWire) {
		log.Debugf("CACHE: corrupt entry (name=%s type=%d) — %d offsets do not fit %d bytes", qname, qtype, numOffsets, len(msgWire))
		return nil, false, false
	}
	var offsets []uint16
	if numOffsets > 0 {
		offsets = AcquireTTLOffsets(numOffsets)
		for i := range numOffsets {
			offsets[i] = binary.BigEndian.Uint16(msgWire[3+i*2:])
		}
	}
	wire := msgWire[wireStart:]

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
			// Debug, not Warn: a corrupt BLOB is dropped by the caller
			// (self-healing delete), so this fires once per corrupt entry,
			// not per read (2026-09 C-M3).
			log.Debugf("CACHE: decompress wire for entry (name=%s type=%d): %v", qname, qtype, err)
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
	// Each offset must address a complete TTL field (4 bytes) inside the
	// FINAL wire (post-decompression — the table indexes the uncompressed
	// layout).  A corrupt value degrades to a cache miss, never a
	// slice-bounds panic on the serve path (2026-09 H-M2).
	for _, off := range offsets {
		if int(off)+4 > len(owned) {
			ReleaseTTLOffsets(offsets)
			log.Debugf("CACHE: corrupt entry (name=%s type=%d) — TTL offset %d out of wire range (%d)", qname, qtype, off, len(owned))
			return nil, false, false
		}
	}
	entry := &Entry{
		Timestamp:    ts,
		TTL:          entryTTL,
		Validated:    validated,
		ResponseWire: owned,
		TTLOffsets:   offsets,
	}
	entry.HasDNSSEC = entryHasDNSSEC
	// When latency data is available, sort A/AAAA records and
	// rebuild ResponseWire so the pre-packed response serves IPs
	// in latency order.  This is the only path that mutates
	// ResponseWire after Set() — latency data may arrive after the
	// entry was stored.
	// Latency sorting reorders only A/AAAA answers — every other qtype
	// (TXT, MX, DNSKEY, ...) paid the full Unpack + clone + map allocs for
	// a sort that could never change the wire.
	if s.hasLatencyData.Load() && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		// Sorted-wire fast path: when this entry was already sorted under
		// the current latency-table generation, serve the cached result —
		// the per-hit Unpack + sort + maps were the dominant cost of a
		// multi-answer A/AAAA cache hit (3× CPU, 6× allocs at 8 answers).
		gen := s.latencyGen.Load()
		if ce != nil {
			if blob := ce.sorted.Load(); blob != nil && blob.version == gen {
				fast := &Entry{
					Timestamp:    ts,
					TTL:          entryTTL,
					Validated:    validated,
					ResponseWire: slices.Clone(blob.wire),
					TTLOffsets:   clonePooledOffsets(blob.offsets),
				}
				fast.HasDNSSEC = entryHasDNSSEC
				return fast, true, ttl.IsExpired(ts, entryTTL)
			}
		}
		if err := entry.Unpack(); err != nil {
			log.Debugf("CACHE: latency sort unpack failed (name=%s type=%d): %v", qname, qtype, err) // corrupt wire — served unsorted (E9)
		}
		if s.sortAnswerByLatency(entry) && len(entry.Answer) > 0 {
			entry.rebuildResponseWire()
		}
		// Cache the sorted pair for same-generation hits (bounded: large
		// wires re-sort per hit instead of doubling memory).
		if ce != nil && len(entry.ResponseWire) <= maxSortedWireCache && entry.TTLOffsets != nil {
			wcopy := make([]byte, len(entry.ResponseWire))
			copy(wcopy, entry.ResponseWire)
			ocopy := make([]uint16, len(entry.TTLOffsets))
			copy(ocopy, entry.TTLOffsets)
			ce.sorted.Store(&latencySortedWire{wire: wcopy, offsets: ocopy, version: gen})
		}
	}
	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// clonePooledOffsets copies an offsets table into a pooled slice for a
// per-hit Entry (the cached copy stays owned by the entry).
func clonePooledOffsets(src []uint16) []uint16 {
	if len(src) == 0 {
		return nil
	}
	dst := AcquireTTLOffsets(len(src))
	copy(dst, src)
	return dst
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
// latency map.  Caps at maxLatencyLookupIPs to bound the lookup on unusually
// large answer sets (64+ A/AAAA records).
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

// Set stores a DNS response in the cache.  Wire format is zstd-compressed
// above the threshold.  Prep work (TTL calculation, wire packing, zstd
// compression) runs before the synchronous in-memory write.
func (s *Cache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption,
	answer, authority, additional []dns.RR, validated bool, rcode uint16,
) {
	// ── Prep work ────────────────────────────────────────────────────────
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)
	if entryTTL <= 0 {
		// Zero TTL (incl. RFC 2181 §8 MSB-set values) — nothing to cache.
		return
	}

	var key cacheKey
	key.qname, key.qtype, key.qclass = qname, qtype, qclass
	key.setECS(ecs)
	qname = dnsutil.Canonical(qname)

	// Strip EDNS OPT pseudo-record from additional before caching
	// (padding and other EDNS options have no semantic value and waste
	// storage space, up to 468 bytes per encrypted response). The
	// single-pass clone+filter below avoids a second deep copy of the input.
	additional = cloneRRsNoOPT(additional)

	// Clone records to prevent downstream mutations (e.g. TTL deduction in
	// the response path rewriting rr.Header()) from corrupting the cache.
	answer = zdnsutil.CloneRRs(answer)
	authority = zdnsutil.CloneRRs(authority)

	// The upstream may echo a CapsGuard-randomized question case into record
	// owners via compression pointers (draft-vixie-dnsext-dns0x20-00 §5.4) —
	// canonicalize owners so that random case never reaches the cache or
	// subsequent responses (records folded by the resolver fold to a no-op
	// here).  additional was already deep-cloned above.
	zdnsutil.FoldCase(answer)
	zdnsutil.FoldCase(authority)
	zdnsutil.FoldCase(additional)

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
		return
	}

	// Sort A/AAAA records by latency before packing — the pre-packed
	// wire preserves this order and serves it directly without re-sorting.
	if s.hasLatencyData.Load() && len(answer) > 1 && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
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
		return
	}

	// Scan TTL offsets in the packed response, skipping the 12-byte
	// header plus the question section.  queryMsg.Data = query_header(12)
	// + question_wire, so len(queryMsg.Data) = response_header(12) +
	// question_wire — the exact offset where the answer section begins.
	ttlOffsets := scanTTLOffsets(msg.Data, len(queryMsg.Data))

	// hasDNSSEC must be computed BEFORE the Put below — Message.Put zeroes
	// the struct (*msg = dns.Msg{}), so msg.Data reads as nil afterwards
	// and the flag would never be set (2026-09 D1).
	hasDNSSEC := WireHasDNSSEC(msg.Data)

	// Build the pre-packed BLOB:
	//   [0x02] [2:num_offsets] [2 each:offset] [wire]
	// The wire portion may be zstd-compressed if above threshold.
	wire := msg.Data
	if len(wire) > config.DefaultCompressionThreshold {
		wire = zdnsutil.Compress(wire)
	}
	pool.DefaultMessage.Put(msg)

	// Build the BLOB with exact-size preallocation — a bytes.Buffer would
	// grow geometrically and copy.  [0x02] [2:num_offsets|flag] [2 each:offset] [wire]
	// The num_offsets field's top bit (bit 7 of msgWire[1]) is the
	// has-DNSSEC flag, precomputed here so the DO=0 serve gate never
	// re-scans the wire per hit; the offset count itself is bounded by
	// (wire size / min RR size) ≈ 5.4k, far below the 2^15 the mask leaves.
	field := uint16(len(ttlOffsets)) //nolint:gosec // G115: offset count bounded by wire size / min RR size (< 2^15)
	msgWire := make([]byte, 0, 3+2*len(ttlOffsets)+len(wire))
	msgWire = append(msgWire, cacheFormatPrePacked)
	var lenBuf [2]byte
	if hasDNSSEC {
		field |= dnssecFlagMask
	}
	binary.BigEndian.PutUint16(lenBuf[:], field) //nolint:gosec // G115: offset count bounded by RR count
	msgWire = append(msgWire, lenBuf[:]...)
	for _, off := range ttlOffsets {
		binary.BigEndian.PutUint16(lenBuf[:], off)
		msgWire = append(msgWire, lenBuf[:]...)
	}
	msgWire = append(msgWire, wire...)
	ReleaseTTLOffsets(ttlOffsets)

	// ── Synchronous memory write ───────────────────────────────────────────
	// Set is immediately visible to Get — no async layer needed.
	s.entries.Set(key, &cacheEntry{msgWire: msgWire, ts: now, ttl: entryTTL, validated: validated})
}

// ── Set-path helpers ──────────────────────────────────────────────────────

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

// cloneRRsNoOPT returns a deep copy of rrs excluding OPT pseudo-records.
// These carry transport-layer padding which has no semantic value but can
// occupy up to 468 bytes per encrypted response. The input slice belongs to
// the caller, so filtering must not modify it in place.
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
