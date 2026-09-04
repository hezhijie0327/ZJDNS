// Cache entry storage: the Get/Set hot path, pre-packed entry
// materialisation (buildEntry), and the internal cacheEntry representation.
package cache

import (
	"encoding/binary"
	"sync/atomic"
	"zjdns/config"
	zdnsutil "zjdns/internal/dnsutil"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

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
		// and race its writes.  Copy per hit into the pooled wire class
		// (H7/H10); the copy is recycled by Message.Put after the response
		// is written.
		owned = pool.AcquireWire(len(wire))
		copy(owned, wire)
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
				fastWire := pool.AcquireWire(len(blob.wire))
				copy(fastWire, blob.wire)
				fast := &Entry{
					Timestamp:    ts,
					TTL:          entryTTL,
					Validated:    validated,
					ResponseWire: fastWire,
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
