package cache

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/lrumap"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
)

// entryKey is the map key for a cached response — typed fields, no binary
// encoding (the BadgerDB-era e: prefix and byte-packed keys are gone).
type entryKey struct {
	qname     string
	ecsAddr   string
	ecsPrefix uint16
	dnssecOK  bool
	qtype     uint16
	qclass    uint16
}

// listEntry is one cached response, chained in LRU order. The embedded list
// pointers follow the lrumap pattern (no container/list allocation).
type listEntry struct {
	key       entryKey
	value     []byte // DNS wire format
	ts        int64  // unix seconds at write
	expiresAt int64  // ts + entryTTL + staleMaxAge — hard removal deadline
	validated bool
	prev      *listEntry
	next      *listEntry
}

// latencyEntry holds an IP latency measurement with its expiry time, so the
// in-memory LRU cache honours the same TTL semantics as before (2 ×
// DefaultLatencyProbeMinInterval). Transient — never persisted.
type latencyEntry struct {
	value     int   // latency in milliseconds
	expiresAt int64 // unix timestamp after which the entry is considered stale
}

// ptrRecord is one reverse-lookup (PTR) record derived from a cache entry's
// A/AAAA records. ownerKey links it to its source entry so eviction can
// clean it up precisely.
type ptrRecord struct {
	name      string
	ttl       int32
	ts        int64
	expiresAt int64
	ownerKey  entryKey
}

// dnscryptState is the DNSCrypt server state handed to the cache for
// persistence. The DNSCrypt server owns it; the cache just stores and saves.
type dnscryptState struct {
	identity []byte
	windows  []Window
}

// Cache is an in-memory DNS response cache: O(1) map lookup, LRU eviction by
// total value bytes, and optional persist file (load at startup, dump at
// shutdown / DNSCrypt rotation).
type Cache struct {
	mu        sync.RWMutex
	store     map[entryKey]*listEntry
	head      *listEntry // sentinel: most-recent side
	tail      *listEntry // sentinel: least-recent side
	maxSize   int64      // max total value bytes
	totalSize int64      // Σ len(value)
	len       int

	ptrIndex map[string][]*ptrRecord // ip → derived reverse records
	latency  *lrumap.Map[string, latencyEntry]

	file     string // persist file path; empty = no persistence
	dnscrypt atomic.Pointer[dnscryptState]
}

// ecsCandidate is a single ECS cache-key candidate used during fallback lookup.
type ecsCandidate struct {
	addr   string
	prefix int
}

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap per-Get latency lookups to bound iteration overhead
)

// ECS fallback prefix boundaries — standard CIDR granularities most commonly
// used by CDN and authoritative DNS operators (RFC 7871).
var (
	ipv4FallbackPrefixes = []int{24, 16, 8, 0}
	ipv6FallbackPrefixes = []int{56, 48, 32, 0}
)

// New creates an in-memory cache. maxSizeBytes caps total stored value bytes
// (0 = config default); file is the optional persist path, loaded eagerly.
func New(maxSizeBytes int64, file string) *Cache {
	if maxSizeBytes <= 0 {
		maxSizeBytes = int64(config.DefaultCacheMaxSizeMB) << 20
	}
	head := &listEntry{}
	tail := &listEntry{}
	head.next = tail
	tail.prev = head
	c := &Cache{
		store:    make(map[entryKey]*listEntry),
		head:     head,
		tail:     tail,
		maxSize:  maxSizeBytes,
		ptrIndex: make(map[string][]*ptrRecord),
		latency:  lrumap.New[string, latencyEntry](config.DefaultLatencyCacheCapacity),
		file:     file,
	}
	c.loadFromDisk()
	return c
}

// Get retrieves a cached DNS response. Returns the entry, whether it was
// found, and whether it's expired (expired entries are still returned for
// stale-serving and prefetch — the middleware decides).
func (c *Cache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	qname = dnsutil.Canonical(qname)
	for _, cand := range ecsFallbackCandidates(ecs) {
		key := entryKey{qname: qname, ecsAddr: cand.addr, ecsPrefix: uint16(cand.prefix), dnssecOK: dnssecOK, qtype: qtype, qclass: qclass} //nolint:gosec // G115: prefix ≤ 128 by CIDR semantics
		e := c.lookup(key)
		if e == nil {
			continue
		}

		msg := pool.DefaultMessage.Get()
		msg.Data = e.value
		if err := msg.Unpack(); err != nil {
			pool.DefaultMessage.Put(msg)
			log.Debugf("CACHE: unpack wire for %s (type=%d): %v", qname, qtype, err)
			continue
		}

		// The pooled msg is zeroed on Put but its backing arrays survive —
		// the returned Entry's RR slices stay valid (same contract as before).
		entryTTL := minTTL(msg.Answer, msg.Ns, msg.Extra)
		entry := &Entry{
			Answer:     msg.Answer,
			Authority:  msg.Ns,
			Additional: msg.Extra,
			Timestamp:  e.ts,
			TTL:        entryTTL,
			Validated:  e.validated,
			Rcode:      int(msg.Rcode), //nolint:gosec // G115: DNS rcode — protocol-bounded uint16
		}
		pool.DefaultMessage.Put(msg)

		return entry, true, ttl.IsExpired(e.ts, entryTTL)
	}
	log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
	return nil, false, false
}

// Set stores a DNS response in the cache. Wire format is raw DNS wire format
// (compression happens once, at persist-file write time — the in-memory hot
// path is uncompressed). Returns whether the entry was stored (false when
// TTL=0, which must not be cached per RFC 8767 §7).
func (c *Cache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool, rcode uint16,
) bool {
	now := log.NowUnix()
	// Strip the EDNS OPT pseudo-record before computing the TTL — the OPT TTL
	// field encodes flags/extended RCODE (RFC 6891), not a cacheable RR TTL.
	additional = stripOPT(additional)
	entryTTL := minTTL(answer, authority, additional)
	if entryTTL <= 0 {
		return false // RFC 8767 §7: TTL=0 data must not be cached
	}

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = dnsutil.Canonical(qname)

	// Clone records to prevent downstream mutations from corrupting the cache.
	answer = cloneRRs(answer)
	authority = cloneRRs(authority)
	additional = cloneRRs(additional)

	// Pack wire format. The rcode is stored in the wire so Get can recover it
	// (Entry.Rcode) — negative responses (NXDOMAIN) must be served and cached
	// with their correct rcode.
	msg := pool.DefaultMessage.Get()
	msg.Rcode = rcode
	msg.Answer = answer
	msg.Ns = authority
	msg.Extra = additional
	if err := msg.Pack(); err != nil {
		log.Debugf("CACHE: pack failed for %s (type=%d): %v — not stored", qname, qtype, err)
		pool.DefaultMessage.Put(msg)
		return false
	}
	// Clone out of the pooled buffer: the pool reuses backing arrays, and the
	// stored wire must stay stable while the pool churns.
	wire := bytes.Clone(msg.Data)
	pool.DefaultMessage.Put(msg)

	expiresAt := now + int64(entryTTL) + defaultStaleMaxAge
	key := entryKey{qname: qname, ecsAddr: ecsAddr, ecsPrefix: uint16(ecsPrefix), dnssecOK: dnssecOK, qtype: qtype, qclass: qclass} //nolint:gosec // G115: prefix ≤ 128 by CIDR semantics
	c.insert(key, wire, now, expiresAt, validated)
	c.updatePtrIndex(key, answer, authority, additional, now, expiresAt)
	return true
}

// ── Store interface implementation (lifecycle + latency) ────────────────

// LookupIPLatencies fetches latencies for a batch of IPs (exported for the
// resolver's root-server ordering). Pure in-memory LRU — no backing store.
func (c *Cache) LookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}
	latencies := make(map[string]int, min(len(ips), maxLatencyLookupIPs))
	now := log.NowUnix()
	for _, ip := range ips {
		if e, ok := c.latency.Get(ip); ok && now < e.expiresAt {
			latencies[ip] = e.value
		}
	}
	return latencies
}

// UpdateLatency stores a latency measurement keyed by IP.
func (c *Cache) UpdateLatency(ip string, latencyMS int) {
	if latencyMS < 0 {
		latencyMS = 0
	}
	c.latency.Set(ip, latencyEntry{
		value:     latencyMS,
		expiresAt: log.NowUnix() + config.DefaultLatencyProbeMinInterval*2,
	})
}

// LatencyLastProbe returns the last probe time for an IP (derived from the
// LRU entry's expiry, same semantics as the old BadgerDB key).
func (c *Cache) LatencyLastProbe(ip string) (int64, bool) {
	e, ok := c.latency.Get(ip)
	if !ok || e.expiresAt < log.NowUnix() {
		return 0, false
	}
	return e.expiresAt - int64(config.DefaultLatencyProbeMinInterval)*2, true
}

// Len returns the current number of cached entries.
func (c *Cache) Len() int {
	c.mu.RLock()
	n := c.len
	c.mu.RUnlock()
	return n
}

// SizeBytes returns the current total value size in bytes.
func (c *Cache) SizeBytes() int64 {
	c.mu.RLock()
	n := c.totalSize
	c.mu.RUnlock()
	return n
}

// ── LRU map operations (internal) ───────────────────────────────────────

// lookup returns the entry for key, bumping it to the front. Expired entries
// are returned — expiry is judged by the caller (stale-serve/prefetch need
// the entry itself); physical removal happens on eviction, Save/Load, Clear.
func (c *Cache) lookup(key entryKey) *listEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.store[key]; ok {
		c.moveToFront(e)
		return e
	}
	return nil
}

// insert stores (or updates) an entry, evicting least-recently-used entries
// until the size budget allows the new value.
func (c *Cache) insert(key entryKey, value []byte, ts, expiresAt int64, validated bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	size := int64(len(value))

	if e, ok := c.store[key]; ok {
		c.totalSize += size - int64(len(e.value))
		e.value = value
		e.ts = ts
		e.expiresAt = expiresAt
		e.validated = validated
		c.moveToFront(e)
		return
	}
	for c.totalSize+size > c.maxSize && c.len > 0 {
		c.evictLocked()
	}
	c.totalSize += size
	e := &listEntry{key: key, value: value, ts: ts, expiresAt: expiresAt, validated: validated}
	c.store[key] = e
	c.pushFront(e)
	c.len++
}

// evictLocked removes the least-recently-used entry (just before the tail
// sentinel) and its derived PTR records. Must hold c.mu.
func (c *Cache) evictLocked() {
	if e := c.tail.prev; e != c.head {
		c.remove(e)
		delete(c.store, e.key)
		c.totalSize -= int64(len(e.value))
		c.len--
		c.cleanupPtrIndexLocked(e.key)
	}
}

func (c *Cache) moveToFront(e *listEntry) {
	if e.prev == c.head {
		return // already at front
	}
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = c.head
	e.next = c.head.next
	c.head.next.prev = e
	c.head.next = e
}

func (c *Cache) pushFront(e *listEntry) {
	e.prev = c.head
	e.next = c.head.next
	c.head.next.prev = e
	c.head.next = e
}

func (c *Cache) remove(e *listEntry) {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.prev = nil
	e.next = nil
}

// ── Set-path helpers (moved from the BadgerDB-era store) ────────────────

// minTTL returns the smallest positive TTL across all RR sections.
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
		return 0 // RFC 8767 §7: TTL=0 data must not be cached
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

// maskIP applies a CIDR mask to ip.
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
// to least specific. The final candidate is always the no-ECS key to handle
// scope=0 entries (RFC 7871 §7.3.1: when the authoritative response scope is
// zero, the answer is cached globally without an ECS key).
func ecsFallbackCandidates(ecs *config.ECSOption) []ecsCandidate {
	if ecs == nil {
		// Include both address-family /0 fallbacks so that entries stored with
		// an ECS key (from a prior ECS query) can be found by a non-ECS query.
		return []ecsCandidate{{"", 0}, {"0.0.0.0", 0}, {"::", 0}}
	}
	var standardPrefixes []int
	if ecs.Address.To4() != nil {
		standardPrefixes = ipv4FallbackPrefixes
	} else {
		standardPrefixes = ipv6FallbackPrefixes
	}
	candidates := []ecsCandidate{
		{ecs.Address.String(), int(ecs.SourcePrefix)},
	}
	for _, p := range standardPrefixes {
		if p < int(ecs.SourcePrefix) {
			masked := maskIP(ecs.Address, p)
			candidates = append(candidates, ecsCandidate{masked.String(), p})
		}
	}
	// Always include the no-ECS fallback: authoritatives with scope=0
	// produce cache entries without an ECS key, and those must be
	// reachable from ECS queries.
	candidates = append(candidates, ecsCandidate{"", 0})
	return candidates
}

// stripOPT removes EDNS OPT pseudo-records from an RR slice, returning a new
// slice. It must NOT compact the input in place: callers continue to use
// their slice afterwards (e.g. to build the response's Additional section),
// and in-place compaction would leave a duplicated trailing element behind.
func stripOPT(rrs []dns.RR) []dns.RR {
	hasOPT := false
	for _, rr := range rrs {
		if dns.RRToType(rr) == dns.TypeOPT {
			hasOPT = true
			break
		}
	}
	if !hasOPT {
		return rrs
	}
	out := make([]dns.RR, 0, len(rrs)-1)
	for _, rr := range rrs {
		if dns.RRToType(rr) != dns.TypeOPT {
			out = append(out, rr)
		}
	}
	return out
}
