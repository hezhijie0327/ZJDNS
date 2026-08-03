package cache

import (
	"bytes"
	"net"
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

// cacheEntry is the stored value for one cached response. The wire format
// value stays uncompressed in memory; compression happens once, at persist
// file write time.
type cacheEntry struct {
	value     []byte // DNS wire format
	ts        int64  // unix seconds at write
	expiresAt int64  // ts + entryTTL + staleMaxAge — hard removal deadline
	validated bool
	ips       []string // distinct IPs in the entry (for targeted PTR-index cleanup on eviction; not persisted)
}

// latencyEntry holds an IP latency measurement with its expiry time, so the
// in-memory LRU cache honours the same TTL semantics as before (2 ×
// DefaultLatencyProbeMinInterval). Transient — never persisted.
type latencyEntry struct {
	value     int   // latency in milliseconds
	expiresAt int64 // unix timestamp after which the entry is considered stale
}

// Cache is an in-memory DNS response cache: O(1) map lookup, LRU eviction by
// total value bytes, and optional persist files. All three maps are
// lrumap.Map instances with their own internal mutexes — the cache holds no
// lock of its own. The PTR index (ip → owning entryKeys, optionally
// persisted to ptr.zst) and the latency map (optionally persisted to
// latency.zst) are transient-friendly: a missing file falls back to
// derivation / cold start.
type Cache struct {
	store    *lrumap.Map[entryKey, cacheEntry]
	ptrIndex *lrumap.Map[string, []entryKey] // ip → entries containing that IP
	latency  *lrumap.Map[string, latencyEntry]
}

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap per-Get latency lookups to bound iteration overhead
)

// New creates an in-memory cache. maxSizeBytes caps total stored value bytes
// (0 = config default); file is the optional cache persist path, loaded
// eagerly. The PTR index and latency maps are optionally persisted via
// SetPtrPersist / SetLatencyPersist (called right after New by the server).
func New(maxSizeBytes int64, file string) *Cache {
	if maxSizeBytes <= 0 {
		maxSizeBytes = int64(config.DefaultCacheMaxSizeMB) << 20
	}
	// Count capacity is not enforced once weight eviction is configured — the
	// value only pre-sizes the hash map.
	store := lrumap.New[entryKey, cacheEntry](64)
	c := &Cache{
		store:    store,
		ptrIndex: lrumap.New[string, []entryKey](64),
		latency:  lrumap.New[string, latencyEntry](config.DefaultLatencyCacheCapacity),
	}
	store.SetWeight(maxSizeBytes, func(e cacheEntry) int64 { return int64(len(e.value)) })
	store.SetOnEvict(func(k entryKey, e cacheEntry) { c.cleanupPtrIndex(k, e.ips) })
	// Byte-budget the PTR index: one IP can map to hundreds of entries, so a
	// count cap alone would not bound memory. Same mechanism as the cache.
	c.ptrIndex.SetWeight(config.DefaultPtrIndexMaxBytes, ptrIndexWeight)
	if file != "" {
		if n, err := store.EnablePersist(lrumap.PersistConfig[entryKey, cacheEntry]{
			Path:  file,
			Codec: cacheCodec{},
			Keep: func(_ entryKey, e cacheEntry) bool {
				return e.expiresAt == 0 || e.expiresAt >= log.NowUnix()
			},
		}); err != nil {
			log.Warnf("CACHE: persist load failed (starting cold): %v", err)
		} else if n > 0 {
			log.Infof("CACHE: loaded %d entries from %s", n, file)
		}
	}
	return c
}

// SetPtrPersist attaches file persistence to the PTR index and eagerly loads
// it. When the file is missing, corrupt, or empty, the index is derived from
// the loaded cache entries instead. Must be called immediately after New,
// before the cache serves queries.
func (c *Cache) SetPtrPersist(path string) {
	if path == "" {
		return
	}
	// Entry keys carry no expiry — staleness is judged against the owning
	// entry at query time, so no Keep filter is needed on save or load.
	n, err := c.ptrIndex.EnablePersist(lrumap.PersistConfig[string, []entryKey]{
		Path:  path,
		Codec: ptrCodec{},
	})
	if err != nil {
		log.Warnf("CACHE: ptr persist load failed (deriving index from entries): %v", err)
	} else if n > 0 {
		log.Infof("CACHE: loaded %d ptr mappings from %s", n, path)
	}
	if c.ptrIndex.Len() == 0 {
		// Cold start, or the file was missing/corrupt/empty — derive the
		// index from the entries that just loaded from cache.zst.
		c.rebuildPtrIndex()
	}
}

// SavePtrIndex persists the PTR index (registered on the persist manager).
func (c *Cache) SavePtrIndex() error { return c.ptrIndex.Save() }

// SetLatencyPersist attaches file persistence to the latency map and eagerly
// loads it (expired measurements are dropped). Must be called immediately
// after New, before the cache serves queries.
func (c *Cache) SetLatencyPersist(path string) {
	if path == "" {
		return
	}
	n, err := c.latency.EnablePersist(lrumap.PersistConfig[string, latencyEntry]{
		Path:  path,
		Codec: latencyCodec{},
		Keep: func(_ string, v latencyEntry) bool {
			return v.expiresAt == 0 || v.expiresAt >= log.NowUnix()
		},
	})
	if err != nil {
		log.Warnf("CACHE: latency persist load failed (starting empty): %v", err)
	} else if n > 0 {
		log.Infof("CACHE: loaded %d latency entries from %s", n, path)
	}
}

// SaveLatency persists the latency map (registered on the persist manager).
func (c *Cache) SaveLatency() error { return c.latency.Save() }

// Get retrieves a cached DNS response. Returns the entry, whether it was
// found, and whether it's expired (expired entries are still returned for
// stale-serving and prefetch — the middleware decides).
func (c *Cache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	qname = dnsutil.Canonical(qname)
	ecAddr, ecsPrefix := ecsCacheKey(ecs)
	key := entryKey{qname: qname, ecsAddr: ecAddr, ecsPrefix: ecsPrefix, dnssecOK: dnssecOK, qtype: qtype, qclass: qclass} //nolint:gosec // G115: prefix ≤ 128 by CIDR semantics
	e, ok := c.store.Get(key)
	if !ok {
		log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
		return nil, false, false
	}

	msg := pool.DefaultMessage.Get()
	msg.Data = e.value
	if err := msg.Unpack(); err != nil {
		pool.DefaultMessage.Put(msg)
		return nil, false, false
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
	// Reorder A/AAAA records fastest-first by cached probe latency — the
	// client-facing counterpart of the resolver's NS address ordering.
	if (qtype == dns.TypeA || qtype == dns.TypeAAAA) && len(entry.Answer) > 1 {
		if latencies := c.recordLatencyLookup(entry.Answer); latencies != nil {
			sortAnswerByLatency(entry.Answer, latencies)
		}
	}
	pool.DefaultMessage.Put(msg)

	return entry, true, ttl.IsExpired(e.ts, entryTTL)
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
	// Extract the IP set once and store it on the entry: on eviction the
	// OnEvict callback can then remove the owner from exactly these PTR
	// mappings instead of scanning the whole index under the store lock.
	ips := extractIPs(answer, authority, additional)
	// Retrieve the previous entry IPs for targeted PTR cleanup.
	var oldIPs []string
	if old, ok := c.store.Get(key); ok {
		oldIPs = old.ips
	}
	c.store.Set(key, cacheEntry{value: wire, ts: now, expiresAt: expiresAt, validated: validated, ips: ips})
	c.updatePtrIndex(key, ips, oldIPs)
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
	return c.store.Len()
}

// SizeBytes returns the current total value size in bytes.
func (c *Cache) SizeBytes() int64 {
	return c.store.TotalWeight()
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

// ecsCacheKey returns the ECS cache-key components: address string and prefix.
// Returns ("", 0) when ECS is nil (no client subnet).
func ecsCacheKey(ecs *config.ECSOption) (addr string, prefix uint16) {
	if ecs == nil {
		return addr, prefix
	}
	addr = ecs.Address.String()
	prefix = uint16(ecs.SourcePrefix)
	return addr, prefix
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
