package cache

import (
	"net"
	"slices"
	"zjdns/config"
	"zjdns/database"
	"zjdns/internal/log"
	"zjdns/internal/pool"
	"zjdns/internal/ttl"

	zdnsutil "zjdns/internal/dnsutil"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"github.com/dgraph-io/badger/v4"
)

// Cache is a DNS response cache backed by a BadgerDB key-value store.
type Cache struct {
	db *database.DB
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

// New creates a BadgerDB-backed DNS cache. Panics if db is nil (caller must
// provide a valid database handle — the server wiring always does).
func New(db *database.DB) *Cache {
	if db == nil {
		panic("cache: nil database")
	}
	return &Cache{db: db}
}

// Close closes the database.
func (c *Cache) Close() error {
	return c.db.Close()
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
func (c *Cache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	if c.db.IsClosed() {
		return nil, false, false
	}

	qname = dnsutil.Canonical(qname)
	var validated bool
	var msgWire []byte
	var expiresAt uint64
	found := false

	_ = c.db.View(func(txn *badger.Txn) error {
		for _, cand := range ecsFallbackCandidates(ecs) {
			key := database.EntryKey(qname, cand.addr, cand.prefix, dnssecOK, qtype, qclass)
			item, err := txn.Get(key)
			if err != nil {
				continue
			}
			validated = item.UserMeta() == database.UserMetaValidated(true)
			expiresAt = item.ExpiresAt()
			if err := item.Value(func(v []byte) error {
				msgWire = v
				return nil
			}); err != nil {
				continue
			}
			found = true
			return nil
		}
		return nil
	})

	if !found {
		log.Debugf("CACHE: miss for %s (type=%d)", qname, qtype)
		return nil, false, false
	}

	if len(msgWire) == 0 {
		return nil, false, false
	}

	msg := pool.DefaultMessage.Get()
	msg.Data = msgWire
	if err := msg.Unpack(); err != nil {
		pool.DefaultMessage.Put(msg)
		log.Debugf("CACHE: unpack wire for %s (type=%d): %v", qname, qtype, err)
		return nil, false, false
	}
	defer pool.DefaultMessage.Put(msg)

	// Derive entry TTL from the unpacked wire (minimum positive TTL across all sections).
	// Derive store timestamp from Badger's native expiry clock.
	// Badger TTL = entryTTL + defaultStaleMaxAge seconds.
	// expiresAt = timestamp + entryTTL + defaultStaleMaxAge
	// → timestamp = expiresAt - entryTTL - defaultStaleMaxAge
	entryTTL := minTTL(msg.Answer, msg.Ns, msg.Extra)
	var ts int64
	if expiresAt != 0 {
		ts = int64(expiresAt) - int64(entryTTL) - defaultStaleMaxAge
	} else {
		// Defensive: entry stored without TTL (should not happen).
		ts = log.NowUnix()
	}

	entry := &Entry{
		Answer:     msg.Answer,
		Authority:  msg.Ns,
		Additional: msg.Extra,
		Timestamp:  ts,
		TTL:        entryTTL,
		Validated:  validated,
	}

	// Sort A/AAAA answer records by latency.
	c.sortAnswerByLatency(entry)

	isExpired := ttl.IsExpired(ts, entryTTL)
	return entry, true, isExpired
}

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records at the front.
func (c *Cache) sortAnswerByLatency(entry *Entry) {
	if len(entry.Answer) <= 1 {
		return
	}

	rrToIP := make(map[dns.RR]string, len(entry.Answer))
	addrRRs := make([]dns.RR, 0, len(entry.Answer))
	for _, rr := range entry.Answer {
		if ip, ok := zdnsutil.ExtractIPString(rr); ok {
			rrToIP[rr] = ip
			addrRRs = append(addrRRs, rr)
		}
	}
	if len(addrRRs) <= 1 {
		return
	}

	ips := make([]string, len(addrRRs))
	for i, rr := range addrRRs {
		ips[i] = rrToIP[rr]
	}
	latencies := c.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return
	}

	slices.SortStableFunc(addrRRs, func(a, b dns.RR) int {
		aLat, aOK := latencies[rrToIP[a]]
		bLat, bOK := latencies[rrToIP[b]]
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

	// Merge sorted A/AAAA back into Answer — non-IP records stay in place.
	j := 0
	for i, rr := range entry.Answer {
		if _, ok := rrToIP[rr]; ok {
			entry.Answer[i] = addrRRs[j]
			j++
		}
	}
}

// lookupIPLatencies fetches latencies for a batch of IPs.
func (c *Cache) lookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}
	latencies := make(map[string]int, min(len(ips), maxLatencyLookupIPs))

	_ = c.db.View(func(txn *badger.Txn) error {
		var buf []byte
		for _, ip := range ips {
			item, err := txn.Get(database.EIPLatencyKey(ip))
			if err != nil {
				continue
			}
			if item.IsDeletedOrExpired() {
				continue
			}
			buf, err = item.ValueCopy(buf)
			if err != nil {
				continue
			}
			latencies[ip] = database.DecodeLatencyValue(buf)
		}
		return nil
	})
	return latencies
}

// Set stores a DNS response in the cache. Wire format is raw DNS wire format
// (BadgerDB handles block-level zstd compression at the SSTable layer).
func (c *Cache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool,
) int64 {
	if c.db.IsClosed() {
		return 0
	}

	// ── Prep work (parallel-safe) ─────────────────────────────────────────
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)
	if entryTTL <= 0 {
		return 0 // RFC 8767 §7: TTL=0 data must not be cached
	}

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = dnsutil.Canonical(qname)

	// Strip EDNS OPT pseudo-record from additional before caching (stripOPT allocates a new slice).
	additional = stripOPT(additional)

	// Clone records to prevent downstream mutations from corrupting the cache.
	answer = cloneRRs(answer)
	authority = cloneRRs(authority)
	additional = cloneRRs(additional)

	// Pack wire format and compress.
	msg := pool.DefaultMessage.Get()
	msg.Answer = answer
	msg.Ns = authority
	msg.Extra = additional
	var msgWire []byte
	if err := msg.Pack(); err == nil {
		msgWire = msg.Data
	} else {
		log.Debugf("CACHE: pack failed for %s (type=%d): %v — not stored", qname, qtype, err)
		pool.DefaultMessage.Put(msg)
		return 0
	}
	pool.DefaultMessage.Put(msg)

	// ── Transaction ──────────────────────────────────────────────────────
	var entryID uint64
	ttlDurationSec := int64(entryTTL) + defaultStaleMaxAge

	err := c.db.Update(func(txn *badger.Txn) error {
		id, idErr := c.db.NextEntryID()
		if idErr != nil {
			return idErr
		}
		entryID = id

		key := database.EntryKey(qname, ecsAddr, ecsPrefix, dnssecOK, qtype, qclass)
		e := badger.NewEntry(key, msgWire)
		e.UserMeta = database.UserMetaValidated(validated)
		e.ExpiresAt = uint64(now + ttlDurationSec) //nolint:gosec // G115: protocol-bounded value fits target type

		if err := txn.SetEntry(e); err != nil {
			return err
		}

		// Populate ptr_map for reverse (PTR) lookups — best-effort.
		allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
		allRRs = append(allRRs, answer...)
		allRRs = append(allRRs, authority...)
		allRRs = append(allRRs, additional...)
		if ptrErr := insertPtrMap(txn, id, allRRs, now, ttlDurationSec); ptrErr != nil {
			log.Warnf("CACHE: insert ptr_map failed for %s (non-fatal): %v", qname, ptrErr)
		}

		return nil
	})
	if err != nil {
		log.Warnf("CACHE: insert entry failed for %s (type=%d): %v", qname, qtype, err)
		return 0
	}

	return int64(entryID)
}

// ── Set-path helpers ──────────────────────────────────────────────────────

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
// to least specific.
func ecsFallbackCandidates(ecs *config.ECSOption) []ecsCandidate {
	if ecs == nil {
		return []ecsCandidate{{"", 0}}
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
	return candidates
}

// stripOPT removes EDNS OPT pseudo-records from an RR slice in-place.
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
