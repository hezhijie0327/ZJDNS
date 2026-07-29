package cache

import (
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
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

// Cache is a DNS response cache backed by a BadgerDB key-value store. It
// implements the Store interface.
type Cache struct {
	db          *database.DB
	evictCount  atomic.Int64
	asyncWriter *AsyncStatsWriter
}

// ecsCandidate is a single ECS cache-key candidate used during fallback lookup.
type ecsCandidate struct {
	addr   string
	prefix int
}

const (
	defaultStaleMaxAge  = int64(config.DefaultStaleMaxAge)
	maxLatencyLookupIPs = 64 // cap per-Get latency lookups to bound iteration overhead
	decompressBufCap    = 4096
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

// New creates a BadgerDB-backed DNS cache. Panics if db is nil (caller must
// provide a valid database handle — the server wiring always does).
func New(db *database.DB) *Cache {
	if db == nil {
		panic("cache: nil database")
	}
	return &Cache{
		db:          db,
		asyncWriter: NewAsyncStatsWriter(db, config.DefaultAsyncStatsBufferSize),
	}
}

// Close shuts down the async stats writer and then closes the database.
func (c *Cache) Close() error {
	c.asyncWriter.Close()
	return c.db.Close()
}

// Flush forces the async stats writer to write any buffered records immediately.
// Primarily for tests that need to observe RecordRequest results synchronously.
func (c *Cache) Flush() {
	c.asyncWriter.Flush()
}

// ── Store interface ──────────────────────────────────────────────────────────

// Get retrieves a cached DNS response by decompressing and unpacking the stored
// wire format. Returns the entry, whether it was found, and whether it's expired.
func (c *Cache) Get(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool) (*Entry, bool, bool) {
	if c.db.IsClosed() {
		return nil, false, false
	}

	qname = dnsutil.Canonical(qname)
	var id uint64
	var ts int64
	var entryTTL int32
	var validated bool
	var msgWire []byte
	found := false

	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		for _, cand := range ecsFallbackCandidates(ecs) {
			key := database.EntryKey(qname, cand.addr, cand.prefix, dnssecOK, qtype, qclass)
			item, err := txn.Get(key)
			if err != nil {
				continue
			}
			validated = item.UserMeta() == 1
			if err := item.Value(func(v []byte) error {
				id, ts, entryTTL, msgWire = database.DecodeEntryValue(v)
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

	// Decompress and unpack the wire format into a dns.Msg.
	dbuf, ok := decompressBufPool.Get().(*[]byte)
	if !ok {
		b := make([]byte, 0, decompressBufCap)
		dbuf = &b
	}
	wire, err := zdnsutil.DecompressTo(msgWire, *dbuf)
	if err != nil {
		clear(*dbuf)
		decompressBufPool.Put(dbuf)
		log.Warnf("CACHE: decompress wire for entry %d (name=%s type=%d): %v", id, qname, qtype, err)
		return nil, false, false
	}
	defer func() { clear(*dbuf); decompressBufPool.Put(dbuf) }()

	msg := pool.DefaultMessage.Get()
	msg.Data = wire
	if err := msg.Unpack(); err != nil {
		log.Warnf("CACHE: unpack wire for entry %d (name=%s type=%d): %v", id, qname, qtype, err)
		return nil, false, false
	}
	defer pool.DefaultMessage.Put(msg)

	entry := &Entry{
		ID:         int64(id),
		Answer:     msg.Answer,
		Authority:  msg.Ns,
		Additional: msg.Extra,
		Timestamp:  ts,
		TTL:        int(entryTTL),
		Validated:  validated,
	}

	// Sort A/AAAA answer records by latency.
	c.sortAnswerByLatency(entry)

	isExpired := ttl.IsExpired(ts, int(entryTTL))
	return entry, true, isExpired
}

// sortAnswerByLatency reorders A/AAAA records in entry.Answer by probe
// latency (fastest first), keeping non-A/AAAA records at the front.
func (c *Cache) sortAnswerByLatency(entry *Entry) {
	if len(entry.Answer) <= 1 {
		return
	}

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

	latencies := c.lookupIPLatencies(ips)
	if len(latencies) == 0 {
		return
	}

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

// lookupIPLatencies fetches latencies for a batch of IPs.
func (c *Cache) lookupIPLatencies(ips []string) map[string]int {
	if len(ips) > maxLatencyLookupIPs {
		ips = ips[:maxLatencyLookupIPs]
	}
	latencies := make(map[string]int, min(len(ips), maxLatencyLookupIPs))

	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		for _, ip := range ips {
			item, err := txn.Get(database.LatencyKey(ip))
			if err != nil {
				continue
			}
			_ = item.Value(func(v []byte) error {
				_, latMS, _ := database.DecodeLatencyValue(v)
				latencies[ip] = latMS
				return nil
			})
		}
		return nil
	})
	return latencies
}

// Set stores a DNS response in the cache. Wire format is zstd-compressed.
func (c *Cache) Set(qname string, qtype, qclass uint16, ecs *config.ECSOption, dnssecOK bool,
	answer, authority, additional []dns.RR, validated bool,
) int64 {
	if c.db.IsClosed() {
		return 0
	}

	// ── Prep work (parallel-safe) ─────────────────────────────────────────
	now := log.NowUnix()
	entryTTL := minTTL(answer, authority, additional)

	ecsAddr, ecsPrefix := ecsParams(ecs)
	qname = dnsutil.Canonical(qname)

	// Strip EDNS OPT pseudo-record from additional before caching.
	additional = stripOPT(cloneRRs(additional))

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
		msgWire = zdnsutil.Compress(msg.Data)
	}
	pool.DefaultMessage.Put(msg)

	// ── Transaction ──────────────────────────────────────────────────────
	var entryID uint64
	expiresAt := now + int64(entryTTL) + defaultStaleMaxAge
	ttlDurationSec := int64(entryTTL) + defaultStaleMaxAge

	err := c.db.Badger.Update(func(txn *badger.Txn) error {
		id, idErr := c.db.NextEntryID()
		if idErr != nil {
			return idErr
		}
		entryID = id

		key := database.EntryKey(qname, ecsAddr, ecsPrefix, dnssecOK, qtype, qclass)
		val := database.EncodeEntryValue(id, now, int32(entryTTL), msgWire) //nolint:gosec // G115: protocol-bounded value fits target type
		entry := badger.NewEntry(key, val).
			WithMeta(database.UserMetaValidated(validated)).
			WithTTL(time.Duration(ttlDurationSec) * time.Second)

		if err := txn.SetEntry(entry); err != nil {
			return err
		}

		// Populate ptr_map for reverse (PTR) lookups — best-effort.
		allRRs := make([]dns.RR, 0, len(answer)+len(authority)+len(additional))
		allRRs = append(allRRs, answer...)
		allRRs = append(allRRs, authority...)
		allRRs = append(allRRs, additional...)
		if ptrErr := insertPtrMap(txn, id, allRRs, expiresAt); ptrErr != nil {
			log.Warnf("CACHE: insert ptr_map failed (non-fatal): %v", ptrErr)
		}

		return nil
	})
	if err != nil {
		log.Warnf("CACHE: insert entry failed: %v", err)
		return 0
	}

	c.db.AddEntryCount(1)
	c.evictIfNeeded()
	return int64(entryID)
}

// ── Eviction ─────────────────────────────────────────────────────────────────

func (c *Cache) evictIfNeeded() {
	if c.db.MaxEntries() <= 0 {
		return
	}

	count := c.db.EntryCount()
	maxEntries := int64(c.db.MaxEntries())
	if count < maxEntries*9/10 {
		return
	}

	// Resync from DB every 20 evictions.
	if count < 0 || c.evictCount.Load()%20 == 0 {
		var n int64
		_ = c.db.Badger.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.Prefix = database.EntryKeyPrefix()
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				n++
			}
			return nil
		})
		c.db.SetEntryCount(n)
		count = n
	}

	excess := count - maxEntries
	if excess <= 0 {
		return
	}

	c.evictOldest(excess)
	c.evictCount.Add(1)
}

func (c *Cache) evictOldest(toEvict int64) {
	type entryInfo struct {
		key       []byte
		timestamp int64
	}

	// Collect all entries with timestamps.
	var entries []entryInfo
	_ = c.db.Badger.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.EntryKeyPrefix()
		opts.PrefetchValues = true
		it := txn.NewIterator(opts)
		defer it.Close()

		entries = make([]entryInfo, 0, c.db.EntryCount())
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)
			_ = item.Value(func(v []byte) error {
				_, ts, _, _ := database.DecodeEntryValue(v)
				entries = append(entries, entryInfo{key: k, timestamp: ts})
				return nil
			})
		}
		return nil
	})

	if len(entries) == 0 {
		return
	}

	// Sort by timestamp ascending (oldest first).
	slices.SortStableFunc(entries, func(a, b entryInfo) int {
		if a.timestamp < b.timestamp {
			return -1
		}
		if a.timestamp > b.timestamp {
			return 1
		}
		return 0
	})

	// Delete the oldest entries.
	toDelete := min(int(toEvict), len(entries))

	_ = c.db.Badger.Update(func(txn *badger.Txn) error {
		for i := range toDelete {
			if err := txn.Delete(entries[i].key); err != nil {
				continue
			}
		}
		return nil
	})

	n := int64(toDelete)
	c.db.AddEntryCount(-n)
	log.Debugf("CACHE: evicted %d entries (oldest, max=%d)", n, c.db.MaxEntries())
}

// ── PruneQueryJournal ────────────────────────────────────────────────────────

// PruneQueryJournal removes query_stats rows with stat_day older than the
// retention window and query_log rows with timestamp older than retentionSec.
func (c *Cache) PruneQueryJournal(retentionSec int64) (int64, error) {
	batchSize := int64(config.DefaultPruneBatchSize)
	dayCutoff := log.NowUnix()/86400 - retentionSec/86400
	var totalDeleted int64

	// query_stats: delete by prefix scan + timestamp check.
	err := c.db.Badger.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = database.QueryStatsPrefix()
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		var keysToDelete [][]byte
		for it.Rewind(); it.Valid(); it.Next() {
			day, ok := database.ParseStatDay(it.Item().Key())
			if ok && day < dayCutoff {
				k := it.Item().KeyCopy(nil)
				keysToDelete = append(keysToDelete, k)
			}
		}
		for _, k := range keysToDelete {
			if err := txn.Delete(k); err != nil {
				continue
			}
			totalDeleted++
		}
		return nil
	})
	if err != nil {
		return totalDeleted, fmt.Errorf("cleanup query_stats: %w", err)
	}

	// query_log: batched delete to avoid long write transactions.
	for {
		var batchDeleted int64
		err := c.db.Badger.Update(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.Prefix = database.QueryLogPrefix()
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()

			var keysToDelete [][]byte
			for it.Rewind(); it.Valid() && int64(len(keysToDelete)) < batchSize; it.Next() {
				ts, ok := database.ParseQueryLogTimestamp(it.Item().Key())
				if ok && ts < log.NowUnix()-retentionSec {
					k := it.Item().KeyCopy(nil)
					keysToDelete = append(keysToDelete, k)
				}
			}
			for _, k := range keysToDelete {
				if err := txn.Delete(k); err != nil {
					continue
				}
				batchDeleted++
			}
			return nil
		})
		if err != nil {
			return totalDeleted, fmt.Errorf("cleanup query_log: %w", err)
		}
		totalDeleted += batchDeleted
		if batchDeleted < batchSize {
			break
		}
	}

	return totalDeleted, nil
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
