package cache

import (
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"codeberg.org/miekg/dns"
	dnsutilv2 "codeberg.org/miekg/dns/dnsutil"

	"zjdns/config"
	"zjdns/internal/log"
	"zjdns/internal/ttl"
)

// entryBaseOverhead estimates the per-cache-entry fixed memory cost:
//
//	64 B — map bucket overhead (Go runtime estimate)
//
//	208 B — cacheItem struct (timestamps, flags, ECS option, CompactRecord slice header)
//
//	72 B — CompactRecord struct (Text string header + Type/Class/TTL fields)
//
// entryRecordOverhead (44 B) is the per-record cost: CompactRecord.Text string
// payload plus Go string header overhead.
//
// entryPTROverhead (72 B) is the per-PTR-index cost: ptrTTL struct plus
// reverse-lookup map bucket allocation.
const (
	evictSampleSize     = config.DefaultCacheEvictSampleSize
	entryBaseOverhead   = 64 + 208 + 72
	entryRecordOverhead = 44
	entryPTROverhead    = 72
)

// MemoryCache is an in-memory DNS response cache with optional SQLite persistence.
type MemoryCache struct {
	mu          sync.RWMutex
	entries     map[string]*cacheItem
	entryPTRs   map[string][]ptrRecord
	limitBytes  int64
	currentSize int64
	closed      int32
	ptrIndex    map[string]map[string]ptrTTL

	sqlite       *sqliteStore
	persistPath  string
	ptrSweepStop chan struct{}
}

type cacheItem struct {
	entry      *Entry
	size       int64
	lastAccess atomic.Int64
}

type ptrRecord struct {
	IP   string
	Name string
	TTL  uint32
}

// ptrTTL wraps a TTL with the cache insertion timestamp so the
// reverse-lookup index can return a countdown TTL via ttl.RemainingTTL.
type ptrTTL struct {
	TTL       uint32
	Timestamp int64
}

// New creates a MemoryCache configured with the given settings, restoring any
// persisted SQLite database and writing entries on each Set.
func New(settings config.CacheSettings) *MemoryCache {
	limit := settings.Size
	if limit <= 0 {
		limit = config.DefaultCacheSize
	}
	log.Debugf("CACHE: %d MB cache budget", limit/(1024*1024))

	m := &MemoryCache{
		entries:     make(map[string]*cacheItem),
		entryPTRs:   make(map[string][]ptrRecord),
		limitBytes:  limit,
		ptrIndex:    make(map[string]map[string]ptrTTL),
		persistPath: settings.Persist.File,
	}

	if m.persistPath != "" {
		store, err := openSQLite(m.persistPath)
		if err != nil {
			log.Warnf("CACHE: failed to open sqlite db %s: %v", m.persistPath, err)
		} else {
			m.sqlite = store
			items, err := store.LoadAll()
			if err != nil {
				log.Warnf("CACHE: failed to load entries from sqlite: %v", err)
			} else if len(items) > 0 {
				now := time.Now().Unix()
				loaded := 0
				m.mu.Lock()
				for _, item := range items {
					if item.Key == "" || item.Entry == nil || item.Entry.TTL <= 0 {
						continue
					}
					if now-item.Entry.Timestamp > int64(item.Entry.TTL+config.DefaultStaleMaxAge) {
						continue
					}
					if _, exists := m.entries[item.Key]; exists {
						continue
					}
					entryCopy := cloneEntry(item.Entry)
					ptrs := extractPTRRecords(entryCopy)
					ci := &cacheItem{entry: entryCopy}
					ci.lastAccess.Store(time.Now().UnixNano())
					m.entries[item.Key] = ci
					m.storePTRLocked(item.Key, ptrs, item.Entry.Timestamp)
					ci.size = estimateEntrySize(item.Key, entryCopy, ptrs)
					m.currentSize += ci.size
					loaded++
				}
				m.evictToBudget()
				m.mu.Unlock()
				log.Infof("CACHE: restored %d entries (%d MB) from sqlite %s", loaded, m.currentSize/(1024*1024), m.persistPath)
			}
			log.Infof("CACHE: persistence enabled (sqlite=%s)", m.persistPath)
		}
	} else {
		log.Debugf("CACHE: persistence disabled")
	}

	log.Infof("CACHE: Memory cache enabled (budget=%d MB)", limit/(1024*1024))
	m.startPTRSweeper()
	return m
}

// Get retrieves a cache entry by key, returning the entry, whether found,
// and whether the entry is expired.
func (m *MemoryCache) Get(key string) (*Entry, bool, bool) {
	if atomic.LoadInt32(&m.closed) != 0 {
		return nil, false, false
	}

	m.mu.RLock()
	item, found := m.entries[key]
	if !found || item == nil || item.entry == nil {
		m.mu.RUnlock()
		return nil, false, false
	}

	item.lastAccess.Store(log.NowUnixNano())
	entry := item.entry
	m.mu.RUnlock()

	return entry, true, entry.IsExpired()
}

// Set stores a DNS response in the cache with the given key and metadata.
func (m *MemoryCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *config.ECSOption) {
	m.SetWithDNSSEC(key, answer, authority, additional, validated, false, ecs)
}

// SetWithDNSSEC stores a DNS response with explicit DNSSEC cryptographic
// validation status.
func (m *MemoryCache) SetWithDNSSEC(key string, answer, authority, additional []dns.RR, validated bool, dnssecValidated bool, ecs *config.ECSOption) {
	if atomic.LoadInt32(&m.closed) != 0 {
		return
	}
	now := log.NowUnix()
	ttl := minTTL(answer, authority, additional)

	// RFC 9077: cap TTL for negative responses (NSEC/NSEC3 in authority).
	if hasNSECOrNSEC3(authority) {
		if capTTL := negativeTTLCap(authority); capTTL < ttl {
			ttl = capTTL
		}
	}

	entry := &Entry{
		Answer:          compact(answer),
		Authority:       compact(authority),
		Additional:      compact(additional),
		TTL:             ttl,
		Timestamp:       now,
		Validated:       validated,
		DNSSECValidated: dnssecValidated,
		AccessTime:      now,
	}
	if ecs != nil {
		entry.ECSFamily = ecs.Family
		entry.ECSSourcePrefix = ecs.SourcePrefix
		entry.ECSScopePrefix = ecs.ScopePrefix
		entry.ECSAddress = ecs.Address.String()
	}
	m.setEntryInternal(key, entry)
}

// SetEntry stores a pre-built Entry in the cache under the given key.
// It deep-clones the entry to protect against callers that retain a reference.
func (m *MemoryCache) SetEntry(key string, entry *Entry) {
	if atomic.LoadInt32(&m.closed) != 0 || entry == nil {
		return
	}
	m.setEntryInternal(key, cloneEntry(entry))
}

// setEntryInternal stores an entry in the cache without cloning. The caller
// must not retain any reference to the entry after this call — ownership is
// transferred to the cache. This avoids a wasted clone-and-copy when the
// entry is freshly allocated (e.g. from SetWithDNSSEC).
func (m *MemoryCache) setEntryInternal(key string, entry *Entry) {
	ptrRecords := extractPTRRecords(entry)
	estSize := estimateEntrySize(key, entry, ptrRecords)

	m.mu.Lock()
	defer m.mu.Unlock()
	if atomic.LoadInt32(&m.closed) != 0 {
		return
	}

	if existing, ok := m.entries[key]; ok {
		oldSize := existing.size
		m.removePTRLocked(key)
		existing.entry = entry
		existing.lastAccess.Store(log.NowUnixNano())
		m.storePTRLocked(key, ptrRecords, entry.Timestamp)
		existing.size = estSize
		m.currentSize += estSize - oldSize
		m.evictToBudget()
		if m.sqlite != nil {
			_ = m.sqlite.SaveEntry(key, entry, ptrRecords)
		}
		return
	}

	item := &cacheItem{entry: entry}
	item.lastAccess.Store(log.NowUnixNano())
	m.entries[key] = item
	m.storePTRLocked(key, ptrRecords, entry.Timestamp)
	item.size = estSize
	m.currentSize += estSize

	m.evictToBudget()
	if m.sqlite != nil {
		_ = m.sqlite.SaveEntry(key, entry, ptrRecords)
	}
}

// Close shuts down the cache, finalizing any pending persistence write.
// startPTRSweeper periodically removes stale PTR index entries that no longer
// have a corresponding cache entry, preventing unbounded ptrIndex growth.
func (m *MemoryCache) startPTRSweeper() {
	m.ptrSweepStop = make(chan struct{})
	go func() {
		ticker := time.NewTicker(config.DefaultSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
			case <-m.ptrSweepStop:
				return
			}
			if atomic.LoadInt32(&m.closed) != 0 {
				return
			}
			m.mu.Lock()
			for key, records := range m.entryPTRs {
				if _, ok := m.entries[key]; !ok {
					for _, rec := range records {
						if domains, exists := m.ptrIndex[rec.IP]; exists {
							delete(domains, rec.Name)
							if len(domains) == 0 {
								delete(m.ptrIndex, rec.IP)
							}
						}
					}
					delete(m.entryPTRs, key)
				}
			}
			m.mu.Unlock()
		}
	}()
}

func (m *MemoryCache) Close() error {
	if !atomic.CompareAndSwapInt32(&m.closed, 0, 1) {
		return nil
	}
	if m.ptrSweepStop != nil {
		close(m.ptrSweepStop)
	}
	if m.sqlite != nil {
		if n, err := m.sqlite.DeleteStale(int64(config.DefaultStaleMaxAge)); err != nil {
			log.Errorf("CACHE: sqlite stale cleanup failed: %v", err)
		} else if n > 0 {
			log.Infof("CACHE: sqlite cleaned %d stale entries", n)
		}
		if err := m.sqlite.Close(); err != nil {
			log.Errorf("CACHE: sqlite close failed: %v", err)
		}
	}
	m.mu.Lock()
	m.entries = nil
	m.ptrIndex = nil
	m.mu.Unlock()
	log.Infof("CACHE: Memory cache shut down")
	return nil
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (m *MemoryCache) ReverseLookup(ip net.IP) []LookupResult {
	if ip == nil {
		return nil
	}
	m.mu.RLock()
	candidates, ok := m.ptrIndex[ip.String()]
	if !ok || len(candidates) == 0 {
		m.mu.RUnlock()
		return nil
	}
	results := make([]LookupResult, 0, len(candidates))
	for name, pttl := range candidates {
		results = append(results, LookupResult{Name: name, TTL: ttl.RemainingTTL(pttl.Timestamp, int(pttl.TTL), uint32(config.DefaultStaleTTL))})
	}
	m.mu.RUnlock()

	for i := 1; i < len(results); i++ {
		j := i
		for j > 0 && results[j-1].Name > results[j].Name {
			results[j-1], results[j] = results[j], results[j-1]
			j--
		}
	}
	return results
}

func (m *MemoryCache) evictToBudget() {
	if m.limitBytes <= 0 || m.currentSize <= m.limitBytes || len(m.entries) == 0 {
		return
	}

	evicted := 0
	for m.currentSize > m.limitBytes && len(m.entries) > 0 {
		// Randomly sample entries from the map to approximate LRU without
		// allocating a full keys slice under the write lock. Scale sample
		// size with sqrt(|entries|) to maintain fidelity in large caches
		// while staying O(√n) per eviction.
		sampleSize := evictSampleSize
		if n := len(m.entries); n > sampleSize*sampleSize {
			sampleSize = int(math.Sqrt(float64(n)))
		}
		var oldestKey string
		var oldestLast int64 = math.MaxInt64
		var oldestSize int64

		sampleCount := 0
		for k, item := range m.entries {
			if sampleCount >= sampleSize {
				break
			}
			sampleCount++
			last := item.lastAccess.Load()
			if last < oldestLast {
				oldestLast = last
				oldestKey = k
				oldestSize = item.size
			}
		}

		if oldestKey == "" {
			break
		}
		m.currentSize -= oldestSize
		m.removePTRLocked(oldestKey)
		delete(m.entries, oldestKey)
		evicted++
	}

	if evicted > 0 {
		log.Debugf("CACHE: evicted %d entries to enforce budget (current=%d MB, limit=%d MB)", evicted, m.currentSize/(1024*1024), m.limitBytes/(1024*1024))
	}
}

func extractPTRRecords(entry *Entry) []ptrRecord {
	if entry == nil {
		return nil
	}
	records := make([]ptrRecord, 0, len(entry.Answer))
	for _, cr := range entry.Answer {
		if cr == nil {
			continue
		}
		rr := expand(cr)
		if rr == nil {
			continue
		}
		var ip net.IP
		var name string
		var ttl uint32
		switch r := rr.(type) {
		case *dns.A:
			ip, name, ttl = net.IP(r.Addr.AsSlice()), r.Hdr.Name, r.Hdr.TTL
		case *dns.AAAA:
			ip, name, ttl = net.IP(r.Addr.AsSlice()), r.Hdr.Name, r.Hdr.TTL
		default:
			continue
		}
		if ip == nil || name == "" {
			continue
		}
		records = append(records, ptrRecord{IP: ip.String(), Name: dnsutilv2.Fqdn(name), TTL: ttl})
	}
	return records
}

func (m *MemoryCache) storePTRLocked(key string, records []ptrRecord, timestamp int64) {
	if len(records) == 0 {
		delete(m.entryPTRs, key)
		return
	}
	cloned := make([]ptrRecord, len(records))
	copy(cloned, records)
	m.entryPTRs[key] = cloned
	for _, rec := range cloned {
		if m.ptrIndex[rec.IP] == nil {
			m.ptrIndex[rec.IP] = make(map[string]ptrTTL)
		}
		m.ptrIndex[rec.IP][rec.Name] = ptrTTL{TTL: rec.TTL, Timestamp: timestamp}
	}
}

func (m *MemoryCache) removePTRLocked(key string) {
	records, ok := m.entryPTRs[key]
	if !ok || len(records) == 0 {
		delete(m.entryPTRs, key)
		return
	}
	for _, rec := range records {
		if domains, ok := m.ptrIndex[rec.IP]; ok {
			delete(domains, rec.Name)
			if len(domains) == 0 {
				delete(m.ptrIndex, rec.IP)
			}
		}
	}
	delete(m.entryPTRs, key)
}

func estimateEntrySize(key string, entry *Entry, ptrs []ptrRecord) int64 {
	if entry == nil {
		return 0
	}
	size := int64(len(key)) + entryBaseOverhead

	for _, cr := range entry.Answer {
		if cr != nil {
			size += int64(len(cr.Text)) + entryRecordOverhead
		}
	}
	for _, cr := range entry.Authority {
		if cr != nil {
			size += int64(len(cr.Text)) + entryRecordOverhead
		}
	}
	for _, cr := range entry.Additional {
		if cr != nil {
			size += int64(len(cr.Text)) + entryRecordOverhead
		}
	}
	size += int64(len(entry.Payload))

	for _, pr := range ptrs {
		size += int64(len(pr.IP)+len(pr.Name)) + entryPTROverhead
	}
	return size
}

func cloneEntry(entry *Entry) *Entry {
	if entry == nil {
		return nil
	}
	cloned := *entry
	cloned.Answer = cloneRecords(entry.Answer)
	cloned.Authority = cloneRecords(entry.Authority)
	cloned.Additional = cloneRecords(entry.Additional)
	return &cloned
}

func cloneRecords(records []*CompactRecord) []*CompactRecord {
	if len(records) == 0 {
		return nil
	}
	cloned := make([]*CompactRecord, len(records))
	for i, r := range records {
		if r == nil {
			continue
		}
		rr := *r
		cloned[i] = &rr
	}
	return cloned
}

func compact(rrs []dns.RR) []*CompactRecord {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]*CompactRecord, 0, len(rrs))
	seen := make(map[string]struct{}, len(rrs))
	for _, rr := range rrs {
		if rr == nil || dns.RRToType(rr) == dns.TypeOPT {
			continue
		}
		rrText := rr.String()
		if _, dup := seen[rrText]; dup {
			continue
		}
		seen[rrText] = struct{}{}
		if cr := newCompactRecord(rr); cr != nil {
			result = append(result, cr)
		}
	}
	return result
}

func expand(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.New(cr.Text)
	return rr
}

func minTTL(answer, authority, additional []dns.RR) int {
	minT := -1
	for _, rrs := range [][]dns.RR{answer, authority, additional} {
		for _, rr := range rrs {
			if rr == nil {
				continue
			}
			if ttl := int(rr.Header().TTL); ttl > 0 && (minT < 0 || ttl < minT) {
				minT = ttl
			}
		}
	}
	if minT <= 0 {
		return config.DefaultTTL
	}
	return minT
}

// hasNSECOrNSEC3 reports whether any record in the authority section is an
// NSEC or NSEC3 record, indicating a negative (NXDOMAIN/NODATA) response.
func hasNSECOrNSEC3(authority []dns.RR) bool {
	for _, rr := range authority {
		if rr == nil {
			continue
		}
		switch dns.RRToType(rr) {
		case dns.TypeNSEC, dns.TypeNSEC3:
			return true
		}
	}
	return false
}

// negativeTTLCap returns the maximum TTL for a negative cache entry per
// RFC 9077. It extracts the SOA record from the authority section and
// computes min(SOA.MINIMUM, SOA TTL), capped at DefaultMaxNegativeTTL.
// If no SOA is present, returns DefaultMaxNegativeTTL.
func negativeTTLCap(authority []dns.RR) int {
	capTTL := config.DefaultMaxNegativeTTL
	for _, rr := range authority {
		if rr == nil {
			continue
		}
		soa, ok := rr.(*dns.SOA)
		if !ok {
			continue
		}
		soaTTL := int(soa.Header().TTL)
		soaMin := int(soa.Minttl)
		soaBased := soaTTL
		if soaMin < soaBased {
			soaBased = soaMin
		}
		if soaBased < capTTL {
			capTTL = soaBased
		}
		break // first SOA is authoritative
	}
	return capTTL
}
