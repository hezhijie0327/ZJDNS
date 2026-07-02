package cache

import (
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/internal/log"
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
// entryPTROverhead (56 B) is the per-PTR-index cost: ptrRecord struct plus
// reverse-lookup map bucket allocation.
const (
	evictSampleSize     = config.DefaultCacheEvictSampleSize
	entryBaseOverhead   = 64 + 208 + 72
	entryRecordOverhead = 44
	entryPTROverhead    = 56
)

// MemoryCache is an in-memory DNS response cache with optional disk persistence.
type MemoryCache struct {
	mu          sync.RWMutex
	entries     map[string]*cacheItem
	entryPTRs   map[string][]ptrRecord
	limitBytes  int64
	currentSize int64
	closed      int32
	ptrIndex    map[string]map[string]uint32

	persistPath     string
	persistInterval time.Duration
	persistStop     chan struct{}
	persistDone     chan struct{}
	ptrSweepStop    chan struct{}
	persistGen      atomic.Int64
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

// New creates a MemoryCache configured with the given settings, restoring any
// persisted snapshot and starting the persistence worker if configured.
func New(settings config.CacheSettings) *MemoryCache {
	limit := settings.Size
	if limit <= 0 {
		limit = config.DefaultCacheSize
	}
	log.Infof("CACHE: %d MB cache budget", limit/(1024*1024))

	m := &MemoryCache{
		entries:         make(map[string]*cacheItem),
		entryPTRs:       make(map[string][]ptrRecord),
		limitBytes:      limit,
		ptrIndex:        make(map[string]map[string]uint32),
		persistPath:     settings.Persist.File,
		persistInterval: time.Duration(settings.Persist.Interval) * time.Second,
	}

	if m.persistInterval <= 0 {
		m.persistInterval = config.DefaultCachePersistInterval
	}

	if m.persistPath != "" {
		if loaded, err := m.loadSnapshotFromDisk(); err != nil {
			log.Warnf("CACHE: failed to load snapshot file %s: %v", m.persistPath, err)
		} else if loaded > 0 {
			log.Infof("CACHE: restored %d entries (%d MB) from snapshot %s", loaded, m.currentSize/(1024*1024), m.persistPath)
		}
		m.startPersistWorker()
		log.Infof("CACHE: persistence enabled (file=%s interval=%s)", m.persistPath, m.persistInterval)
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

	entry := &Entry{
		Answer:          compact(answer),
		Authority:       compact(authority),
		Additional:      compact(additional),
		TTL:             ttl,
		OriginalTTL:     ttl,
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
		m.storePTRLocked(key, ptrRecords)
		existing.size = estSize
		m.currentSize += estSize - oldSize
		m.persistGen.Add(1)
		m.evictToBudget()
		return
	}

	item := &cacheItem{entry: entry}
	item.lastAccess.Store(log.NowUnixNano())
	m.entries[key] = item
	m.storePTRLocked(key, ptrRecords)
	item.size = estSize
	m.currentSize += estSize

	m.persistGen.Add(1)
	m.evictToBudget()
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
	if m.persistStop != nil {
		close(m.persistStop)
		if m.persistDone != nil {
			timer := time.NewTimer(config.DefaultBackgroundTimeout)
			select {
			case <-m.persistDone:
				timer.Stop()
			case <-timer.C:
				log.Errorf("CACHE: persist worker shutdown timeout")
			}
		}
	}
	if m.persistPath != "" {
		if err := m.persistSnapshot(); err != nil {
			log.Errorf("CACHE: final snapshot failed: %v", err)
		} else {
			log.Infof("CACHE: snapshot flushed to %s", m.persistPath)
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
	for name, ttl := range candidates {
		results = append(results, LookupResult{Name: name, TTL: ttl})
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
			ip, name, ttl = r.A, r.Hdr.Name, r.Hdr.Ttl
		case *dns.AAAA:
			ip, name, ttl = r.AAAA, r.Hdr.Name, r.Hdr.Ttl
		default:
			continue
		}
		if ip == nil || name == "" {
			continue
		}
		records = append(records, ptrRecord{IP: ip.String(), Name: dns.Fqdn(name), TTL: ttl})
	}
	return records
}

func (m *MemoryCache) storePTRLocked(key string, records []ptrRecord) {
	if len(records) == 0 {
		delete(m.entryPTRs, key)
		return
	}
	cloned := make([]ptrRecord, len(records))
	copy(cloned, records)
	m.entryPTRs[key] = cloned
	for _, rec := range cloned {
		if m.ptrIndex[rec.IP] == nil {
			m.ptrIndex[rec.IP] = make(map[string]uint32)
		}
		m.ptrIndex[rec.IP][rec.Name] = rec.TTL
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

// cloneEntryForPersist deep-copies a Entry and clears cached RR fields
// (which are interface types) so gob can encode without type registration.
func cloneEntryForPersist(entry *Entry) *Entry {
	cloned := cloneEntry(entry)
	if cloned == nil {
		return nil
	}
	clearRRFields(cloned.Answer)
	clearRRFields(cloned.Authority)
	clearRRFields(cloned.Additional)
	return cloned
}

func clearRRFields(records []*CompactRecord) {
	for _, r := range records {
		if r != nil {
			r.RR = nil
		}
	}
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

func clonePTRs(records []ptrRecord) []ptrRecord {
	if len(records) == 0 {
		return nil
	}
	cloned := make([]ptrRecord, len(records))
	copy(cloned, records)
	return cloned
}

func compact(rrs []dns.RR) []*CompactRecord {
	if len(rrs) == 0 {
		return nil
	}
	result := make([]*CompactRecord, 0, len(rrs))
	seen := make(map[string]struct{}, len(rrs))
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
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
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

func minTTL(answer, authority, additional []dns.RR) int {
	minT := -1
	for _, rrs := range [][]dns.RR{answer, authority, additional} {
		for _, rr := range rrs {
			if rr == nil {
				continue
			}
			if ttl := int(rr.Header().Ttl); ttl > 0 && (minT < 0 || ttl < minT) {
				minT = ttl
			}
		}
	}
	if minT <= 0 {
		return config.DefaultTTL
	}
	return minT
}
