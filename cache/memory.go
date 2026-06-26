package cache

import (
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/log"
)

const evictSampleSize = config.DefaultCacheEvictSampleSize

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
	persistGen      atomic.Int64
}

type cacheItem struct {
	entry      *CacheEntry
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

	mc := &MemoryCache{
		entries:         make(map[string]*cacheItem),
		entryPTRs:       make(map[string][]ptrRecord),
		limitBytes:      limit,
		ptrIndex:        make(map[string]map[string]uint32),
		persistPath:     settings.Persist.File,
		persistInterval: time.Duration(settings.Persist.Interval) * time.Second,
	}

	if mc.persistInterval <= 0 {
		mc.persistInterval = config.DefaultCachePersistInterval
	}

	if mc.persistPath != "" {
		if loaded, err := mc.loadSnapshotFromDisk(); err != nil {
			log.Warnf("CACHE: failed to load snapshot file %s: %v", mc.persistPath, err)
		} else if loaded > 0 {
			log.Infof("CACHE: restored %d entries (%d MB) from snapshot %s", loaded, mc.currentSize/(1024*1024), mc.persistPath)
		}
		mc.startPersistWorker()
		log.Infof("CACHE: persistence enabled (file=%s interval=%s)", mc.persistPath, mc.persistInterval)
	} else {
		log.Debugf("CACHE: persistence disabled")
	}

	log.Infof("CACHE: Memory cache enabled (budget=%d MB)", limit/(1024*1024))
	return mc
}

// Get retrieves a cache entry by key, returning the entry, whether found,
// and whether the entry is expired.
func (mc *MemoryCache) Get(key string) (*CacheEntry, bool, bool) {
	if atomic.LoadInt32(&mc.closed) != 0 {
		return nil, false, false
	}

	mc.mu.RLock()
	item, found := mc.entries[key]
	if !found || item == nil || item.entry == nil {
		mc.mu.RUnlock()
		return nil, false, false
	}

	item.lastAccess.Store(time.Now().UnixNano())
	entry := item.entry
	mc.mu.RUnlock()

	return entry, true, entry.IsExpired()
}

// Set stores a DNS response in the cache with the given key and metadata.
func (mc *MemoryCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption) {
	mc.SetWithDNSSEC(key, answer, authority, additional, validated, false, ecs)
}

// SetWithDNSSEC stores a DNS response with explicit DNSSEC cryptographic
// validation status.
func (mc *MemoryCache) SetWithDNSSEC(key string, answer, authority, additional []dns.RR, validated bool, dnssecValidated bool, ecs *edns.ECSOption) {
	if atomic.LoadInt32(&mc.closed) != 0 {
		return
	}
	now := time.Now().Unix()
	ttl := minTTL(answer, authority, additional)

	entry := &CacheEntry{
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
	mc.setEntryInternal(key, entry)
}

// SetEntry stores a pre-built CacheEntry in the cache under the given key.
// It deep-clones the entry to protect against callers that retain a reference.
func (mc *MemoryCache) SetEntry(key string, entry *CacheEntry) {
	if atomic.LoadInt32(&mc.closed) != 0 || entry == nil {
		return
	}
	mc.setEntryInternal(key, cloneEntry(entry))
}

// setEntryInternal stores an entry in the cache without cloning. The caller
// must not retain any reference to the entry after this call — ownership is
// transferred to the cache. This avoids a wasted clone-and-copy when the
// entry is freshly allocated (e.g. from SetWithDNSSEC).
func (mc *MemoryCache) setEntryInternal(key string, entry *CacheEntry) {
	ptrRecords := extractPTRRecords(entry)
	estSize := estimateEntrySize(key, entry, ptrRecords)

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if atomic.LoadInt32(&mc.closed) != 0 {
		return
	}

	if existing, ok := mc.entries[key]; ok {
		oldSize := existing.size
		mc.removePTRLocked(key)
		existing.entry = entry
		existing.lastAccess.Store(time.Now().UnixNano())
		mc.storePTRLocked(key, ptrRecords)
		existing.size = estSize
		mc.currentSize += estSize - oldSize
		mc.persistGen.Add(1)
		mc.evictToBudget()
		return
	}

	item := &cacheItem{entry: entry}
	item.lastAccess.Store(time.Now().UnixNano())
	mc.entries[key] = item
	mc.storePTRLocked(key, ptrRecords)
	item.size = estSize
	mc.currentSize += estSize

	mc.persistGen.Add(1)
	mc.evictToBudget()
}

// Close shuts down the cache, finalizing any pending persistence write.
func (mc *MemoryCache) Close() error {
	if !atomic.CompareAndSwapInt32(&mc.closed, 0, 1) {
		return nil
	}
	if mc.persistStop != nil {
		close(mc.persistStop)
		if mc.persistDone != nil {
			timer := time.NewTimer(config.DefaultBackgroundTimeout)
			select {
			case <-mc.persistDone:
				timer.Stop()
			case <-timer.C:
				log.Errorf("CACHE: persist worker shutdown timeout")
			}
		}
	}
	if mc.persistPath != "" {
		if err := mc.persistSnapshot(); err != nil {
			log.Errorf("CACHE: final snapshot failed: %v", err)
		} else {
			log.Infof("CACHE: snapshot flushed to %s", mc.persistPath)
		}
	}
	mc.mu.Lock()
	mc.entries = nil
	mc.ptrIndex = nil
	mc.mu.Unlock()
	log.Infof("CACHE: Memory cache shut down")
	return nil
}

// ReverseLookup returns all cached domain names mapped to the given IP address.
func (mc *MemoryCache) ReverseLookup(ip net.IP) []LookupResult {
	if ip == nil {
		return nil
	}
	mc.mu.RLock()
	candidates, ok := mc.ptrIndex[ip.String()]
	if !ok || len(candidates) == 0 {
		mc.mu.RUnlock()
		return nil
	}
	results := make([]LookupResult, 0, len(candidates))
	for name, ttl := range candidates {
		results = append(results, LookupResult{Name: name, TTL: ttl})
	}
	mc.mu.RUnlock()

	for i := 1; i < len(results); i++ {
		j := i
		for j > 0 && results[j-1].Name > results[j].Name {
			results[j-1], results[j] = results[j], results[j-1]
			j--
		}
	}
	return results
}

func (mc *MemoryCache) evictToBudget() {
	if mc.limitBytes <= 0 || mc.currentSize <= mc.limitBytes || len(mc.entries) == 0 {
		return
	}

	evicted := 0
	for mc.currentSize > mc.limitBytes && len(mc.entries) > 0 {
		// Randomly sample entries from the map to approximate LRU without
		// allocating a full keys slice under the write lock.
		var oldestKey string
		var oldestLast int64 = math.MaxInt64
		var oldestSize int64

		sampleCount := 0
		for k, item := range mc.entries {
			if sampleCount >= evictSampleSize {
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
		mc.currentSize -= oldestSize
		mc.removePTRLocked(oldestKey)
		delete(mc.entries, oldestKey)
		evicted++
	}

	if evicted > 0 {
		log.Debugf("CACHE: evicted %d entries to enforce budget (current=%d MB, limit=%d MB)", evicted, mc.currentSize/(1024*1024), mc.limitBytes/(1024*1024))
	}
}

func extractPTRRecords(entry *CacheEntry) []ptrRecord {
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

func (mc *MemoryCache) storePTRLocked(key string, records []ptrRecord) {
	if len(records) == 0 {
		delete(mc.entryPTRs, key)
		return
	}
	cloned := make([]ptrRecord, len(records))
	copy(cloned, records)
	mc.entryPTRs[key] = cloned
	for _, rec := range cloned {
		if mc.ptrIndex[rec.IP] == nil {
			mc.ptrIndex[rec.IP] = make(map[string]uint32)
		}
		mc.ptrIndex[rec.IP][rec.Name] = rec.TTL
	}
}

func (mc *MemoryCache) removePTRLocked(key string) {
	records, ok := mc.entryPTRs[key]
	if !ok || len(records) == 0 {
		delete(mc.entryPTRs, key)
		return
	}
	for _, rec := range records {
		if domains, ok := mc.ptrIndex[rec.IP]; ok {
			delete(domains, rec.Name)
			if len(domains) == 0 {
				delete(mc.ptrIndex, rec.IP)
			}
		}
	}
	delete(mc.entryPTRs, key)
}

func estimateEntrySize(key string, entry *CacheEntry, ptrs []ptrRecord) int64 {
	if entry == nil {
		return 0
	}
	size := int64(len(key)) + 64 + 208 + 72

	for _, cr := range entry.Answer {
		if cr != nil {
			size += int64(len(cr.Text)) + 44
		}
	}
	for _, cr := range entry.Authority {
		if cr != nil {
			size += int64(len(cr.Text)) + 44
		}
	}
	for _, cr := range entry.Additional {
		if cr != nil {
			size += int64(len(cr.Text)) + 44
		}
	}
	size += int64(len(entry.Payload))

	for _, pr := range ptrs {
		size += int64(len(pr.IP)+len(pr.Name)) + 56
	}
	return size
}

func cloneEntry(entry *CacheEntry) *CacheEntry {
	if entry == nil {
		return nil
	}
	cloned := *entry
	cloned.Answer = cloneRecords(entry.Answer)
	cloned.Authority = cloneRecords(entry.Authority)
	cloned.Additional = cloneRecords(entry.Additional)
	return &cloned
}

// cloneEntryForPersist deep-copies a CacheEntry and clears cached RR fields
// (which are interface types) so gob can encode without type registration.
func cloneEntryForPersist(entry *CacheEntry) *CacheEntry {
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
	seen := make(map[string]bool, len(rrs))
	result := make([]*CompactRecord, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil || rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		rrText := rr.String()
		if !seen[rrText] {
			seen[rrText] = true
			if cr := createCompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

func expand(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	if cr.RR != nil {
		return cr.RR
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
