// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"container/list"
	"encoding/gob"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/miekg/dns"
)

const (
	DefaultTTL = 10 // Default TTL for cache entries in seconds

	StaleTTL    = 30        // Additional TTL for serving expired cache entries in seconds
	StaleMaxAge = 3 * 86400 // Maximum age for serving expired cache entries in seconds

	ResultBufferCapacity = 128 // Initial capacity for building cache keys to minimize allocations
	MaxResultLength      = 512 // Maximum length for cache keys before hashing

	DefaultCachePersistInterval = 30 * time.Second // Default memory cache snapshot interval
	DefaultCacheSize            = 16384            // Default maximum number of entries in the in-memory cache

	CacheKeyDNSPrefix     = "dns:" // Prefix for DNS cache keys
	CacheSnapshotMagic    = "ZJDNSCACHE-GOB-ZSTD-v1"
	CacheZSTDEncoderLevel = zstd.SpeedBetterCompression // Compression level for cache snapshot persistence (SpeedFastest, SpeedDefault, SpeedBetterCompression, SpeedBestCompression)
)

// CacheEntry stores serialized DNS response data, metadata, and ECS state.
type CacheEntry struct {
	Answer          []*CompactRecord `json:"answer"`
	Authority       []*CompactRecord `json:"authority"`
	Additional      []*CompactRecord `json:"additional"`
	ECSAddress      string           `json:"ecs_address,omitempty"`
	Timestamp       int64            `json:"timestamp"`
	AccessTime      int64            `json:"access_time"`
	RefreshTime     int64            `json:"refresh_time,omitempty"`
	TTL             int              `json:"ttl"`
	OriginalTTL     int              `json:"original_ttl"`
	ECSFamily       uint16           `json:"ecs_family,omitempty"`
	ECSSourcePrefix uint8            `json:"ecs_source_prefix,omitempty"`
	ECSScopePrefix  uint8            `json:"ecs_scope_prefix,omitempty"`
	Validated       bool             `json:"validated"`
}

// CompactRecord stores a compact representation of a DNS RR.
type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// reverseLookupResult represents a candidate result for a reverse PTR lookup, including the target name and TTL.
type reverseLookupResult struct {
	Name string
	TTL  uint32
}

// CacheManager defines the interface for DNS response caches.
type CacheManager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption)
	Close() error
}

// MemoryCache provides an in-memory LRU cache for DNS responses.
type MemoryCache struct {
	mu       sync.RWMutex
	entries  map[string]*memoryCacheItem
	order    *list.List
	limit    int
	closed   int32
	ptrIndex map[string]map[string]uint32

	persistPath     string
	persistInterval time.Duration
	persistStop     chan struct{}
	persistDone     chan struct{}
	persistDirty    atomic.Int32
}

// memoryCacheItem wraps a CacheEntry with its position in the LRU order.
type memoryCacheItem struct {
	entry   *CacheEntry
	element *list.Element
}

type persistedCacheSnapshot struct {
	Version int                  `json:"version"`
	SavedAt int64                `json:"saved_at"`
	Entries []persistedCacheItem `json:"entries"`
}

type persistedCacheItem struct {
	Key   string      `json:"key"`
	Entry *CacheEntry `json:"entry"`
}

func init() {
	gob.Register(&persistedCacheSnapshot{})
	gob.Register(&persistedCacheItem{})
	gob.Register(&CacheEntry{})
	gob.Register(&CompactRecord{})
}

// NewMemoryCache creates a new high-performance in-memory cache.
func NewMemoryCache(settings CacheSettings) *MemoryCache {
	size := settings.Size
	if size <= 0 {
		size = DefaultCacheSize
	}

	mc := &MemoryCache{
		entries:         make(map[string]*memoryCacheItem),
		order:           list.New(),
		limit:           size,
		ptrIndex:        make(map[string]map[string]uint32),
		persistPath:     strings.TrimSpace(settings.Persist.File),
		persistInterval: time.Duration(settings.Persist.Interval) * time.Second,
	}

	if mc.persistInterval <= 0 {
		mc.persistInterval = DefaultCachePersistInterval
	}

	if mc.persistPath != "" {
		if loaded, err := mc.loadSnapshotFromDisk(); err != nil {
			LogWarn("CACHE: failed to load snapshot file %s: %v", mc.persistPath, err)
		} else if loaded > 0 {
			LogInfo("CACHE: restored %d entries from snapshot %s", loaded, mc.persistPath)
		} else {
			LogDebug("CACHE: snapshot file %s contained no valid entries or was empty", mc.persistPath)
		}
		mc.startPersistWorker()
		LogInfo("CACHE: persistence enabled (file=%s interval=%s)", mc.persistPath, mc.persistInterval)
		LogDebug("CACHE: persistence worker started for file %s", mc.persistPath)
	} else {
		LogDebug("CACHE: persistence disabled (no persist.file configured)")
	}

	LogInfo("CACHE: Memory cache enabled (limit=%d)", size)
	return mc
}

// CreateCompactRecord creates a compact representation of a DNS record.
func CreateCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{
		Text:    rr.String(),
		OrigTTL: rr.Header().Ttl,
		Type:    rr.Header().Rrtype,
	}
}

// ExpandRecord expands a compact record back to a DNS RR.
func ExpandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

// compactRecords converts DNS RRs to compact records.
func compactRecords(rrs []dns.RR) []*CompactRecord {
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
			if cr := CreateCompactRecord(rr); cr != nil {
				result = append(result, cr)
			}
		}
	}
	return result
}

// ExpandRecords expands compact records to DNS RRs.
func ExpandRecords(crs []*CompactRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := ExpandRecord(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

// ProcessRecords processes DNS records for response.
// If isElapsed is false, the second parameter is treated as a fixed TTL to assign.
// If isElapsed is true, the second parameter is treated as elapsed seconds to subtract from each record's original TTL.
func ProcessRecords(rrs []dns.RR, value int64, isElapsed bool, includeDNSSEC bool) []dns.RR {
	if len(rrs) == 0 {
		return nil
	}

	result := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil {
			continue
		}

		if !includeDNSSEC {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3, *dns.DNSKEY, *dns.DS:
				continue
			}
		}

		newRR := dns.Copy(rr)
		if newRR != nil {
			if value > 0 {
				if isElapsed {
					remaining := int64(newRR.Header().Ttl) - value
					if remaining < 0 {
						remaining = 0
					}
					newRR.Header().Ttl = uint32(remaining)
				} else {
					newRR.Header().Ttl = uint32(value)
				}
			}
			result = append(result, newRR)
		}
	}
	return result
}

// BuildCacheKey generates a cache key from question and options.
func BuildCacheKey(question dns.Question, ecs *ECSOption, clientRequestedDNSSEC bool) string {
	var buf strings.Builder
	buf.Grow(ResultBufferCapacity)
	buf.WriteString(CacheKeyDNSPrefix)

	buf.WriteString(NormalizeDomain(question.Name))
	buf.WriteByte(':')

	buf.WriteString(strconv.FormatUint(uint64(question.Qtype), 10))
	buf.WriteByte(':')
	buf.WriteString(strconv.FormatUint(uint64(question.Qclass), 10))

	if ecs != nil {
		buf.WriteString(":ecs:")
		buf.WriteString(ecs.Address.String())
		buf.WriteByte('/')
		buf.WriteString(strconv.FormatUint(uint64(ecs.SourcePrefix), 10))
	}

	if clientRequestedDNSSEC {
		buf.WriteString(":dnssec")
	}

	result := buf.String()
	if len(result) > MaxResultLength {
		hash := fnv.New64a()
		hash.Write([]byte(result))
		return fmt.Sprintf("h:%x", hash.Sum64())
	}
	return result
}

// calculateTTL calculates the minimum TTL from DNS records.
func calculateTTL(rrs []dns.RR) int {
	if len(rrs) == 0 {
		return DefaultTTL
	}

	minTTL := int(rrs[0].Header().Ttl)
	for _, rr := range rrs {
		if rr == nil {
			continue
		}
		if ttl := int(rr.Header().Ttl); ttl > 0 && (minTTL == 0 || ttl < minTTL) {
			minTTL = ttl
		}
	}

	if minTTL <= 0 {
		minTTL = DefaultTTL
	}

	return minTTL
}

// cloneCompactRecords creates a deep copy of a slice of compact records.
func cloneCompactRecords(records []*CompactRecord) []*CompactRecord {
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

// cloneCacheEntry creates a deep copy of a CacheEntry.
func cloneCacheEntry(entry *CacheEntry) *CacheEntry {
	if entry == nil {
		return nil
	}

	cloned := *entry
	cloned.Answer = cloneCompactRecords(entry.Answer)
	cloned.Authority = cloneCompactRecords(entry.Authority)
	cloned.Additional = cloneCompactRecords(entry.Additional)
	return &cloned
}

// touchEntryLocked moves the accessed cache entry to the front of the LRU order.
func (mc *MemoryCache) touchEntryLocked(item *memoryCacheItem) {
	if item == nil || item.element == nil {
		return
	}
	mc.order.MoveToFront(item.element)
}

// updatePTRIndexLocked updates the PTR index for a cache entry.
func (mc *MemoryCache) updatePTRIndexLocked(entry *CacheEntry, key string) {
	if entry == nil {
		return
	}
	for _, cr := range entry.Answer {
		if cr == nil {
			continue
		}
		rr := ExpandRecord(cr)
		if rr == nil {
			continue
		}

		var ip net.IP
		var name string
		ttl := uint32(0)
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
			name = r.Hdr.Name
			ttl = r.Hdr.Ttl
		case *dns.AAAA:
			ip = r.AAAA
			name = r.Hdr.Name
			ttl = r.Hdr.Ttl
		default:
			continue
		}

		if ip == nil || name == "" {
			continue
		}

		ipStr := ip.String()
		if mc.ptrIndex[ipStr] == nil {
			mc.ptrIndex[ipStr] = make(map[string]uint32)
		}
		mc.ptrIndex[ipStr][dns.Fqdn(name)] = ttl
	}
}

// removeFromPTRIndexLocked removes a cache entry from the PTR index.
func (mc *MemoryCache) removeFromPTRIndexLocked(entry *CacheEntry, key string) {
	if entry == nil {
		return
	}
	for _, cr := range entry.Answer {
		if cr == nil {
			continue
		}
		rr := ExpandRecord(cr)
		if rr == nil {
			continue
		}

		var ip net.IP
		var name string
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
			name = r.Hdr.Name
		case *dns.AAAA:
			ip = r.AAAA
			name = r.Hdr.Name
		default:
			continue
		}

		if ip == nil || name == "" {
			continue
		}

		ipStr := ip.String()
		if domains, ok := mc.ptrIndex[ipStr]; ok {
			delete(domains, dns.Fqdn(name))
			if len(domains) == 0 {
				delete(mc.ptrIndex, ipStr)
			}
		}
	}
}

// evictOldestLocked evicts the oldest cache entry when the cache limit is exceeded.
func (mc *MemoryCache) evictOldestLocked() {
	oldest := mc.order.Back()
	if oldest == nil {
		return
	}
	key, ok := oldest.Value.(string)
	if !ok {
		return
	}

	if item, exists := mc.entries[key]; exists && item != nil && item.entry != nil {
		mc.removeFromPTRIndexLocked(item.entry, key)
	}

	mc.order.Remove(oldest)
	delete(mc.entries, key)
}

// Get retrieves a value from the memory cache.
func (mc *MemoryCache) Get(key string) (*CacheEntry, bool, bool) {
	if atomic.LoadInt32(&mc.closed) != 0 {
		return nil, false, false
	}

	mc.mu.Lock()
	item, found := mc.entries[key]
	if !found || item == nil || item.entry == nil {
		mc.mu.Unlock()
		return nil, false, false
	}

	item.entry.AccessTime = time.Now().Unix()
	mc.touchEntryLocked(item)
	cloned := cloneCacheEntry(item.entry)
	mc.mu.Unlock()

	return cloned, true, cloned.IsExpired()
}

// ReverseLookup searches the memory cache for A or AAAA answers that match the
// provided IP address and returns candidate reverse PTR targets.
func (mc *MemoryCache) ReverseLookup(ip net.IP) []reverseLookupResult {
	if ip == nil {
		return nil
	}

	ipStr := ip.String()
	mc.mu.RLock()
	candidates, ok := mc.ptrIndex[ipStr]
	mc.mu.RUnlock()

	if !ok || len(candidates) == 0 {
		return nil
	}

	results := make([]reverseLookupResult, 0, len(candidates))
	for name, ttl := range candidates {
		results = append(results, reverseLookupResult{Name: name, TTL: ttl})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	return results
}

// Set stores a value in the memory cache.
func (mc *MemoryCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	if atomic.LoadInt32(&mc.closed) != 0 {
		return
	}

	allRRs := slices.Concat(answer, authority, additional)
	cacheTTL := calculateTTL(allRRs)
	now := time.Now().Unix()

	entry := &CacheEntry{
		Answer:      compactRecords(answer),
		Authority:   compactRecords(authority),
		Additional:  compactRecords(additional),
		TTL:         cacheTTL,
		OriginalTTL: cacheTTL,
		Timestamp:   now,
		Validated:   validated,
		AccessTime:  now,
	}

	if ecs != nil {
		entry.ECSFamily = ecs.Family
		entry.ECSSourcePrefix = ecs.SourcePrefix
		entry.ECSScopePrefix = ecs.ScopePrefix
		entry.ECSAddress = ecs.Address.String()
	}

	mc.SetEntry(key, entry)
}

// SetEntry stores an existing CacheEntry in the memory cache.
func (mc *MemoryCache) SetEntry(key string, entry *CacheEntry) {
	if atomic.LoadInt32(&mc.closed) != 0 || entry == nil {
		return
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if atomic.LoadInt32(&mc.closed) != 0 {
		return
	}

	if existing, ok := mc.entries[key]; ok {
		mc.removeFromPTRIndexLocked(existing.entry, key)
		existing.entry = cloneCacheEntry(entry)
		mc.touchEntryLocked(existing)
		mc.updatePTRIndexLocked(existing.entry, key)
		mc.persistDirty.Store(1)
		return
	}

	element := mc.order.PushFront(key)
	mc.entries[key] = &memoryCacheItem{entry: cloneCacheEntry(entry), element: element}
	mc.updatePTRIndexLocked(mc.entries[key].entry, key)
	if mc.limit > 0 && mc.order.Len() > mc.limit {
		mc.evictOldestLocked()
	}
	mc.persistDirty.Store(1)
}

func (mc *MemoryCache) startPersistWorker() {
	if mc.persistPath == "" {
		return
	}

	mc.persistStop = make(chan struct{})
	mc.persistDone = make(chan struct{})

	go func() {
		defer HandlePanic("cache persist worker")
		defer close(mc.persistDone)

		ticker := time.NewTicker(mc.persistInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if mc.persistDirty.Load() == 0 {
					continue
				}
				LogDebug("CACHE: persist worker triggered snapshot write (dirty=1)")
				if err := mc.persistSnapshotToDisk(); err != nil {
					LogWarn("CACHE: persist snapshot failed: %v", err)
				} else {
					mc.persistDirty.Store(0)
				}
			case <-mc.persistStop:
				return
			}
		}
	}()
}

func (mc *MemoryCache) loadSnapshotFromDisk() (int, error) {
	file, err := os.Open(mc.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer func() { _ = file.Close() }()

	header := make([]byte, len(CacheSnapshotMagic))
	if _, err := io.ReadFull(file, header); err != nil {
		return 0, err
	}
	if string(header) != CacheSnapshotMagic {
		return 0, fmt.Errorf("invalid cache snapshot format")
	}

	decoder, err := zstd.NewReader(file)
	if err != nil {
		return 0, err
	}
	defer decoder.Close()

	var snapshot persistedCacheSnapshot
	if err := gob.NewDecoder(decoder).Decode(&snapshot); err != nil {
		return 0, err
	}

	if len(snapshot.Entries) == 0 {
		return 0, nil
	}

	now := time.Now().Unix()
	loaded := 0

	mc.mu.Lock()
	for _, item := range snapshot.Entries {
		if item.Key == "" || item.Entry == nil || item.Entry.TTL <= 0 {
			continue
		}
		if now-item.Entry.Timestamp > int64(item.Entry.TTL+StaleMaxAge) {
			continue
		}
		if _, exists := mc.entries[item.Key]; exists {
			continue
		}
		element := mc.order.PushFront(item.Key)
		entryCopy := cloneCacheEntry(item.Entry)
		mc.entries[item.Key] = &memoryCacheItem{entry: entryCopy, element: element}
		mc.updatePTRIndexLocked(entryCopy, item.Key)
		loaded++
		if mc.limit > 0 && mc.order.Len() > mc.limit {
			mc.evictOldestLocked()
		}
	}
	mc.mu.Unlock()

	mc.persistDirty.Store(0)
	return loaded, nil
}

func (mc *MemoryCache) persistSnapshotToDisk() error {
	if mc.persistPath == "" {
		return nil
	}

	now := time.Now().Unix()
	snapshot := persistedCacheSnapshot{
		Version: 1,
		SavedAt: now,
	}

	mc.mu.RLock()
	if mc.entries != nil && mc.order != nil {
		snapshot.Entries = make([]persistedCacheItem, 0, len(mc.entries))
		for elem := mc.order.Front(); elem != nil; elem = elem.Next() {
			key, ok := elem.Value.(string)
			if !ok {
				continue
			}
			item := mc.entries[key]
			if item == nil || item.entry == nil || item.entry.TTL <= 0 {
				continue
			}
			if now-item.entry.Timestamp > int64(item.entry.TTL+StaleMaxAge) {
				continue
			}
			snapshot.Entries = append(snapshot.Entries, persistedCacheItem{
				Key:   key,
				Entry: cloneCacheEntry(item.entry),
			})
		}
	}
	mc.mu.RUnlock()

	dir := filepath.Dir(mc.persistPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp := mc.persistPath + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}

	if _, err := file.WriteString(CacheSnapshotMagic); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}

	zw, err := zstd.NewWriter(file, zstd.WithEncoderLevel(CacheZSTDEncoderLevel))
	if err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := gob.NewEncoder(zw).Encode(&snapshot); err != nil {
		_ = zw.Close()
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := zw.Close(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if err := os.Rename(tmp, mc.persistPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	if stat, err := os.Stat(mc.persistPath); err == nil {
		LogDebug("CACHE: snapshot saved to %s (%d entries, %d bytes)", mc.persistPath, len(snapshot.Entries), stat.Size())
	} else {
		LogDebug("CACHE: snapshot saved to %s (%d entries)", mc.persistPath, len(snapshot.Entries))
	}

	return nil
}

// Close shuts down the memory cache.
func (mc *MemoryCache) Close() error {
	if !atomic.CompareAndSwapInt32(&mc.closed, 0, 1) {
		return nil
	}

	if mc.persistStop != nil {
		close(mc.persistStop)
		if mc.persistDone != nil {
			select {
			case <-mc.persistDone:
			case <-time.After(IdleTimeout):
				LogWarn("CACHE: persist worker shutdown timeout")
			}
		}
	}

	if mc.persistPath != "" {
		if err := mc.persistSnapshotToDisk(); err != nil {
			LogWarn("CACHE: final snapshot failed: %v", err)
		} else {
			LogInfo("CACHE: snapshot flushed to %s", mc.persistPath)
		}
	}

	mc.mu.Lock()
	mc.entries = nil
	mc.order = nil
	mc.ptrIndex = nil
	mc.mu.Unlock()

	LogInfo("CACHE: Memory cache shut down")
	return nil
}

// CacheEntry stores serialized DNS response data and metadata.
// IsExpired checks if the cache entry is expired.
func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// ShouldRefresh checks if the cache entry should be refreshed.
func (c *CacheEntry) ShouldRefresh() bool {
	if c == nil {
		return false
	}
	now := time.Now().Unix()
	refreshInterval := int64(c.OriginalTTL)
	if refreshInterval <= 0 {
		refreshInterval = int64(c.TTL)
	}
	return c.IsExpired() && (now-c.Timestamp) > refreshInterval
}

// ShouldPrefetch checks whether a non-expired cache entry has reached the
// prefetch window based on a percentage of the original TTL.
func (c *CacheEntry) ShouldPrefetch(thresholdPercent int) bool {
	if c == nil || c.IsExpired() || thresholdPercent <= 0 {
		return false
	}

	if thresholdPercent > 100 {
		thresholdPercent = 100
	}

	now := time.Now().Unix()
	remaining := int64(c.TTL) - (now - c.Timestamp)
	if remaining <= 0 {
		return false
	}

	originalTTL := c.OriginalTTL
	if originalTTL <= 0 {
		originalTTL = c.TTL
	}
	if originalTTL <= 0 {
		return false
	}

	threshold := int64((originalTTL*thresholdPercent + 99) / 100)
	if threshold < 1 {
		threshold = 1
	}

	return remaining <= threshold
}

// CanServeExpired checks whether an expired cache entry is within the allowed
// serve-expired age window.
func (c *CacheEntry) CanServeExpired(maxAgeSeconds int) bool {
	if c == nil || !c.IsExpired() {
		return false
	}
	if maxAgeSeconds <= 0 {
		return true
	}
	expiredAge := time.Now().Unix() - c.Timestamp - int64(c.TTL)
	return expiredAge <= int64(maxAgeSeconds)
}

// GetRemainingTTL returns the remaining TTL for the cache entry.
func (c *CacheEntry) GetRemainingTTL() uint32 {
	if c == nil {
		return 0
	}
	now := time.Now().Unix()
	elapsed := now - c.Timestamp
	remaining := int64(c.TTL) - elapsed
	if remaining > 0 {
		return uint32(remaining)
	}

	staleElapsed := elapsed - int64(c.TTL)
	staleCycle := staleElapsed % int64(StaleTTL)
	staleTTLRemaining := int64(StaleTTL) - staleCycle
	if staleTTLRemaining <= 0 {
		staleTTLRemaining = int64(StaleTTL)
	}
	return uint32(staleTTLRemaining)
}

// GetECSOption returns the ECS option from the cache entry.
func (c *CacheEntry) GetECSOption() *ECSOption {
	if c == nil || c.ECSAddress == "" {
		return nil
	}
	if ip := net.ParseIP(c.ECSAddress); ip != nil {
		return &ECSOption{
			Family:       c.ECSFamily,
			SourcePrefix: c.ECSSourcePrefix,
			ScopePrefix:  c.ECSScopePrefix,
			Address:      ip,
		}
	}
	return nil
}
