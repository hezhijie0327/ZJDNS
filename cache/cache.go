// Package cache provides an in-memory DNS response cache with optional disk persistence.
package cache

import (
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

	"zjdns/config"
	"zjdns/edns"
	"zjdns/internal/dnsutil"
	"zjdns/internal/log"

	"github.com/miekg/dns"
)

const (
	StaleTTL    = 30
	StaleMaxAge = 45 * 86400

	resultBufferCapacity = 128
	maxResultLength      = 512

	cacheKeyDNSPrefix    = "dns:"
	cacheSnapshotVersion = 2
)

var cacheSnapshotMagic = "ZJDNS-CACHE-V" + strconv.Itoa(cacheSnapshotVersion)

func init() {
	gob.Register(&persistedCacheSnapshot{})
	gob.Register(&persistedCacheItem{})
	gob.Register(&CacheEntry{})
	gob.Register(&CompactRecord{})
}

// ── Interfaces ──

// Manager is the interface for DNS response caches.
type Manager interface {
	Get(key string) (*CacheEntry, bool, bool)
	Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption)
	SetEntry(key string, entry *CacheEntry)
	Close() error
}

// ── Types ──

// CacheEntry stores serialized DNS response data and metadata.
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
	Payload         []byte           `json:"payload,omitempty"`
}

// CompactRecord stores a compact representation of a DNS RR.
type CompactRecord struct {
	Text    string `json:"text"`
	OrigTTL uint32 `json:"orig_ttl"`
	Type    uint16 `json:"type"`
}

// LookupResult represents a candidate for reverse PTR lookup.
type LookupResult struct {
	Name string
	TTL  uint32
}

// ── MemoryCache ──

// MemoryCache provides a concurrent in-memory DNS response cache.
// Gets use RLock (no contention between readers). Sets use a full Lock.
// Eviction scans for the entry with the lowest access time (O(n), acceptable
// at 16K entries since Sets are infrequent relative to Gets).
type MemoryCache struct {
	mu        sync.RWMutex
	entries   map[string]*cacheItem
	entryPTRs map[string][]ptrRecord
	limit     int
	closed    int32
	ptrIndex  map[string]map[string]uint32

	persistPath     string
	persistInterval time.Duration
	persistStop     chan struct{}
	persistDone     chan struct{}
	persistDirty    atomic.Int32
}

type cacheItem struct {
	entry      *CacheEntry
	lastAccess atomic.Int64
}

type ptrRecord struct {
	IP   string
	Name string
	TTL  uint32
}

type persistedCacheSnapshot struct {
	Version int                  `json:"version"`
	SavedAt int64                `json:"saved_at"`
	Entries []persistedCacheItem `json:"entries"`
}

type persistedCacheItem struct {
	Key   string      `json:"key"`
	Entry *CacheEntry `json:"entry,omitempty"`
	PTRs  []ptrRecord `json:"ptrs,omitempty"`
}

// ── Constructor ──

// New creates a MemoryCache with the given settings.
func New(settings config.CacheSettings) *MemoryCache {
	size := settings.Size
	if size <= 0 {
		size = config.DefaultCacheSize
	}

	mc := &MemoryCache{
		entries:         make(map[string]*cacheItem),
		entryPTRs:       make(map[string][]ptrRecord),
		limit:           size,
		ptrIndex:        make(map[string]map[string]uint32),
		persistPath:     strings.TrimSpace(settings.Persist.File),
		persistInterval: time.Duration(settings.Persist.Interval) * time.Second,
	}

	if mc.persistInterval <= 0 {
		mc.persistInterval = config.DefaultCachePersistInterval
	}

	if mc.persistPath != "" {
		if loaded, err := mc.loadSnapshotFromDisk(); err != nil {
			log.Warnf("CACHE: failed to load snapshot file %s: %v", mc.persistPath, err)
		} else if loaded > 0 {
			log.Infof("CACHE: restored %d entries from snapshot %s", loaded, mc.persistPath)
		}
		mc.startPersistWorker()
		log.Infof("CACHE: persistence enabled (file=%s interval=%s)", mc.persistPath, mc.persistInterval)
	} else {
		log.Debugf("CACHE: persistence disabled")
	}

	log.Infof("CACHE: Memory cache enabled (limit=%d)", size)
	return mc
}

// ── Get (RLock — no contention between readers) ──

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

	// Record access time atomically (for approximate LRU eviction).
	item.lastAccess.Store(time.Now().UnixNano())
	cloned := cloneEntry(item.entry)
	mc.mu.RUnlock()

	return cloned, true, cloned.IsExpired()
}

// ── Set ──

func (mc *MemoryCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *edns.ECSOption) {
	if atomic.LoadInt32(&mc.closed) != 0 {
		return
	}
	now := time.Now().Unix()
	ttl := minTTL(answer, authority, additional)

	entry := &CacheEntry{
		Answer:      compact(answer),
		Authority:   compact(authority),
		Additional:  compact(additional),
		TTL:         ttl,
		OriginalTTL: ttl,
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

func (mc *MemoryCache) SetEntry(key string, entry *CacheEntry) {
	if atomic.LoadInt32(&mc.closed) != 0 || entry == nil {
		return
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	if atomic.LoadInt32(&mc.closed) != 0 {
		return
	}

	fullCopy := cloneEntry(entry)

	if existing, ok := mc.entries[key]; ok {
		mc.removePTRLocked(key)
		existing.entry = fullCopy
		existing.lastAccess.Store(time.Now().UnixNano())
		mc.updatePTRLocked(fullCopy, key)
		mc.persistDirty.Store(1)
		return
	}

	item := &cacheItem{entry: fullCopy}
	item.lastAccess.Store(time.Now().UnixNano())
	mc.entries[key] = item
	mc.updatePTRLocked(fullCopy, key)

	if mc.limit > 0 && len(mc.entries) > mc.limit {
		mc.evictLocked()
	}
	mc.persistDirty.Store(1)
}

// evictLocked removes the entry with the oldest access time. Must be called under mu.Lock.
func (mc *MemoryCache) evictLocked() {
	var oldestKey string
	var oldestTime int64 = -1
	for k, item := range mc.entries {
		t := item.lastAccess.Load()
		if oldestTime == -1 || t < oldestTime {
			oldestTime = t
			oldestKey = k
		}
	}
	if oldestKey != "" {
		mc.removePTRLocked(oldestKey)
		delete(mc.entries, oldestKey)
	}
}

// ── Reverse Lookup ──

func (mc *MemoryCache) ReverseLookup(ip net.IP) []LookupResult {
	if ip == nil {
		return nil
	}
	mc.mu.RLock()
	candidates, ok := mc.ptrIndex[ip.String()]
	mc.mu.RUnlock()
	if !ok || len(candidates) == 0 {
		return nil
	}
	results := make([]LookupResult, 0, len(candidates))
	for name, ttl := range candidates {
		results = append(results, LookupResult{Name: name, TTL: ttl})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].Name < results[j].Name })
	return results
}

// ── PTR index helpers ──

func (mc *MemoryCache) updatePTRLocked(entry *CacheEntry, key string) {
	if entry == nil {
		return
	}
	records := make([]ptrRecord, 0)
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
		ipStr := ip.String()
		if mc.ptrIndex[ipStr] == nil {
			mc.ptrIndex[ipStr] = make(map[string]uint32)
		}
		mc.ptrIndex[ipStr][dns.Fqdn(name)] = ttl
		records = append(records, ptrRecord{IP: ipStr, Name: dns.Fqdn(name), TTL: ttl})
	}
	if len(records) > 0 {
		mc.entryPTRs[key] = records
	}
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

// ── Persistence ──

func (mc *MemoryCache) startPersistWorker() {
	if mc.persistPath == "" {
		return
	}
	mc.persistStop = make(chan struct{})
	mc.persistDone = make(chan struct{})
	go func() {
		defer dnsutil.HandlePanic("cache persist worker")
		defer close(mc.persistDone)
		ticker := time.NewTicker(mc.persistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if mc.persistDirty.Load() == 0 {
					continue
				}
				if err := mc.persistSnapshot(); err != nil {
					log.Warnf("CACHE: persist snapshot failed: %v", err)
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

	header := make([]byte, len(cacheSnapshotMagic))
	if _, err := io.ReadFull(file, header); err != nil {
		return 0, err
	}
	if string(header) != cacheSnapshotMagic {
		return 0, fmt.Errorf("invalid cache snapshot format")
	}

	var snapshot persistedCacheSnapshot
	if err := gob.NewDecoder(file).Decode(&snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != cacheSnapshotVersion {
		return 0, fmt.Errorf("unsupported snapshot version: %d", snapshot.Version)
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
		entryCopy := cloneEntry(item.Entry)
		ci := &cacheItem{entry: entryCopy}
		ci.lastAccess.Store(time.Now().UnixNano())
		mc.entries[item.Key] = ci
		mc.storePTRLocked(item.Key, item.PTRs)
		loaded++
		if mc.limit > 0 && len(mc.entries) > mc.limit {
			mc.evictLocked()
		}
	}
	mc.mu.Unlock()
	mc.persistDirty.Store(0)
	return loaded, nil
}

func (mc *MemoryCache) persistSnapshot() error {
	if mc.persistPath == "" {
		return nil
	}
	now := time.Now().Unix()
	snapshot := persistedCacheSnapshot{
		Version: cacheSnapshotVersion,
		SavedAt: now,
	}

	mc.mu.RLock()
	if mc.entries != nil {
		snapshot.Entries = make([]persistedCacheItem, 0, len(mc.entries))
		for key, item := range mc.entries {
			if item == nil || item.entry == nil || item.entry.TTL <= 0 {
				continue
			}
			if now-item.entry.Timestamp > int64(item.entry.TTL+StaleMaxAge) {
				continue
			}
			snapshot.Entries = append(snapshot.Entries, persistedCacheItem{
				Key:   key,
				Entry: cloneEntry(item.entry),
				PTRs:  clonePTRs(mc.entryPTRs[key]),
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
	if _, err := file.WriteString(cacheSnapshotMagic); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := gob.NewEncoder(file).Encode(&snapshot); err != nil {
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
	return nil
}

// ── Close ──

func (mc *MemoryCache) Close() error {
	if !atomic.CompareAndSwapInt32(&mc.closed, 0, 1) {
		return nil
	}
	if mc.persistStop != nil {
		close(mc.persistStop)
		if mc.persistDone != nil {
			select {
			case <-mc.persistDone:
			case <-time.After(config.IdleTimeout):
				log.Warnf("CACHE: persist worker shutdown timeout")
			}
		}
	}
	if mc.persistPath != "" {
		if err := mc.persistSnapshot(); err != nil {
			log.Warnf("CACHE: final snapshot failed: %v", err)
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

// ── CacheEntry methods ──

func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
}
func (c *CacheEntry) ShouldRefresh() bool {
	return c != nil && c.IsExpired() && time.Now().Unix()-c.Timestamp > int64(max(c.OriginalTTL, c.TTL))
}
func (c *CacheEntry) CanServeExpired(maxAge int) bool {
	return c != nil && c.IsExpired() && time.Now().Unix()-c.Timestamp-int64(c.TTL) <= int64(maxAge)
}
func (c *CacheEntry) GetRemainingTTL() uint32 {
	if c == nil {
		return 0
	}
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining > 0 {
		return uint32(remaining)
	}
	return uint32(StaleTTL)
}
func (c *CacheEntry) ECSOption() *edns.ECSOption {
	if c == nil || c.ECSAddress == "" {
		return nil
	}
	if ip := net.ParseIP(c.ECSAddress); ip != nil {
		return &edns.ECSOption{Family: c.ECSFamily, SourcePrefix: c.ECSSourcePrefix, ScopePrefix: c.ECSScopePrefix, Address: ip}
	}
	return nil
}
func (c *CacheEntry) ShouldPrefetch(thresholdPercent int) bool {
	if c == nil || c.IsExpired() || thresholdPercent <= 0 {
		return false
	}
	if thresholdPercent > 100 {
		thresholdPercent = 100
	}
	remaining := int64(c.TTL) - (time.Now().Unix() - c.Timestamp)
	if remaining <= 0 {
		return false
	}
	original := int64(c.OriginalTTL)
	if original <= 0 {
		original = int64(c.TTL)
	}
	if original <= 0 {
		return false
	}
	return remaining <= (original*int64(thresholdPercent)+99)/100
}

// ── Public helpers ──

func BuildCacheKey(question dns.Question, ecs *edns.ECSOption, clientRequestedDNSSEC bool) string {
	var buf strings.Builder
	buf.Grow(resultBufferCapacity)
	buf.WriteString(cacheKeyDNSPrefix)
	buf.WriteString(dnsutil.NormalizeDomain(question.Name))
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
	if len(result) > maxResultLength {
		hash := fnv.New64a()
		hash.Write([]byte(result))
		return fmt.Sprintf("h:%x", hash.Sum64())
	}
	return result
}

func CreateCompactRecord(rr dns.RR) *CompactRecord {
	if rr == nil {
		return nil
	}
	return &CompactRecord{Text: rr.String(), OrigTTL: rr.Header().Ttl, Type: rr.Header().Rrtype}
}

func ExpandRecord(cr *CompactRecord) dns.RR {
	if cr == nil || cr.Text == "" {
		return nil
	}
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

func ExpandRecords(crs []*CompactRecord) []dns.RR {
	if len(crs) == 0 {
		return nil
	}
	result := make([]dns.RR, 0, len(crs))
	for _, cr := range crs {
		if rr := expand(cr); rr != nil {
			result = append(result, rr)
		}
	}
	return result
}

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
			if isElapsed {
				remaining := int64(newRR.Header().Ttl) - value
				if remaining < 0 {
					remaining = 0
				}
				newRR.Header().Ttl = uint32(remaining)
			} else if value > 0 {
				newRR.Header().Ttl = uint32(value)
			}
			result = append(result, newRR)
		}
	}
	return result
}

// ── Internal helpers ──

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
			if cr := CreateCompactRecord(rr); cr != nil {
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
	rr, _ := dns.NewRR(cr.Text)
	return rr
}

func minTTL(answer, authority, additional []dns.RR) int {
	all := slices.Concat(answer, authority, additional)
	if len(all) == 0 {
		return config.DefaultTTL
	}
	minT := int(all[0].Header().Ttl)
	for _, rr := range all {
		if rr == nil {
			continue
		}
		if ttl := int(rr.Header().Ttl); ttl > 0 && ttl < minT {
			minT = ttl
		}
	}
	if minT <= 0 {
		minT = config.DefaultTTL
	}
	return minT
}
