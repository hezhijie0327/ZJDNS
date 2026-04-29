// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/logging"
	"golang.org/x/sync/errgroup"
)

const (
	DefaultTTL             = 10    // Default TTL for cache entries in seconds
	DefaultMemoryCacheSize = 10000 // Default maximum number of entries in the in-memory cache

	StaleTTL    = 30         // Additional TTL for serving expired cache entries in seconds
	StaleMaxAge = 30 * 86400 // Maximum age for serving expired cache entries (30 days in seconds)

	ResultBufferCapacity = 128 // Initial capacity for building cache keys to minimize allocations
	MaxResultLength      = 512 // Maximum length for cache keys before hashing

	RedisPrefixDNS = "dns:" // Prefix for DNS cache keys in Redis
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
}

// memoryCacheItem wraps a CacheEntry with its position in the LRU order.
type memoryCacheItem struct {
	entry   *CacheEntry
	element *list.Element
}

// HybridCache combines an in-memory cache with Redis persistence.
type HybridCache struct {
	memory  *MemoryCache
	redis   *RedisCache
	ctx     context.Context
	cancel  context.CancelCauseFunc
	bgGroup *errgroup.Group
	bgCtx   context.Context
	closed  int32
}

// RedisCache provides Redis-backed cache persistence for DNS entries.
type RedisCache struct {
	client  *redis.Client
	config  *ServerConfig
	ctx     context.Context
	cancel  context.CancelCauseFunc
	closed  int32
	bgGroup *errgroup.Group
	bgCtx   context.Context
}

// NewMemoryCache creates a new high-performance in-memory cache.
func NewMemoryCache(size int) *MemoryCache {
	if size <= 0 {
		size = DefaultMemoryCacheSize
	}
	LogInfo("CACHE: Memory cache enabled (limit=%d)", size)
	return &MemoryCache{
		entries:  make(map[string]*memoryCacheItem),
		order:    list.New(),
		limit:    size,
		ptrIndex: make(map[string]map[string]uint32),
	}
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
func BuildCacheKey(question dns.Question, ecs *ECSOption, clientRequestedDNSSEC bool, globalPrefix string) string {
	var buf strings.Builder
	buf.Grow(ResultBufferCapacity)

	buf.WriteString(globalPrefix)
	buf.WriteString(RedisPrefixDNS)

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

// updatePTRIndexLocked updates the PTR index for a cache entry
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

// removeFromPTRIndexLocked removes a cache entry from the PTR index
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

	// Clean up PTR index for the evicted entry
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

	// Update access time and LRU order
	item.entry.AccessTime = time.Now().Unix()
	mc.touchEntryLocked(item)

	// Clone entry while still holding lock to ensure consistency
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
		// Remove old entry from PTR index before updating
		mc.removeFromPTRIndexLocked(existing.entry, key)
		existing.entry = cloneCacheEntry(entry)
		mc.touchEntryLocked(existing)
		mc.updatePTRIndexLocked(existing.entry, key)
		return
	}

	element := mc.order.PushFront(key)
	mc.entries[key] = &memoryCacheItem{entry: cloneCacheEntry(entry), element: element}
	mc.updatePTRIndexLocked(mc.entries[key].entry, key)
	if mc.limit > 0 && mc.order.Len() > mc.limit {
		mc.evictOldestLocked()
	}
}

// Close shuts down the memory cache.
func (mc *MemoryCache) Close() error {
	if !atomic.CompareAndSwapInt32(&mc.closed, 0, 1) {
		return nil
	}

	mc.mu.Lock()
	mc.entries = nil
	mc.order = nil
	mc.mu.Unlock()
	LogInfo("CACHE: Memory cache shut down")
	return nil
}

// NewRedisCache creates a new Redis-backed cache
func NewRedisCache(config *ServerConfig) (*RedisCache, error) {
	logging.Disable()

	redisSettings := config.Server.Features.Cache.Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisSettings.Address,
		Password: redisSettings.Password,
		DB:       redisSettings.Database,
	})

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection: %w", err)
	}

	cacheCtx, cacheCancel := context.WithCancelCause(context.Background())
	bgGroup, bgCtx := errgroup.WithContext(cacheCtx)

	cache := &RedisCache{
		client:  rdb,
		config:  config,
		ctx:     cacheCtx,
		cancel:  cacheCancel,
		bgGroup: bgGroup,
		bgCtx:   bgCtx,
	}

	LogInfo("CACHE: Redis cache initialized")
	return cache, nil
}

// Get retrieves a value from the cache
func (rc *RedisCache) Get(key string) (*CacheEntry, bool, bool) {
	defer HandlePanic("Redis cache get")

	if atomic.LoadInt32(&rc.closed) != 0 {
		return nil, false, false
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	data, err := rc.client.Get(ctx, key).Result()
	if err != nil {
		return nil, false, false
	}

	var entry CacheEntry
	if err := json.Unmarshal([]byte(data), &entry); err != nil {
		rc.bgGroup.Go(func() error {
			defer HandlePanic("Clean corrupted cache")
			cleanCtx, cleanCancel := context.WithTimeout(rc.bgCtx, OperationTimeout)
			defer cleanCancel()
			if err := rc.client.Del(cleanCtx, key).Err(); err != nil {
				LogError("CACHE: Failed to clean corrupted cache key %s: %v", key, err)
				return nil
			}
			return nil
		})
		return nil, false, false
	}

	isExpired := entry.IsExpired()

	entry.AccessTime = time.Now().Unix()
	rc.bgGroup.Go(func() error {
		defer HandlePanic("Update access time")
		if atomic.LoadInt32(&rc.closed) == 0 {
			updateCtx, updateCancel := context.WithTimeout(rc.bgCtx, OperationTimeout)
			defer updateCancel()
			if data, err := json.Marshal(entry); err == nil {
				if err := rc.client.Set(updateCtx, key, data, redis.KeepTTL).Err(); err != nil {
					LogError("CACHE: Failed to update access time for key %s: %v", key, err)
				}
			}
		}
		return nil
	})

	return &entry, true, isExpired
}

// Set stores a value in the cache
func (rc *RedisCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	defer HandlePanic("Redis cache set")

	if atomic.LoadInt32(&rc.closed) != 0 {
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

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	expiration := time.Duration(cacheTTL)*time.Second + time.Duration(StaleMaxAge)*time.Second
	rc.client.Set(ctx, key, data, expiration)

	// Maintain Redis reverse PTR index for A/AAAA answers so PTR lookups can
	// fall back to Redis when memory cache has no result.
	if len(answer) > 0 {
		rc.updateRedisPTRIndex(ctx, answer, now)
	}
}

// updateRedisPTRIndex updates the Redis reverse PTR index for A and AAAA records in the answer section.
func (rc *RedisCache) updateRedisPTRIndex(ctx context.Context, answer []dns.RR, timestamp int64) {
	for _, rr := range answer {
		if rr == nil {
			continue
		}

		var ip net.IP
		switch r := rr.(type) {
		case *dns.A:
			ip = r.A
		case *dns.AAAA:
			ip = r.AAAA
		default:
			continue
		}

		if ip == nil {
			continue
		}

		ptrKey := rc.ptrIndexKey(ip)
		expiresAt := float64(timestamp + int64(rr.Header().Ttl))
		member := dns.Fqdn(rr.Header().Name)

		if err := rc.client.ZAdd(ctx, ptrKey, redis.Z{Score: expiresAt, Member: member}).Err(); err != nil {
			LogError("CACHE: Failed to update PTR index for %s: %v", ptrKey, err)
			continue
		}

		if err := rc.client.Expire(ctx, ptrKey, time.Duration(int64(rr.Header().Ttl)+int64(StaleMaxAge))*time.Second).Err(); err != nil {
			LogError("CACHE: Failed to set expiration for PTR index %s: %v", ptrKey, err)
		}
	}
}

// ptrIndexKey generates the Redis key for the PTR index of a given IP address.
func (rc *RedisCache) ptrIndexKey(ip net.IP) string {
	return fmt.Sprintf("%sptr:%s", RedisPrefixDNS, ip.String())
}

// ReverseLookup searches the Redis cache for A or AAAA answers that match the provided IP address and returns candidate reverse PTR targets.
func (rc *RedisCache) ReverseLookup(ip net.IP) []reverseLookupResult {
	if ip == nil || atomic.LoadInt32(&rc.closed) != 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(rc.ctx, OperationTimeout)
	defer cancel()

	ptrKey := rc.ptrIndexKey(ip)
	now := float64(time.Now().Unix())
	if err := rc.client.ZRemRangeByScore(ctx, ptrKey, "-inf", fmt.Sprintf("%f", now)).Err(); err != nil {
		LogError("CACHE: Failed to clean expired PTR index %s: %v", ptrKey, err)
	}

	members, err := rc.client.ZRangeWithScores(ctx, ptrKey, 0, -1).Result()
	if err != nil || len(members) == 0 {
		return nil
	}

	results := make([]reverseLookupResult, 0, len(members))
	for _, z := range members {
		name, ok := z.Member.(string)
		if !ok || name == "" {
			continue
		}

		expiresAt := int64(z.Score)
		ttl := uint32(expiresAt - time.Now().Unix())
		if ttl == 0 {
			continue
		}
		results = append(results, reverseLookupResult{Name: name, TTL: ttl})
	}

	if len(results) == 0 {
		return nil
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})
	return results
}

// Close shuts down the Redis cache
func (rc *RedisCache) Close() error {
	if !atomic.CompareAndSwapInt32(&rc.closed, 0, 1) {
		return nil
	}

	LogInfo("CACHE: Shutting down Redis cache")

	rc.cancel(errors.New("redis cache shutdown"))

	done := make(chan error, 1)
	go func() {
		defer HandlePanic("Redis background group wait")
		done <- rc.bgGroup.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			LogError("CACHE: Background goroutine error: %v", err)
		}
		LogDebug("CACHE: All Redis background goroutines finished gracefully")
	case <-time.After(IdleTimeout):
		LogWarn("CACHE: Redis background goroutine shutdown timeout")
	}

	if err := rc.client.Close(); err != nil {
		LogError("CACHE: Redis client shutdown failed: %v", err)
	}

	LogInfo("CACHE: Redis cache shut down")
	return nil
}

// CacheEntry stores serialized DNS response data and metadata.
// IsExpired checks if the cache entry is expired
func (c *CacheEntry) IsExpired() bool {
	return c != nil && time.Now().Unix()-c.Timestamp > int64(c.TTL)
}

// ShouldRefresh checks if the cache entry should be refreshed
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

// GetRemainingTTL returns the remaining TTL for the cache entry
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

// GetECSOption returns the ECS option from the cache entry
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

// NewHybridCache creates an in-memory first-level cache with Redis persistence.
func NewHybridCache(memory *MemoryCache, redisCache *RedisCache) *HybridCache {
	ctx, cancel := context.WithCancelCause(context.Background())
	bgGroup, bgCtx := errgroup.WithContext(ctx)
	return &HybridCache{
		memory:  memory,
		redis:   redisCache,
		ctx:     ctx,
		cancel:  cancel,
		bgGroup: bgGroup,
		bgCtx:   bgCtx,
	}
}

// Get retrieves a cache entry from the hybrid cache, checking memory first and falling back to Redis if not found.
func (hc *HybridCache) Get(key string) (*CacheEntry, bool, bool) {
	if atomic.LoadInt32(&hc.closed) != 0 {
		return nil, false, false
	}

	if entry, found, isExpired := hc.memory.Get(key); found {
		return entry, found, isExpired
	}

	if hc.redis == nil {
		return nil, false, false
	}

	entry, found, isExpired := hc.redis.Get(key)
	if !found {
		return nil, false, false
	}

	hc.memory.SetEntry(key, entry)
	return entry, true, isExpired
}

// ReverseLookup performs a reverse lookup for the given IP address, checking memory first and falling back to Redis if not found.
func (hc *HybridCache) ReverseLookup(ip net.IP) []reverseLookupResult {
	if hc == nil {
		return nil
	}

	if hc.memory != nil {
		if results := hc.memory.ReverseLookup(ip); len(results) > 0 {
			return results
		}
	}

	if hc.redis == nil {
		return nil
	}

	results := hc.redis.ReverseLookup(ip)
	return results
}

// Set stores a cache entry in the hybrid cache, writing to memory and asynchronously writing through to Redis if enabled.
func (hc *HybridCache) Set(key string, answer, authority, additional []dns.RR, validated bool, ecs *ECSOption) {
	if atomic.LoadInt32(&hc.closed) != 0 {
		return
	}

	hc.memory.Set(key, answer, authority, additional, validated, ecs)
	if hc.redis == nil {
		return
	}

	hc.bgGroup.Go(func() error {
		defer HandlePanic("Hybrid cache write-through")
		if atomic.LoadInt32(&hc.closed) != 0 {
			return nil
		}
		hc.redis.Set(key, answer, authority, additional, validated, ecs)
		return nil
	})
}

// Close shuts down the hybrid cache and all underlying caches.
func (hc *HybridCache) Close() error {
	if !atomic.CompareAndSwapInt32(&hc.closed, 0, 1) {
		return nil
	}

	LogInfo("CACHE: Shutting down hybrid cache")
	hc.cancel(errors.New("hybrid cache shutdown"))

	if hc.memory != nil {
		if err := hc.memory.Close(); err != nil {
			LogError("CACHE: Memory cache shutdown failed: %v", err)
		}
	}

	done := make(chan error, 1)
	go func() {
		defer HandlePanic("Hybrid cache background wait")
		done <- hc.bgGroup.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			LogError("CACHE: Hybrid background goroutine error: %v", err)
		}
		LogDebug("CACHE: Hybrid background goroutines finished gracefully")
	case <-time.After(IdleTimeout):
		LogWarn("CACHE: Hybrid background goroutine shutdown timeout")
	}

	if hc.redis != nil {
		if err := hc.redis.Close(); err != nil {
			LogError("CACHE: Redis cache shutdown failed: %v", err)
		}
	}

	LogInfo("CACHE: Hybrid cache shut down")
	return nil
}
