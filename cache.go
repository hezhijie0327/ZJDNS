// Package main implements ZJDNS - High Performance DNS Server
package main

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
	"github.com/redis/go-redis/v9/logging"
	"golang.org/x/sync/errgroup"
)

// =============================================================================
// MemoryCache Implementation
// =============================================================================

// NewMemoryCache creates a new high-performance in-memory cache.
func NewMemoryCache(size int) *MemoryCache {
	if size <= 0 {
		size = DefaultMemoryCacheSize
	}
	LogInfo("CACHE: Memory cache enabled (limit=%d)", size)
	return &MemoryCache{
		entries: make(map[string]*memoryCacheItem),
		order:   list.New(),
		limit:   size,
	}
}

func (mc *MemoryCache) touchEntryLocked(item *memoryCacheItem) {
	if item == nil || item.element == nil {
		return
	}
	mc.order.MoveToFront(item.element)
}

func (mc *MemoryCache) evictOldestLocked() {
	oldest := mc.order.Back()
	if oldest == nil {
		return
	}
	key, ok := oldest.Value.(string)
	if !ok {
		return
	}
	mc.order.Remove(oldest)
	delete(mc.entries, key)
}

// Get retrieves a value from the memory cache.
func (mc *MemoryCache) Get(key string) (*CacheEntry, bool, bool) {
	if atomic.LoadInt32(&mc.closed) != 0 {
		return nil, false, false
	}

	mc.mu.RLock()
	item, found := mc.entries[key]
	mc.mu.RUnlock()
	if !found || item == nil || item.entry == nil {
		return nil, false, false
	}

	mc.mu.Lock()
	item.entry.AccessTime = time.Now().Unix()
	mc.touchEntryLocked(item)
	cloned := cloneCacheEntry(item.entry)
	mc.mu.Unlock()

	return cloned, true, cloned.IsExpired()
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
		existing.entry = cloneCacheEntry(entry)
		mc.touchEntryLocked(existing)
		return
	}

	element := mc.order.PushFront(key)
	mc.entries[key] = &memoryCacheItem{entry: cloneCacheEntry(entry), element: element}
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

// =============================================================================
// RedisCache Implementation
// =============================================================================

// NewRedisCache creates a new Redis-backed cache
func NewRedisCache(config *ServerConfig) (*RedisCache, error) {
	logging.Disable()

	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.Database,
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

// =============================================================================
// CacheEntry Implementation
// =============================================================================

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

// =============================================================================
// HybridCache Implementation
// =============================================================================

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
